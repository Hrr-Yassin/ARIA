"""Versioned, owner-bound program research. Imported text is never authority.

Snapshots and review events use the existing durable DecisionLog ledger. Keeping
these engagement-bound also applies the existing retention/ownership boundary.
"""
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from orchestrator.program_scope import ExecutionRules

from memory.database_models import DecisionLog, PentestSession, async_session

CATEGORIES = ('included_assets', 'exclusions', 'eligible_issue_classes',
              'account_requirements', 'automation_restrictions', 'prerequisites')
HEADINGS = {
    'in scope': 'included_assets', 'included assets': 'included_assets',
    'out of scope': 'exclusions', 'exclusions': 'exclusions',
    'eligible issue classes': 'eligible_issue_classes',
    'account requirements': 'account_requirements',
    'automation restrictions': 'automation_restrictions',
    'prerequisites': 'prerequisites',
}


class ProgramImport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=200)
    source_url: str = Field(max_length=2048)
    text: str = Field(min_length=1, max_length=200000)
    program_type: Literal['paid_bounty', 'disclosure_only', 'unknown'] = 'unknown'
    retrieved_at: datetime | None = None

    @field_validator('retrieved_at')
    @classmethod
    def retrieval_has_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError('Retrieval time must include a timezone')
        if value is not None and value > datetime.now(timezone.utc):
            raise ValueError('Retrieval time cannot be in the future')
        return value

    @field_validator('source_url')
    @classmethod
    def source_is_https(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError('Use the official HTTPS program policy URL without credentials or fragment')
        return value


class ProgramRecord(BaseModel):
    """One researcher-owned candidate per engagement; revisions share this ID."""
    model_config = ConfigDict(extra='forbid')
    id: str
    engagement_id: str
    owner_id: str
    name: str
    source_url: str
    program_type: Literal['paid_bounty', 'disclosure_only', 'unknown']


class PolicySnapshot(BaseModel):
    """Immutable source record, distinct from a human review or execution policy."""
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal[1] = 1
    program: ProgramRecord
    id: str
    session_id: str
    engagement_owner: str
    revision: int = Field(ge=1)
    name: str
    source_url: str
    retrieved_at: datetime | None
    imported_at: datetime
    import_method: Literal['manual_text', 'public_https'] = 'manual_text'
    response_sha256: str | None = None
    source_verified: Literal[False] = False
    content_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    source_text: str
    program_type: Literal['paid_bounty', 'disclosure_only', 'unknown']
    program_type_status: Literal['researcher_supplied'] = 'researcher_supplied'
    state: Literal['draft'] = 'draft'
    discovery_authorizes_testing: Literal[False] = False
    rules: dict[str, list[dict]]
    unknown: list[str]


class RuleReview(BaseModel):
    model_config = ConfigDict(extra='forbid')
    category: Literal['included_assets', 'exclusions', 'eligible_issue_classes',
                      'account_requirements', 'automation_restrictions', 'prerequisites']
    quote: str = Field(min_length=1, max_length=4000)
    start: int = Field(ge=0)
    interpretation: str = Field(min_length=1, max_length=2000)


class PolicyReview(BaseModel):
    model_config = ConfigDict(extra='forbid')
    content_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    rules: list[RuleReview] = Field(max_length=200)
    decision: Literal['reviewed', 'rejected']
    note: str = Field(min_length=1, max_length=4000)
    execution: ExecutionRules | None = None


def extract_rules(text: str) -> dict:
    """Conservative heading parser: preserve quotes; never infer permissions."""
    rules = {key: [] for key in CATEGORIES}
    category = None
    offset = 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        heading = stripped.strip('# :').lower()
        if heading in HEADINGS:
            category = HEADINGS[heading]
        elif stripped and category:
            # Unknown Markdown headings terminate the current section.
            if stripped.startswith('#') or stripped.endswith(':'):
                category = None
            else:
                start = offset + line.index(stripped)
                rules[category].append({'quote': stripped, 'start': start,
                                        'end': start + len(stripped), 'status': 'draft', 'permission': 'unknown'})
        offset += len(line)
    return {'rules': rules, 'unknown': [key for key, value in rules.items() if not value]}


def make_snapshot(body: ProgramImport, session_id: str, owner_id: str, revision: int) -> dict:
    program = ProgramRecord(id=str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-program:' + session_id)),
                            engagement_id=session_id, owner_id=owner_id, name=body.name,
                            source_url=body.source_url, program_type=body.program_type)
    data = {'program': program.model_dump(), 'schema_version': 1, 'id': str(uuid.uuid4()), 'session_id': session_id,
            'engagement_owner': owner_id, 'revision': revision, 'name': body.name,
            'source_url': body.source_url,
            'retrieved_at': body.retrieved_at.isoformat() if body.retrieved_at else None,
            'imported_at': datetime.now(timezone.utc).isoformat(),
            'import_method': 'manual_text', 'source_verified': False,
            'content_sha256': hashlib.sha256(body.text.encode()).hexdigest(),
            'source_text': body.text, 'program_type': body.program_type,
            'program_type_status': 'researcher_supplied', 'state': 'draft',
            'discovery_authorizes_testing': False, **extract_rules(body.text)}
    return PolicySnapshot.model_validate(data).model_dump(mode='json')


def validate_review(snapshot: dict, review: PolicyReview) -> dict:
    if snapshot['content_sha256'] != review.content_sha256:
        raise HTTPException(409, 'Policy content changed; review the current snapshot')
    for rule in review.rules:
        if snapshot['source_text'][rule.start:rule.start + len(rule.quote)] != rule.quote:
            raise HTTPException(422, 'Every rule must quote its exact source text at the recorded offset')
    if review.execution is not None:
        validate_execution_sources(review)
    categories = {rule.category for rule in review.rules}
    return {**review.model_dump(), 'unknown': sorted(set(CATEGORIES) - categories),
            'execution_enabled': False}


def validate_execution_sources(review: PolicyReview) -> None:
    execution = review.execution
    def source(index: int, category: str):
        if index >= len(review.rules) or review.rules[index].category != category:
            raise HTTPException(422, 'Execution fields must reference a source-linked rule of the correct category')
    for asset in execution.assets:
        source(asset.source_rule, 'included_assets')
    for asset in execution.exclusions + execution.third_party_exclusions:
        source(asset.source_rule, 'exclusions')
    for index, category in [(execution.automation_source_rule, 'automation_restrictions'),
                            (execution.budget_source_rule, 'automation_restrictions'),
                            (execution.accounts_source_rule, 'account_requirements'),
                            (execution.prerequisites_source_rule, 'prerequisites'),
                            (execution.classes_source_rule, 'eligible_issue_classes'),
                            (execution.exclusions_source_rule, 'exclusions')]:
        source(index, category)


async def owned_engagement(db, session_id: str, owner_id: str):
    # No administrator override: only the engagement owner can review its policy.
    row = (await db.execute(select(PentestSession).where(
        PentestSession.id == session_id, PentestSession.user_id == owner_id).with_for_update())).scalar_one_or_none()
    if not row:
        raise HTTPException(404, 'Engagement not found')
    if str(getattr(row.status, 'value', row.status)) != 'active':
        raise HTTPException(409, 'Engagement is not active')
    return row


class ProgramPolicyStore:
    async def status(self, session_id: str, owner_id: str) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, session_id, owner_id)
            policy = (session.scope or {}).get('program_policy') or {}
            metadata = session.metadata_ or {}
            used = int(metadata.get('program_requests_used', 0))
            limit = policy.get('rules', {}).get('max_requests')
            return {'state': policy.get('state', 'unactivated'), 'requests_used': used,
                    'request_limit': limit, 'remaining': max(0, limit - used) if limit is not None else None,
                    'next_request_at': metadata.get('program_next_request_at'),
                    'backoff_until': metadata.get('program_backoff_until'),
                    'overloaded': bool(metadata.get('program_overloaded'))}

    async def history(self, session_id: str, owner_id: str) -> list[dict]:
        async with async_session() as db:
            await owned_engagement(db, session_id, owner_id)
            rows = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type.in_(['program_policy_snapshot', 'program_policy_review', 'program_policy_activation', 'program_fit']))
                .order_by(DecisionLog.created_at, DecisionLog.id))).scalars().all()
            return [{'id': row.id, 'type': row.decision_type, 'data': row.metadata_} for row in rows]

    async def import_text(self, session_id: str, owner_id: str, body: ProgramImport, fetched: dict | None = None) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, session_id, owner_id)
            rows = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == 'program_policy_snapshot'))).scalars().all()
            revision = max((row.metadata_['revision'] for row in rows), default=0) + 1
            snapshot = make_snapshot(body, session_id, owner_id, revision)
            if fetched:
                snapshot.update(import_method='public_https', response_sha256=fetched['response_sha256'])
            # Once activated, every subsequent source revision suspends all dispatch.
            if (session.scope or {}).get('program_policy'):
                scope = dict(session.scope)
                scope['program_policy'] = {**scope['program_policy'], 'state': 'suspended', 'pending_snapshot': snapshot['id']}
                session.scope = scope
                metadata = dict(session.metadata_ or {})
                metadata['worker_epoch'] = int(metadata.get('worker_epoch', 0)) + 1
                session.metadata_ = metadata
            snapshot['execution_suspended'] = bool((session.scope or {}).get('program_policy'))
            db.add(DecisionLog(id=snapshot['id'], session_id=session_id, user_id=owner_id,
                               decision_type='program_policy_snapshot', metadata_=snapshot))
            await db.commit()
            return snapshot

    async def review(self, session_id: str, owner_id: str, snapshot_id: str, body: PolicyReview) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, session_id, owner_id)
            rows = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == 'program_policy_snapshot'))).scalars().all()
            row = next((row for row in rows if row.id == snapshot_id), None)
            if not row:
                raise HTTPException(404, 'Policy snapshot not found')
            if row.metadata_['revision'] != max(row.metadata_['revision'] for row in rows):
                raise HTTPException(409, 'A newer policy snapshot requires review')
            result = {**validate_review(row.metadata_, body), 'id': str(uuid.uuid4()), 'snapshot_id': snapshot_id,
                      'reviewer_id': owner_id, 'reviewed_at': datetime.now(timezone.utc).isoformat()}
            if (session.scope or {}).get('program_policy'):
                scope = dict(session.scope)
                scope['program_policy'] = {**scope['program_policy'], 'state': 'suspended'}
                session.scope = scope
                metadata = dict(session.metadata_ or {})
                metadata['worker_epoch'] = int(metadata.get('worker_epoch', 0)) + 1
                session.metadata_ = metadata
                result['execution_suspended'] = True
            db.add(DecisionLog(id=result['id'], session_id=session_id, user_id=owner_id,
                               decision_type='program_policy_review', human_involved=True,
                               human_decision=body.decision, metadata_=result))
            await db.commit()
            return result


    async def activate(self, session_id: str, owner_id: str, snapshot_id: str, review_id: str) -> dict:
        from memory.worker_jobs import TERMINAL
        from memory.database_models import WebAction
        async with async_session() as db:
            session = await owned_engagement(db, session_id, owner_id)
            snapshots = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == 'program_policy_snapshot'))).scalars().all()
            latest = max(snapshots, key=lambda row: row.metadata_['revision'], default=None)
            if not latest or latest.id != snapshot_id:
                raise HTTPException(409, 'Review the latest policy snapshot')
            reviews = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == 'program_policy_review').order_by(DecisionLog.created_at.desc()))).scalars().all()
            review = next((row for row in reviews if row.metadata_['snapshot_id'] == snapshot_id), None)
            if not review or review.id != review_id or review.user_id != owner_id:
                raise HTTPException(409, 'The latest owner review is required')
            body = PolicyReview.model_validate({key: review.metadata_[key] for key in PolicyReview.model_fields if key in review.metadata_})
            validate_review(latest.metadata_, body)
            if body.decision != 'reviewed' or body.execution is None:
                raise HTTPException(409, 'An explicit execution policy review is required')
            rules = body.execution
            if (rules.automation != 'allowed' or not rules.accounts_confirmed or
                    not rules.prerequisites_confirmed or not rules.permission_confirmed):
                raise HTTPException(403, 'Unknown or prohibited permission cannot activate testing')
            jobs = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id, DecisionLog.decision_type == 'worker_job',
                DecisionLog.metadata_['state'].as_string().not_in(TERMINAL)))).scalars().all()
            web = (await db.execute(select(WebAction).where(WebAction.session_id == session_id,
                WebAction.state.in_(['claimed', 'unknown', 'cancel_requested'])))).scalars().all()
            if jobs or web:
                raise HTTPException(409, 'Stop and reconcile active execution before activating policy')
            policy = {'state': 'active', 'snapshot_id': snapshot_id, 'review_id': review_id,
                      'content_sha256': latest.metadata_['content_sha256'], 'rules': rules.model_dump(),
                      'activated_by': owner_id, 'activation_id': str(uuid.uuid4())}
            # Budgets live in metadata and NEVER reset when a policy is revised.
            session.scope = {'targets': [asset.host for asset in rules.assets], 'exclusions': [],
                             'program_policy': policy}
            metadata = dict(session.metadata_ or {})
            metadata['worker_epoch'] = int(metadata.get('worker_epoch', 0)) + 1
            metadata['worker_blocked'] = False
            session.metadata_ = metadata
            db.add(DecisionLog(session_id=session_id, user_id=owner_id,
                               decision_type='program_policy_activation', human_involved=True,
                               human_decision='activate', metadata_=policy))
            await db.commit()
            return policy


program_policies = ProgramPolicyStore()


class ProgramFit(BaseModel):
    model_config = ConfigDict(extra='forbid')
    technical_fit: Literal['good', 'partial', 'poor', 'unknown'] = 'unknown'
    accessible_accounts: Literal['yes', 'no', 'unknown'] = 'unknown'
    eligible_classes: Literal['yes', 'no', 'unknown'] = 'unknown'
    automation_compatibility: Literal['yes', 'no', 'unknown'] = 'unknown'
    research_cost: Literal['low', 'medium', 'high', 'unknown'] = 'unknown'
    participation_eligibility: Literal['confirmed', 'ineligible', 'unknown'] = 'unknown'
    basis: str = Field(min_length=1, max_length=4000)


def rank_candidate(snapshot: dict, fit: dict | None) -> dict:
    fit = ProgramFit.model_validate(fit or {'basis': 'Not assessed'}).model_dump()
    mappings = {'technical_fit': {'good': 2, 'partial': 1, 'poor': 0},
                'accessible_accounts': {'yes': 2, 'no': 0},
                'eligible_classes': {'yes': 2, 'no': 0},
                'automation_compatibility': {'yes': 2, 'no': 0},
                'research_cost': {'low': 2, 'medium': 1, 'high': 0}}
    scores = {key: values.get(fit[key]) for key, values in mappings.items()}
    return {'program_id': snapshot.get('program', {}).get('id', str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-program:' + snapshot['session_id']))), 'snapshot_id': snapshot['id'], 'session_id': snapshot['session_id'],
            'name': snapshot['name'], 'source_url': snapshot['source_url'],
            'program_type': snapshot['program_type'], 'fit': fit, 'scores': scores,
            'score': sum(value for value in scores.values() if value is not None),
            'unknown': [key for key, value in fit.items() if value == 'unknown'],
            'prerequisites': snapshot['rules']['prerequisites'],
            'discovery_authorizes_testing': False}


async def program_catalog(owner_id: str) -> list[dict]:
    async with async_session() as db:
        rows = (await db.execute(select(DecisionLog).join(PentestSession,
            DecisionLog.session_id == PentestSession.id).where(PentestSession.user_id == owner_id,
            DecisionLog.decision_type.in_(['program_policy_snapshot', 'program_fit']))
            .order_by(DecisionLog.created_at, DecisionLog.id))).scalars().all()
        snapshots, fits = {}, {}
        for row in rows:
            if row.decision_type == 'program_policy_snapshot':
                old = snapshots.get(row.session_id)
                if not old or old['revision'] < row.metadata_['revision']:
                    snapshots[row.session_id] = row.metadata_
            else:
                fits[row.metadata_['snapshot_id']] = row.metadata_['fit']
        candidates = [rank_candidate(snapshot, fits.get(snapshot['id'])) for snapshot in snapshots.values()]
        return sorted(candidates, key=lambda item: (-item['score'], len(item['unknown']), item['name']))


async def save_program_fit(session_id: str, owner_id: str, snapshot_id: str, fit: ProgramFit) -> dict:
    async with async_session() as db:
        await owned_engagement(db, session_id, owner_id)
        row = (await db.execute(select(DecisionLog).where(DecisionLog.id == snapshot_id,
            DecisionLog.session_id == session_id, DecisionLog.decision_type == 'program_policy_snapshot'))).scalar_one_or_none()
        if not row:
            raise HTTPException(404, 'Policy snapshot not found')
        db.add(DecisionLog(session_id=session_id, user_id=owner_id, decision_type='program_fit',
                           metadata_={'snapshot_id': snapshot_id, 'fit': fit.model_dump()}))
        await db.commit()
        return rank_candidate(row.metadata_, fit.model_dump())
