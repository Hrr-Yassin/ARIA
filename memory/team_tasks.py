"""Owner-bound team ledger. Mutations and their polling events commit together."""
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select

from agents.result_contract import AgentResult, normalize_unverified_result, valid_prior_claim_indices
from memory.database_models import ChatLog, DecisionLog, PentestSession, PentestPhase, async_session
from memory.program_policy import owned_engagement
from memory.traffic_observations import HAR_SOURCE, har_metadata_content, verified_har_inspection
from security.har import HAR_CAPTURE_TYPE
from security.redaction import redact, deployment_secrets

Reference = Annotated[str, Field(min_length=1, max_length=100)]
Criterion = Annotated[str, Field(min_length=1, max_length=2000)]

State = Literal['queued', 'running', 'awaiting_review', 'blocked', 'completed', 'cancelled', 'failed', 'analyzed']
Role = Literal['recon', 'scan', 'vuln', 'web_intel', 'correlation', 'report']
TRANSITIONS = {
    'queued': {'running', 'blocked', 'cancelled'},
    'running': {'awaiting_review', 'blocked', 'failed', 'cancelled', 'analyzed'},
    'awaiting_review': {'completed', 'blocked', 'cancelled'},
    'blocked': {'queued', 'cancelled'},
    'completed': set(), 'cancelled': set(), 'failed': set(), 'analyzed': set(),
}
INTERNAL_REVIEW_LIMIT = 2
MAX_ENGAGEMENT_TASKS = 500


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


class PriorReviewClaim(Strict):
    task_id: Reference
    run_id: Reference
    revision: int = Field(strict=True, ge=1)
    hypothesis_index: int = Field(strict=True, ge=0)


class TaskBudget(Strict):
    max_attempts: int = Field(default=2, ge=1, le=10)
    max_model_calls: int = Field(default=5, ge=0, le=50)
    max_tokens: int = Field(default=50000, ge=0, le=1000000)


class TaskSpec(Strict):
    owner_role: Role
    objective: str = Field(min_length=1, max_length=4000)
    dependencies: list[Reference] = Field(default_factory=list, max_length=50)
    evidence_inputs: list[Reference] = Field(default_factory=list, max_length=100)
    budget: TaskBudget = Field(default_factory=TaskBudget)
    expected_output: str = Field(min_length=1, max_length=2000)
    completion_criteria: list[Criterion] = Field(min_length=1, max_length=20)
    security_questions: list[Reference] = Field(default_factory=list, max_length=20)
    phase: Literal['scope', 'reconnaissance', 'scanning', 'vulnerability_analysis', 'exploitation', 'post_exploitation', 'reporting'] | None = None
    specialty: Literal['authorization', 'authentication', 'exposure', 'input_validation', 'business_logic'] | None = None
    internal_review: Literal['analyze', 'challenge'] | None = None
    require_all_evidence: bool = Field(default=False, strict=True)

    @model_validator(mode='after')
    def specialty_questions(self):
        if self.internal_review and (self.owner_role != 'correlation' or self.phase or
                self.specialty or self.security_questions or not self.evidence_inputs):
            raise ValueError('Internal reviews require correlation and saved evidence')
        if self.require_all_evidence and not self.internal_review:
            raise ValueError('Complete evidence is required only for saved reviews')
        if self.specialty and (not self.phase or not self.security_questions or
                len(set(self.security_questions)) != len(self.security_questions)):
            raise ValueError('Specialist tasks require a phase and distinct security question keys')
        return self


class CreateTask(Strict):
    request_id: uuid.UUID
    task: TaskSpec


class MigrateTask(Strict):
    request_id: uuid.UUID
    expected_revision: int = Field(ge=1)
    phase: Literal['scope', 'reconnaissance', 'scanning', 'vulnerability_analysis', 'exploitation', 'post_exploitation', 'reporting']
    security_questions: list[Reference] = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=1, max_length=2000)


class Transition(Strict):
    request_id: uuid.UUID
    expected_revision: int = Field(ge=1)
    state: State
    reason: str = Field(min_length=1, max_length=2000)


class EvidenceInput(Strict):
    request_id: uuid.UUID
    source_kind: Literal['chat', 'worker']
    source_id: str = Field(min_length=1, max_length=100)


class KnowledgeInput(Strict):
    request_id: uuid.UUID
    kind: Literal['observation', 'hypothesis']
    text: str = Field(min_length=1, max_length=4000)
    evidence_references: list[Reference] = Field(default_factory=list, max_length=100)
    uncertainty: str = Field(max_length=2000)
    disposition: Literal['open', 'rejected', 'inconclusive'] = 'open'
    contradicts: list[Reference] = Field(default_factory=list, max_length=100)


class CoverageInput(Strict):
    request_id: uuid.UUID
    key: str = Field(min_length=1, max_length=100)
    question: str = Field(min_length=1, max_length=2000)
    feature: str = Field(min_length=1, max_length=500)
    status: Literal['untested', 'tested', 'unresolved', 'blocked']
    gap_reason: str = Field(max_length=2000)
    evidence_references: list[Reference] = Field(default_factory=list, max_length=100)


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def public(value):
    return redact(value, deployment_secrets())


def materialize(events: list[dict]) -> dict:
    state = {'tasks': {}, 'evidence': {}, 'knowledge': {}, 'coverage': {}, 'verification_findings': {}, 'report_drafts': {}, 'report_signoffs': {},
             'report_outcomes': {}, 'report_retests': {}, 'report_correspondence': {},
             'research_hypotheses': {}, 'research_models': {}, 'investigation_reasoning': {}, 'orchestration_plans': {}, 'cursor': 0}
    for event in events:
        state[event['collection']][event['entity_id']] = event['data']
        state['cursor'] = max(state['cursor'], event['sequence'])
    return state


def transition_task(task: dict, target: str, reason: str, *, internal: bool = False) -> dict:
    if target not in TRANSITIONS[task['state']]:
        raise HTTPException(409, 'Invalid task transition')
    if target in {'running', 'awaiting_review', 'failed', 'analyzed'} and not internal:
        raise HTTPException(403, 'Coordinator owns execution transitions')
    if target == 'completed' and not task.get('result'):
        raise HTTPException(409, 'Review a collected specialist result before completion')
    return {**task, 'state': target, 'reason': public(reason), 'revision': task['revision'] + 1}


def task_id_for_request(sid: str, request_id: uuid.UUID) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-task:{sid}:{request_id}'))


def saved_review_challenge(parent: dict) -> CreateTask | None:
    if parent.get('state') != 'analyzed' or parent.get('internal_review') != 'analyze':
        return None
    claims = (parent.get('result') or {}).get('hypotheses', [])
    refs = list(dict.fromkeys(ref for claim in claims for ref in claim.get('evidence_references', [])))
    if not refs:
        return None
    task_id = parent['id']
    request_id = uuid.uuid5(uuid.NAMESPACE_URL, f'aria-internal-challenge:{task_id}')
    comparison = parent.get('require_all_evidence', False)
    return CreateTask(request_id=request_id, task=TaskSpec(
        owner_role='correlation', internal_review='challenge', dependencies=[task_id],
        evidence_inputs=parent['evidence_inputs'] if comparison else refs, require_all_evidence=comparison,
        objective=parent['objective'], expected_output='Evidence-linked counterinterpretation',
        completion_criteria=['Identify uncertainty'], budget=parent['budget']))


def _task_fields(task: TaskSpec) -> dict:
    excluded = {key for key in ('phase', 'internal_review') if getattr(task, key) is None}
    if not task.require_all_evidence:
        excluded.add('require_all_evidence')
    return task.model_dump(exclude=excluded)


def _queued_task(sid: str, owner: str, task_id: str, fields: dict) -> dict:
    return {**fields, 'id': task_id, 'session_id': sid, 'owner_id': owner, 'state': 'queued',
            'revision': 1, 'attempts': 0, 'result': None, 'created_at': datetime.now(timezone.utc).isoformat()}


def completion_readiness(task: dict, state: dict) -> dict:
    """Describe required human-recorded coverage without treating it as verified."""
    questions = []
    for key in task.get('security_questions', []):
        coverage = state['coverage'].get(key)
        refs = coverage.get('evidence_references', []) if coverage else []
        ready = bool(coverage and coverage.get('status') == 'tested' and refs and
                     all(ref in state['evidence'] for ref in refs))
        questions.append({'key': key, 'ready': ready,
                          'question': coverage.get('question') if coverage else None,
                          'feature': coverage.get('feature') if coverage else None,
                          'status': coverage.get('status') if coverage else 'missing',
                          'evidence_references': list(refs) if ready else []})
    return {'mode': 'security_questions' if questions else 'legacy',
            'ready': task.get('state') == 'awaiting_review' and bool(task.get('result')) and all(item['ready'] for item in questions),
            'questions': questions,
            'limitation': 'Coverage is a human assertion and does not verify a finding.'}


class TeamStore:
    async def _events(self, db, sid: str) -> list[dict]:
        rows = (await db.execute(select(DecisionLog).where(
            DecisionLog.session_id == sid, DecisionLog.decision_type == 'team_event'))).scalars().all()
        return sorted([row.metadata_ for row in rows], key=lambda item: item['sequence'])

    async def view(self, sid: str, owner: str) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            events = await self._events(db, sid)
            state = materialize(events)
            return {**{key: list(value.values()) for key, value in state.items() if key != 'cursor'},
                    'cursor': state['cursor'], 'target': getattr(session, 'target', ''), 'scope': session.scope or {}}

    async def completion_readiness(self, sid: str, owner: str, task_id: str) -> dict:
        async with async_session() as db:
            await owned_engagement(db, sid, owner)
            state = materialize(await self._events(db, sid))
            task = state['tasks'].get(task_id)
            if not task:
                raise HTTPException(404, 'Task not found')
            return {'task_id': task_id, 'revision': task['revision'],
                    **completion_readiness(task, state)}

    async def events(self, sid: str, owner: str, after: int = 0) -> dict:
        async with async_session() as db:
            await owned_engagement(db, sid, owner)
            events = [event for event in await self._events(db, sid) if event['sequence'] > after][:100]
            return {'events': events, 'cursor': events[-1]['sequence'] if events else after}

    async def event_page(self, sid: str, owner: str, after: int | None, limit: int,
                         *, before: int | None = None, entity: tuple[str, str] | None = None) -> tuple[list[dict], bool]:
        """Return the latest page or older-cursor increments without materializing the ledger."""
        async with async_session() as db:
            sequence = DecisionLog.metadata_['sequence'].as_integer()
            query = select(DecisionLog.metadata_).where(DecisionLog.session_id == sid,
                DecisionLog.user_id == owner, DecisionLog.decision_type == 'team_event')
            if entity is not None:
                collection, entity_id = entity
                query = query.join(PentestSession, PentestSession.id == DecisionLog.session_id).where(
                    PentestSession.user_id == owner, DecisionLog.metadata_['collection'].as_string() == collection,
                    DecisionLog.metadata_['entity_id'].as_string() == entity_id)
            if after is None:
                if before is not None:
                    query = query.where(sequence < before)
                query = query.order_by(sequence.desc(), DecisionLog.id.desc())
            else:
                query = query.where(sequence > after).order_by(sequence, DecisionLog.id)
            records = (await db.execute(query.limit(limit + 1))).scalars().all()
            page = records[:limit]
            page = page[::-1] if after is None else page
            if any(not isinstance(record, dict) for record in page):
                raise HTTPException(503, 'Saved team events are unavailable')
            return [record for record in page if isinstance(record, dict)], len(records) > limit

    async def task_trace(self, sid: str, owner: str, task_id: str) -> dict:
        """Read the 50 most recent retained revisions for an owned task."""
        records, truncated = await self.event_page(sid, owner, None, 50, entity=('tasks', task_id))
        if not records:
            raise HTTPException(404, 'Task history unavailable')
        revisions = []
        for event in records:
            task = event['data']
            run_id = task.get('run_id')
            # A later transition can carry the same result. Only the original
            # collection event identifies a newly recorded specialist result.
            result_event = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-team:{sid}:{run_id}:result')) if run_id else None
            claim_event = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-team:{sid}:{run_id}')) if run_id else None
            result = task.get('result') if result_event == event['id'] else None
            revisions.append({
                'event_id': event['id'], 'sequence': event['sequence'], 'timestamp': event['timestamp'],
                'revision': task['revision'], 'state': task['state'], 'role': task['owner_role'],
                'run_id': run_id, 'reason': task.get('reason', '')[:300],
                'dependency_ids': task.get('dependencies', []),
                'dependencies_at_claim': task.get('dependencies_at_claim') if claim_event == event['id'] else None,
                'assigned_evidence_ids': task.get('evidence_inputs', []),
                'prepared_review_evidence': task.get('prepared_review_evidence') if result is not None else None,
                'result_evidence_ids': result.get('evidence_references', []) if result is not None else None,
                'rejections': [entry['detail'][:300] for entry in (result.get('rejections') or [])[:20]
                               if isinstance(entry, dict) and isinstance(entry.get('detail'), str)]
                              if result is not None else None,
            })
        return {'task_id': task_id, 'revisions': revisions, 'truncated': truncated}

    async def task_summary(self, sid: str, owner: str, task_ids) -> dict:
        """Bounded state counts for the given run-linked specialist tasks."""
        ids = [task_id for task_id in (task_ids or [])
               if isinstance(task_id, str) and task_id][:20]
        states = ('queued', 'running', 'awaiting_review', 'blocked',
                  'completed', 'cancelled', 'failed', 'missing')
        counts = {state: 0 for state in states}
        async with async_session() as db:
            await owned_engagement(db, sid, owner)
            if not ids:
                return {'schema': 'aria.specialist.summary.v1',
                        'counts': counts, 'task_ids': [], 'available': True}
            state = materialize(await self._events(db, sid))
            for task_id in ids:
                task = state['tasks'].get(task_id)
                label = task.get('state') if task else 'missing'
                counts[label if label in counts else 'missing'] += 1
        active = sum(counts[name] for name in
                     ('queued', 'running', 'awaiting_review'))
        return {'schema': 'aria.specialist.summary.v1', 'counts': counts,
                'task_ids': ids, 'active': active, 'total': len(ids),
                'available': True}

    async def mutate(self, sid: str, owner: str, request_id: str, operation: dict, build, *,
                     enqueue_review_challenge: bool = False) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            events = await self._events(db, sid)
            event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-team:{sid}:{request_id}'))
            fingerprint = digest(operation)
            previous = next((event for event in events if event['id'] == event_id), None)
            if previous:
                if previous['fingerprint'] != fingerprint:
                    raise HTTPException(409, 'Request ID already bound to a different operation')
                return {**previous, 'duplicate': True}
            state = materialize(events)
            collection, entity_id, data = await build(db, session, state)
            event = {'id': event_id, 'sequence': state['cursor'] + 1, 'collection': collection,
                     'entity_id': entity_id, 'data': public(data), 'fingerprint': fingerprint,
                     'timestamp': datetime.now(timezone.utc).isoformat(), 'actor': owner}
            db.add(DecisionLog(id=event_id, session_id=sid, user_id=owner,
                               decision_type='team_event', metadata_=event))
            if enqueue_review_challenge:
                self._append_review_challenge(db, sid, owner, state, event)
            await db.commit()  # These immutable events also form the durable UI outbox.
            return {**event, 'duplicate': False}

    def _append_review_challenge(self, db, sid: str, owner: str, state: dict, result_event: dict) -> None:
        """Keep a cited result and its queued follow-up in the same transaction."""
        if len(state['tasks']) >= MAX_ENGAGEMENT_TASKS:
            return
        proposal = saved_review_challenge(result_event['data'])
        if proposal is None:
            return
        task_id = task_id_for_request(sid, proposal.request_id)
        if task_id in state['tasks'] or any(ref not in state['evidence'] for ref in proposal.task.evidence_inputs):
            return
        task_data = _task_fields(proposal.task)
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-team:{sid}:{proposal.request_id}'))
        event = {**result_event, 'id': event_id, 'sequence': result_event['sequence'] + 1,
                 'entity_id': task_id, 'data': public(_queued_task(sid, owner, task_id, task_data)),
                 'fingerprint': digest({'create': task_data})}
        db.add(DecisionLog(id=event_id, session_id=sid, user_id=owner, decision_type='team_event', metadata_=event))

    def _references(self, state: dict, references: list[str], collection='evidence') -> None:
        if any(ref not in state[collection] for ref in references):
            raise HTTPException(422, 'Reference is not in this engagement catalog')

    async def create(self, sid: str, owner: str, body: CreateTask) -> dict:
        return await self._create(sid, owner, body, {})

    async def create_investigation(self, sid: str, owner: str, body: CreateTask,
                                   *, campaign_id: str,
                                   investigation_key: str) -> dict:
        """Internal campaign binding for an evidence-driven specialist task.

        These fields are not part of the public ``TaskSpec``: ordinary task
        creation cannot claim to be a campaign investigation or squat a
        semantic investigation identity.
        """
        if (not isinstance(campaign_id, str) or not campaign_id
                or len(campaign_id) > 100
                or not isinstance(investigation_key, str)
                or not re.fullmatch(r'[0-9a-f]{64}', investigation_key)):
            raise ValueError('Specialist investigation metadata is invalid')
        return await self._create(sid, owner, body, {
            'campaign_id': campaign_id,
            'investigation_key': investigation_key,
        })

    async def _create(self, sid: str, owner: str, body: CreateTask,
                      internal: dict) -> dict:
        task_data = _task_fields(body.task)
        if internal and body.task.internal_review:
            raise HTTPException(422, 'Campaign tasks cannot be internal reviews')
        if set(internal) & set(task_data):
            raise ValueError('Internal task metadata conflicts with the task contract')
        task_data.update(internal)
        async def build(db, session, state):
            if len(state['tasks']) >= MAX_ENGAGEMENT_TASKS:
                raise HTTPException(409, 'Engagement task limit reached')
            self._references(state, body.task.dependencies, 'tasks')
            self._references(state, body.task.evidence_inputs)
            task_id = task_id_for_request(sid, body.request_id)
            return 'tasks', task_id, _queued_task(sid, owner, task_id, task_data)
        return await self.mutate(sid, owner, str(body.request_id), {'create': task_data}, build)

    async def migrate_task(self, sid: str, owner: str, task_id: str, body: MigrateTask) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task:
                raise HTTPException(404, 'Task not found')
            if task.get('internal_review'):
                raise HTTPException(409, 'Internal reviews cannot acquire a protected phase')
            if task['revision'] != body.expected_revision:
                raise HTTPException(409, 'Task changed; reload before migration')
            if task['state'] in {'running', 'cancelled', 'failed'}:
                raise HTTPException(409, 'This task cannot be migrated in its current state')
            if task.get('phase') and task.get('security_questions'):
                raise HTTPException(409, 'Task already has phase and security questions')
            if len(set(body.security_questions)) != len(body.security_questions) or not body.reason.strip():
                raise HTTPException(422, 'Distinct questions and a migration reason are required')
            self._references(state, body.security_questions, 'coverage')
            updated = {**task, 'phase': body.phase, 'security_questions': body.security_questions,
                       'revision': task['revision'] + 1, 'migration_reason': public(body.reason)}
            if task['state'] == 'completed':
                # Migration is an explicit new review of the selected evidence.
                review = completion_readiness({**updated, 'state': 'awaiting_review'}, state)
                if not review['ready']:
                    raise HTTPException(409, 'Completed tasks require a result and tested evidence for every question')
                updated['completion_review'] = review['questions']
                updated['reviewed_by'] = owner
            return 'tasks', task_id, updated
        return await self.mutate(sid, owner, str(body.request_id),
            {'migrate_task': task_id, **body.model_dump(mode='json')}, build)

    async def update_phase(self, sid: str, owner: str, phase: str) -> None:
        from config.tools_registry import PENTEST_PHASES
        from orchestrator.workflow_engine import workflow_engine
        if phase not in PENTEST_PHASES:
            raise HTTPException(422, 'Unknown phase')
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            current = getattr(session.current_phase, 'value', session.current_phase) or 'scope'
            if current not in PENTEST_PHASES:
                raise HTTPException(409, 'Current phase is unknown')
            if PENTEST_PHASES.index(phase) > PENTEST_PHASES.index(current):
                if PENTEST_PHASES.index(phase) != PENTEST_PHASES.index(current) + 1:
                    raise HTTPException(409, 'Advance one phase at a time')
                state = materialize(await self._events(db, sid))
                ledger = {key: list(value.values()) for key, value in state.items() if key != 'cursor'}
                if workflow_engine.evidence_readiness(current, ledger)['state'] != 'ready':
                    raise HTTPException(409, 'Current phase requires tested evidence and human review')
            session.current_phase = PentestPhase(phase)
            session.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            await db.commit()
        from memory.session_manager import session_manager
        if session_manager._redis:
            await session_manager._redis.delete(f'session:{sid}')

    async def transition(self, sid: str, owner: str, task_id: str, body: Transition) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task:
                raise HTTPException(404, 'Task not found')
            if task['revision'] != body.expected_revision:
                raise HTTPException(409, 'Task changed; reload before reviewing')
            if (task.get('internal_review') and body.state == 'queued'
                    and task['attempts'] >= task['budget']['max_attempts']):
                raise HTTPException(409, 'Task attempt budget exhausted')
            updated = transition_task(task, body.state, body.reason)
            if body.state == 'completed':
                # Snapshot the exact evidence at review; later coverage edits do not
                # rewrite the historical basis of this completion event.
                readiness = completion_readiness(task, state)
                if not readiness['ready']:
                    raise HTTPException(409, 'Each required security question needs tested coverage and evidence')
                if readiness['mode'] == 'security_questions':
                    updated['completion_review'] = readiness['questions']
                updated['reviewed_by'] = owner
            return 'tasks', task_id, updated
        return await self.mutate(sid, owner, str(body.request_id), {'task': task_id, **body.model_dump(mode='json')}, build)

    async def claim(self, sid: str, owner: str, task_id: str, request_id: str, *,
                    internal_batch: bool = False) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task:
                raise HTTPException(404, 'Task not found')
            if task['state'] != 'queued':
                raise HTTPException(409, 'Only queued tasks can be delegated')
            internal_review = task.get('internal_review')
            if bool(internal_review) != internal_batch or (internal_batch and task.get('campaign_id')):
                raise HTTPException(409, 'Task belongs to a different execution mode')
            dependencies = [state['tasks'][ref] for ref in dict.fromkeys(task['dependencies'])]
            if any(dep['state'] != 'completed' and not (
                    internal_review and dep.get('internal_review') and dep['state'] == 'analyzed')
                   for dep in dependencies):
                raise HTTPException(409, 'Dependencies require completed human review')
            if internal_review and sum(
                    entry['state'] == 'running' and bool(entry.get('internal_review'))
                    for entry in state['tasks'].values()) >= INTERNAL_REVIEW_LIMIT:
                raise HTTPException(409, 'Internal review concurrency limit reached')
            if task['attempts'] >= task['budget']['max_attempts']:
                raise HTTPException(409, 'Task attempt budget exhausted')
            updated = transition_task(task, 'running', 'Delegated to specialist', internal=True)
            updated.update(attempts=task['attempts'] + 1, run_id=request_id, result=None,
                           prepared_review_evidence=None,
                           dependencies_at_claim=[{'task_id': dependency['id'], 'role': dependency['owner_role'],
                               'revision': dependency['revision'], 'run_id': dependency.get('run_id')}
                               for dependency in dependencies])
            updated.pop('prepared_review_claims', None)
            return 'tasks', task_id, updated
        operation: dict[str, str | bool] = {'claim': task_id}
        if internal_batch:
            operation['internal_batch'] = True
        return await self.mutate(sid, owner, request_id, operation, build)

    def _check_prior_review_claims(self, task: dict, state: dict, claims: list[PriorReviewClaim],
                                   evidence: list[str]) -> None:
        if task.get('internal_review') != 'challenge' or len(claims) > 10:
            raise HTTPException(422, 'Prior claim references require a challenge review')
        snapshot = {entry['task_id']: entry for entry in task['dependencies_at_claim']}
        selected = set(evidence)
        for claim in claims:
            dependency = snapshot.get(claim.task_id)
            producer = state['tasks'].get(claim.task_id)
            if (not dependency or not producer or not producer.get('internal_review')
                    or dependency['revision'] != claim.revision or producer['revision'] != claim.revision
                    or dependency.get('run_id') != claim.run_id or producer.get('run_id') != claim.run_id):
                raise HTTPException(422, 'Prior claim does not match the assigned dependency revision')
            hypotheses = (producer.get('result') or {}).get('hypotheses', [])
            if claim.hypothesis_index >= len(hypotheses):
                raise HTTPException(422, 'Prior claim was not retained by its producer')
            refs = hypotheses[claim.hypothesis_index].get('evidence_references', [])
            if not refs or not selected.issuperset(refs):
                raise HTTPException(422, 'Prior claim cites evidence absent from the prepared context')

    async def collect(self, sid: str, owner: str, task_id: str, run_id: str, result: AgentResult, *,
                      prepared_review_evidence: list[str] | None = None,
                      prepared_review_claims: list[PriorReviewClaim] | None = None) -> dict:
        # Storage is the trust boundary.  Even a direct caller cannot persist
        # an LLM observation or hypothesis as verified; worker receipts remain
        # separately cataloged with their own provenance.
        normalized = normalize_unverified_result(result)
        prior_claims = prepared_review_claims or []
        prepared_claim_records = [claim.model_dump() for claim in prior_claims]
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task or task['state'] != 'running' or task['run_id'] != run_id:
                raise HTTPException(409, 'Task no longer owns this specialist run')
            self._references(state, normalized.evidence_references)
            if not set(normalized.evidence_references).issubset(task['evidence_inputs']):
                raise HTTPException(422, 'Result cites evidence outside its task inputs')
            for entry in normalized.observations + normalized.hypotheses:
                refs = entry.get('evidence_references', [])
                if entry.get('evidence_id'):
                    refs = [*refs, entry['evidence_id']]
                if not set(refs).issubset(normalized.evidence_references):
                    raise HTTPException(422, 'Conclusion cites unattributed evidence')
                if not refs and not normalized.uncertainty:
                    raise HTTPException(422, 'Unattributed conclusions require explicit uncertainty')
            if not normalized.evidence_references and not normalized.uncertainty:
                raise HTTPException(422, 'Result requires evidence or explicit uncertainty')
            for hypothesis in normalized.hypotheses:
                indices = hypothesis.get('prior_claim_indices', [])
                if (not valid_prior_claim_indices(indices, len(prior_claims)) or
                        (indices and not hypothesis.get('evidence_references'))):
                    raise HTTPException(422, 'Interpretation cites an unprepared prior claim')
            target = 'blocked' if normalized.status == 'blocked' else 'awaiting_review'
            if task.get('internal_review'):
                if prepared_review_evidence is None or normalized.proposed_actions or normalized.status == 'proposed':
                    raise HTTPException(422, 'Internal reviews require prepared evidence and analysis only')
                if normalized.status == 'analysis':
                    if task.get('require_all_evidence') and set(prepared_review_evidence) != set(task['evidence_inputs']):
                        raise HTTPException(422, 'Comparison requires all assigned evidence to be prepared')
                    target = 'analyzed'
            updated = transition_task(task, target, 'Specialist result collected', internal=True)
            updated['result'] = normalized.model_dump()
            if prepared_review_evidence is not None:
                if (task['owner_role'] not in {'correlation', 'report'} or
                        not set(prepared_review_evidence).issubset(task['evidence_inputs'])):
                    raise HTTPException(422, 'Prepared review evidence must belong to the review task')
                if not set(normalized.evidence_references).issubset(prepared_review_evidence):
                    raise HTTPException(422, 'Review result cites evidence absent from its prepared context')
                updated['prepared_review_evidence'] = prepared_review_evidence
            if prior_claims:
                self._check_prior_review_claims(task, state, prior_claims, prepared_review_evidence or [])
                updated['prepared_review_claims'] = prepared_claim_records
            return 'tasks', task_id, updated
        operation = {'collect': task_id, 'result': normalized.model_dump()}
        if prepared_review_evidence is not None:
            operation['prepared_review_evidence'] = prepared_review_evidence
        if prior_claims:
            operation['prepared_review_claims'] = prepared_claim_records
        return await self.mutate(sid, owner, run_id + ':result', operation, build,
                                 enqueue_review_challenge=True)

    async def block(self, sid: str, owner: str, task_id: str, run_id: str, reason: str, *, failed: bool = False) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task or task['state'] != 'running' or task.get('run_id') != run_id:
                raise HTTPException(409, 'Task no longer owns this run')
            return 'tasks', task_id, transition_task(task, 'failed' if failed else 'blocked', reason, internal=True)
        return await self.mutate(sid, owner, run_id + ':blocked', {'block': task_id, 'reason': reason, 'failed': failed}, build)

    async def catalog(self, sid: str, owner: str, body: EvidenceInput) -> dict:
        async def build(db, session, state):
            if body.source_kind == 'chat':
                row = (await db.execute(select(ChatLog).where(ChatLog.session_id == sid,
                    ChatLog.id == body.source_id, ChatLog.role == 'tool_output'))).scalar_one_or_none()
                if not row:
                    raise HTTPException(404, 'Owned evidence not found')
                data = row.data or {}
                if not isinstance(data, dict):
                    raise HTTPException(409, 'Saved evidence metadata is unavailable')
                content = row.content or ''
                provenance = data.get('source', 'manual_unverified')
                is_har = row.msg_type == HAR_CAPTURE_TYPE or provenance == HAR_SOURCE
                if is_har:
                    retained = data.get('summary')
                    if (row.msg_type != HAR_CAPTURE_TYPE or provenance != HAR_SOURCE or not isinstance(retained, dict)
                            or verified_har_inspection(sid, body.source_id, retained, data.get('sealed_inspection')) is None
                            or content != har_metadata_content(body.source_id, retained)):
                        raise HTTPException(409, {'code': 'har_integrity_invalid',
                                                  'message': 'Saved HAR capture failed integrity validation'})
                hashes = {'content_sha256': hashlib.sha256(content.encode()).hexdigest()}
                if row.msg_type == 'burp_evidence':
                    hashes['capture_sha256'] = data['digest']
                source_time, summary = row.created_at.isoformat(), public(content[:2000])
                job_id = None if is_har else data.get('job_id')
            else:
                from memory.worker_jobs import (
                    SQLJobStore, TERMINAL, attested_declared_version, catalogable_receipt_hashes,
                    saved_source_review,
                )
                row = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == sid,
                    DecisionLog.id == SQLJobStore.key(body.source_id),
                    DecisionLog.decision_type == 'worker_job'))).scalar_one_or_none()
                if not row or not isinstance(row.metadata_, dict):
                    raise HTTPException(404, 'Terminal worker receipt not found')
                data = row.metadata_
                state_name = data.get('state')
                if not isinstance(state_name, str) or state_name not in TERMINAL:
                    raise HTTPException(404, 'Terminal worker receipt not found')
                exit_code = data.get('exit_code')
                try:
                    hashes = catalogable_receipt_hashes(data)
                except ValueError as error:
                    raise HTTPException(409, str(error)) from None
                exit_status = str(exit_code) if type(exit_code) is int else 'not recorded'
                source_time, summary = row.created_at.isoformat(), f'Worker observation: {state_name}; exit {exit_status}'
                version = attested_declared_version(data)
                capability = data.get('adapter_capability')
                if version and isinstance(capability, str) and re.fullmatch(r'[a-z0-9_.-]{1,100}', capability):
                    summary += f'; capability {capability}; attested declared version {version}'
                review = saved_source_review(data)
                if review:
                    parser = review['parser_status'].replace('_', ' ')
                    summary += f". Saved source review: {parser}; {review['unverified_observations']} unverified observations"
                    if 'dynamic_python_evaluation_matches' in review:
                        summary += f"; {review['dynamic_python_evaluation_matches']} dynamic Python evaluation rule matches"
                    summary += '; output truncated.' if review['truncated'] else '.'
                else:
                    summary += '. Receipt metadata only.'
                job_id, provenance = body.source_id, 'worker_receipt'
            eid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-evidence:{sid}:{body.source_kind}:{body.source_id}'))
            existing = state['evidence'].get(eid)
            entry = {'id': eid, 'owner_id': owner, 'session_id': sid, 'source_kind': body.source_kind,
                'source_id': body.source_id, 'job_id': job_id, 'source_timestamp': source_time,
                'cataloged_at': datetime.now(timezone.utc).isoformat(), 'hashes': hashes,
                'summary': summary, 'provenance': provenance, 'trust': 'untrusted_observation'}
            if existing:
                if existing['hashes'] != hashes:
                    raise HTTPException(409, 'Source changed after cataloging')
                entry = existing
            return 'evidence', eid, entry
        return await self.mutate(sid, owner, str(body.request_id), body.model_dump(mode='json'), build)

    async def knowledge(self, sid: str, owner: str, body: KnowledgeInput) -> dict:
        async def build(db, session, state):
            self._references(state, body.evidence_references)
            self._references(state, body.contradicts, 'knowledge')
            if not body.evidence_references and not body.uncertainty.strip():
                raise HTTPException(422, 'Evidence or explicit uncertainty is required')
            kid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-knowledge:{sid}:{body.request_id}'))
            return 'knowledge', kid, {**body.model_dump(mode='json'), 'id': kid, 'verified': False}
        return await self.mutate(sid, owner, str(body.request_id), body.model_dump(mode='json'), build)

    async def coverage(self, sid: str, owner: str, body: CoverageInput) -> dict:
        async def build(db, session, state):
            self._references(state, body.evidence_references)
            if body.status == 'tested' and not body.evidence_references:
                raise HTTPException(422, 'Tested coverage requires evidence')
            if body.status != 'tested' and not body.gap_reason.strip():
                raise HTTPException(422, 'Untested or unresolved coverage requires a reason')
            return 'coverage', body.key, body.model_dump(mode='json')
        return await self.mutate(sid, owner, str(body.request_id), body.model_dump(mode='json'), build)

    async def recover(self) -> None:
        async with async_session() as db:
            sessions = (await db.execute(select(PentestSession).where(
                PentestSession.status == 'active').with_for_update())).scalars().all()
            for session in sessions:
                events = await self._events(db, session.id)
                state = materialize(events)
                sequence = state['cursor']
                for task in state['tasks'].values():
                    if task['state'] != 'running':
                        continue
                    sequence += 1
                    updated = transition_task(task, 'blocked', 'Restart reconciliation; no specialist or command replayed', internal=True)
                    event_id = str(uuid.uuid4())
                    event = {'id': event_id, 'sequence': sequence, 'collection': 'tasks',
                             'entity_id': task['id'], 'data': updated, 'fingerprint': '',
                             'timestamp': datetime.now(timezone.utc).isoformat(), 'actor': 'recovery'}
                    db.add(DecisionLog(id=event_id, session_id=session.id, user_id=session.user_id,
                                       decision_type='team_event', metadata_=event))
            await db.commit()


team_store = TeamStore()
