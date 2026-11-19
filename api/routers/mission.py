"""Read-only Mission Control projections of owner-scoped retained records."""
from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import AwareDatetime, Field, ValidationError
from sqlalchemy import and_, func, or_, select

from agents.autonomous_engine import autonomous_engine
from api.auth import TokenData, get_current_user
from api.session_access import get_accessible_session
from llm.engagement_budget import MAX_ATTEMPTS, USAGE_FIELDS, model_accounting
from llm.request_metrics import safe_timings
from memory.campaign_observability import MAX_EVENTS, operations_view
from memory.campaign_store import LIVE_STATES, TERMINAL_STATES, campaign_store
from memory.command_registry import command_registry
from memory.database_models import AutonomousCampaign, DecisionLog, PentestSession, WebAction, async_session
from memory.team_tasks import Strict, team_store
from memory.worker_jobs import STATES
from orchestrator.team_coordinator import team_coordinator

router = APIRouter()

RecordID = Annotated[str, Field(min_length=1, max_length=100, pattern=r'^[A-Za-z0-9._:-]+$')]
Source = Literal['team', 'campaign']
CAPTURED_STAGES = {
    'tasks': 'Agent task', 'evidence': 'Evidence', 'coverage': 'Verification',
    'verification_findings': 'Verification', 'research_hypotheses': 'Planning',
    'research_models': 'Observation', 'knowledge': 'Observation',
    'report_drafts': 'Review', 'report_signoffs': 'Review', 'report_outcomes': 'Outcome',
    'report_retests': 'Verification', 'report_correspondence': 'Review',
}
CAMPAIGN_STAGES = {
    'campaign_created': 'Objective', 'campaign_step_succeeded': 'Observation',
    'campaign_completed': 'Outcome', 'campaign_cancelled': 'Outcome',
    'campaign_failed': 'Outcome', 'campaign_stopped': 'Outcome',
}


class TimelineEvent(Strict):
    id: RecordID
    source: Source
    sequence: Annotated[int, Field(strict=True, ge=1)]
    timestamp: AwareDatetime
    kind: RecordID
    stage: str
    session_id: RecordID
    entity_id: RecordID | None = None
    campaign_id: RecordID | None = None
    run_id: RecordID | None = None
    agent: RecordID | None = None
    task_id: RecordID | None = None
    job_id: RecordID | None = None
    state: RecordID | None = None
    reason_code: RecordID | None = None
    correlation_id: RecordID | None = None
    evidence_ids: list[RecordID] = Field(default_factory=list, max_length=100)
    dependency_ids: list[RecordID] = Field(default_factory=list, max_length=50)


class EventPage(Strict):
    state: Literal['available', 'not_started', 'unavailable']
    cursor: int | None = None
    oldest: int | None = None
    has_more: bool = False
    has_older: bool = False
    gap: bool = False
    rejected_records: int = 0
    campaign_id: RecordID | None = None
    events: list[TimelineEvent] = Field(default_factory=list)


class Timeline(Strict):
    schema_version: Literal['aria.mission.events.v1'] = 'aria.mission.events.v1'
    team: EventPage
    campaign: EventPage


async def require_owner(sid: str, user: TokenData) -> None:
    session = await get_accessible_session(sid, user)
    if session.get('user_id') != user.user_id:
        raise HTTPException(403, 'Mission records are available to the session owner')


def identifier(value) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,100}', value) else None


def references(data: dict, field: str, limit: int) -> list[str]:
    values = data.get(field)
    if not isinstance(values, list):
        return []
    return list(dict.fromkeys(clean for value in values[:limit] if (clean := identifier(value))))


def as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def team_event(sid: str, record: dict) -> TimelineEvent:
    kind = record['collection']
    data = record['data']
    entity = identifier(record.get('entity_id'))
    source_id = identifier(data.get('source_id')) if kind == 'evidence' and data.get('source_kind') == 'worker' else None
    refs = references(data, 'evidence_inputs', 100) if kind == 'tasks' else references(data, 'evidence_references', 100)
    if kind == 'evidence' and entity:
        refs = [entity]
    return TimelineEvent(id=record['id'], sequence=record['sequence'], timestamp=record['timestamp'],
        source='team', kind=kind, stage=CAPTURED_STAGES[kind], session_id=sid, entity_id=entity,
        agent=identifier(data.get('owner_role')), campaign_id=identifier(data.get('campaign_id')),
        run_id=identifier(data.get('run_id')), task_id=entity if kind == 'tasks' else None, job_id=source_id,
        state=identifier(data.get('state')), evidence_ids=refs,
        dependency_ids=references(data, 'dependencies', 50) if kind == 'tasks' else [])


async def get_team_page(sid: str, owner: str, after: int | None, limit: int,
                        before: int | None) -> EventPage:
    window = {'before': before} if before is not None else {}
    records, more = await team_store.event_page(sid, owner, after, limit, **window)
    events = []
    sequences = []
    rejected = 0
    for record in records:
        if isinstance(record, dict) and type(record.get('sequence')) is int and record['sequence'] > 0:
            sequences.append(record['sequence'])
        try:
            events.append(team_event(sid, record))
        except (ValidationError, AttributeError, KeyError, TypeError):
            rejected += 1
    previous = after if after is not None else (sequences[0] - 1 if sequences else 0)
    gap = any(seq - prior != 1 for prior, seq in zip([previous, *sequences], sequences))
    gap = gap or bool(before and sequences and sequences[-1] != before - 1)
    return EventPage(state='available', cursor=max(sequences, default=after or 0),
                     oldest=sequences[0] if sequences else None, has_more=bool(more and after is not None),
                     has_older=bool(more and after is None),
                     gap=gap or rejected > 0, rejected_records=rejected, events=events)


async def get_campaign_page(sid: str, owner: str, cid: str | None, after: int, limit: int) -> EventPage:
    row = await campaign_store.latest_for_session(sid)
    if row is None:
        return EventPage(state='not_started')
    if row.get('owner_id') != owner or not identifier(row.get('id')):
        raise HTTPException(403, 'Campaign access denied')
    return campaign_event_page(sid, row['id'], row.get('operations'), after, limit, same=cid == row['id'])


def campaign_event_page(sid: str, cid: str, operations: object, after: int, limit: int, *, same: bool = False) -> EventPage:
    raw = operations_view(operations, after=0)
    records = raw['events']
    oldest = records[0]['sequence'] if records else None
    rewound = bool(same and after > raw['next_cursor'])
    if not same or rewound or after == 0:
        selected = records[-limit:]
    else:
        selected = [record for record in records if record['sequence'] > after][:limit]
    cursor = selected[-1]['sequence'] if selected else (after if same and not rewound else 0)
    events = [TimelineEvent(id=r['id'], sequence=r['sequence'], timestamp=r['timestamp'], source='campaign',
        kind=r['event'], stage=CAMPAIGN_STAGES.get(r['event'], 'Campaign supervision'), session_id=sid,
        campaign_id=cid, state=identifier(r['to_state']), reason_code=identifier(r['reason_code']),
        correlation_id=identifier(r['correlation_id']), run_id=identifier(r['attributes'].get('run_id')))
        for r in selected]
    skipped = any(b['sequence'] != a['sequence'] + 1 for a, b in zip(records, records[1:]))
    return EventPage(state='available', cursor=cursor, oldest=oldest, campaign_id=cid,
                     has_more=cursor < raw['next_cursor'], events=events,
                     gap=skipped or rewound or bool(oldest and ((same and after and oldest > after + 1) or
                                                     (not same and oldest > 1))))


async def available_source(operation) -> EventPage:
    try:
        async with asyncio.timeout(4):
            return await operation
    except Exception:
        return EventPage(state='unavailable')


@router.get('/{sid}/events', response_model=Timeline)
async def timeline(sid: RecordID, response: Response,
                   team_after: int | None = Query(None, ge=0, le=2_147_483_647),
                   team_before: int | None = Query(None, ge=1, le=2_147_483_647),
                   campaign_after: int = Query(0, ge=0, le=1_000_000_000),
                   campaign_id: RecordID | None = Query(None), limit: int = Query(50, ge=1, le=100),
                   user: TokenData = Depends(get_current_user)) -> Timeline:
    await require_owner(sid, user)
    if team_after is not None and team_before is not None:
        raise HTTPException(422, 'Use either an older or a newer team cursor')
    response.headers['Cache-Control'] = 'no-store'
    team, campaign = await asyncio.gather(
        available_source(get_team_page(sid, user.user_id, team_after, limit, team_before)),
        available_source(get_campaign_page(sid, user.user_id, campaign_id, campaign_after, limit)))
    return Timeline(team=team, campaign=campaign)


class CampaignHistoryItem(Strict):
    id: RecordID
    state: str
    created_at: AwareDatetime
    updated_at: AwareDatetime


class CampaignHistoryPage(Strict):
    session_id: RecordID
    campaigns: list[CampaignHistoryItem]
    next_before: RecordID | None = None


def _owned_campaign_query(sid: str, owner: str, *columns):
    return select(*columns).join(PentestSession, PentestSession.id == AutonomousCampaign.session_id).where(
        AutonomousCampaign.session_id == sid, AutonomousCampaign.owner_id == owner, PentestSession.user_id == owner)


async def read_campaign_history(sid: str, owner: str, before: str | None, limit: int) -> CampaignHistoryPage:
    campaign = AutonomousCampaign
    query = _owned_campaign_query(sid, owner, campaign.id, campaign.state, campaign.created_at, campaign.updated_at)
    async with async_session() as db:
        if before is not None:
            anchor = query.with_only_columns(campaign.created_at).where(campaign.id == before)
            created = (await db.execute(anchor)).scalar_one_or_none()
            if created is None:
                raise HTTPException(404, 'Campaign history cursor not found')
            query = query.where(or_(campaign.created_at < created,
                                   and_(campaign.created_at == created, campaign.id < before)))
        rows = (await db.execute(query.order_by(campaign.created_at.desc(), campaign.id.desc()).limit(limit + 1))).all()
    campaigns = [CampaignHistoryItem(id=cid, state=state if state in LIVE_STATES | TERMINAL_STATES else 'unknown',
        created_at=as_utc(created), updated_at=as_utc(updated)) for cid, state, created, updated in rows[:limit]]
    return CampaignHistoryPage(session_id=sid, campaigns=campaigns,
        next_before=campaigns[-1].id if len(rows) > limit else None)


async def read_campaign_operations(sid: str, owner: str, cid: str) -> dict:
    query = _owned_campaign_query(sid, owner, AutonomousCampaign.operations).where(AutonomousCampaign.id == cid)
    async with async_session() as db:
        row = (await db.execute(query)).one_or_none()
    if row is None:
        raise HTTPException(404, 'Campaign not found')
    operations, = row
    if not isinstance(operations, dict):
        raise HTTPException(503, 'Campaign journal unavailable')
    return operations


@router.get('/{sid}/campaigns', response_model=CampaignHistoryPage)
async def campaign_history(sid: RecordID, response: Response, before: RecordID | None = Query(None),
                           limit: int = Query(25, ge=1, le=50),
                           user: TokenData = Depends(get_current_user)) -> CampaignHistoryPage:
    await require_owner(sid, user)
    response.headers['Cache-Control'] = 'no-store'
    return await read_campaign_history(sid, user.user_id, before, limit)


@router.get('/{sid}/campaigns/{cid}/events', response_model=EventPage)
async def retained_campaign_events(sid: RecordID, cid: RecordID, response: Response,
                                   user: TokenData = Depends(get_current_user)) -> EventPage:
    await require_owner(sid, user)
    operations = await read_campaign_operations(sid, user.user_id, cid)
    response.headers['Cache-Control'] = 'no-store'
    return campaign_event_page(sid, cid, operations, 0, MAX_EVENTS)


MAX_SAFE_COUNT = (1 << 53) - 1
Count = Annotated[int, Field(strict=True, ge=0, le=MAX_SAFE_COUNT)]
Provider = Literal['local', 'openrouter', 'groq', 'gemini']
MODEL_ID_PATTERN = r'^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,199}$'
ModelID = Annotated[str, Field(pattern=MODEL_ID_PATTERN)]
ATTEMPT_ERRORS = frozenset({
    'timeout', 'client_timeout', 'provider_timeout', 'request_timeout', 'read_timeout', 'rate_limited',
    'no_key', 'no_candidates', 'model_output_truncated', 'empty_response', 'provider_request_failed',
    'local_model_request_failed', 'provider_model_mismatch', 'provider_response_incomplete',
})


class AccountingAmounts(Strict):
    reserved_tokens: Count | None = None
    reported_tokens: Count | None = None
    reserved_cost_microusd: Count | None = None
    reported_cost_microusd: Count | None = None


class AccountingUsage(AccountingAmounts):
    calls: Count | None = None
    unknown_usage_calls: Count | None = None
    unknown_cost_calls: Count | None = None


class AccountingLimits(Strict):
    max_calls: Count
    max_tokens: Count
    max_cost_microusd: Count


class ModelSelection(Strict):
    provider: Provider
    model: ModelID | None


class AdmissionRemaining(Strict):
    calls: Count | None
    tokens: Count | None
    cost_microusd: Count | None


class Admission(Strict):
    state: Literal['blocked', 'undetermined']
    reasons: list[Literal['accounting_inconsistent', 'provider_overrun', 'unknown_usage',
                          'accounting_stopped', 'call_limit', 'token_reservation_floor', 'cost_reservation_floor']]
    configured_provider_prerequisites: list[Literal['model_tariff_missing', 'model_tariff_invalid']]
    remaining: AdmissionRemaining
    minimum_tokens: Count
    minimum_cost_microusd: Count | None


class ProviderCharge(Strict):
    cost: str


class ModelAttempt(AccountingAmounts):
    id: RecordID
    session_id: RecordID
    campaign_id: RecordID | None = None
    task_id: RecordID | None = None
    run_id: RecordID | None = None
    logical_request_id: RecordID | None = None
    provider: Provider | None = None
    model: ModelID | None = None
    timestamp: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    state: Literal['reserved', 'succeeded', 'failed', 'unknown']
    error_code: RecordID | None = None
    input_tokens: Count | None = None
    output_tokens: Count | None = None
    attempt_index: Count | None = None
    timings: dict[str, int | float | None]
    provider_usage: ProviderCharge | None = None


class AccountingView(Strict):
    schema_version: Literal['aria.mission.accounting.v1'] = 'aria.mission.accounting.v1'
    session_id: RecordID
    limits: AccountingLimits
    configured_selection: ModelSelection
    admission: Admission
    usage: AccountingUsage
    attempts: list[ModelAttempt] = Field(max_length=MAX_ATTEMPTS)
    attempts_limit: Count
    omitted_attempts: Count


def public_counts(value: object, fields: Iterable[str]) -> dict[str, int | None]:
    data = value if isinstance(value, dict) else {}
    return {key: item if type(item := data.get(key)) is int and 0 <= item <= MAX_SAFE_COUNT else None
            for key in fields}


def recorded_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        when = datetime.fromisoformat(value)
    except ValueError:
        return None
    return when if when.tzinfo is not None else None


def model_identifier(value: object) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(MODEL_ID_PATTERN, value) else None


def public_model_attempt(sid: str, record: object) -> ModelAttempt | None:
    if not isinstance(record, dict) or record.get('session_id') != sid or not (key := identifier(record.get('id'))):
        return None
    provider, model, state, error = (record.get(field) for field in ('provider', 'model', 'state', 'error_code'))
    receipt = record.get('provider_usage')
    cost = receipt.get('cost') if isinstance(receipt, dict) else None
    charge = (ProviderCharge(cost=cost) if provider == 'openrouter' and isinstance(cost, str) and len(cost) <= 64
              and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?(?:[Ee][+-]?[0-9]{1,2})?', cost) else None)
    public_error = (error if isinstance(error, str)
                    and (error in ATTEMPT_ERRORS or re.fullmatch(r'http_[45][0-9]{2}', error)) else None)
    return ModelAttempt(id=key, session_id=sid,
        provider=provider if provider in ('local', 'openrouter', 'groq', 'gemini') else None,
        model=model_identifier(model),
        state=state if state in ('reserved', 'succeeded', 'failed') else 'unknown', error_code=public_error,
        timestamp=recorded_timestamp(record.get('timestamp')), finished_at=recorded_timestamp(record.get('finished_at')),
        timings=safe_timings(record.get('timings')), provider_usage=charge,
        **{name: identifier(record.get(name)) for name in ('campaign_id', 'task_id', 'run_id', 'logical_request_id')},
        **public_counts(record, (*AccountingAmounts.model_fields, 'input_tokens', 'output_tokens', 'attempt_index')))


@router.get('/{sid}/accounting', response_model=AccountingView)
async def accounting_view(sid: RecordID, response: Response, user: TokenData = Depends(get_current_user)) -> AccountingView:
    """Use the existing accounting read and its owner check without exporting stored metadata."""
    try:
        data = await model_accounting.status(sid, user.user_id)
        if not isinstance(data['attempts'], list):
            raise HTTPException(503, 'Accounting records are unavailable')
        rows = data['attempts'][-MAX_ATTEMPTS:]
        attempts = [item for row in rows if (item := public_model_attempt(sid, row)) is not None]
        selection = data['configured_selection']
        view = AccountingView(session_id=sid, limits=public_counts(data['limits'], AccountingLimits.model_fields),
            configured_selection=ModelSelection(provider=selection['provider'], model=model_identifier(selection['model'])),
            admission=data['admission'],
            usage=public_counts(data['usage'], USAGE_FIELDS), attempts=attempts,
            attempts_limit=data['attempts_limit'], omitted_attempts=len(rows) - len(attempts))
    except (ValidationError, TypeError, KeyError):
        raise HTTPException(503, 'Accounting records are unavailable') from None
    response.headers['Cache-Control'] = 'no-store'
    return view


class Receipt(Strict):
    id: RecordID
    state: str
    created_at: datetime | None = None
    output_sha256: str | None = None
    exit_code: int | None = None
    cancel_requested: bool = False


class RecordedCommand(Strict):
    id: RecordID
    tool: str | None = None
    state: str
    timestamp: datetime
    duration_ms: int | None = None
    agent: RecordID | None = None
    http_status: int | None = None


class PendingReview(Strict):
    action_id: RecordID
    tool: RecordID | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None


AuthorizationEvent = Literal['proposal_registered', 'approval_recorded', 'rejection_recorded', 'authorization_consumed']
AUTHORIZATION_EVENTS: dict[str, AuthorizationEvent] = {
    'execution_authorization': 'proposal_registered',
    'execution_approved': 'approval_recorded',
    'execution_rejected': 'rejection_recorded',
    'execution_consumed': 'authorization_consumed',
}


class RecordedAuthorization(Strict):
    id: RecordID
    action_id: RecordID
    timestamp: AwareDatetime
    event: AuthorizationEvent
    decision: Literal['approve', 'modify', 'reject'] | None = None


class AuthorizationHistory(Strict):
    records: list[RecordedAuthorization]
    limit: int
    truncated: bool = False
    omitted: int = 0


class WebReplaySummary(Strict):
    records: Count
    pending_cancellations: Count
    unknown_outcomes: Count


class OperationHistory(Strict):
    receipts: list[Receipt] | None
    authorizations: AuthorizationHistory | None
    web_replays: WebReplaySummary | None
    commands: list[RecordedCommand]
    pending: list[PendingReview]
    receipt_limit: int
    command_limit: int


async def web_replay_summary(sid: str, owner: str) -> dict[str, int]:
    """Read stored states only; never contact the connector or expose captures."""
    query = (select(WebAction.state, func.count()).join(PentestSession, PentestSession.id == WebAction.session_id)
             .where(PentestSession.id == sid, PentestSession.user_id == owner, WebAction.requester_id == owner)
             .group_by(WebAction.state))
    async with async_session() as db:
        rows = (await db.execute(query)).all()
    known = {'pending', 'approved', 'claimed', 'completed', 'failed', 'unknown',
             'cancel_requested', 'cancelled_after_dispatch', 'rejected', 'cancelled'}
    return {'records': sum(count for _, count in rows),
            'pending_cancellations': sum(count for state, count in rows if state == 'cancel_requested'),
            'unknown_outcomes': sum(count for state, count in rows if state == 'unknown' or state not in known)}


async def recent_worker_receipts(sid: str, owner: str, limit: int) -> list[Receipt]:
    query = select(DecisionLog.created_at, DecisionLog.metadata_).where(DecisionLog.session_id == sid,
        DecisionLog.user_id == owner, DecisionLog.decision_type == 'worker_job').order_by(
        DecisionLog.created_at.desc(), DecisionLog.id.desc()).limit(limit)
    async with async_session() as db:
        rows = (await db.execute(query)).all()
    receipts = []
    for created, record in rows:
        if not isinstance(record, dict) or not identifier(record.get('job_id')):
            continue
        digest = record.get('output_hash')
        state = identifier(record.get('state'))
        receipts.append(Receipt(id=record['job_id'], state=state if state in STATES else 'unknown',
            created_at=as_utc(created) if created else None,
            output_sha256=digest if isinstance(digest, str) and re.fullmatch(r'[a-f0-9]{64}', digest) else None,
            exit_code=record.get('exit_code') if type(record.get('exit_code')) is int else None,
            cancel_requested=record.get('cancel_requested') is True))
    return receipts


async def recent_authorizations(sid: str, owner: str, limit: int) -> AuthorizationHistory:
    """Project only identifiers and recorded dispositions from the durable journal."""
    action_ref = DecisionLog.metadata_['action_id'].as_string().label('action_id')
    query = (select(DecisionLog.id, DecisionLog.created_at, DecisionLog.decision_type,
                    action_ref, DecisionLog.human_decision)
             .join(PentestSession, PentestSession.id == DecisionLog.session_id)
             .where(PentestSession.id == sid, PentestSession.user_id == owner,
                    DecisionLog.decision_type.in_(tuple(AUTHORIZATION_EVENTS)))
             .order_by(DecisionLog.created_at.desc().nulls_last(), DecisionLog.id.desc()).limit(limit + 1))
    async with async_session() as db:
        rows = (await db.execute(query)).all()
    records = []
    omitted = 0
    for row_id, timestamp, kind, reference, recorded in rows[:limit]:
        action_id = row_id if kind == 'execution_authorization' else reference
        if not identifier(row_id) or not identifier(action_id) or not isinstance(timestamp, datetime):
            omitted += 1
            continue
        decision = None
        if kind == 'execution_approved' and recorded in ('approve', 'modify'):
            decision = recorded
        if kind == 'execution_rejected' and recorded == 'reject':
            decision = recorded
        records.append(RecordedAuthorization(id=row_id, action_id=action_id, timestamp=as_utc(timestamp),
            event=AUTHORIZATION_EVENTS[kind], decision=decision))
    return AuthorizationHistory(records=records, limit=limit, truncated=len(rows) > limit, omitted=omitted)


@router.get('/{sid}/operations', response_model=OperationHistory)
async def operation_history(sid: RecordID, response: Response,
                            user: TokenData = Depends(get_current_user)) -> OperationHistory:
    await require_owner(sid, user)
    response.headers['Cache-Control'] = 'no-store'
    receipts, authorizations, replays = await asyncio.gather(
        asyncio.wait_for(recent_worker_receipts(sid, user.user_id, 100), timeout=4),
        asyncio.wait_for(recent_authorizations(sid, user.user_id, 100), timeout=4),
        asyncio.wait_for(web_replay_summary(sid, user.user_id), timeout=4),
        return_exceptions=True)
    commands = []
    for entry in reversed(command_registry.get_history(sid)[-100:]):
        # The registry stores arbitrary stdout and arguments. Project only a known tool and HTTP status.
        tool = entry.command.split(maxsplit=1)[0] if entry.command.strip() else ''
        status = re.search(r'^HTTP/[12](?:\.\d)?\s+([1-5]\d{2})\b', entry.stdout[:8192], re.MULTILINE)
        commands.append(RecordedCommand(id=entry.cmd_hash, tool=tool if tool in {'curl', 'nmap'} else None,
            state=entry.status if entry.status in {'success', 'failed', 'running', 'killed'} else 'unknown',
            timestamp=datetime.fromtimestamp(entry.executed_at, timezone.utc), agent=identifier(entry.agent),
            duration_ms=entry.execution_time_ms if type(entry.execution_time_ms) is int and entry.execution_time_ms > 0 else None,
            http_status=int(status[1]) if status else None))
    pending = []
    for item in autonomous_engine.get_pending_approvals(sid)[:100]:
        try:
            pending.append(PendingReview(action_id=item['action_id'], tool=identifier(item.get('tool')),
                created_at=item.get('created_at'), expires_at=item.get('expires_at')))
        except (ValidationError, KeyError):
            continue
    return OperationHistory(receipts=receipts if isinstance(receipts, list) else None,
        web_replays=replays if isinstance(replays, dict) else None,
        authorizations=authorizations if isinstance(authorizations, AuthorizationHistory) else None,
        commands=commands, pending=pending, receipt_limit=100, command_limit=100)


class RegisteredAgent(Strict):
    id: RecordID
    role: str
    registration: Literal['team_specialist', 'internal', 'review_only', 'unavailable']


class AgentInventory(Strict):
    agents: list[RegisteredAgent]


@router.get('/agents', response_model=AgentInventory)
async def agents(user: TokenData = Depends(get_current_user)) -> AgentInventory:
    from agents.attack_planner_agent import attack_planner_agent
    from agents.coding_agent import coding_agent
    from agents.coordinator_agent import coordinator_agent
    from agents.orchestrator_agent import orchestrator_agent
    from agents.post_exploitation_agent import post_exploitation_agent

    specialists = [RegisteredAgent(id=key, role=agent.agent_role, registration='team_specialist')
                   for key, agent in team_coordinator.specialists().items()]
    internal = [RegisteredAgent(id=agent.agent_name, role=agent.agent_role, registration='internal')
                for agent in (attack_planner_agent, coordinator_agent, orchestrator_agent)]
    return AgentInventory(agents=[*specialists, *internal,
        RegisteredAgent(id=coding_agent.agent_name, role=coding_agent.agent_role, registration='review_only'),
        RegisteredAgent(id=post_exploitation_agent.agent_name, role='Post-access execution unavailable', registration='unavailable')])


class Service(Strict):
    port: Annotated[int, Field(ge=1, le=65535)]
    service: str | None = None
    version: str | None = None


class Host(Strict):
    ip: RecordID
    hostname: RecordID | None = None
    ports: list[Service]


class Topology(Strict):
    hosts: list[Host]
    truncated: bool


@router.get('/{sid}/topology', response_model=Topology)
async def topology(sid: RecordID, response: Response,
                   user: TokenData = Depends(get_current_user)) -> Topology:
    from memory.attack_knowledge_base import attack_kb
    from security.redaction import deployment_secrets, redact

    await require_owner(sid, user)
    response.headers['Cache-Control'] = 'no-store'
    detail = attack_kb.get_all_hosts(sid)
    secrets = deployment_secrets()
    hosts = []
    truncated = len(detail) > 100
    for host in detail[:100]:
        if not identifier(host.ip):
            continue
        ports = [Service(port=port, service=identifier(entry.get('service')),
            version=redact(entry['version'], secrets)[:160] if isinstance(entry.get('version'), str) else None)
            for port, entry in host.ports.items() if type(port) is int and 0 < port <= 65535 and entry.get('state') == 'open']
        truncated = truncated or len(ports) > 100
        hosts.append(Host(ip=host.ip, hostname=identifier(host.hostname), ports=ports[:100]))
    return Topology(hosts=hosts, truncated=truncated)
