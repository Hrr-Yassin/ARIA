"""SQL-serialized accounting for every physical pool call, including failover.

Reservations are never refunded: missing usage, crashes and cancelled calls remain
charged at their declared ceiling. OpenRouter requires authenticated expiring
provider quotes; other hosted providers retain owner-entered conservative rates.
"""
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import re
import uuid
from typing import Literal

from fastapi import HTTPException
from pydantic import Field, model_validator
from sqlalchemy import select

from memory.database_models import (
    AutonomousCampaign, DecisionLog, PentestSession, async_session,
)
from memory.program_policy import owned_engagement
from memory.team_tasks import Strict

engagement_context = ContextVar('aria_model_engagement', default=None)
task_context = ContextVar('aria_model_task', default=None)
model_request_context = ContextVar('aria_model_request', default=None)


def bound_model_context(sid: str, owner: str, run_id: str | None = None) -> dict:
    """Carry correlation only within the same owner/session; grant no authority."""
    parent = engagement_context.get()
    if run_id is None and isinstance(parent, dict) and parent.get('session_id') == sid and parent.get('owner') == owner:
        run_id = parent.get('run_id')
    result = {'session_id': sid, 'owner': owner}
    if isinstance(run_id, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', run_id):
        result['run_id'] = run_id
    return result

STOP_REASONS = frozenset({'', 'provider_overrun', 'unknown_usage',
                          'accounting_inconsistent'})
USAGE_FIELDS = ('calls', 'reserved_tokens', 'reserved_cost_microusd',
                'reported_tokens', 'reported_cost_microusd',
                'unknown_usage_calls', 'unknown_cost_calls')
MAX_ATTEMPTS = 100


class Tariff(Strict):
    provider: Literal['groq', 'gemini', 'openrouter']
    model: str = Field(min_length=1, max_length=200)
    # Conservative combined input/output rate in micro-USD per million tokens.
    microusd_per_million: int = Field(ge=1, le=10000000000)
    quote_id: str | None = Field(default=None, max_length=36)


class ModelLimits(Strict):
    max_calls: int = Field(default=20, ge=0, le=10000)
    max_tokens: int = Field(default=200000, ge=0, le=100000000)
    max_cost_microusd: int = Field(default=2000000, ge=0, le=1000000000)
    tariffs: list[Tariff] = Field(default_factory=list, max_length=100)


    @model_validator(mode='after')
    def unique_tariffs(self):
        keys = [(tariff.provider, tariff.model) for tariff in self.tariffs]
        if len(keys) != len(set(keys)):
            raise ValueError('Use exactly one tariff per provider/model')
        return self


def reservation_ceiling(prompt: str, system: str, rate: int) -> tuple[int, int]:
    # Conservative byte-based bound plus framing allowance and output maximum.
    tokens = len((prompt + system).encode()) + 8192
    return tokens, (tokens * rate + 999999) // 1000000


def _read_usage(value) -> tuple[dict, bool]:
    """Canonicalise a model-usage ledger, reporting any untrusted field."""
    if value is None:
        return {**{field: 0 for field in USAGE_FIELDS},
                'stopped': False, 'stop_reason': ''}, False
    if not isinstance(value, dict):
        return {**{field: 0 for field in USAGE_FIELDS},
                'stopped': True, 'stop_reason': 'accounting_inconsistent'}, True
    invalid = False
    usage: dict = {}
    for field in USAGE_FIELDS:
        item = value.get(field, 0)
        if type(item) is int and item >= 0:
            usage[field] = item
        else:
            usage[field] = 0
            invalid = True
    stopped = value.get('stopped', False)
    if type(stopped) is not bool:
        stopped = True
        invalid = True
    stop_reason = value.get('stop_reason', '')
    if not isinstance(stop_reason, str) or stop_reason not in STOP_REASONS:
        stop_reason = 'accounting_inconsistent'
        invalid = True
    usage.update(stopped=stopped, stop_reason=stop_reason)
    if usage['reported_tokens'] > usage['reserved_tokens'] or (
            usage['reported_cost_microusd'] > usage['reserved_cost_microusd']):
        usage['stopped'] = True
        usage['stop_reason'] = 'accounting_inconsistent'
        invalid = True
    return usage, invalid


def admission_snapshot(metadata: dict, limits: ModelLimits, selection: dict) -> dict:
    """Explain hard lower bounds using accounting inputs, without reserving anything."""
    usage, invalid = _read_usage(metadata.get('model_usage'))
    remaining = {resource: None if invalid else max(0, limit - usage[field])
                 for resource, limit, field in (
                     ('calls', limits.max_calls, 'calls'),
                     ('tokens', limits.max_tokens, 'reserved_tokens'),
                     ('cost_microusd', limits.max_cost_microusd, 'reserved_cost_microusd'))}
    provider, model = selection['provider'], selection['model']
    tariff = next((item for item in limits.tariffs if item.provider == provider and item.model == model), None)
    rate = 0 if provider == 'local' else tariff.microusd_per_million if tariff else None
    minimum_tokens, minimum_cost = reservation_ceiling('', '', rate or 0)
    reasons = []
    if invalid:
        reasons.append('accounting_inconsistent')
    else:
        if usage['stopped']:
            reasons.append(usage['stop_reason'] or 'accounting_stopped')
        if remaining['calls'] < 1:
            reasons.append('call_limit')
        if remaining['tokens'] < minimum_tokens:
            reasons.append('token_reservation_floor')
        if rate is not None and remaining['cost_microusd'] < minimum_cost:
            reasons.append('cost_reservation_floor')
    prerequisites = []
    if provider != 'local' and tariff is None:
        prerequisites.append('model_tariff_missing')
    elif provider == 'openrouter':
        from llm.provider_tariffs import checked_quote
        try:
            checked_quote(metadata, tariff)
        except (HTTPException, ValueError, TypeError, AttributeError, KeyError):
            prerequisites.append('model_tariff_invalid')
    return {'state': 'blocked' if reasons else 'undetermined', 'reasons': reasons,
            'configured_provider_prerequisites': prerequisites, 'remaining': remaining,
            'minimum_tokens': minimum_tokens, 'minimum_cost_microusd': minimum_cost if rate is not None else None}


class ModelAccounting:
    async def configure(self, sid: str, owner: str, limits: ModelLimits) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            metadata = dict(session.metadata_ or {})
            from llm.provider_tariffs import checked_quote
            for tariff in limits.tariffs:
                if tariff.provider == 'openrouter':
                    checked_quote(metadata, tariff)
            metadata['model_limits'] = limits.model_dump()
            metadata['model_budget_approved_at'] = datetime.now(timezone.utc).isoformat()
            session.metadata_ = metadata  # Counters and reservations are retained.
            db.add(DecisionLog(session_id=sid, user_id=owner, decision_type='model_limits',
                               human_involved=True, metadata_=limits.model_dump()))
            await db.commit()
            return limits.model_dump()

    async def reserve(self, owner: str, provider: str, model: str, prompt: str, system: str, *, check_only: bool = False) -> dict:
        context = engagement_context.get()
        if not context or context['owner'] != owner:
            raise HTTPException(403, 'An owner-bound model engagement is required')
        sid = context['session_id']
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            metadata = dict(session.metadata_ or {})
            from memory.engagement_profiles import stored_profile
            profile = stored_profile(getattr(session, 'scope', None) or {})
            if profile and profile.get('model_sharing') != 'redacted_metadata' and provider != 'local':
                # A profile can only restrict sharing; it never relaxes the application data policy.
                raise HTTPException(403, {'code': 'model_provider_sharing_denied',
                                          'message': 'The engagement authorization profile denies model provider sharing'})
            if metadata.get('application_mapping'):
                from memory.application_map import unseal, known_secrets
                key = str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-application-map:' + sid))
                mapping = await db.get(DecisionLog, key)
                if mapping is None:
                    raise HTTPException(403, 'Application data consent is unavailable')
                state = unseal(mapping.metadata_['sealed'])
                if state['policy']['provider_sharing'] != 'redacted_metadata':
                    raise HTTPException(403, 'Engagement provider sharing is disabled')
                if any(secret and secret in prompt + system for secret in known_secrets(state)):
                    raise HTTPException(403, 'Registered identity credential cannot enter provider context')
            limits = ModelLimits.model_validate(metadata.get('model_limits', {}))
            tariffs = [t for t in limits.tariffs if t.provider == provider and t.model == model]
            if provider != 'local' and len(tariffs) != 1:
                raise HTTPException(409, {'code': 'model_tariff_missing', 'message': 'Configure exactly one conservative tariff for this provider/model'})
            quote = None
            if provider == 'openrouter':
                from llm.provider_tariffs import checked_quote
                quote = checked_quote(metadata, tariffs[0])
            schema_text = ''
            if provider == 'openrouter':
                from llm.base_llm import response_schema
                schema_text = json.dumps(response_schema.get() or {}, ensure_ascii=True)
            tokens, cost = reservation_ceiling(prompt, system + schema_text, 0 if provider == 'local' else tariffs[0].microusd_per_million)
            raw_usage = metadata.get('model_usage')
            used, invalid = _read_usage(raw_usage)
            if isinstance(raw_usage, dict) and isinstance(raw_usage.get('tasks'), dict):
                used['tasks'] = dict(raw_usage['tasks'])
            if invalid:
                raise HTTPException(409, {
                    'code': 'model_accounting_inconsistent',
                    'message': 'Engagement model accounting cannot be trusted; calls are denied'})
            if used['stopped']:
                inconsistent = used['stop_reason'] in {'unknown_usage',
                                                       'accounting_inconsistent'}
                raise HTTPException(409 if inconsistent else 429, {
                    'code': ('model_accounting_inconsistent' if inconsistent
                             else 'model_budget_exhausted'),
                    'message': ('Engagement accounting stopped after unknown usage'
                                if inconsistent
                                else 'Engagement model budget exhausted')})
            if (used['calls'] + 1 > limits.max_calls
                    or used['reserved_tokens'] + tokens > limits.max_tokens
                    or used['reserved_cost_microusd'] + cost > limits.max_cost_microusd):
                raise HTTPException(429, {'code': 'model_budget_exhausted', 'message': 'Engagement model budget exhausted'})
            campaign_id = metadata.get('active_campaign_id')
            if campaign_id:
                # The campaign ledger is enforced in the same transaction as the
                # per-session reservation; a denial prevents both and the call.
                from memory.campaign_store import reserve_campaign_usage
                await reserve_campaign_usage(
                    db, campaign_id=campaign_id, session_id=sid, owner_id=owner,
                    tokens=tokens, cost_microusd=cost, check_only=check_only)
            task = task_context.get()
            if task:
                # Resolve the authoritative task from its immutable transitions.
                from memory.team_tasks import team_store, materialize
                state = materialize(await team_store._events(db, sid))
                record = state['tasks'].get(task['id'])
                if not record or record['state'] != 'running' or record.get('run_id') != task['run_id']:
                    raise HTTPException(409, {'code': 'task_not_running', 'message': 'Task cancelled or superseded before provider call'})
                task_used = dict((used.get('tasks') or {}).get(task['id']) or {})
                if (task_used.get('calls', 0) + 1 > record['budget']['max_model_calls']
                        or task_used.get('reserved_tokens', 0) + tokens > record['budget']['max_tokens']):
                    raise HTTPException(429, {'code': 'task_model_budget_exhausted', 'message': 'Task model budget exhausted'})
                if check_only:
                    return {'ready': True}
                task_used.update(calls=task_used.get('calls', 0) + 1,
                                 reserved_tokens=task_used.get('reserved_tokens', 0) + tokens)
                used['tasks'] = {**used.get('tasks', {}), task['id']: task_used}
            if check_only:
                return {'ready': True}
            used.update(calls=used.get('calls', 0) + 1,
                        reserved_tokens=used.get('reserved_tokens', 0) + tokens,
                        reserved_cost_microusd=used.get('reserved_cost_microusd', 0) + cost)
            metadata['model_usage'] = used
            session.metadata_ = metadata
            attempt = {'id': str(uuid.uuid4()), 'session_id': sid, 'owner': owner,
                       'campaign_id': campaign_id, 'task_id': task['id'] if task else None,
                       'run_id': bound_model_context(sid, owner).get('run_id'),
                       'task_run_id': task['run_id'] if task else None,
                       'provider': provider, 'model': model,
                       'reserved_tokens': tokens, 'reserved_cost_microusd': cost,
                       'timestamp': datetime.now(timezone.utc).isoformat(), 'state': 'reserved'}
            logical = model_request_context.get()
            if isinstance(logical, dict):
                attempt['logical_request_id'] = logical['id']
                attempt['attempt_index'] = logical['reserved_attempts'] + 1
            if quote:
                attempt['tariff'] = quote
            db.add(DecisionLog(id=attempt['id'], session_id=sid, user_id=owner,
                               decision_type='model_attempt', metadata_=attempt))
            await db.commit()  # Required before physical provider I/O.
            if isinstance(logical, dict):
                logical['reserved_attempts'] = attempt['attempt_index']
            return attempt

    async def settle(self, attempt: dict, result: dict) -> None:
        async with async_session() as db:
            session = (await db.execute(select(PentestSession).where(
                PentestSession.id == attempt['session_id'], PentestSession.user_id == attempt['owner'])
                .with_for_update())).scalar_one()
            row = await db.get(DecisionLog, attempt['id'])
            if row is None or row.metadata_.get('state') != 'reserved':
                return
            tokens = result.get('tokens_used')
            tokens = tokens if type(tokens) is int and tokens >= 0 else None
            cost = result.get('cost_microusd')
            cost = cost if type(cost) is int and cost >= 0 else None
            success = bool(result.get('success'))
            metadata = dict(session.metadata_ or {})
            used = dict(metadata.get('model_usage') or {})
            used['reported_tokens'] = int(used.get('reported_tokens', 0) or 0) + (tokens or 0)
            used['reported_cost_microusd'] = int(used.get('reported_cost_microusd', 0) or 0) + (cost or 0)
            used['unknown_usage_calls'] = int(used.get('unknown_usage_calls', 0) or 0) + int(tokens is None)
            used['unknown_cost_calls'] = int(used.get('unknown_cost_calls', 0) or 0) + int(cost is None)
            # A provider exceeding a declared ceiling stops all later calls.
            if ((tokens is not None and tokens > attempt['reserved_tokens'])
                    or (cost is not None and cost > attempt['reserved_cost_microusd'])):
                used['stopped'] = True
                used['stop_reason'] = 'provider_overrun'
            # Unknown OpenRouter usage or cost stops all later calls, including
            # failures that may have reached the provider before timing out.
            elif (success and tokens is None) or (attempt.get('provider') == 'openrouter' and (tokens is None or cost is None)):
                used['stopped'] = True
                used['stop_reason'] = 'unknown_usage'
            metadata['model_usage'] = used
            session.metadata_ = metadata

            campaign_id = attempt.get('campaign_id')
            if campaign_id:
                from memory.campaign_store import (
                    CampaignValidationError, apply_settlement,
                )
                campaign_row = (await db.execute(select(AutonomousCampaign).where(
                    AutonomousCampaign.id == campaign_id,
                    AutonomousCampaign.session_id == attempt['session_id'],
                    AutonomousCampaign.owner_id == attempt['owner'],
                ).with_for_update())).scalar_one_or_none()
                if campaign_row is None:
                    used['stopped'] = True
                    used['stop_reason'] = 'accounting_inconsistent'
                else:
                    try:
                        campaign_row.usage = apply_settlement(
                            campaign_row.usage,
                            reserved_tokens=attempt['reserved_tokens'],
                            reserved_cost_microusd=attempt['reserved_cost_microusd'],
                            reported_tokens=tokens,
                            reported_cost_microusd=cost,
                            success=success)
                        campaign_row.updated_at = datetime.now(
                            timezone.utc).replace(tzinfo=None)
                    except CampaignValidationError:
                        used['stopped'] = True
                        used['stop_reason'] = 'accounting_inconsistent'
                metadata['model_usage'] = used
                session.metadata_ = metadata
            row.metadata_ = {**row.metadata_, 'state': 'succeeded' if success else 'failed',
                             'error_code': str(result.get('error', ''))[:100],
                             'reported_tokens': tokens, 'reported_cost_microusd': cost,
                             'provider_usage': result.get('provider_usage'),
                             'provider_error': (result.get('provider_error')
                                                if isinstance(result.get('provider_error'), dict) else None),
                             'finished_at': datetime.now(timezone.utc).isoformat()}
            from llm.request_metrics import safe_timings
            def token_count(key):
                count = result.get(key)
                return count if type(count) is int and count >= 0 else None
            row.metadata_.update(input_tokens=token_count('input_tokens'),
                output_tokens=token_count('output_tokens'),
                timings=safe_timings(result.get('timings')))
            await db.commit()

    async def usage_summary(self, sid: str, owner: str) -> dict:
        """Bounded accounting summary for monitoring; never lists attempts."""
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            metadata = dict(session.metadata_ or {})
            usage, invalid = _read_usage(metadata.get('model_usage'))
            raw = metadata.get('model_usage')
            tasks = raw.get('tasks') if isinstance(raw, dict) else None
            if tasks is not None and not isinstance(tasks, dict):
                invalid = True
            try:
                limits = ModelLimits.model_validate(
                    metadata.get('model_limits', {})).model_dump()
            except Exception:  # noqa: BLE001 - monitoring must stay readable
                limits = {}
                invalid = True
            return {
                'schema': 'aria.model.usage.v1',
                'limits': limits,
                'usage': {field: usage[field] for field in USAGE_FIELDS},
                'stopped': bool(usage.get('stopped')),
                'stop_reason': usage.get('stop_reason', ''),
                'task_ledgers': len(tasks) if isinstance(tasks, dict) else 0,
                'invalid': invalid,
                'cost_basis': ('Verified OpenRouter quotes or owner-entered tariffs; '
                               'actual usage may be unknown. Reservations never refunded.'),
            }

    async def status(self, sid: str, owner: str) -> dict:
        from config.settings import settings
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            rows = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == sid, DecisionLog.user_id == owner,
                DecisionLog.decision_type == 'model_attempt').order_by(
                DecisionLog.created_at.desc(), DecisionLog.id.desc()).limit(MAX_ATTEMPTS))).scalars().all()
            metadata = session.metadata_ or {}
            limits = ModelLimits.model_validate(metadata.get('model_limits', {}))
            selection = ({'provider': 'local', 'model': settings.LOCAL_LLM_MODEL}
                         if settings.LLM_ROUTING == 'local' else
                         {'provider': 'openrouter', 'model': settings.OPENROUTER_MODEL})
            admission = admission_snapshot(metadata, limits, selection)
            from memory.engagement_profiles import stored_profile
            profile = stored_profile(getattr(session, 'scope', None) or {})
            if profile and profile.get('model_sharing') != 'redacted_metadata' and selection['provider'] != 'local':
                admission['reasons'].append('profile_model_sharing_denied')
                admission['state'] = 'blocked'
            return {'limits': limits.model_dump(), 'configured_selection': selection,
                    'admission': admission,
                    'tariff_quotes': metadata.get('model_tariffs', {}),
                    'approved_at': metadata.get('model_budget_approved_at'),
                    'usage': metadata.get('model_usage', {}),
                    'attempts': [row.metadata_ for row in reversed(rows)],
                    'attempts_limit': MAX_ATTEMPTS,
                    'cost_basis': 'Verified OpenRouter quotes or owner-entered tariffs; actual usage may be unknown. Reservations never refunded.'}


    async def reconcile_unknown(self, sid: str, owner: str, attempt_id: str, reason: str,
                                evidence: dict | None = None) -> dict:
        """Owner settlement of a failed attempt whose usage is unknown.

        The attempt is settled at its full reserved tokens and cost, so spending is
        never understated against the approved ceiling. Accounting resumes only when
        every unknown attempt has been settled. The decision is audited.
        """
        from sqlalchemy.orm.attributes import flag_modified
        if not isinstance(reason, str) or not reason.strip():
            raise HTTPException(422, 'A reconciliation reason is required')
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            metadata = dict(session.metadata_ or {})
            raw = dict(metadata.get('model_usage') or {})
            used, invalid = _read_usage(raw)
            if invalid or not used['stopped'] or used['stop_reason'] != 'unknown_usage':
                raise HTTPException(409, 'Only accounting stopped for unknown usage can be reconciled')
            rows = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == sid, DecisionLog.decision_type == 'model_attempt'))).scalars().all()
            row = next((r for r in rows if (r.metadata_ or {}).get('id') == attempt_id), None)
            attempt = dict(row.metadata_ or {}) if row else {}
            if (not row or attempt.get('state') != 'failed' or attempt.get('reported_cost_microusd') is not None
                    or attempt.get('reconciliation')):
                raise HTTPException(409, 'Attempt is not an unsettled failed attempt with unknown usage')
            tokens, cost = int(attempt['reserved_tokens']), int(attempt['reserved_cost_microusd'])
            raw['reported_tokens'] = used['reported_tokens'] + tokens
            raw['reported_cost_microusd'] = used['reported_cost_microusd'] + cost
            raw['reconciled_unknown_calls'] = int(raw.get('reconciled_unknown_calls', 0) or 0) + 1
            if raw['reconciled_unknown_calls'] >= used['unknown_usage_calls']:
                raw['stopped'], raw['stop_reason'] = False, ''
            record = {'attempt_id': attempt_id, 'settled_tokens': tokens, 'settled_cost_microusd': cost,
                      'basis': 'settled at full reservation (conservative)', 'reason': reason.strip()[:2000],
                      'evidence': evidence or {}, 'resumed': not raw.get('stopped', False), 'actor': owner}
            attempt['reconciliation'] = record
            row.metadata_ = attempt
            flag_modified(row, 'metadata_')
            metadata['model_usage'] = raw
            session.metadata_ = metadata
            db.add(DecisionLog(session_id=sid, user_id=owner, decision_type='model_accounting_reconciled',
                               human_involved=True, human_decision='settle_reserved', metadata_=record))
            await db.commit()
            return {'usage': raw, 'reconciliation': record}

model_accounting = ModelAccounting()
