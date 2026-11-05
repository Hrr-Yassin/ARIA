"""SQL-serialized accounting for every physical pool call, including failover.

Reservations are never refunded: missing usage, crashes and cancelled calls remain
charged at their declared ceiling. Monetary ceilings use owner-entered tariffs,
not an assertion about current provider prices.
"""
from contextvars import ContextVar
from datetime import datetime, timezone
import uuid
from typing import Literal

from fastapi import HTTPException
from pydantic import Field, model_validator
from sqlalchemy import select

from memory.database_models import DecisionLog, PentestSession, async_session
from memory.program_policy import owned_engagement
from memory.team_tasks import Strict

engagement_context = ContextVar('aria_model_engagement', default=None)
task_context = ContextVar('aria_model_task', default=None)


class Tariff(Strict):
    provider: Literal['groq', 'gemini', 'openrouter']
    model: str = Field(min_length=1, max_length=200)
    # Conservative combined input/output rate in micro-USD per million tokens.
    microusd_per_million: int = Field(ge=1, le=10000000000)


class ModelLimits(Strict):
    max_calls: int = Field(default=20, ge=0, le=10000)
    max_tokens: int = Field(default=200000, ge=0, le=100000000)
    max_cost_microusd: int = Field(default=1000000, ge=0, le=1000000000)
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


class ModelAccounting:
    async def configure(self, sid: str, owner: str, limits: ModelLimits) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            metadata = dict(session.metadata_ or {})
            metadata['model_limits'] = limits.model_dump()
            session.metadata_ = metadata  # Counters and reservations are retained.
            db.add(DecisionLog(session_id=sid, user_id=owner, decision_type='model_limits',
                               human_involved=True, metadata_=limits.model_dump()))
            await db.commit()
            return limits.model_dump()

    async def reserve(self, owner: str, provider: str, model: str, prompt: str, system: str) -> dict:
        context = engagement_context.get()
        if not context or context['owner'] != owner:
            raise HTTPException(403, 'An owner-bound model engagement is required')
        sid = context['session_id']
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            metadata = dict(session.metadata_ or {})
            limits = ModelLimits.model_validate(metadata.get('model_limits', {}))
            tariffs = [t for t in limits.tariffs if t.provider == provider and t.model == model]
            if len(tariffs) != 1:
                raise HTTPException(409, 'Configure exactly one conservative tariff for this provider/model')
            tokens, cost = reservation_ceiling(prompt, system, tariffs[0].microusd_per_million)
            used = dict(metadata.get('model_usage') or {})
            if (used.get('stopped') or used.get('calls', 0) + 1 > limits.max_calls
                    or used.get('reserved_tokens', 0) + tokens > limits.max_tokens
                    or used.get('reserved_cost_microusd', 0) + cost > limits.max_cost_microusd):
                raise HTTPException(429, 'Engagement model budget exhausted')
            task = task_context.get()
            if task:
                # Resolve the authoritative task from its immutable transitions.
                from memory.team_tasks import team_store, materialize
                state = materialize(await team_store._events(db, sid))
                record = state['tasks'].get(task['id'])
                if not record or record['state'] != 'running' or record.get('run_id') != task['run_id']:
                    raise HTTPException(409, 'Task cancelled or superseded before provider call')
                task_used = dict((used.get('tasks') or {}).get(task['id']) or {})
                if (task_used.get('calls', 0) + 1 > record['budget']['max_model_calls']
                        or task_used.get('reserved_tokens', 0) + tokens > record['budget']['max_tokens']):
                    raise HTTPException(429, 'Task model budget exhausted')
                task_used.update(calls=task_used.get('calls', 0) + 1,
                                 reserved_tokens=task_used.get('reserved_tokens', 0) + tokens)
                used['tasks'] = {**used.get('tasks', {}), task['id']: task_used}
            used.update(calls=used.get('calls', 0) + 1,
                        reserved_tokens=used.get('reserved_tokens', 0) + tokens,
                        reserved_cost_microusd=used.get('reserved_cost_microusd', 0) + cost)
            metadata['model_usage'] = used
            session.metadata_ = metadata
            attempt = {'id': str(uuid.uuid4()), 'session_id': sid, 'owner': owner,
                       'task_id': task['id'] if task else None, 'provider': provider, 'model': model,
                       'reserved_tokens': tokens, 'reserved_cost_microusd': cost,
                       'timestamp': datetime.now(timezone.utc).isoformat(), 'state': 'reserved'}
            db.add(DecisionLog(id=attempt['id'], session_id=sid, user_id=owner,
                               decision_type='model_attempt', metadata_=attempt))
            await db.commit()  # Required before physical provider I/O.
            return attempt

    async def settle(self, attempt: dict, result: dict) -> None:
        async with async_session() as db:
            session = (await db.execute(select(PentestSession).where(
                PentestSession.id == attempt['session_id'], PentestSession.user_id == attempt['owner'])
                .with_for_update())).scalar_one()
            row = await db.get(DecisionLog, attempt['id'])
            if row.metadata_['state'] != 'reserved':
                return
            tokens = result.get('tokens_used')
            tokens = tokens if type(tokens) is int and tokens >= 0 else None
            cost = result.get('cost_microusd')
            cost = cost if type(cost) is int and cost >= 0 else None
            metadata = dict(session.metadata_ or {})
            used = dict(metadata.get('model_usage') or {})
            used['reported_tokens'] = used.get('reported_tokens', 0) + (tokens or 0)
            used['reported_cost_microusd'] = used.get('reported_cost_microusd', 0) + (cost or 0)
            used['unknown_usage_calls'] = used.get('unknown_usage_calls', 0) + int(tokens is None)
            used['unknown_cost_calls'] = used.get('unknown_cost_calls', 0) + int(cost is None)
            # A provider exceeding a declared ceiling stops all later calls.
            if ((tokens is not None and tokens > attempt['reserved_tokens'])
                    or (cost is not None and cost > attempt['reserved_cost_microusd'])):
                used['stopped'] = True
            metadata['model_usage'] = used
            session.metadata_ = metadata
            row.metadata_ = {**row.metadata_, 'state': 'succeeded' if result.get('success') else 'failed',
                             'reported_tokens': tokens, 'reported_cost_microusd': cost,
                             'finished_at': datetime.now(timezone.utc).isoformat()}
            await db.commit()

    async def status(self, sid: str, owner: str) -> dict:
        async with async_session() as db:
            session = await owned_engagement(db, sid, owner)
            rows = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == sid,
                DecisionLog.decision_type == 'model_attempt').order_by(DecisionLog.created_at))).scalars().all()
            metadata = session.metadata_ or {}
            return {'limits': ModelLimits.model_validate(metadata.get('model_limits', {})).model_dump(),
                    'usage': metadata.get('model_usage', {}), 'attempts': [row.metadata_ for row in rows],
                    'cost_basis': 'Owner-entered conservative tariffs; actual cost may be unknown. Reservations never refunded.'}


model_accounting = ModelAccounting()
