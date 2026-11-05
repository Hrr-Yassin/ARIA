"""Owner-bound team ledger. Mutations and their polling events commit together."""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from agents.result_contract import AgentResult
from memory.database_models import ChatLog, DecisionLog, PentestSession, async_session
from memory.program_policy import owned_engagement
from security.redaction import redact, deployment_secrets

Reference = Annotated[str, Field(min_length=1, max_length=100)]
Criterion = Annotated[str, Field(min_length=1, max_length=2000)]

State = Literal['queued', 'running', 'awaiting_review', 'blocked', 'completed', 'cancelled', 'failed']
Role = Literal['recon', 'scan', 'vuln', 'web_intel', 'correlation', 'report']
TRANSITIONS = {
    'queued': {'running', 'blocked', 'cancelled'},
    'running': {'awaiting_review', 'blocked', 'failed', 'cancelled'},
    'awaiting_review': {'completed', 'blocked', 'cancelled'},
    'blocked': {'queued', 'cancelled'},
    'completed': set(), 'cancelled': set(), 'failed': set(),
}


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')


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


class CreateTask(Strict):
    request_id: uuid.UUID
    task: TaskSpec


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
    state = {'tasks': {}, 'evidence': {}, 'knowledge': {}, 'coverage': {}, 'cursor': 0}
    for event in events:
        state[event['collection']][event['entity_id']] = event['data']
        state['cursor'] = max(state['cursor'], event['sequence'])
    return state


def transition_task(task: dict, target: str, reason: str, *, internal: bool = False) -> dict:
    if target not in TRANSITIONS[task['state']]:
        raise HTTPException(409, 'Invalid task transition')
    if target in {'running', 'awaiting_review', 'failed'} and not internal:
        raise HTTPException(403, 'Coordinator owns execution transitions')
    if target == 'completed' and not task.get('result'):
        raise HTTPException(409, 'Review a collected specialist result before completion')
    return {**task, 'state': target, 'reason': public(reason), 'revision': task['revision'] + 1}


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
                    'cursor': state['cursor'], 'target': getattr(session, 'target', '')}

    async def events(self, sid: str, owner: str, after: int = 0) -> dict:
        async with async_session() as db:
            await owned_engagement(db, sid, owner)
            events = [event for event in await self._events(db, sid) if event['sequence'] > after][:100]
            return {'events': events, 'cursor': events[-1]['sequence'] if events else after}

    async def mutate(self, sid: str, owner: str, request_id: str, operation: dict, build) -> dict:
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
            await db.commit()  # This immutable event is also the durable UI outbox.
            return {**event, 'duplicate': False}

    def _references(self, state: dict, references: list[str], collection='evidence') -> None:
        if any(ref not in state[collection] for ref in references):
            raise HTTPException(422, 'Reference is not in this engagement catalog')

    async def create(self, sid: str, owner: str, body: CreateTask) -> dict:
        async def build(db, session, state):
            if len(state['tasks']) >= 500:
                raise HTTPException(409, 'Engagement task limit reached')
            self._references(state, body.task.dependencies, 'tasks')
            self._references(state, body.task.evidence_inputs)
            task_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-task:{sid}:{body.request_id}'))
            return 'tasks', task_id, {**body.task.model_dump(), 'id': task_id, 'session_id': sid,
                'owner_id': owner, 'state': 'queued', 'revision': 1, 'attempts': 0, 'result': None,
                'created_at': datetime.now(timezone.utc).isoformat()}
        return await self.mutate(sid, owner, str(body.request_id), {'create': body.task.model_dump()}, build)

    async def transition(self, sid: str, owner: str, task_id: str, body: Transition) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task:
                raise HTTPException(404, 'Task not found')
            if task['revision'] != body.expected_revision:
                raise HTTPException(409, 'Task changed; reload before reviewing')
            updated = transition_task(task, body.state, body.reason)
            if body.state == 'completed':
                updated['reviewed_by'] = owner
            return 'tasks', task_id, updated
        return await self.mutate(sid, owner, str(body.request_id), {'task': task_id, **body.model_dump(mode='json')}, build)

    async def claim(self, sid: str, owner: str, task_id: str, request_id: str) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task:
                raise HTTPException(404, 'Task not found')
            if task['state'] != 'queued':
                raise HTTPException(409, 'Only queued tasks can be delegated')
            if any(state['tasks'][ref]['state'] != 'completed' for ref in task['dependencies']):
                raise HTTPException(409, 'Dependencies require completed human review')
            if task['attempts'] >= task['budget']['max_attempts']:
                raise HTTPException(409, 'Task attempt budget exhausted')
            updated = transition_task(task, 'running', 'Delegated to specialist', internal=True)
            updated.update(attempts=task['attempts'] + 1, run_id=request_id)
            return 'tasks', task_id, updated
        return await self.mutate(sid, owner, request_id, {'claim': task_id}, build)

    async def collect(self, sid: str, owner: str, task_id: str, run_id: str, result: AgentResult) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task or task['state'] != 'running' or task['run_id'] != run_id:
                raise HTTPException(409, 'Task no longer owns this specialist run')
            self._references(state, result.evidence_references)
            if not set(result.evidence_references).issubset(task['evidence_inputs']):
                raise HTTPException(422, 'Result cites evidence outside its task inputs')
            for entry in result.observations + result.hypotheses:
                refs = entry.get('evidence_references', [])
                if entry.get('evidence_id'):
                    refs = [*refs, entry['evidence_id']]
                if not set(refs).issubset(result.evidence_references):
                    raise HTTPException(422, 'Conclusion cites unattributed evidence')
                if not refs and not result.uncertainty:
                    raise HTTPException(422, 'Unattributed conclusions require explicit uncertainty')
            if not result.evidence_references and not result.uncertainty:
                raise HTTPException(422, 'Result requires evidence or explicit uncertainty')
            target = 'blocked' if result.status == 'blocked' else 'awaiting_review'
            updated = transition_task(task, target, 'Specialist result collected', internal=True)
            updated['result'] = result.model_dump()
            return 'tasks', task_id, updated
        return await self.mutate(sid, owner, run_id + ':result', {'collect': task_id, 'result': result.model_dump()}, build)

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
                hashes = {'content_sha256': hashlib.sha256((row.content or '').encode()).hexdigest()}
                if row.msg_type == 'burp_evidence':
                    hashes['capture_sha256'] = data['digest']
                source_time, summary = row.created_at.isoformat(), public((row.content or '')[:2000])
                job_id = data.get('job_id')
                provenance = data.get('source', 'manual_unverified')
            else:
                from memory.worker_jobs import SQLJobStore, TERMINAL
                row = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == sid,
                    DecisionLog.id == SQLJobStore.key(body.source_id),
                    DecisionLog.decision_type == 'worker_job'))).scalar_one_or_none()
                if not row or row.metadata_['state'] not in TERMINAL:
                    raise HTTPException(404, 'Terminal worker receipt not found')
                data = row.metadata_
                hashes = {key: data[key] for key in ('output_hash', 'stderr_hash') if data.get(key)}
                if not hashes:
                    raise HTTPException(409, 'Worker receipt has no stored output hashes')
                source_time, summary = row.created_at.isoformat(), f"Worker observation: {data['state']}; exit {data.get('exit_code')}"
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
