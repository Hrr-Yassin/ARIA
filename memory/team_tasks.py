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

from agents.result_contract import AgentResult, normalize_unverified_result
from memory.database_models import ChatLog, DecisionLog, PentestSession, PentestPhase, async_session
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
    security_questions: list[Reference] = Field(default_factory=list, max_length=20)
    phase: Literal['scope', 'reconnaissance', 'scanning', 'vulnerability_analysis', 'exploitation', 'post_exploitation', 'reporting'] | None = None
    specialty: Literal['authorization', 'authentication', 'exposure', 'input_validation', 'business_logic'] | None = None

    @model_validator(mode='after')
    def specialty_questions(self):
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
             'research_hypotheses': {}, 'research_models': {}, 'cursor': 0}
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
                         *, before: int | None = None) -> tuple[list[dict], bool]:
        """Return the latest page or older-cursor increments without materializing the ledger."""
        async with async_session() as db:
            sequence = DecisionLog.metadata_['sequence'].as_integer()
            query = select(DecisionLog.metadata_).where(DecisionLog.session_id == sid,
                DecisionLog.user_id == owner, DecisionLog.decision_type == 'team_event')
            if after is None:
                if before is not None:
                    query = query.where(sequence < before)
                query = query.order_by(sequence.desc(), DecisionLog.id.desc())
            else:
                query = query.where(sequence > after).order_by(sequence, DecisionLog.id)
            records = (await db.execute(query.limit(limit + 1))).scalars().all()
            page = records[:limit]
            return (page[::-1] if after is None else page), len(records) > limit

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
        task_data = body.task.model_dump(exclude={'phase'} if body.task.phase is None else set())
        if set(internal) & set(task_data):
            raise ValueError('Internal task metadata conflicts with the task contract')
        task_data.update(internal)
        async def build(db, session, state):
            if len(state['tasks']) >= 500:
                raise HTTPException(409, 'Engagement task limit reached')
            self._references(state, body.task.dependencies, 'tasks')
            self._references(state, body.task.evidence_inputs)
            task_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-task:{sid}:{body.request_id}'))
            return 'tasks', task_id, {**task_data, 'id': task_id, 'session_id': sid,
                'owner_id': owner, 'state': 'queued', 'revision': 1, 'attempts': 0, 'result': None,
                'created_at': datetime.now(timezone.utc).isoformat()}
        return await self.mutate(sid, owner, str(body.request_id), {'create': task_data}, build)

    async def migrate_task(self, sid: str, owner: str, task_id: str, body: MigrateTask) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(task_id)
            if not task:
                raise HTTPException(404, 'Task not found')
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
        # Storage is the trust boundary.  Even a direct caller cannot persist
        # an LLM observation or hypothesis as verified; worker receipts remain
        # separately cataloged with their own provenance.
        normalized = normalize_unverified_result(result)
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
            target = 'blocked' if normalized.status == 'blocked' else 'awaiting_review'
            updated = transition_task(task, target, 'Specialist result collected', internal=True)
            updated['result'] = normalized.model_dump()
            return 'tasks', task_id, updated
        return await self.mutate(sid, owner, run_id + ':result', {'collect': task_id, 'result': normalized.model_dump()}, build)

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
