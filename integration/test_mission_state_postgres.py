"""Mission/task consistency on disposable SQL, with harmless fixture evidence."""
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

ENABLED = os.environ.get('ARIA_INTEGRATION') == '1'


@unittest.skipUnless(ENABLED, 'requires disposable *_test PostgreSQL database')
class MissionStatePostgres(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        if not (make_url(os.environ['DATABASE_URL']).database or '').endswith('_test'):
            raise RuntimeError('Disposable *_test database required')
        subprocess.run([sys.executable, '-B', '-m', 'alembic', 'upgrade', 'head'], check=True)

    async def asyncSetUp(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from memory.database_models import User, PentestSession, DecisionLog, async_session, engine
        from memory.worker_jobs import SQLJobStore
        from memory.knowledge_store import KnowledgeStore, scope_identity_digest
        from memory.autonomous_runs import RunStore, command_digest
        from memory.team_tasks import TeamStore, EvidenceInput
        await engine.dispose()
        self.owner, self.sid = 'mission-owner-' + uuid.uuid4().hex[:12], 'mission-' + uuid.uuid4().hex[:12]
        self.job = str(uuid.uuid4())
        scope = {'targets': ['192.0.2.1'], 'ports': [80]}
        stdout = 'HTTP/1.1 200 OK\r\nServer: synthetic-fixture\r\n'
        async with async_session() as db:
            db.add(User(id=self.owner, username=self.owner, password_hash='unused'))
            await db.flush()
            db.add(PentestSession(id=self.sid, user_id=self.owner, target='192.0.2.1', scope=scope))
            await db.flush()
            db.add(DecisionLog(id=SQLJobStore.key(self.job), session_id=self.sid, user_id=self.owner,
                decision_type='worker_job', metadata_={'job_id': self.job, 'session_id': self.sid,
                    'user_id': self.owner, 'state': 'succeeded', 'exit_code': 0, 'synthetic': True,
                    'output_hash': hashlib.sha256(stdout.encode()).hexdigest(),
                    'stderr_hash': hashlib.sha256(b'').hexdigest()}))
            await db.commit()
        self.state = SessionRunState(self.sid, self.owner, 'http_check', '192.0.2.1', 'expert',
            owner_id=self.owner, objective='Observe the approved synthetic HTTP fixture',
            run_state='completed', active=False, steps_taken=1, successful_steps=1,
            capabilities={'tools': ['curl']}, reason_code='required_observations_completed',
            reason='Required observations completed with durable worker receipts: http_response',
            scope_digest=scope_identity_digest(scope, '192.0.2.1'),
            evidence_job_ids=[self.job], completed_observations=['http_response'],
            observation_job_ids={'http_response': [self.job]},
            executed_commands=['curl -I http://192.0.2.1'],
            executed_command_hashes=[command_digest('curl -I http://192.0.2.1')])
        await KnowledgeStore().record_observation(session_id=self.sid, owner_id=self.owner,
            run_id=self.state.run_id, job_id=self.job, tool='curl', observation='http_response',
            target='192.0.2.1', stdout=stdout, stderr='', exit_code=0)
        engine_fixture = AutonomousEngine()
        engine_fixture._runs[self.sid] = self.state
        self.runs = RunStore()
        await self.runs.save(engine_fixture.get_status(self.sid))
        self.tasks = TeamStore()
        evidence = await self.tasks.catalog(self.sid, self.owner, EvidenceInput(
            request_id=uuid.uuid4(), source_kind='worker', source_id=self.job))
        self.evidence = evidence['entity_id']

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    async def create_task(self, *, dependencies=()):
        from memory.team_tasks import TaskSpec, CreateTask
        return await self.tasks.create(self.sid, self.owner, CreateTask(
            request_id=uuid.uuid4(), task=TaskSpec(owner_role='web_intel',
                objective='Review the harmless saved HTTP fixture',
                expected_output='Evidence-linked analysis with explicit uncertainty',
                completion_criteria=['Cite the saved fixture or explain uncertainty'],
                dependencies=list(dependencies), evidence_inputs=[self.evidence])))

    async def test_expired_human_gate_persists_blocker_without_a_decision_or_dispatch(self):
        from dataclasses import replace
        import time
        from fastapi import HTTPException
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from memory.execution_authorization import ExecutionAuthorization
        service = ExecutionAuthorization()
        async def expired_proposal(*args, **kwargs):
            proposal = await service.propose(*args, **kwargs)
            expired = replace(proposal, expires_at=time.time() - 1)
            self.assertTrue(await service.store.transition(proposal, expired))
            return expired
        engine_fixture = AutonomousEngine()
        state = SessionRunState(self.sid, self.owner, 'discovery', '192.0.2.1', 'expert',
            owner_id=self.owner, risk_threshold='manual',
            objective='Observe the authorized synthetic fixture; stop on expired authorization')
        engine_fixture._runs[self.sid] = state
        engine_fixture._approvals[self.sid] = {}
        with patch('agents.autonomous_engine.execution_authorization.propose', AsyncMock(side_effect=expired_proposal)) as propose, \
             patch.object(engine_fixture, '_plan_next_step', AsyncMock(return_value={
                 'tool': 'curl', 'command': 'curl -I http://192.0.2.1:80'})) as plan, \
             patch.object(engine_fixture, '_execute_command', AsyncMock()) as execute:
            await engine_fixture._run_loop(state)
        execute.assert_not_awaited()
        propose.assert_awaited_once()
        plan.assert_awaited_once()
        saved = await self.runs.latest(self.sid)
        self.assertEqual(saved['run_state'], 'blocked')
        self.assertEqual(saved['reason_code'], 'authorization_expired_or_invalid')
        self.assertEqual(saved['original_objective'], state.objective)
        self.assertEqual(saved['evidence_job_ids'], [])
        self.assertFalse(saved['waiting_approval'])
        action_id = next(iter(engine_fixture._approvals[self.sid]))
        proposal = await service.store.get(action_id)
        self.assertEqual(proposal.status, 'pending')
        self.assertEqual(proposal.decision, '')
        self.assertLess(proposal.expires_at, time.time())
        with self.assertRaises(HTTPException) as denied:
            await service.decide(self.owner, self.sid, action_id, 'approve')
        self.assertEqual(denied.exception.status_code, 403)

    async def test_pending_work_survives_recovery_and_a_fresh_process(self):
        from orchestrator.mission_status import mission_status
        task = await self.create_task()
        await self.tasks.claim(self.sid, self.owner, task['entity_id'], str(uuid.uuid4()))
        await self.runs.recover()
        await self.tasks.recover()
        run, ledger = await self.runs.latest(self.sid), await self.tasks.view(self.sid, self.owner)
        projection = mission_status(run, ledger)
        self.assertEqual(projection['bounded_run_state'], 'completed')
        self.assertEqual(projection['state'], 'work_pending')
        self.assertEqual(projection['pending_tasks'][0]['state'], 'blocked')
        cursor = ledger['cursor']
        await self.tasks.recover()
        self.assertEqual((await self.tasks.view(self.sid, self.owner))['cursor'], cursor)
        reader = '''
import asyncio, json, os
from memory.autonomous_runs import RunStore
from memory.team_tasks import TeamStore
from memory.database_models import engine
from orchestrator.mission_status import mission_status
async def run():
    sid, owner = json.loads(os.environ['ARIA_MISSION_FIXTURE'])
    view = mission_status(await RunStore().latest(sid), await TeamStore().view(sid, owner))
    assert view['state'] == 'work_pending'
    assert view['pending_tasks'][0]['state'] == 'blocked'
    assert view['bounded_run_state'] == 'completed'
    print(json.dumps({'state':view['state'],'pending':len(view['pending_tasks'])}))
    await engine.dispose()
asyncio.run(run())
'''
        child = await asyncio.to_thread(subprocess.run, [sys.executable, '-B', '-c', reader],
            env={**os.environ, 'ARIA_MISSION_FIXTURE': json.dumps([self.sid, self.owner])},
            capture_output=True, timeout=30)
        self.assertEqual(child.returncode, 0)
        self.assertEqual(json.loads(child.stdout), {'state': 'work_pending', 'pending': 1})

    async def test_concurrent_delivery_attributes_one_result_and_requires_owner_review(self):
        from agents.result_contract import AgentResult
        from memory.team_tasks import Transition
        from orchestrator.team_coordinator import TeamCoordinator
        from orchestrator.mission_status import mission_status
        task = await self.create_task()
        tid, request = task['entity_id'], str(uuid.uuid4())
        specialist = SimpleNamespace(process=AsyncMock(return_value={'agent_result': AgentResult(
            interpreted_request='Review saved fixture', evidence_references=[self.evidence],
            uncertainty=['Synthetic observation; no vulnerability established']).model_dump()}))
        coordinator = TeamCoordinator()
        with patch.object(coordinator, 'specialists', return_value={'web_intel': specialist}), \
             patch('memory.worker_jobs.worker_jobs.execute', AsyncMock()) as execute:
            results = await asyncio.gather(*[
                coordinator.run(self.sid, self.owner, tid, request, 'expert') for _ in range(5)])
        specialist.process.assert_awaited_once()
        execute.assert_not_awaited()
        self.assertEqual(sum(bool(item['duplicate']) for item in results), 4)
        ledger = await self.tasks.view(self.sid, self.owner)
        self.assertEqual(ledger['tasks'][0]['state'], 'awaiting_review')
        self.assertEqual(mission_status(await self.runs.latest(self.sid), ledger)['state'], 'work_pending')
        collected = ledger['tasks'][0]
        await self.tasks.transition(self.sid, self.owner, tid, Transition(request_id=uuid.uuid4(),
            expected_revision=collected['revision'], state='completed',
            reason='Synthetic owner reviewed the result and its limitations'))
        final = mission_status(await self.runs.latest(self.sid), await self.tasks.view(self.sid, self.owner))
        self.assertEqual(final['state'], 'completed')
        self.assertEqual(final['completed_task_ids'], [tid])

    async def test_owner_delegation_overlaps_and_recovers_saved_reviews(self):
        from agents.coordinator_agent import coordinator_agent
        from llm.engagement_budget import task_context
        from memory.database_models import engine
        from memory.team_tasks import CreateTask, TaskSpec
        from orchestrator.team_coordinator import TeamCoordinator

        async def create():
            return (await self.tasks.create(self.sid, self.owner, CreateTask(request_id=uuid.uuid4(),
                task=TaskSpec(owner_role='correlation', internal_review='challenge',
                              objective='Evaluate the saved response receipt',
                              expected_output='Cited interpretation',
                              completion_criteria=['Explicit uncertainty'],
                              evidence_inputs=[self.evidence]))))['entity_id']

        ids = [await create(), await create()]
        entered = set()
        both = asyncio.Event()
        release = asyncio.Event()

        async def provider(owner, prompt, system):
            self.assertEqual(owner, self.owner)
            entered.add(task_context.get()['id'])
            if entered == set(ids):
                both.set()
            await release.wait()
            return {'success': True, 'content': json.dumps({'correlations': [
                {'finding': 'The receipt alone leaves ownership uncertain',
                 'evidence_references': [self.evidence], 'disposition': 'inconclusive'}]})}

        with (
            patch('orchestrator.team_coordinator.team_coordinator', TeamCoordinator()),
            patch('llm.pool_manager.pool_manager.query', AsyncMock(side_effect=provider)) as query,
            patch('memory.worker_jobs.worker_jobs.execute', AsyncMock()) as execute,
        ):
            calls = [asyncio.create_task(coordinator_agent.delegate_task(
                self.sid, self.owner, tid, str(uuid.uuid4()))) for tid in ids]
            try:
                await asyncio.wait_for(both.wait(), timeout=5)
                self.assertEqual({task['state'] for task in (await self.tasks.view(self.sid, self.owner))['tasks']},
                                 {'running'})
            finally:
                release.set()
                outcomes = await asyncio.gather(*calls)
            self.assertEqual([outcome['states'] for outcome in outcomes],
                             [{tid: 'analyzed'} for tid in ids])
            await engine.dispose()
            await self.tasks.recover()
            saved = await self.tasks.view(self.sid, self.owner)
            with patch('orchestrator.team_coordinator.team_coordinator', TeamCoordinator()):
                for tid in ids:
                    await coordinator_agent.delegate_task(self.sid, self.owner, tid, str(uuid.uuid4()))
            self.assertEqual(await self.tasks.view(self.sid, self.owner), saved)
            self.assertEqual(query.await_count, 2)
            execute.assert_not_awaited()

    async def test_dependencies_cancellation_stale_updates_and_owner_isolation(self):
        from fastapi import HTTPException
        from agents.result_contract import AgentResult
        from memory.team_tasks import Transition
        from orchestrator.mission_status import mission_status
        first = await self.create_task()
        second = await self.create_task(dependencies=[first['entity_id']])
        with self.assertRaises(HTTPException):
            await self.tasks.claim(self.sid, self.owner, second['entity_id'], str(uuid.uuid4()))
        with self.assertRaises(HTTPException):
            await self.tasks.view(self.sid, 'other-owner')
        claim_id = str(uuid.uuid4())
        claim = await self.tasks.claim(self.sid, self.owner, first['entity_id'], claim_id)
        await self.tasks.transition(self.sid, self.owner, first['entity_id'], Transition(
            request_id=uuid.uuid4(), expected_revision=claim['data']['revision'],
            state='cancelled', reason='Synthetic owner cancelled analysis'))
        with self.assertRaises(HTTPException):
            await self.tasks.collect(self.sid, self.owner, first['entity_id'], claim_id,
                AgentResult(interpreted_request='Late result', uncertainty=['Must not resurrect']))
        with self.assertRaises(HTTPException):
            await self.tasks.transition(self.sid, self.owner, first['entity_id'], Transition(
                request_id=uuid.uuid4(), expected_revision=claim['data']['revision'],
                state='blocked', reason='Stale owner update'))
        await self.tasks.recover()
        view = mission_status(await self.runs.latest(self.sid), await self.tasks.view(self.sid, self.owner))
        self.assertEqual(view['state'], 'work_pending')
        self.assertEqual(view['cancelled_task_ids'], [first['entity_id']])
        self.assertEqual(view['pending_tasks'][0]['id'], second['entity_id'])
