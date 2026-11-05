"""Offline run-state and history regressions. No model or worker is contacted."""
import copy
from unittest.mock import AsyncMock, patch
from api.main import app
from api.auth import get_current_user
from agents.autonomous_engine import AutonomousEngine, SessionRunState
from agents.orchestrator_agent import orchestrator_agent
from memory.autonomous_runs import RunStore
from tests.support import OfflineCase
from tests.test_access import OWNER, SESSION


class ReliabilityTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_asset_hash_and_html_revalidation(self):
        for path in ['/', '/chat/engagement', '/login', '/admin']:
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['cache-control'], 'no-cache')
            self.assertEqual(len(response.headers['x-aria-build']), 16)
            self.assertIn('?v=', response.text)

    async def test_history_page_retains_chronology_and_owner_check(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        rows = [{'content': str(i)} for i in range(3)]
        with patch('api.routers.sessions.get_accessible_session', AsyncMock(return_value=SESSION)), patch('api.routers.sessions.session_manager.get_chat_logs', AsyncMock(return_value=rows)) as logs, patch('api.routers.sessions.session_manager.get_findings_summary', AsyncMock(return_value={})):
            response = await self.client.get('/api/session/engagement/restore?limit=2&offset=4')
            self.assertEqual(response.json()['logs'], rows[1:])
            self.assertTrue(response.json()['has_more'])
            logs.assert_awaited_once_with('engagement', limit=3, offset=4)
        self.assertEqual((await self.client.get('/api/session/engagement/restore?limit=0')).status_code, 422)

    async def test_invalid_proposals_get_two_corrections_and_no_dispatch(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert', capabilities={'tools':['nmap']})
        engine._runs[state.session_id] = state
        planner = AsyncMock(return_value={'commands':[{'command':'nmap -p 80 198.51.100.1'}]})
        context = {'scope':{'targets':['192.0.2.1'], 'ports':[80]}}
        with patch.object(orchestrator_agent, 'process', planner), patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value=context)):
            self.assertIsNone(await engine._plan_next_step(state))
        self.assertEqual(planner.await_count, 3)
        self.assertEqual(state.reason_code, 'invalid_planner_output')
        self.assertTrue(planner.await_args.kwargs['input_data']['validation_feedback'])
        self.assertEqual(planner.await_args.kwargs['input_data']['worker_capabilities'], {'tools':['nmap']})

    async def test_no_proposal_is_blocked_not_complete(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement','owner','discovery','192.0.2.1','expert')
        engine._runs[state.session_id] = state
        snapshots = []
        async def save(value): snapshots.append(copy.deepcopy(value))
        with patch('agents.autonomous_engine.run_store.save', AsyncMock(side_effect=save)), patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={})), patch.object(engine, '_plan_next_step', AsyncMock(return_value=None)), patch.object(engine, '_write_decision_log', AsyncMock()):
            await engine._run_loop(state)
        self.assertEqual(state.run_state, 'blocked')
        self.assertEqual(snapshots[-1]['reason_code'], 'no_executable_proposal')
        self.assertFalse(snapshots[-1]['active'])
        self.assertFalse(any(e.get('type') == 'goal_achieved' for e in state.activity_log))

    async def test_unsupported_goal_preserved_without_planning(self):
        engine = AutonomousEngine()
        with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={})), patch('agents.autonomous_engine.execution_authorization._validate'), patch.object(engine, '_run_loop', AsyncMock()) as loop:
            result = await engine.start('engagement','owner',goal='initial_access',target='192.0.2.1')
        self.assertEqual(result['goal'], 'initial_access')
        self.assertEqual(result['reason_code'], 'unsupported_goal')
        loop.assert_not_awaited()

    async def test_persistence_failure_prevents_start(self):
        engine = AutonomousEngine()
        with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={})), patch('agents.autonomous_engine.execution_authorization._validate'), patch('agents.autonomous_engine.run_store.save', AsyncMock(side_effect=RuntimeError('database outage'))):
            with self.assertRaises(RuntimeError):
                await engine.start('engagement','owner',goal='initial_access')
        self.assertNotIn('engagement', engine._runs)
        self.assertEqual(engine._tasks, {})

    async def test_restart_blocks_unfinished_without_replay(self):
        from types import SimpleNamespace
        row = SimpleNamespace(state='executing', snapshot={'run_id':'run','active':True}, updated_at=None)
        db = AsyncMock()
        result = db.execute.return_value
        from unittest.mock import Mock
        result.scalars = Mock(return_value=Mock(all=Mock(return_value=[row])))
        with patch('memory.autonomous_runs.async_session') as factory:
            factory.return_value.__aenter__.return_value = db
            await RunStore().recover()
        self.assertEqual(row.state, 'blocked')
        self.assertEqual(row.snapshot['reason_code'], 'restart_reconciliation')
        self.assertFalse(row.snapshot['active'])
        db.commit.assert_awaited_once()

    async def test_success_requires_job_receipt_and_output(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement','owner','discovery','192.0.2.1','expert')
        for result, expected in [({'exit_code':0, 'stdout':'hello'}, False),
            ({'exit_code':0, 'job_id':'job', 'stdout':''}, False),
            ({'exit_code':1, 'job_id':'job', 'stdout':'misleading success'}, False),
            ({'exit_code':0, 'job_id':'job', 'stdout':'HTTP/1.0 200 OK'}, True)]:
            with patch('agents.autonomous_engine.execution_authorization.execute', AsyncMock(return_value=result)):
                self.assertEqual((await engine._execute_command(state,'curl','curl -I http://192.0.2.1'))[2], expected)
        self.assertEqual(state.evidence_job_ids, ['job'])

    async def test_valid_correction_keeps_goal_scope_and_capabilities(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement','owner','discovery','192.0.2.1','expert', capabilities={'tools':['nmap']})
        engine._runs[state.session_id] = state
        planner = AsyncMock(side_effect=[{'commands':[None]}, {'commands':[{'command':'nmap -p 80 192.0.2.1'}]}])
        with patch.object(orchestrator_agent, 'process', planner), patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={'scope':{'targets':['192.0.2.1'], 'ports':[80]}})):
            proposal = await engine._plan_next_step(state)
        self.assertEqual(proposal['tool'], 'nmap')
        self.assertEqual(planner.await_count, 2)
        self.assertEqual(state.goal, 'discovery')
        self.assertIn('Command must be an object', planner.await_args.kwargs['input_data']['validation_feedback'])

    async def test_completed_snapshot_never_restores_as_active(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement','owner','discovery','192.0.2.1','expert', run_state='completed')
        engine._runs[state.session_id] = state
        self.assertFalse(engine.get_status(state.session_id)['active'])

    async def test_discovery_replans_until_both_observations_have_receipts(self):
        from types import SimpleNamespace
        engine=AutonomousEngine()
        state=SessionRunState('engagement','owner','discovery','192.0.2.1','expert',max_steps=3)
        engine._runs[state.session_id]=state
        steps=[{'tool':'nmap','command':'nmap -p 80 192.0.2.1'}, {'tool':'curl','command':'curl -I http://192.0.2.1'}]
        async def propose(uid,sid,command,tool,**kwargs):
            return SimpleNamespace(command=command,tool=tool,risk='green',id=tool,status='authorized')
        parsed=SimpleNamespace(events=[],ports_added=[],vulns_added=[],creds_added=[],shells_added=[])
        with patch('agents.autonomous_engine.execution_authorization._context',AsyncMock(return_value={})), patch('agents.autonomous_engine.execution_authorization.propose',AsyncMock(side_effect=propose)), patch('agents.autonomous_engine.execution_authorization.execute',AsyncMock(side_effect=[{'exit_code':0,'job_id':'j1','stdout':'80/tcp open http'},{'exit_code':0,'job_id':'j2','stdout':'HTTP/1.1 200 OK'}])), patch.object(engine,'_plan_next_step',AsyncMock(side_effect=steps)) as planner, patch.object(engine,'_write_decision_log',AsyncMock()), patch('agents.autonomous_engine.dispatch_parser',return_value=parsed), patch.object(engine,'STEP_DELAY',0):
            await engine._run_loop(state)
        self.assertEqual(planner.await_count,2)
        self.assertEqual(state.run_state,'completed')
        self.assertEqual(set(state.completed_observations),{'port_discovery','http_response'})
        self.assertEqual(state.evidence_job_ids,['j1','j2'])
