"""An expired human gate stops without a decision, dispatch or replanning."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agents.autonomous_engine import ApprovalRequest, AutonomousEngine, SessionRunState
from tests.support import OfflineCase


class ApprovalExpiryTests(OfflineCase):
    def request(self, expires_at):
        req = ApprovalRequest('action', 'engagement', 2, 'curl -I http://192.0.2.1:80',
            'curl', 'orange', 'Observe', created_at=90, created_monotonic_ns=90_000_000_000)
        req.expires_at = expires_at
        return req

    async def test_wait_stops_at_expiry_without_fabricating_a_human_decision(self):
        for expiry in (99, 100, 101, None, True, float('nan'), float('inf')):
            with self.subTest(expiry=expiry):
                engine = AutonomousEngine()
                state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
                req = self.request(expiry)
                clock = {'now': 100, 'sleeps': 0}
                async def advance(*args):
                    clock['now'] += 1
                    clock['sleeps'] += 1
                    # Terminate the defective old implementation deterministically.
                    if clock['sleeps'] >= 2:
                        state.stop_requested = True
                with patch('agents.autonomous_engine.time', SimpleNamespace(
                        time=lambda: clock['now'], monotonic_ns=lambda: clock['now'] * 1_000_000_000)), \
                     patch('agents.autonomous_engine.asyncio.sleep', AsyncMock(side_effect=advance)), \
                     patch.object(engine, '_emit', AsyncMock()) as emit:
                    result = await engine._wait_for_approval(state, req)
                self.assertEqual(result, 'expired')
                self.assertIsNone(req.decision)
                self.assertIsNone(req.decided_monotonic_ns)
                self.assertLessEqual(clock['sleeps'], 1)
                event = emit.await_args.args[1]
                self.assertEqual(event['status'], 'authorization_expired_or_invalid')
                self.assertIsNone(event['timings']['approval_decision_accepted_ms'])
                self.assertIsNone(event['timings']['approval_release_after_decision_ms'])

    async def test_expired_loop_preserves_evidence_and_stops_without_replanning(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert',
            successful_steps=1, steps_taken=1, evidence_job_ids=['port-job'],
            completed_observations=['port_discovery'], observation_job_ids={'port_discovery': ['port-job']})
        engine._runs[state.session_id] = state
        engine._approvals[state.session_id] = {}
        command = 'curl -I http://192.0.2.1:80'
        proposal = SimpleNamespace(id='action', command=command, tool='curl', risk='orange',
                                   status='pending', expires_at=99)
        async def interrupt_old_loop(*args):
            state.stop_requested = True
        with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={})), \
             patch('agents.autonomous_engine.execution_authorization.propose', AsyncMock(return_value=proposal)) as propose, \
             patch('agents.autonomous_engine.time', SimpleNamespace(time=lambda: 100, monotonic_ns=lambda: 100_000_000_000)), \
             patch('agents.autonomous_engine.asyncio.sleep', AsyncMock(side_effect=interrupt_old_loop)), \
             patch.object(engine, '_persist', AsyncMock()), \
             patch.object(engine, '_write_decision_log', AsyncMock()), \
             patch.object(engine, '_plan_next_step', AsyncMock(return_value={'command': command, 'tool': 'curl'})) as plan, \
             patch.object(engine, '_execute_command', AsyncMock()) as execute:
            await engine._run_loop(state)
        self.assertEqual(state.run_state, 'blocked')
        self.assertEqual(state.reason_code, 'authorization_expired_or_invalid')
        self.assertFalse(state.active)
        self.assertEqual(state.evidence_job_ids, ['port-job'])
        self.assertEqual(state.completed_observations, ['port_discovery'])
        self.assertIsNone(state.pending_approval)
        self.assertIsNone(engine._approvals[state.session_id]['action'].decision)
        execute.assert_not_awaited()
        plan.assert_awaited_once()
        propose.assert_awaited_once()
        self.assertFalse(any('REJECTED by human' in event.get('action', '') for event in state.activity_log))
        self.assertEqual(engine.get_pending_approvals(state.session_id), [])

    async def test_expiry_does_not_override_an_explicit_stop(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert', stop_requested=True)
        with patch.object(engine, '_emit', AsyncMock()) as emit:
            result = await engine._wait_for_approval(state, self.request(0))
        self.assertEqual(result, 'reject')
        self.assertEqual(emit.await_args.args[1]['status'], 'stopped')

    def test_pending_projection_excludes_expired_and_invalid_deadlines(self):
        engine = AutonomousEngine()
        invalid = [self.request(value) for value in (99, 100, None, True, float('nan'), float('inf'))]
        current = self.request(101)
        current.action_id = 'current'
        engine._approvals['engagement'] = {str(index): req for index, req in enumerate(invalid)}
        engine._approvals['engagement']['current'] = current
        with patch('agents.autonomous_engine.time', SimpleNamespace(time=lambda: 100, monotonic_ns=lambda: 100_000_000_000)):
            pending = engine.get_pending_approvals('engagement')
        self.assertEqual([item['action_id'] for item in pending], ['current'])
        self.assertEqual(pending[0]['expires_at'], 101)
