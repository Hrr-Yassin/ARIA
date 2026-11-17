"""Mission finalization must be identical after an observation or a restart.

All execution, providers and persistence are offline fixtures. These tests drive
real loop control flow and inspect public terminal state and side effects.
"""
from contextlib import ExitStack
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from agents.autonomous_engine import (
    ApprovalRequest, AutonomousEngine, InvestigationReviewError, SessionRunState,
)
from tests.support import OfflineCase


class MissionContinuityTests(OfflineCase):
    async def test_approval_timing_distinguishes_accepted_decision_from_stop(self):
        for stopped in (False, True):
            with self.subTest(stopped=stopped):
                engine = AutonomousEngine()
                state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
                req = ApprovalRequest('action', 'engagement', 1, 'fixture', 'curl', 'orange', 'test',
                    created_monotonic_ns=1_000_000_000, expires_at=1000)
                async def decide_or_stop(*args):
                    if stopped:
                        state.stop_requested = True
                    else:
                        req.decided_monotonic_ns = 2_000_000_000
                        req.decision = 'approve'
                with patch('agents.autonomous_engine.time', SimpleNamespace(
                        time=lambda: 100,
                        monotonic_ns=iter((1_200_000_000, 2_500_000_000)).__next__)), \
                     patch('agents.autonomous_engine.asyncio.sleep', AsyncMock(side_effect=decide_or_stop)), \
                     patch.object(engine, '_emit', AsyncMock()) as emit:
                    decision = await engine._wait_for_approval(state, req)
                event = emit.await_args.args[1]
                self.assertEqual(event['action_id'], 'action')
                self.assertEqual(event['timings'], {
                    'approval_gate_pending_ms': 1500, 'approval_poll_loop_ms': 1300,
                    'approval_decision_accepted_ms': None if stopped else 1000,
                    'approval_release_after_decision_ms': None if stopped else 500})
                self.assertEqual(event['status'], 'stopped' if stopped else 'decided')
                self.assertEqual(decision, 'reject' if stopped else 'approve')

    def test_pending_approval_age_uses_monotonic_clock(self):
        engine = AutonomousEngine()
        req = ApprovalRequest('action', 'engagement', 1, 'fixture', 'curl', 'orange', 'test',
            created_at=9_999_999_999, created_monotonic_ns=1_000_000_000, expires_at=1000)
        engine._approvals['engagement'] = {'action': req}
        with patch('agents.autonomous_engine.time', SimpleNamespace(time=lambda: 100, monotonic_ns=lambda: 3_400_000_000)):
            self.assertEqual(engine.get_pending_approvals('engagement')[0]['waiting_seconds'], 2)

    async def test_stop_during_approval_wait_is_not_recorded_as_human_rejection(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert',
            successful_steps=1, steps_taken=1, evidence_job_ids=['port-job'],
            completed_observations=['port_discovery'], observation_job_ids={'port_discovery':['port-job']})
        engine._runs[state.session_id] = state
        engine._approvals[state.session_id] = {}
        waiting, cancelling, release_cancel = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def approval_wait(*args):
            waiting.set()
            await cancelling.wait()
            return 'reject'  # Existing polling contract when stop_requested becomes true.
        async def slow_cancellation(*args):
            cancelling.set()
            await release_cancel.wait()
            return {'pending': 1, 'cancelled': 0, 'jobs': []}
        command = 'curl -I http://192.0.2.1:80'
        proposal = SimpleNamespace(id='action', command=command, tool='curl', risk='orange', status='pending',
                                   expires_at=9_999_999_999)
        with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={})), \
             patch('agents.autonomous_engine.execution_authorization.propose', AsyncMock(return_value=proposal)), \
             patch('agents.autonomous_engine.worker_jobs.cancel_session', AsyncMock(side_effect=slow_cancellation)), \
             patch.object(engine, '_persist', AsyncMock()), \
             patch.object(engine, '_write_decision_log', AsyncMock()), \
             patch.object(engine, '_plan_next_step', AsyncMock(return_value={'command':command,'tool':'curl','purpose':'Observe'})), \
             patch.object(engine, '_wait_for_approval', AsyncMock(side_effect=approval_wait)), \
             patch.object(engine, '_execute_command', AsyncMock()) as execute:
            loop = asyncio.create_task(engine._run_loop(state))
            engine._tasks[state.session_id] = loop
            await asyncio.wait_for(waiting.wait(), timeout=2)
            stop = asyncio.create_task(engine.request_stop(state.session_id, 'owner'))
            try:
                await asyncio.wait_for(loop, timeout=2)
            finally:
                release_cancel.set()
                await asyncio.gather(stop, return_exceptions=True)
            execute.assert_not_awaited()
        self.assertEqual(state.reason_code, 'cancelled')
        self.assertFalse(state.cancellation_confirmed)
        self.assertEqual(state.evidence_job_ids, ['port-job'])
        self.assertFalse(any('REJECTED by human' in e.get('action', '') for e in state.activity_log))

    def completed_observations(self):
        return SessionRunState(
            'engagement', 'owner', 'discovery', '192.0.2.1', 'expert',
            objective='Observe authorized services and preserve pending hypotheses',
            successful_steps=2, steps_taken=2,
            capabilities={'tools': ['nmap', 'curl'],
                          'typed_adapters': {'httpx.http.probe.v1': 1}},
            evidence_job_ids=['port-job', 'http-job'],
            completed_observations=['port_discovery', 'http_response'],
            observation_job_ids={'port_discovery': ['port-job'],
                                 'http_response': ['http-job']},
        )

    async def run_completed(self, state, *, review_error=None, context=None, context_error=None):
        engine = AutonomousEngine()
        engine._runs[state.session_id] = state
        with ExitStack() as stack:
            stack.enter_context(patch(
                'agents.autonomous_engine.execution_authorization._context',
                AsyncMock(return_value=context or {}, side_effect=context_error)))
            stack.enter_context(patch.object(engine, '_persist', AsyncMock()))
            stack.enter_context(patch.object(engine, '_write_decision_log', AsyncMock()))
            review = stack.enter_context(patch.object(
                engine, '_review_investigation', AsyncMock(side_effect=review_error)))
            specialist = stack.enter_context(patch.object(
                engine, '_run_specialist_phase_guarded', AsyncMock(return_value=True)))
            planner = stack.enter_context(patch.object(engine, '_plan_next_step', AsyncMock()))
            execute = stack.enter_context(patch.object(engine, '_execute_command', AsyncMock()))
            await engine._run_loop(state)
        return engine.get_status(state.session_id), review, specialist, planner, execute

    async def test_resumed_observations_require_review_before_completion(self):
        state = self.completed_observations()
        status, review, specialist, planner, execute = await self.run_completed(state)
        review.assert_awaited_once_with(state)
        specialist.assert_awaited_once_with(state)
        planner.assert_not_awaited()
        execute.assert_not_awaited()
        self.assertEqual(status['run_state'], 'completed')
        self.assertEqual(status['reason_code'], 'required_observations_completed')
        self.assertIn('durable worker receipts', status['reason'])
        self.assertEqual(status['evidence_job_ids'], ['port-job', 'http-job'])
        self.assertFalse(status['active'])

    async def test_resumed_invalid_review_remains_blocked_with_completed_work(self):
        state = self.completed_observations()
        failure = InvestigationReviewError('invalid_review_output', 'Review schema rejected')
        status, review, specialist, planner, execute = await self.run_completed(
            state, review_error=failure)
        review.assert_awaited_once_with(state)
        specialist.assert_not_awaited()
        planner.assert_not_awaited()
        execute.assert_not_awaited()
        self.assertEqual(status['run_state'], 'blocked')
        self.assertEqual(status['reason_code'], 'invalid_review_output')
        self.assertTrue(status['completion']['complete'])
        self.assertEqual(status['successful_steps'], 2)
        self.assertEqual(status['evidence_job_ids'], ['port-job', 'http-job'])
        self.assertFalse(any(event['type'] == 'goal_achieved'
                             for event in state.activity_log))

    async def test_accepted_review_is_not_repeated_for_same_receipts(self):
        state = self.completed_observations()
        state.reviewed_evidence_job_ids = ['http-job', 'port-job']
        status, review, specialist, planner, execute = await self.run_completed(state)
        review.assert_not_awaited()
        specialist.assert_awaited_once_with(state)
        planner.assert_not_awaited()
        execute.assert_not_awaited()
        self.assertEqual(status['reason_code'], 'required_observations_completed')

    async def test_added_receipt_requires_a_new_review(self):
        state = self.completed_observations()
        state.reviewed_evidence_job_ids = ['port-job']
        status, review, _, planner, execute = await self.run_completed(state)
        review.assert_awaited_once_with(state)
        planner.assert_not_awaited()
        execute.assert_not_awaited()
        self.assertEqual(status['reviewed_evidence_job_ids'], ['port-job', 'http-job'])

    async def test_final_operation_at_step_limit_can_finish_processing(self):
        state = self.completed_observations()
        state.max_steps = state.steps_taken
        status, review, _, planner, execute = await self.run_completed(state)
        review.assert_awaited_once_with(state)
        planner.assert_not_awaited()
        execute.assert_not_awaited()
        self.assertEqual(status['run_state'], 'completed')

    async def test_step_limit_with_pending_observations_never_dispatches(self):
        state = self.completed_observations()
        state.max_steps = state.steps_taken
        state.observation_job_ids.pop('http_response')
        state.completed_observations.remove('http_response')
        state.evidence_job_ids.remove('http-job')
        status, review, specialist, planner, execute = await self.run_completed(state)
        review.assert_not_awaited()
        specialist.assert_not_awaited()
        planner.assert_not_awaited()
        execute.assert_not_awaited()
        self.assertEqual(status['run_state'], 'blocked')
        self.assertEqual(status['reason_code'], 'step_budget_exhausted')
        self.assertEqual(status['completion']['missing'], ['http_response'])

    async def test_pause_during_review_preserves_review_without_completing(self):
        state = self.completed_observations()

        async def pause_after_review(_):
            state.stop_requested = True
            state.pause_requested = True

        status, review, specialist, planner, execute = await self.run_completed(
            state, review_error=pause_after_review)
        review.assert_awaited_once_with(state)
        specialist.assert_not_awaited()
        planner.assert_not_awaited()
        execute.assert_not_awaited()
        self.assertEqual(status['run_state'], 'blocked')
        self.assertEqual(status['reason_code'], 'run_interrupted')
        self.assertIn('paused', status['reason'].lower())
        self.assertEqual(status['reviewed_evidence_job_ids'], ['port-job', 'http-job'])

    async def test_persistence_failure_during_cleanup_restores_accounting_context(self):
        from llm.engagement_budget import engagement_context
        previous = {'session_id': 'previous-session', 'owner': 'previous-owner'}
        token = engagement_context.set(previous)
        state = self.completed_observations()
        engine = AutonomousEngine()
        try:
            with patch('agents.autonomous_engine.execution_authorization._context',
                       AsyncMock(return_value={})), \
                 patch.object(engine, '_check_goal_achieved',
                              AsyncMock(side_effect=RuntimeError('Synthetic processing failure'))), \
                 patch.object(engine, '_persist',
                              AsyncMock(side_effect=RuntimeError('Synthetic persistence failure'))), \
                 patch.object(engine, '_write_decision_log', AsyncMock()):
                with self.assertRaises(RuntimeError):
                    await engine._run_loop(state)
            self.assertEqual(engagement_context.get(), previous)
            self.assertFalse(state.active)
            self.assertNotEqual(state.run_state, 'completed')
        finally:
            engagement_context.reset(token)

    async def test_stop_without_a_live_loop_records_worker_acknowledgement(self):
        from orchestrator.mission_status import mission_status
        for pending, expected in [(0, 'cancelled'), (1, 'cancellation_pending')]:
            with self.subTest(pending=pending):
                state = self.completed_observations()
                engine = AutonomousEngine()
                engine._runs[state.session_id] = state
                with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock()), \
                     patch('agents.autonomous_engine.worker_jobs.cancel_session',
                           AsyncMock(return_value={'pending': pending, 'cancelled': 0, 'jobs': []})), \
                     patch.object(engine, '_persist', AsyncMock()):
                    await engine.request_stop(state.session_id, state.user_id)
                self.assertFalse(state.active)
                view = mission_status(engine.get_status(state.session_id), {'tasks': []})
                self.assertEqual(view['state'], expected)
                self.assertEqual(state.evidence_job_ids, ['port-job', 'http-job'])

    async def test_authorization_changes_stop_with_exact_safe_reason(self):
        for context, code in [({'auth_revision': 1}, 'authorization_changed'),
                              ({'worker_epoch': 1}, 'worker_epoch_changed')]:
            with self.subTest(context=context):
                state = self.completed_observations()
                status, review, _, planner, execute = await self.run_completed(state, context=context)
                self.assertEqual(status['run_state'], 'blocked')
                self.assertEqual(status['reason_code'], code)
                self.assertTrue(status['reason'])
                self.assertEqual(status['evidence_job_ids'], ['port-job', 'http-job'])
                review.assert_not_awaited()
                planner.assert_not_awaited()
                execute.assert_not_awaited()

    async def test_pause_before_iteration_retains_an_explicit_terminal_reason(self):
        state = self.completed_observations()
        state.stop_requested = True
        state.pause_requested = True
        status, review, _, planner, execute = await self.run_completed(state)
        self.assertEqual(status['run_state'], 'blocked')
        self.assertEqual(status['reason_code'], 'run_interrupted')
        self.assertIn('paused', status['reason'].lower())
        review.assert_not_awaited()
        planner.assert_not_awaited()
        execute.assert_not_awaited()

    async def test_policy_denials_are_blocked_with_exact_safe_reason(self):
        cases = [(403, 'Command is not permitted by engagement policy', 'execution_policy_denied'),
                 (409, 'Engagement execution is fenced', 'execution_fenced'),
                 (503, 'Authorization storage unavailable', 'authorization_storage_unavailable'),
                 (409, {'code': 'model_accounting_inconsistent', 'message': 'private-sentinel'},
                  'model_accounting_inconsistent'),
                 (403, 'private-sentinel', 'operation_denied'),
                 (409, {'code': []}, 'operation_blocked')]
        for status_code, detail, code in cases:
            with self.subTest(code=code):
                state = self.completed_observations()
                status, review, _, planner, execute = await self.run_completed(
                    state, context_error=HTTPException(status_code, detail))
                self.assertEqual(status['run_state'], 'blocked')
                self.assertEqual(status['reason_code'], code)
                self.assertNotIn('private-sentinel', status['reason'])
                self.assertEqual(status['evidence_job_ids'], ['port-job', 'http-job'])
                self.assertEqual(status['successful_steps'], 2)
                review.assert_not_awaited()
                planner.assert_not_awaited()
                execute.assert_not_awaited()
