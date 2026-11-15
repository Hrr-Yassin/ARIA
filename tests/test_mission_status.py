"""Operator-visible mission states derive from actual work, never a percentage."""
import unittest
from orchestrator.mission_status import mission_status


class MissionStatusTests(unittest.TestCase):
    def run_record(self, **changes):
        return {'run_id': 'run', 'run_state': 'completed', 'active': False,
                'original_objective': 'Observe the bounded authorized fixture',
                'current_phase': 'recon', 'completion': {'complete': True, 'missing': []},
                **changes}

    def test_phase_completion_keeps_pending_tasks_and_their_owners(self):
        tasks = [{'id': 'review', 'state': 'awaiting_review', 'owner_role': 'correlation'},
                 {'id': 'blocked', 'state': 'blocked', 'owner_role': 'vuln'},
                 {'id': 'done', 'state': 'completed', 'owner_role': 'web_intel'}]
        view = mission_status(self.run_record(), {'cursor': 9, 'tasks': tasks})
        self.assertTrue(view['observations_completed'])
        self.assertEqual(view['bounded_run_state'], 'completed')
        self.assertEqual(view['state'], 'work_pending')
        self.assertEqual(view['pending_tasks'], tasks[:2])
        self.assertEqual(view['completed_task_ids'], ['done'])
        self.assertEqual(view['task_ledger_cursor'], 9)

    def test_optional_hypotheses_do_not_force_extra_execution(self):
        view = mission_status(self.run_record(), {'tasks': [], 'cursor': 1,
            'research_hypotheses': [{'id': 'unverified', 'state': 'HYPOTHESIZED'}]})
        self.assertEqual(view['state'], 'completed')
        self.assertEqual(view['scope'], 'current_authorized_objective')
        self.assertEqual(view['proposed_hypothesis_count'], 1)
        self.assertFalse(view['proposals_require_execution'])

    def test_recorded_research_states_are_not_all_counted_as_proposals_or_findings(self):
        view = mission_status(self.run_record(), {'tasks': [], 'research_hypotheses':[
            {'id': 'candidate', 'state': 'HYPOTHESIZED'},
            {'id': 'rejected', 'state': 'REJECTED'},
            {'id': 'recorded-confirmation', 'state': 'CONFIRMED'}]})
        self.assertEqual(view['proposed_hypothesis_count'], 1)
        self.assertEqual(view['recorded_hypothesis_count'], 3)
        self.assertEqual(view['hypothesis_state_counts']['CONFIRMED'], 1)
        self.assertIn('independent verification is not inferred', view['hypothesis_counts_basis'])

    def test_unknown_or_incomplete_evidence_cannot_prove_mission_completion(self):
        for ledger in (None, {}, {'tasks': [{'id': 't', 'state': 'invented'}]},
                       {'tasks': [{'id': 't', 'state': {}}]}):
            with self.subTest(ledger=ledger):
                view = mission_status(self.run_record(), ledger)
                self.assertEqual(view['state'], 'blocked')
                self.assertEqual(view['reason_code'], 'task_ledger_unavailable')
                self.assertIsNone(view['pending_tasks'])
        for completion in (None, {}, {'complete': False, 'missing': ['http_response']}):
            with self.subTest(completion=completion):
                view = mission_status(self.run_record(completion=completion), {'tasks': []})
                self.assertEqual(view['reason_code'], 'completion_evidence_unavailable')

    def test_failed_task_remains_failed_and_cancelled_task_remains_visible(self):
        view = mission_status(self.run_record(), {'tasks': [
            {'id': 'error', 'state': 'failed'}, {'id': 'cancelled', 'state': 'cancelled'}]})
        self.assertEqual(view['state'], 'failed')
        self.assertEqual(view['failed_task_ids'], ['error'])
        self.assertEqual(view['cancelled_task_ids'], ['cancelled'])

    def test_operational_state_matrix_retains_actual_blockers(self):
        cases = [
            ({'run_state': 'planning', 'active': True}, 'running'),
            ({'run_state': 'executing', 'active': True}, 'running'),
            ({'run_state': 'awaiting_approval', 'active': True}, 'waiting_for_approval'),
            ({'run_state': 'blocked', 'reason_code': 'capability_unavailable'}, 'blocked'),
            ({'run_state': 'blocked', 'reason_code': 'step_budget_exhausted'}, 'budget_exhausted'),
            ({'run_state': 'blocked', 'reason_code': 'model_call_budget'}, 'budget_exhausted'),
            ({'run_state': 'blocked', 'reason_code': 'run_interrupted', 'pause_requested': True}, 'paused'),
            ({'run_state': 'failed', 'reason_code': 'run_error', 'pause_requested': True}, 'failed'),
            ({'run_state': 'cancelling'}, 'cancellation_pending'),
            ({'run_state': 'blocked', 'reason_code': 'cancelled'}, 'cancellation_pending'),
            ({'run_state': 'blocked', 'reason_code': 'cancelled', 'cancellation_confirmed': False}, 'cancellation_pending'),
            ({'run_state': 'blocked', 'reason_code': 'cancelled', 'cancellation_confirmed': True}, 'cancelled'),
        ]
        for changes, expected in cases:
            with self.subTest(changes=changes):
                view = mission_status(self.run_record(**changes), {'tasks': []})
                self.assertEqual(view['state'], expected)
                self.assertTrue(view['reason_code'] or view['state'] == 'running')
                self.assertEqual(view['objective'], 'Observe the bounded authorized fixture')

    def test_blocker_exposes_safe_component_and_operator_action(self):
        view = mission_status(self.run_record(run_state='blocked',
            reason_code='worker_command_rejected'), {'tasks': []})
        blocker = view['blocker']
        self.assertEqual(blocker['reason_code'], 'worker_command_rejected')
        self.assertEqual(blocker['component'], 'worker')
        self.assertEqual(blocker['status'], 'blocked')
        self.assertIn('durable receipt', blocker['operator_action'])
        self.assertIsNone(mission_status(self.run_record(), {'tasks': []})['blocker'])
