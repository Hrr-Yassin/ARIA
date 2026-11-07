import unittest
from orchestrator.workflow_engine import workflow_engine


class WorkflowReadinessTests(unittest.TestCase):
    def ledger(self):
        return {'tasks': [{'phase': 'scanning', 'security_questions': ['access', 'surface'], 'state': 'completed'}],
                'coverage': [{'key': 'access', 'status': 'tested', 'evidence_references': ['e1']},
                             {'key': 'surface', 'status': 'untested', 'evidence_references': []}],
                'evidence': [{'id': 'e1'}]}

    def test_tools_and_findings_cannot_advance_or_inflate_progress(self):
        self.assertIsNone(workflow_engine.suggest_next_phase('scanning', ['nmap', 'nuclei'], has_findings=True, has_shell=True))
        self.assertIsNone(workflow_engine.get_tool_phase_transition('nmap'))
        progress = workflow_engine.get_overall_progress('scanning', ['nmap'] * 100)
        self.assertEqual(progress['overall_pct'], 0)
        self.assertEqual(progress['readiness']['state'], 'unknown')

    def test_question_coverage_requires_evidence_and_human_completed_task(self):
        ledger = self.ledger()
        result = workflow_engine.evidence_readiness('scanning', ledger)
        self.assertEqual((result['percent'], result['state']), (50, 'not_ready'))
        ledger['coverage'][1].update(status='tested', evidence_references=['other'])
        self.assertEqual(workflow_engine.evidence_readiness('scanning', ledger)['percent'], 50)
        ledger['coverage'][1]['evidence_references'] = ['e1']
        ledger['tasks'][0]['state'] = 'awaiting_review'
        self.assertEqual(workflow_engine.evidence_readiness('scanning', ledger)['state'], 'not_ready')
        ledger['tasks'][0]['state'] = 'completed'
        self.assertEqual(workflow_engine.evidence_readiness('scanning', ledger)['state'], 'not_ready')
        ledger['tasks'][0]['reviewed_by'] = 'owner'
        ledger['tasks'][0]['completion_review'] = [{**item, 'ready': True} for item in ledger['coverage']]
        self.assertEqual(workflow_engine.evidence_readiness('scanning', ledger)['state'], 'ready')
        ledger['coverage'][0]['question'] = 'A different question'
        self.assertEqual(workflow_engine.evidence_readiness('scanning', ledger)['state'], 'not_ready')
        ledger['coverage'][0]['status'] = 'unresolved'
        self.assertEqual(workflow_engine.evidence_readiness('scanning', ledger)['state'], 'not_ready')

    def test_missing_questions_and_foreign_phase_never_imply_readiness(self):
        ledger = self.ledger()
        self.assertEqual(workflow_engine.evidence_readiness('scope', ledger)['state'], 'unknown')
        ledger['tasks'].append({'phase': 'scanning', 'security_questions': [], 'state': 'completed'})
        self.assertEqual(workflow_engine.evidence_readiness('scanning', ledger)['state'], 'unknown')

    def test_tool_telemetry_does_not_affect_evidence_percent(self):
        ledger = self.ledger()
        one = workflow_engine.get_current_phase_info('scanning', [], ledger)
        two = workflow_engine.get_current_phase_info('scanning', ['nmap', 'nmap', 'curl'], ledger)
        self.assertEqual(one['phase_progress'], two['phase_progress'])
        self.assertEqual(two['readiness']['state'], 'not_ready')


class WorkflowLedgerTests(unittest.IsolatedAsyncioTestCase):
    async def test_ledger_is_owner_bound_and_failure_is_unknown(self):
        from unittest.mock import AsyncMock, patch
        from fastapi import HTTPException
        from api.routers.pentest import _phase_ledger
        with patch('memory.team_tasks.team_store.view', AsyncMock(side_effect=HTTPException(404))) as view:
            self.assertIsNone(await _phase_ledger('engagement', 'foreign'))
            view.assert_awaited_once_with('engagement', 'foreign')
        with patch('memory.team_tasks.team_store.view', AsyncMock()) as view:
            self.assertIsNone(await _phase_ledger('engagement', None))
            view.assert_not_awaited()
