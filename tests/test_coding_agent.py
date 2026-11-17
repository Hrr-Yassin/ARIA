"""Coding artifacts remain data through ownership, budget and static-review paths."""
import asyncio
from contextlib import ExitStack
import json
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from agents.coding_agent import CodingAgent, CodingSubmission, static_review
from api.auth import get_current_user
from api.main import app
from evaluation.competence import FIXTURES, load_cases, measure
from llm.engagement_budget import engagement_context
from tests.support import OfflineCase
from tests.test_access import OWNER


def submission() -> dict:
    return load_cases(FIXTURES / 'coding-development-v1.json')['cases'][0]['input']


class CodingAgentTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    def fixtures(self, payload=None):
        stack = ExitStack()
        stack.enter_context(patch('api.auth.current_identity', AsyncMock(return_value=OWNER)))
        stack.enter_context(patch('api.session_access.get_accessible_session', AsyncMock(return_value={
            'user_id':'owner','target':'192.0.2.1','scope':{'targets':['192.0.2.1'],'ports':[80]}})))
        stack.enter_context(patch('memory.session_manager.session_manager.get_chat_logs', AsyncMock(return_value=[])))
        stack.enter_context(patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(return_value={'tools':['curl']})))
        response = {'success':True, 'content':json.dumps(payload or submission())}
        provider = stack.enter_context(patch('llm.pool_manager.pool_manager.query_for_task', AsyncMock(return_value=response)))
        return stack, provider

    async def test_frozen_static_quality_profile(self):
        result = measure(load_cases(FIXTURES / 'coding-development-v1.json'))
        self.assertEqual(result['components']['coding_static'], {'passed':10,'assessed':10})

    async def test_real_bounded_validator_never_executes_artifacts(self):
        result = await static_review(CodingSubmission.model_validate(submission()))
        self.assertEqual(result['status'], 'static_checks_passed')
        self.assertFalse(result['candidate_code_executed'])
        self.assertFalse(result['tests_executed'])
        self.assertFalse(result['independent_review'])
        payload = submission()
        payload['files'][0]['content'] = '"""Untrusted fixture."""\nraise RuntimeError("would fail if executed")\n'
        result = await static_review(CodingSubmission.model_validate(payload))
        self.assertEqual(result['status'], 'static_checks_passed')
        self.assertFalse(result['candidate_code_executed'])
        self.assertFalse(result['tests_executed'])

    async def test_static_review_rejects_python_that_cannot_compile(self):
        invalid_sources = {
            'return at module scope': 'return None\n',
            'break outside a loop': 'break\n',
            'duplicate parameters': (
                'def parse(value: int, value: int) -> int:\n'
                '    """Return a status value."""\n'
                '    return value\n'
            ),
        }
        for name, source in invalid_sources.items():
            with self.subTest(name=name):
                payload = submission()
                payload['files'][0]['content'] = '"""Invalid parser fixture."""\n' + source
                result = await static_review(CodingSubmission.model_validate(payload))
                self.assertEqual(result['status'], 'changes_required')
                self.assertIn('status_parser.py: invalid Python syntax', result['issues'])
                self.assertFalse(result['candidate_code_executed'])
                self.assertFalse(result['tests_executed'])

    async def test_actual_authenticated_route_returns_only_review_artifacts(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        stack, provider = self.fixtures()
        with stack, patch('memory.execution_authorization.execution_authorization.execute', AsyncMock()) as execute:
            response = await self.client.post('/api/coding/engagement/proposals', json={
                'objective':'Design a synthetic status parser and negative regression tests'})
        self.assertEqual(response.status_code,200)
        result = response.json()
        self.assertEqual(result['commands'],[])
        self.assertEqual(result['agent_result']['proposed_actions'],[])
        self.assertEqual(result['execution_status'],'not_executed')
        self.assertEqual(result['submission']['review_status'],'requires_human_review')
        self.assertEqual(provider.await_args.args[1],'code_generation')
        execute.assert_not_awaited()

    async def test_no_identity_or_other_owner_never_calls_model(self):
        response = await self.client.post('/api/coding/engagement/proposals', json={'objective':'Parse logs'})
        self.assertEqual(response.status_code,401)
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch('api.auth.current_identity', AsyncMock(return_value=OWNER)), \
             patch('api.session_access.get_accessible_session', AsyncMock(side_effect=HTTPException(403,'Denied'))), \
             patch('llm.pool_manager.pool_manager.query_for_task', AsyncMock()) as provider:
            response = await self.client.post('/api/coding/other/proposals', json={'objective':'Parse logs'})
        self.assertEqual(response.status_code,403)
        provider.assert_not_awaited()

    async def test_provider_budget_block_cannot_return_artifacts_or_execute(self):
        stack, provider = self.fixtures()
        provider.return_value = {'success':False, 'error':'model_budget_denied'}
        with stack:
            result = await CodingAgent().process('engagement','owner',{'objective':'Review synthetic logs'})
        self.assertNotIn('submission',result)
        self.assertEqual(result['agent_result']['status'],'blocked')
        self.assertIn('model_budget_denied', [r['code'] for r in result['rejections']])
        self.assertIsNone(engagement_context.get())

    async def test_malicious_contract_and_foreign_evidence_are_blocked(self):
        for field, value in (('commands',[{'command':'curl http://192.0.2.1'}]),
                             ('evidence_references',['foreign-evidence'])):
            payload = submission(); payload[field] = value
            stack, provider = self.fixtures(payload)
            with stack:
                result = await CodingAgent().process('engagement','owner',{'objective':'Review fixture'})
            self.assertEqual(result['agent_result']['status'],'blocked')
            self.assertNotIn('submission',result)

    async def test_cancellation_cleans_context_and_validator_deadline(self):
        stack, provider = self.fixtures()
        provider.side_effect = asyncio.CancelledError()
        with stack, self.assertRaises(asyncio.CancelledError):
            await CodingAgent().process('engagement','owner',{'objective':'Review fixture'})
        self.assertIsNone(engagement_context.get())

    async def test_no_execution_endpoint_and_no_dependency_or_path_escape(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        routes = [r.path for r in app.routes if r.path.startswith('/api/coding')]
        self.assertEqual(routes, ['/api/coding/{session_id}/proposals'])
        self.assertIn((await self.client.post('/api/coding/engagement/execute',json={})).status_code,(404,405))
        for body in ({'objective':'x','execute':True}, {'objective':'x','supplied_artifacts':[{'name':'../secret.py','content':'x'}]}):
            self.assertEqual((await self.client.post('/api/coding/engagement/proposals',json=body)).status_code,422)
