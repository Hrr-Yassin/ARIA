import unittest

from orchestrator.specialist_investigations import InvestigationRequest, TEMPLATES, plan_investigation


class InvestigationPlanTests(unittest.TestCase):
    def test_all_specialties_have_explicit_controls(self):
        for specialty in TEMPLATES:
            with self.subTest(specialty=specialty):
                plan = plan_investigation(InvestigationRequest(specialty=specialty, hypothesis='Test hypothesis'), {})
                for key in ('prerequisites', 'minimum_test', 'normal_result', 'abnormal_result',
                            'stop_conditions', 'disconfirming_evidence'):
                    self.assertTrue(plan[key], key)
                self.assertEqual(plan['status'], 'blocked')
                self.assertTrue(plan['blocked_reasons'])

    def test_capability_enables_review_only(self):
        plan = plan_investigation(InvestigationRequest(specialty='authorization', hypothesis='Unexpected access'),
                                  {'authenticated_http': True})
        self.assertEqual(plan['status'], 'requires_review')
        self.assertIn('does not authorize', plan['limitations'][0])
        self.assertIn('meaningful', plan['abnormal_result'])
        self.assertIn('public', plan['disconfirming_evidence'])

    def test_unknown_or_truthy_capability_does_not_enable(self):
        req = InvestigationRequest(specialty='input_validation', hypothesis='Input boundary')
        self.assertEqual(plan_investigation(req, {'reviewed_input_profile': 'yes'})['status'], 'blocked')
        self.assertEqual(plan_investigation(req, {'authenticated_http': True})['status'], 'blocked')


class InvestigationPlanRouteTests(unittest.IsolatedAsyncioTestCase):
    async def test_foreign_engagement_rejected_before_worker_lookup(self):
        from unittest.mock import AsyncMock, patch
        from types import SimpleNamespace
        from fastapi import HTTPException
        from api.routers.team import investigation_plan
        req = InvestigationRequest(specialty='authorization', hypothesis='Access')
        with patch('api.routers.team.team_store.view', AsyncMock(side_effect=HTTPException(404))) as view, \
             patch('memory.worker_jobs.worker_jobs.client.capabilities', new_callable=AsyncMock) as capabilities:
            with self.assertRaises(HTTPException):
                await investigation_plan('foreign', req, SimpleNamespace(user_id='owner'))
            view.assert_awaited_once_with('foreign', 'owner')
            capabilities.assert_not_awaited()

    async def test_unreachable_worker_blocks_authenticated_plan(self):
        from unittest.mock import AsyncMock, patch
        from types import SimpleNamespace
        from api.routers.team import investigation_plan
        req = InvestigationRequest(specialty='authentication', hypothesis='Session required')
        with patch('api.routers.team.team_store.view', AsyncMock(return_value={'scope': {'web_authenticated_replay': True}})), \
             patch('config.settings.settings.KALI_AGENT_URL', 'http://worker'), \
             patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(side_effect=OSError('offline'))):
            plan = await investigation_plan('owned', req, SimpleNamespace(user_id='owner'))
        self.assertEqual(plan['status'], 'blocked')
        self.assertNotIn('offline', str(plan))

    async def test_worker_http_capability_must_be_exact_version(self):
        from unittest.mock import AsyncMock, patch
        from types import SimpleNamespace
        from api.routers.team import investigation_plan
        req = InvestigationRequest(specialty='authentication', hypothesis='Session required')
        for version, status in [(1, 'requires_review'), (True, 'blocked'), ('1', 'blocked'), (0, 'blocked')]:
            with self.subTest(version=version), \
                 patch('api.routers.team.team_store.view', AsyncMock(return_value={'scope': {'web_authenticated_replay': True}})), \
                 patch('config.settings.settings.KALI_AGENT_URL', 'http://worker'), \
                 patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(return_value={'authenticated_http_version': version})):
                result = await investigation_plan('owned', req, SimpleNamespace(user_id='owner'))
                self.assertEqual(result['status'], status)
                self.assertTrue(result['limitations'])

    async def test_specialty_plan_needs_current_lab_scope_and_worker_profile(self):
        from unittest.mock import AsyncMock, patch
        from types import SimpleNamespace
        from api.routers.team import investigation_plan
        for specialty in ('input_validation', 'business_logic'):
            req = InvestigationRequest(specialty=specialty, hypothesis='Controlled boundary')
            for permitted, version, expected in [(True, 1, 'requires_review'), (False, 1, 'blocked'),
                                                   (True, True, 'blocked'), (True, 0, 'blocked')]:
                with self.subTest(specialty=specialty, permitted=permitted, version=version), \
                     patch('api.routers.team.team_store.view', AsyncMock(return_value={'scope': {
                         'web_authenticated_replay': True, 'web_specialist_profiles': permitted}})), \
                     patch('config.settings.settings.KALI_AGENT_URL', 'http://worker'), \
                     patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(return_value={
                         'authenticated_http_version': 1, 'specialist_http_version': version})):
                    result = await investigation_plan('owned', req, SimpleNamespace(user_id='owner'))
                    self.assertEqual(result['status'], expected)
                    self.assertIn(result['reviewed_profile'], {'integer_query', 'controlled_json_put'})
