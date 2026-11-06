from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agents.base_agent import BaseAgent
from tests.support import OfflineCase
from tests.test_access import OWNER


class FixturePlanner(BaseAgent):
    agent_name = 'planner'
    agent_role = 'fixture'

    def get_system_prompt(self, skill_level='intermediate'):
        return ''

    async def process(self, session_id, user_id, input_data, skill_level='intermediate'):
        return {'commands': [{'command': 'curl -I http://192.0.2.1'}]}


class PlannerCapabilityBoundaryTests(OfflineCase):
    async def test_unavailable_and_malformed_capability_cannot_enable_action(self):
        session = {'session_id': 'engagement', 'user_id': 'owner',
                   'scope': {'targets': ['192.0.2.1'], 'ports': [80]}}
        for advertised, enabled in [({'tools': ['curl']}, True), ({'tools': 'curl'}, False),
                                    ({'tools': ['nmap', None]}, False), ({}, False)]:
            with self.subTest(advertised=advertised), \
                 patch('api.auth.current_identity', AsyncMock(return_value=OWNER)), \
                 patch('api.session_access.get_accessible_session', AsyncMock(return_value=session)), \
                 patch('memory.session_manager.session_manager.get_chat_logs', AsyncMock(return_value=[])), \
                 patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(return_value=advertised)):
                result = await FixturePlanner().process('engagement', 'owner', {'user_input': 'Assess HTTP'})
                self.assertEqual(bool(result['commands']), enabled)
                if not enabled:
                    self.assertEqual(result['agent_result']['status'], 'blocked')
                    self.assertIn('capability', str(result['rejections']).lower())

    async def test_common_rest_and_socket_plan_filter_checks_live_capability_and_scope(self):
        from api.routers.pentest import _filter_plan_commands
        scope = {'targets': ['192.0.2.1'], 'ports': [80]}
        original = {'commands': [{'command': 'curl -I http://192.0.2.1'},
                                  {'command': 'curl -I http://198.51.100.1'}],
                    'suggested_reply': ''}
        for capabilities, count in [({'tools': ['curl']}, 1), ({'tools': ['nmap']}, 0), ({'tools': 'curl'}, 0)]:
            with self.subTest(capabilities=capabilities), \
                 patch('api.routers.pentest.worker_jobs.client.capabilities', AsyncMock(return_value=capabilities)):
                result = await _filter_plan_commands(original, scope)
                self.assertEqual(len(result['commands']), count)
                self.assertIn('removed', result['suggested_reply'])
        with patch('api.routers.pentest.worker_jobs.client.capabilities', AsyncMock(side_effect=OSError('secret worker detail'))):
            result = await _filter_plan_commands(original, scope)
            self.assertEqual(result['commands'], [])
            self.assertNotIn('secret worker detail', str(result))

    async def test_fallback_steps_and_claimed_readiness_cannot_bypass_checks(self):
        class FallbackPlanner(BaseAgent):
            agent_name = 'planner'
            agent_role = 'fixture'
            def get_system_prompt(self, skill_level='intermediate'): return ''
            async def process(self, session_id, user_id, input_data, skill_level='intermediate'):
                return {'commands': [{'command': 'curl -I http://192.0.2.1'}],
                        'fallback_paths': [{'steps': ['unreviewed command']}], 'readiness': 'ready'}
        session = {'session_id': 'engagement', 'user_id': 'owner',
                   'scope': {'targets': ['192.0.2.1'], 'ports': [80]}}
        with patch('api.auth.current_identity', AsyncMock(return_value=OWNER)), \
             patch('api.session_access.get_accessible_session', AsyncMock(return_value=session)), \
             patch('memory.session_manager.session_manager.get_chat_logs', AsyncMock(return_value=[])), \
             patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(return_value={'tools': []})):
            result = await FallbackPlanner().process('engagement', 'owner', {'user_input': 'Assess HTTP'})
        self.assertEqual(result['fallback_paths'], [])
        self.assertIn('capability', result['fallback_blocked_reason'])
        self.assertEqual(result['readiness'], 'blocked')
