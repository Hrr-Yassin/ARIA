"""Planner admission, failure diagnostics and local-only routing regressions."""
import json
from unittest.mock import AsyncMock, patch
import httpx
from config.settings import settings
from agents.autonomous_engine import AutonomousEngine, SessionRunState
from agents.orchestrator_agent import orchestrator_agent
from llm.engagement_budget import model_accounting
from llm.local_client import LocalClient
from llm.pool_manager import LLMPoolManager
from tests.support import OfflineCase


class PlannerReadiness(OfflineCase):
    async def test_no_key_preflight_is_read_only(self):
        manager = LLMPoolManager()
        with patch.object(manager, 'refresh_user_keys', AsyncMock()), patch.object(model_accounting, 'reserve', AsyncMock()) as reserve:
            result = await manager.planner_preflight('owner', 'engagement')
        self.assertEqual(result['code'], 'no_keys')
        reserve.assert_not_awaited()

    async def test_missing_local_model_blocks_before_server_probe(self):
        manager = LLMPoolManager()
        with patch.object(settings, 'LLM_ROUTING', 'local'), patch.object(settings, 'LOCAL_LLM_MODEL', ''), patch.object(manager, 'refresh_user_keys', AsyncMock()), patch.object(LocalClient, 'available', AsyncMock()) as available:
            result = await manager.planner_preflight('owner', 'engagement')
        self.assertEqual(result['code'], 'model_not_configured')
        available.assert_not_awaited()

    async def test_local_preflight_does_not_reserve_usage(self):
        manager = LLMPoolManager()
        with patch.object(settings, 'LLM_ROUTING', 'local'), patch.object(settings, 'LOCAL_LLM_MODEL', 'offline-model'), patch.object(manager, 'refresh_user_keys', AsyncMock()), patch.object(LocalClient, 'available', AsyncMock(return_value=True)), patch.object(model_accounting, 'reserve', AsyncMock(return_value={'ready': True})) as reserve:
            result = await manager.planner_preflight('owner', 'engagement')
        self.assertTrue(result['ready'])
        self.assertTrue(reserve.await_args.kwargs['check_only'])

    async def test_preflight_blocks_start_without_background_task(self):
        engine = AutonomousEngine()
        with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={})), patch('agents.autonomous_engine.execution_authorization._validate'), patch('agents.autonomous_engine.worker_jobs.client.capabilities', AsyncMock(return_value={'tools': ['curl', 'nmap']})), patch('llm.pool_manager.pool_manager.planner_preflight', AsyncMock(return_value={'ready': False, 'code': 'no_keys', 'message': 'Configure a model'})), patch.object(engine, '_run_loop', AsyncMock()) as run:
            result = await engine.start('engagement', 'owner')
        self.assertEqual(result['reason_code'], 'no_keys')
        self.assertFalse(result['active'])
        self.assertEqual(result['planning_attempts'], 0)
        run.assert_not_awaited()
        self.assertEqual(engine._tasks, {})

    async def test_provider_failure_is_not_retried_as_bad_json(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        engine._runs[state.session_id] = state
        with patch.object(orchestrator_agent, 'process', AsyncMock(return_value={'commands': [], 'rejections': [{'code': 'model_tariff_missing'}]})) as planner, patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={'scope': {}})):
            self.assertIsNone(await engine._plan_next_step(state))
        self.assertEqual(planner.await_count, 1)
        self.assertEqual(state.reason_code, 'model_tariff_missing')

    async def test_transient_failure_gets_bounded_retries_and_keeps_cause(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        engine._runs[state.session_id] = state
        with patch.object(orchestrator_agent, 'process', AsyncMock(return_value={'commands': [], 'rejections': [{'code': 'provider_timeout'}]})) as planner, patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={'scope': {}})):
            self.assertIsNone(await engine._plan_next_step(state))
        self.assertEqual(planner.await_count, 3)
        self.assertEqual(state.reason_code, 'provider_timeout')

    async def test_local_failure_never_falls_back_to_cloud(self):
        manager = LLMPoolManager()
        with patch.object(settings, 'LLM_ROUTING', 'local'), patch.object(settings, 'LOCAL_LLM_MODEL', 'offline-model'), patch.object(model_accounting, 'reserve', AsyncMock(return_value={'id': 'attempt'})), patch.object(model_accounting, 'settle', AsyncMock()) as settle, patch.object(LocalClient, 'query', AsyncMock(return_value={'success': False, 'error': 'local_model_request_failed'})), patch.object(manager, '_find_best_key') as cloud:
            result = await manager._query_for_task('owner', 'attack_planning', 'prompt')
        self.assertEqual(result['error'], 'local_model_request_failed')
        cloud.assert_not_called()
        settle.assert_awaited_once()

    async def test_strict_output_rejects_wrong_types_and_extra_commands(self):
        valid = {'commands': [{'tool': 'curl', 'command': 'curl -I http://192.0.2.1:80', 'purpose': 'Observe headers', 'expected_evidence': 'HTTP status'}]}
        malformed = [ {'commands': ['curl']}, {'commands': [dict(valid['commands'][0], command=3)]}, {'commands': valid['commands'] * 2}, {'commands': []} ]
        for output in malformed + [valid]:
            with patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value={'success': True, 'content': json.dumps(output)})):
                result = await orchestrator_agent._bounded_assessment_plan('owner', {}, 'expert')
            self.assertEqual(bool(result['commands']), output == valid)

    async def test_auto_discovery_rejects_tool_for_already_completed_observation(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        state.completed_observations.append('http_response')
        state.capabilities = {'tools': ['curl', 'nmap']}
        feedback = []
        proposal = {'commands': [{'tool': 'curl', 'command': 'curl -I http://192.0.2.1:80',
                                  'purpose': 'Check HTTP', 'expected_evidence': 'HTTP response'}]}
        with patch.object(orchestrator_agent, 'process', AsyncMock(return_value=proposal)), \
             patch('agents.autonomous_engine.execution_authorization._context',
                   AsyncMock(return_value={'scope': {'targets': ['192.0.2.1'], 'ports': [80], 'exclusions': []}})):
            result = await engine._validated_plan(state, orchestrator_agent, [], [], feedback)
        self.assertIsNone(result)
        self.assertTrue(any('cannot satisfy a missing observation' in item for item in feedback))

    async def test_local_transport_uses_loopback_and_no_redirects_or_proxy(self):
        observed = []
        def handler(request):
            observed.append(request)
            if request.url.path.endswith('/models'):
                return httpx.Response(200, json={'data': [{'id': 'offline-model'}]})
            return httpx.Response(200, json={'choices': [{'message': {'content': '{}'}}], 'usage': {'total_tokens': 12}})
        original = httpx.AsyncClient
        def client(**kwargs):
            self.assertFalse(kwargs['trust_env'])
            self.assertFalse(kwargs['follow_redirects'])
            return original(transport=httpx.MockTransport(handler), **kwargs)
        with patch('llm.local_client.httpx.AsyncClient', side_effect=client):
            model = LocalClient(model='offline-model')
            self.assertTrue(await model.available())
            result = await model.query('prompt')
        self.assertTrue(result['success'])
        self.assertEqual(result['cost_microusd'], 0)
        self.assertEqual([request.url.path for request in observed],
                         ['/v1/models', '/api/version', '/api/version', '/v1/chat/completions'])

    async def test_ollama_native_chat_disables_thinking_and_caps_output(self):
        observed = []
        def handler(request):
            observed.append(request)
            if request.url.path == '/v1/models':
                return httpx.Response(200, json={'data': [{'id': 'qwen3:4b-instruct'}]})
            if request.url.path == '/api/version':
                return httpx.Response(200, json={'version': 'test'})
            return httpx.Response(200, json={
                'message': {'content': '{"commands": []}'},
                'prompt_eval_count': 42, 'eval_count': 5,
            })
        original = httpx.AsyncClient
        def client(**kwargs):
            return original(transport=httpx.MockTransport(handler), **kwargs)
        with patch('llm.local_client.settings.LOCAL_LLM_URL', 'http://127.0.0.1:11434/v1'), \
             patch('llm.local_client.httpx.AsyncClient', side_effect=client):
            model = LocalClient(model='qwen3:4b-instruct')
            self.assertTrue(await model.available())
            result = await model.query('prompt', 'system')
        self.assertTrue(result['success'])
        self.assertEqual(result['tokens_used'], 47)
        request = next(item for item in observed if item.url.path == '/api/chat')
        payload = json.loads(request.content)
        self.assertIs(payload['think'], False)
        self.assertEqual(payload['options']['num_predict'], 192)
