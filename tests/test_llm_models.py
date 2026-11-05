"""Provider configuration and visible Gemini text; no real provider calls."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from llm.gemini_client import GeminiClient
from llm.pool_manager import LLMPoolManager
from tests.support import OfflineCase


class ModelTests(OfflineCase):
    async def test_gemini_task_routing_honors_configured_model(self):
        manager = LLMPoolManager()
        row = SimpleNamespace(id='test-key', provider='gemini',
            encrypted_key=manager.encrypt_key('test-only-provider-value'), is_active=True,
            requests_used=0, requests_limit=10, cooldown_until=None, last_error='', label='test')
        manager.load_user_keys('alice', [row])
        client = SimpleNamespace(query=AsyncMock(return_value={'success': True, 'content': 'OK'}))
        factory = MagicMock(return_value=client)
        with patch('llm.pool_manager.settings.GEMINI_MODEL', 'configured-test-model'), \
             patch.object(manager, '_reserve_key', AsyncMock(return_value=True)), \
             patch('llm.engagement_budget.model_accounting.reserve', AsyncMock(return_value={'id':'test-attempt'})), patch('llm.engagement_budget.model_accounting.settle', AsyncMock()), patch.dict('llm.pool_manager.PROVIDER_CLIENTS', {'gemini': factory}):
            result = await manager._query_for_task('alice', 'chat_reply', 'test')
        self.assertTrue(result['success'])
        self.assertEqual(result['model'], 'configured-test-model')
        self.assertEqual(factory.call_args.kwargs['model'], 'configured-test-model')

    async def test_gemini_default_model_visible_parts_and_empty_response(self):
        real_client = httpx.AsyncClient
        seen = []
        responses = iter([
            {'candidates': [{'content': {'parts': [
                {'thought': True, 'text': 'private reasoning'}, {'text': 'O'}, {'text': 'K'}]}}]},
            {'candidates': [{'content': {'parts': []}}]},
        ])
        def handler(request):
            seen.append(request)
            return httpx.Response(200, json=next(responses))
        def factory(**kwargs):
            return real_client(transport=httpx.MockTransport(handler), **kwargs)
        with patch('llm.gemini_client.settings.GEMINI_MODEL', 'configured-test-model'), \
             patch('llm.gemini_client.httpx.AsyncClient', side_effect=factory):
            client = GeminiClient(api_key='test-only-provider-value')
            first = await client.query('test')
            empty = await client.query('test')
        self.assertEqual(first['content'], 'OK')
        self.assertFalse(empty['success'])
        self.assertEqual(empty['error'], 'empty_response')
        self.assertIn('/models/configured-test-model:generateContent', str(seen[0].url))
        self.assertNotIn('test-only-provider-value', str(seen[0].url))
