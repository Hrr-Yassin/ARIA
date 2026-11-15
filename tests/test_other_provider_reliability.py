"""Groq/Gemini transport fault fixtures; no socket, key or inference is used."""
import json
import asyncio
import os
from pathlib import Path
from unittest.mock import patch

import httpx

from llm.groq_client import GroqClient
from llm.gemini_client import GeminiClient
from tests.support import OfflineCase


class OtherProviderReliability(OfflineCase):
    async def response(self, cls, payload=None, *, error=None, slow_close=False):
        original, requests = httpx.AsyncClient, []
        class SlowClose(original):
            async def __aexit__(self, *args):
                await asyncio.sleep(.02)
                return await super().__aexit__(*args)
        def handler(request):
            requests.append(request)
            if error:
                raise error
            return httpx.Response(200, json=payload)
        def client(**kwargs):
            return (SlowClose if slow_close else original)(transport=httpx.MockTransport(handler), **kwargs)
        module = 'llm.groq_client' if cls is GroqClient else 'llm.gemini_client'
        with patch(module + '.httpx.AsyncClient', side_effect=client):
            result = await cls(api_key='offline-fixture', model='fixture-model').query('Synthetic contract')
        self.assertEqual(len(requests), 1)
        self.assertEqual(result['timings']['http_attempts'], 1)
        self.assertGreaterEqual(result['timings']['provider_attempt_ms'], 0)
        self.assertGreaterEqual(result['timings']['client_total_ms'], result['timings']['provider_attempt_ms'])
        self.assertNotIn('private-sentinel', json.dumps(result))
        directory = os.environ.get('ARIA_RELIABILITY_ARTIFACT_DIR')
        if directory:
            path = Path(directory) / 'provider-transport-fixtures.jsonl'
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('a') as file:
                file.write(json.dumps({'provider_fixture': cls.__name__, **result}) + '\n')
        return result

    async def test_client_cleanup_is_outside_provider_and_response_processing(self):
        for cls in (GroqClient, GeminiClient):
            result = await self.response(cls, self.payload(cls), slow_close=True)
            timing = result['timings']
            other = timing['client_total_ms'] - sum(timing[key] for key in (
                'request_construction_ms', 'provider_attempt_ms', 'response_processing_ms'))
            self.assertGreaterEqual(other, 15, 'The injected20ms client cleanup is not inference or parsing')

    @staticmethod
    def payload(cls, usage=None, truncated=False):
        if cls is GroqClient:
            return {'choices': [{'finish_reason': 'length' if truncated else 'stop',
                                  'message': {'content': '{}'}}],
                    'usage': usage or {}}
        return {'candidates': [{'finishReason': 'MAX_TOKENS' if truncated else 'STOP',
                                'content': {'parts': [{'text': '{}'}]}}],
                'usageMetadata': usage or {}}

    async def test_success_unknown_and_reported_zero_are_distinct(self):
        for cls in (GroqClient, GeminiClient):
            with self.subTest(provider=cls.__name__):
                unknown = await self.response(cls, self.payload(cls))
                self.assertTrue(unknown['success'])
                self.assertIsNone(unknown['input_tokens'])
                self.assertIsNone(unknown['output_tokens'])
                self.assertIsNone(unknown['cost_microusd'])
                usage = ({'prompt_tokens': 0, 'completion_tokens': 3, 'total_tokens': 3}
                    if cls is GroqClient else {'promptTokenCount': 0, 'candidatesTokenCount': 3, 'totalTokenCount': 3})
                known = await self.response(cls, self.payload(cls, usage))
                self.assertEqual(known['input_tokens'], 0)
                self.assertEqual(known['output_tokens'], 3)
                self.assertEqual(known['tokens_used'], 3)
                self.assertGreaterEqual(known['timings']['response_processing_ms'], 0)

    async def test_timeout_truncation_and_malformed_envelopes_fail_without_retry(self):
        for cls in (GroqClient, GeminiClient):
            with self.subTest(provider=cls.__name__):
                timeout = await self.response(cls, error=httpx.ReadTimeout('private-sentinel'))
                self.assertEqual(timeout['error'], 'provider_timeout')
                self.assertIsNone(timeout['tokens_used'])
                self.assertIsNone(timeout['timings']['response_processing_ms'])
                truncated = await self.response(cls, self.payload(cls, truncated=True))
                self.assertEqual(truncated['error'], 'model_output_truncated')
                malformed = await self.response(cls, {'choices': ['private-sentinel'],
                                                      'candidates': ['private-sentinel']})
                self.assertEqual(malformed['error'], 'provider_request_failed')
