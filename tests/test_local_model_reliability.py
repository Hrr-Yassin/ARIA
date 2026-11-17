"""Fault-injected local-provider contracts. No socket or inference is used."""
import json
from unittest.mock import patch

import httpx

from llm.local_client import LocalClient
from tests.support import OfflineCase


class LocalModelReliabilityTests(OfflineCase):
    async def native_response(self, payload, *, native=True, error=None):
        original = httpx.AsyncClient
        requests = []

        def handler(request):
            requests.append(request)
            if error:
                raise error
            return httpx.Response(200, json=payload)

        def client(**kwargs):
            return original(transport=httpx.MockTransport(handler), **kwargs)

        local = LocalClient(model='synthetic')
        local._ollama_base = 'http://127.0.0.1:11434' if native else ''
        with patch('llm.local_client.httpx.AsyncClient', side_effect=client), \
             patch('llm.local_client.settings.LOCAL_LLM_URL', 'http://127.0.0.1:11434/fixture'):
            result = await local.query('Synthetic response contract', 'JSON only')
        self.assertEqual(len(requests), 1, 'Exactly one physical call; no hidden retry')
        return result

    async def test_native_missing_or_invalid_counts_remain_unknown(self):
        cases = [{}, {'prompt_eval_count': 10}, {'eval_count': 2},
                 {'prompt_eval_count': True, 'eval_count': 2},
                 {'prompt_eval_count': '10', 'eval_count': 2},
                 {'prompt_eval_count': -1, 'eval_count': 2},
                 {'prompt_eval_count': 10, 'eval_count': None}]
        for counts in cases:
            with self.subTest(counts=counts):
                result = await self.native_response({
                    'message': {'content': '{"answer":"synthetic"}'}, **counts})
                self.assertTrue(result['success'])
                self.assertIsNone(result['tokens_used'])
                self.assertEqual(result['cost_microusd'], 0)

    async def test_native_truncation_does_not_invent_known_zero_usage(self):
        result = await self.native_response({
            'done_reason': 'length', 'message': {'content': '{"answer":'}})
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'model_output_truncated')
        self.assertIsNone(result['tokens_used'])
        self.assertEqual(result['cost_microusd'], 0)

    async def test_native_valid_counts_include_reported_zero(self):
        for counts, expected in [({'prompt_eval_count': 10, 'eval_count': 2}, 12),
                                 ({'prompt_eval_count': 0, 'eval_count': 0}, 0)]:
            with self.subTest(counts=counts):
                result = await self.native_response({
                    'message': {'content': '{"answer":"synthetic"}'}, **counts})
                self.assertTrue(result['success'])
                self.assertEqual(result['tokens_used'], expected)

    async def test_transport_timings_and_token_components_are_separate(self):
        result = await self.native_response({'message': {'content': '{}'},
            'prompt_eval_count': 0, 'eval_count': 3})
        self.assertEqual(result['input_tokens'], 0)
        self.assertEqual(result['output_tokens'], 3)
        timing = result['timings']
        self.assertEqual(timing['http_attempts'], 1)
        self.assertGreaterEqual(timing['client_total_ms'], timing['provider_attempt_ms'])
        self.assertGreaterEqual(timing['request_construction_ms'], 0)
        self.assertGreaterEqual(timing['response_processing_ms'], 0)
        self.assertIsNone(timing['structured_validation_ms'])
        unknown = await self.native_response({'message': {'content': '{}'}})
        self.assertIsNone(unknown['input_tokens'])
        self.assertIsNone(unknown['output_tokens'])

    async def test_native_reported_phases_do_not_replace_client_or_usage_metrics(self):
        result = await self.native_response({'message': {'content': '{}'},
            'load_duration': 9000000, 'prompt_eval_duration': 20000000,
            'eval_duration': 30000000, 'total_duration': 59000000})
        self.assertEqual(result['timings']['provider_load_ms'], 9.0)
        self.assertEqual(result['timings']['provider_prompt_eval_ms'], 20.0)
        self.assertEqual(result['timings']['provider_generation_ms'], 30.0)
        self.assertEqual(result['timings']['provider_reported_total_ms'], 59.0)
        self.assertIsNone(result['tokens_used'])
        self.assertEqual(result['timings']['http_attempts'], 1)

    async def test_malformed_provider_envelopes_fail_without_retry_or_input_leak(self):
        cases = [[], None, {}, {'choices': [None]}, {'choices': ['private-sentinel']},
                 {'choices': {}}, {'choices': [{'message': None}]},
                 {'choices': [{'message': {'content': 12}}]},
                 {'message': {'content': ''}}, {'message': {'content': {}}}]
        for native in (True, False):
            for payload in cases:
                with self.subTest(native=native, payload=payload):
                    result = await self.native_response(payload, native=native)
                    self.assertFalse(result['success'])
                    self.assertEqual(result['error'], 'local_model_request_failed')
                    self.assertNotIn('private-sentinel', json.dumps(result))

    async def test_transport_faults_are_safe_single_attempt_failures(self):
        for error, code in [(httpx.ReadTimeout('private-sentinel'), 'provider_timeout'),
                            (httpx.ConnectError('private-sentinel'), 'local_model_request_failed')]:
            with self.subTest(code=code):
                result = await self.native_response({}, error=error)
                self.assertFalse(result['success'])
                self.assertEqual(result['error'], code)
                self.assertNotIn('private-sentinel', json.dumps(result))
