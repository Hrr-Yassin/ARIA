"""Unknown timing/token data cannot become plausible measurements."""
import unittest

from llm.request_metrics import safe_timings, token_components


class RequestMetricsTests(unittest.TestCase):
    def test_missing_negative_nonfinite_and_untrusted_values_remain_unavailable(self):
        for value in (None, [], {}, {'provider_attempt_ms': True},
                      {'provider_attempt_ms': -1}, {'provider_attempt_ms': float('nan')},
                      {'provider_attempt_ms': float('inf')}, {'provider_attempt_ms': '5'}):
            with self.subTest(value=value):
                self.assertIsNone(safe_timings(value)['provider_attempt_ms'])
        timing = safe_timings({'provider_attempt_ms': 0, 'http_attempts': 1,
                               'private-sentinel': 'secret'})
        self.assertEqual(timing['provider_attempt_ms'], 0)
        self.assertEqual(timing['http_attempts'], 1)
        self.assertNotIn('private-sentinel', timing)
        self.assertIsNone(timing['structured_validation_ms'])

    def test_reported_token_components_do_not_invent_a_breakdown(self):
        self.assertEqual(token_components({'total_tokens': 10}),
                         {'input_tokens': None, 'output_tokens': None})
        self.assertEqual(token_components({'prompt_tokens': 0, 'completion_tokens': 10}),
                         {'input_tokens': 0, 'output_tokens': 10})
        self.assertEqual(token_components({'prompt_tokens': True, 'completion_tokens': -2}),
                         {'input_tokens': None, 'output_tokens': None})
