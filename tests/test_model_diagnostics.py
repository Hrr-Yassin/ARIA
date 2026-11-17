"""Reported server phases remain separate from measured client latency and usage."""
import unittest

from llm.request_metrics import native_provider_timings, safe_timings


class ModelDiagnosticTests(unittest.TestCase):
    def test_reported_phase_units_and_unknowns(self):
        values=native_provider_timings({'load_duration':2000000,'prompt_eval_duration':3000000,
                                       'eval_duration':0,'total_duration':5000000})
        self.assertEqual(values,{'provider_load_ms':2.0,'provider_prompt_eval_ms':3.0,
                                 'provider_generation_ms':0.0,'provider_reported_total_ms':5.0})
        self.assertIsNone(safe_timings(values)['provider_attempt_ms'])
        self.assertIsNone(safe_timings(values)['http_attempts'])

    def test_malformed_reported_phases_never_become_zero(self):
        for value in (None,True,-1,'12',3.4,10**20):
            with self.subTest(value=value):
                self.assertIsNone(native_provider_timings({'eval_duration':value})['provider_generation_ms'])
        self.assertTrue(all(v is None for v in native_provider_timings({}).values()))
