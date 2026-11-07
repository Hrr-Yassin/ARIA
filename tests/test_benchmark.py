"""Phase 7 scoring integrity and actual saved-evidence component controls."""
import copy
import unittest
from evaluation.benchmark import BUDGET, baseline, compare, digest, cases, score


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{'case_id': c['id'], 'candidate': c['vulnerable'],
                      'independently_reproduced': False, 'evidence_sha256': [digest(c)]} for c in cases()]

    def test_actual_component_controls_and_variants(self):
        result = baseline()
        self.assertEqual(result['metrics']['true_positives'], 2)
        self.assertEqual(result['metrics']['false_positives'], 0)
        self.assertEqual(result['metrics']['recall'], 1)
        self.assertEqual(result['metrics']['independent_reproduction_rate'], 0)
        self.assertEqual(result['requests'], 0)
        self.assertEqual(len(result['rows']), 6)

    def test_missing_duplicate_and_unlinked_decisions_fail(self):
        for rows in (self.rows[:-1], self.rows + self.rows[:1],
                     [self.rows[0]] * len(self.rows)):
            with self.assertRaises(ValueError): score(rows)
        rows = copy.deepcopy(self.rows)
        rows[0]['evidence_sha256'] = []
        with self.assertRaises(ValueError): score(rows)

    def test_no_finding_and_false_positive_are_not_perfect_scores(self):
        for r in self.rows: r['candidate'] = False
        self.assertIsNone(score(self.rows)['precision'])
        self.assertEqual(score(self.rows)['recall'], 0)
        self.rows[0]['candidate'] = True
        self.assertEqual(score(self.rows)['precision'], 0)
        self.assertEqual(score(self.rows)['false_positives'], 1)

    def test_equal_conditions_missing_arms_and_exhausted_budget(self):
        run = {'arm': 'aria', 'manifest_sha256': 'frozen', 'operator': 'synthetic',
               'model_identifiers': ['none'], 'protocol_sha256': digest('protocol'), 'rows': self.rows,
               'usage': dict(BUDGET), 'scope_violations': 0}
        result = compare([run], 'frozen')
        self.assertFalse(result['comparison_complete'])
        self.assertFalse(result['public_pilot_ready'])
        self.assertTrue(result['arms']['aria']['within_budget'])
        run['usage']['requests'] += 1
        self.assertFalse(compare([run], 'frozen')['arms']['aria']['within_budget'])
        with self.assertRaises(ValueError): compare([run], 'different')
        with self.assertRaises(ValueError): compare([run, run], 'frozen')
        for bad in (-1, float('nan'), True):
            run['usage']['requests'] = bad
            with self.assertRaises(ValueError): compare([run], 'frozen')

    def test_comparison_does_not_authorize_pilot(self):
        runs = [{'arm': arm, 'manifest_sha256': 'frozen', 'operator': 'synthetic',
                 'model_identifiers': ['none'], 'protocol_sha256': digest('protocol'),
                 'rows': self.rows, 'usage': dict(BUDGET), 'scope_violations': 0}
                for arm in ('manual', 'single_assistant', 'aria')]
        result = compare(runs, 'frozen')
        self.assertTrue(result['comparison_complete'])
        self.assertFalse(result['public_pilot_ready'])

    def test_protocol_mismatch_and_unsupported_reproduction_claim(self):
        self.rows[1]['independently_reproduced'] = True
        with self.assertRaises(ValueError): score(self.rows)
        self.rows[1]['independently_reproduced'] = False
        runs = [{'arm': arm, 'manifest_sha256': 'frozen', 'operator': 'synthetic',
                 'model_identifiers': ['none'], 'protocol_sha256': digest(arm),
                 'rows': self.rows, 'usage': dict(BUDGET), 'scope_violations': 0}
                for arm in ('manual', 'aria')]
        with self.assertRaises(ValueError): compare(runs, 'frozen')
