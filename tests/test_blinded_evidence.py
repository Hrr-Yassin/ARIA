import unittest

from evaluation.blinded_evidence import Review, export_packet, load_corpus, score
from evaluation.competence import digest


class BlindedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.corpus = load_corpus()
        self.packet = export_packet(self.corpus)

    def submission(self, reviewer, *, negative='rejected', round_number=1, kind='scorer_fixture',
                   packet_sha256=None, blind=True):
        decisions = [
            ('C01', 'inconclusive', ['E1'], []),
            ('C02', 'supported', ['E1'], []),
            ('C04', 'rejected', ['E1', 'E2'], [['E2', 'E1']]),
            ('C05', negative, ['E1'], []),
        ]
        return Review.model_validate({
            'schema_version': 'aria.blinded-evidence.review.v1',
            'packet_sha256': packet_sha256 or self.packet['packet_sha256'],
            'reviewer_id': reviewer,
            'kind': kind,
            'round': round_number,
            'blind_attestation': blind,
            'decisions': [{'case_id': case, 'disposition': label, 'evidence_sufficient': label != 'inconclusive',
                           'confidence': 75, 'citations': references, 'conflicts': conflicts,
                           'rationale': 'Fixture for the scoring contract.'}
                          for case, label, references, conflicts in decisions],
        })

    def test_packet_exports_only_blind_inputs_and_has_stable_identity(self):
        body = {key: value for key, value in self.packet.items() if key != 'packet_sha256'}
        self.assertEqual(self.packet['packet_sha256'], digest(body))
        self.assertEqual(self.packet, export_packet(self.corpus))
        self.assertEqual(len(body['cases']), 9)
        for case in body['cases']:
            self.assertEqual(set(case), {'id', 'claim', 'observations'})
            self.assertTrue(all(set(row) == {'id', 'text'} for row in case['observations']))
        self.assertEqual(len(score(self.corpus, [])['design_categories']), 7)

    def test_calculates_metrics_and_keeps_fixture_assessments_separate(self):
        reviews = [self.submission('fixture-a', negative='supported'), self.submission('fixture-a', round_number=2),
                   self.submission('fixture-b')]
        result = score(self.corpus, reviews)
        self.assertEqual(result['independent_assessments']['reviewers'], 0)
        self.assertEqual(result['independent_assessments']['inter_reviewer'], [])
        cohort = result['scorer_fixtures']
        first = cohort['rounds'][0]
        self.assertEqual((first['coverage']['denominator'], first['coverage']['numerator']), (9, 4))
        self.assertEqual(first['false_positive_rate']['rate'], 0.5)
        self.assertEqual(first['evidence_sufficiency_accuracy']['rate'], 1)
        self.assertEqual(first['contradiction_handling']['rate'], 1)
        self.assertEqual(first['confidence_calibration']['brier_correctness'], 0.1875)
        self.assertEqual(cohort['repeatability'][0]['agreement']['rate'], 0.75)
        self.assertEqual(cohort['inter_reviewer'][0]['cohens_kappa'], 0.636364)
        self.assertNotIn('C05', cohort['unanimous_first_round'])
        self.assertEqual(cohort['unanimous_first_round']['C01'], 'inconclusive')

    def test_requires_the_bound_packet_and_attestation_and_rejects_duplicate_rounds(self):
        legitimate = self.submission('fixture')
        for reviews in ([legitimate, legitimate], [self.submission('fixture', packet_sha256='0' * 64)],
                        [self.submission('fixture', kind='independent_human', blind=False)]):
            with self.subTest(count=len(reviews)), self.assertRaises(ValueError):
                score(self.corpus, reviews)

    def test_invalid_citations_and_conflicts_cannot_be_scored(self):
        for citations, conflicts in ((['E9'], []), (['E1'], [['E1', 'E2']]), (['E1', 'E2'], [['E1', 'E1']])):
            payload = self.submission('fixture').model_dump()
            payload['decisions'][2].update(citations=citations, conflicts=conflicts)
            with self.subTest(conflicts=conflicts), self.assertRaises(ValueError):
                score(self.corpus, [Review.model_validate(payload)])
