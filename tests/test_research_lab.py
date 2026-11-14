"""Real in-process laboratory HTTP controls and independent reproduction."""
import copy
from evaluation.research_lab import cases, observe, independently_verify, benchmark, template
from tests.support import OfflineCase


class ResearchLab(OfflineCase):
    async def test_all_secure_and_vulnerable_controls_reproduce_independently(self):
        rows=cases();observations={}
        for case in rows:
            original=await observe(case);fresh=await observe(case)
            observations[case['id']]=original
            verdict=independently_verify(original,fresh)
            self.assertEqual(verdict['confirmed_lab_only'],case['vulnerable'],case)
            self.assertTrue(original['positive_control'])
            self.assertTrue(original['negative_control'])
            self.assertFalse(verdict['production_finding'])
        # Challenge every secure scenario as a candidate; the verifier rejects all.
        report=await benchmark([{'case_id':c['id'],'template':template(c['class'])} for c in rows],observations)
        self.assertEqual(report['metrics']['confirmed_vulnerabilities'],9)
        self.assertEqual(report['metrics']['false_positive_findings'],0)
        self.assertEqual(report['metrics']['vulnerability_class_coverage'],9)

    async def test_shared_sources_failed_controls_and_changed_original_reject(self):
        case=next(c for c in cases() if c['vulnerable'])
        first=await observe(case);fresh=await observe(case)
        self.assertFalse(independently_verify(first,first)['confirmed_lab_only'])
        for key in ('positive_control','negative_control'):
            altered=copy.deepcopy(fresh);altered[key]=False
            self.assertFalse(independently_verify(first,altered)['confirmed_lab_only'])
        fresh['evidence'][0]['body']['unexpected']='tampered'
        self.assertFalse(independently_verify(first,fresh)['confirmed_lab_only'])

    async def test_unknown_duplicate_or_wrong_template_cannot_confirm(self):
        case=next(c for c in cases() if c['vulnerable'])
        observations={c['id']:await observe(c) for c in cases()}
        wrong=next(t for t in ('identity_control','workflow_control','integer_control') if t!=template(case['class']))
        report=await benchmark([{'case_id':case['id'],'template':wrong}],observations)
        self.assertEqual(report['metrics']['confirmed_vulnerabilities'],0)
        for decisions in ([{'case_id':'unknown','template':'identity_control'}],
                [{'case_id':case['id'],'template':'identity_control'}]*2):
            with self.assertRaises(ValueError):await benchmark(decisions,observations)

    async def test_asserted_violation_and_source_aliases_do_not_replace_content(self):
        secure = next(c for c in cases() if not c['vulnerable'])
        first, fresh = await observe(secure), await observe(secure)
        first['violation'] = fresh['violation'] = True
        self.assertFalse(independently_verify(first, fresh)['confirmed_lab_only'])
        vulnerable = next(c for c in cases() if c['vulnerable'])
        first, fresh = await observe(vulnerable), await observe(vulnerable)
        fresh['evidence_ids'] = ['invented']
        self.assertFalse(independently_verify(first, fresh)['confirmed_lab_only'])
