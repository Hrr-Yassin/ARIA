"""Acceptance rejects score inflation, omitted failures, mixed splits and drift."""
import copy
from unittest.mock import patch

from evaluation.competence import FIXTURES, load_cases, measure
from evaluation.competence_acceptance import verify_measurement
from tests.support import OfflineCase


class CompetenceAcceptanceTests(OfflineCase):
    async def test_case_and_source_bound_score_has_no_model_or_senior_claim(self):
        packet=load_cases(FIXTURES/'http-development-v1.json')
        run=measure(packet)
        result=verify_measurement(packet,run)
        self.assertTrue(result['all_cases_pass'])
        self.assertIsNone(result['model_intelligence_score'])
        self.assertEqual(result['independent_senior_assessment'],'BLOCKED')

    async def test_missing_failure_duplicate_or_edited_expectation_is_rejected(self):
        packet=load_cases(FIXTURES/'http-development-v1.json');run=measure(packet)
        for mutation in ('omit','duplicate','expected','actual','inflated','split','source','senior'):
            bad=copy.deepcopy(run)
            if mutation=='omit':bad['rows'].pop()
            if mutation=='duplicate':bad['rows'][1]=bad['rows'][0]
            if mutation=='expected':bad['rows'][0]['expected']='jwt'
            if mutation=='actual':bad['rows'][0]['actual']='jwt'
            if mutation=='inflated':bad['rows'][0]['passed']=1
            if mutation=='split':bad['split']='reserved_evaluation'
            if mutation=='source':bad['source_sha256']={}
            if mutation=='senior':bad['independent_human_assessment']=True
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):verify_measurement(packet,bad)

    async def test_real_failure_is_kept_in_the_denominator(self):
        packet=load_cases(FIXTURES/'http-development-v1.json')
        with patch('agents.web_intel_agent.WebIntelAgent._detect_auth',return_value='wrong'):
            run=measure(packet)
        result=verify_measurement(packet,run)
        self.assertEqual(result['components']['http_auth'],{'passed':0,'assessed':10})
        self.assertFalse(result['all_cases_pass'])

    async def test_boolean_one_cannot_impersonate_strict_expected_classification(self):
        packet=load_cases(FIXTURES/'tool-literacy-development-v1.json');run=measure(packet)
        bad=copy.deepcopy(run);bad['rows'][0]['actual']=1
        with self.assertRaises(ValueError):verify_measurement(packet,bad)
