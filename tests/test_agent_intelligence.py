"""Scorer fixtures validate accounting/grade boundaries;they are not model measurements."""
import copy
import unittest

from evaluation.agent_intelligence import digest, protocol, reviewer_packet, score


class AgentIntelligenceTests(unittest.TestCase):
    def test_public_rationale_prompt_and_capture_do_not_export_private_reasoning(self):
        from agents.web_intel_agent import WebIntelAgent
        from integration.agent_intelligence import public_content
        prompt=WebIntelAgent().get_system_prompt()
        self.assertIn('public_rationale',prompt)
        self.assertNotIn('Include reasoning_chain',prompt)
        self.assertEqual(public_content('{"summary":"public","reasoning_chain":"private",'
            '"nested":{"thinking":"private","evidence":"e1"}}'),
            {'summary':'public','nested':{'evidence':'e1'}})
        self.assertIsNone(public_content('[1,2]'))

    def fixture(self):
        plan=protocol()
        run={'kind':'actual_existing_agent_run','scripted_responses':False,
             'accounting_reconciled':True,'protocol_sha256':digest(plan),
             'cases':[{'case_id':c['case_id'],'actual_model_success':True,'public_result':{'text':'retained fixture text'}} for c in plan['cases']]}
        assessment={'protocol_sha256':digest(plan),'grader_kind':'engineering_rubric_agent',
            'independent_senior_reference':False,'rows':[{'case_id':c['case_id'],
                'response_sha256':digest(run['cases'][i]),'grades':[{'criterion_id':check['id'],
                    'passed':True,'rationale':'Unit fixture only','evidence_excerpt':'retained fixture text'} for check in c['checks']]}
                for i,c in enumerate(plan['cases'])]}
        return plan,run,assessment

    def test_all_four_dimensions_are_separate_and_never_claim_human_or_operational_readiness(self):
        plan,run,assessment=self.fixture();result=score(plan,run,assessment)
        self.assertEqual(set(result['dimensions']),{'decision_quality','reasoning_accuracy','hypothesis_quality','collaboration'})
        self.assertFalse(result['independent_senior_comparison_complete'])
        self.assertFalse(result['operational_8_5_readiness_demonstrated'])
        self.assertEqual(result['dimensions']['collaboration']['opportunities'],2)

    def test_failed_grades_remain_in_denominator_and_failure_evidence(self):
        plan,run,assessment=self.fixture();assessment['rows'][0]['grades'][0]['passed']=False
        result=score(plan,run,assessment)
        self.assertEqual(result['dimensions']['decision_quality']['passed'],15)
        self.assertEqual(result['dimensions']['decision_quality']['assessed'],16)
        self.assertEqual(len(result['failures']),1)

    def test_unavailable_grading_is_explicit_and_never_perfect_accuracy(self):
        plan,run,assessment=self.fixture()
        for row in assessment['rows']:
            for grade in row['grades']:grade['passed']=None
        result=score(plan,run,assessment)
        self.assertFalse(result['grading_complete'])
        self.assertTrue(all(metric['pass_rate'] is None for metric in result['dimensions'].values()))

    def test_missing_duplicate_or_unbound_cases_and_criteria_are_rejected(self):
        plan,run,assessment=self.fixture()
        changes=[]
        item=copy.deepcopy(assessment);item['rows'].pop();changes.append(item)
        item=copy.deepcopy(assessment);item['rows'][1]=item['rows'][0];changes.append(item)
        item=copy.deepcopy(assessment);item['rows'][0]['response_sha256']='0'*64;changes.append(item)
        item=copy.deepcopy(assessment);item['rows'][0]['grades'].pop();changes.append(item)
        for item in changes:
            with self.subTest(item=item['rows'][0]['case_id']),self.assertRaises(ValueError):score(plan,run,item)

    def test_scripted_unaccounted_failed_inference_and_false_human_claims_are_rejected(self):
        plan,run,assessment=self.fixture()
        for key,value in (('scripted_responses',True),('accounting_reconciled',False),('protocol_sha256','other')):
            with self.subTest(key=key),self.assertRaises(ValueError):score(plan,{**run,key:value},assessment)
        run['cases'][0]['actual_model_success']=False;assessment['rows'][0]['response_sha256']=digest(run['cases'][0])
        with self.assertRaises(ValueError):score(plan,run,assessment)
        plan,run,assessment=self.fixture();assessment['independent_senior_reference']=True
        with self.assertRaises(ValueError):score(plan,run,assessment)

    def test_nonboolean_scores_and_unattributed_passing_quotes_are_rejected(self):
        plan,run,assessment=self.fixture()
        for value in (1,'yes',0.0):
            altered=copy.deepcopy(assessment);altered['rows'][0]['grades'][0]['passed']=value
            with self.subTest(value=value),self.assertRaises(ValueError):score(plan,run,altered)
        assessment['rows'][0]['grades'][0]['evidence_excerpt']='invented conclusion'
        with self.assertRaises(ValueError):score(plan,run,assessment)

    def test_reviewer_packet_contains_inputs_without_author_answers_or_agent_final_responses(self):
        packet=reviewer_packet(protocol())
        self.assertFalse(packet['human_assessments_present'])
        self.assertTrue(all('checks' not in case and 'response' not in case for case in packet['cases']))
