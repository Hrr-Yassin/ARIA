"""Reviewed synthetic positive, negative and incomplete-evidence fixtures.
These enforce result quality boundaries; they do not establish live-model expertise.
"""
from agents.result_contract import professional_result
from tests.support import OfflineCase

AGENTS = ['coordinator','orchestrator','recon','scan','web_intel','vuln','correlation','planner','post','report']


class AgentQualityTests(OfflineCase):
    async def test_each_agent_positive_negative_and_incomplete_evidence(self):
        scope = {'targets':['192.0.2.1'], 'ports':[80]}
        request = {'user_input':'Assess only HTTP on 192.0.2.1'}
        evidence = [{'id':'receipt-1','summary':'80/tcp open http; version unknown','command':'nmap -p 80 192.0.2.1'}]
        for agent in AGENTS:
            for scenario in ['positive','out_of_scope','missing_evidence']:
                with self.subTest(agent=agent, scenario=scenario):
                    command = 'curl -I http://198.51.100.1' if scenario == 'out_of_scope' else 'curl -I http://192.0.2.1'
                    result = professional_result(agent, request, {'commands':[{'command':command}]}, scope,
                        [] if scenario == 'missing_evidence' else evidence, {'curl','nmap'})
                    self.assertEqual(result.interpreted_request, request['user_input'])
                    self.assertEqual(result.evidence_references, [] if scenario == 'missing_evidence' else ['receipt-1'])
                    if scenario == 'out_of_scope' or agent == 'post':
                        self.assertEqual(result.proposed_actions, [])
                        self.assertEqual(result.status, 'blocked')
                    elif scenario == 'positive':
                        self.assertEqual(len(result.proposed_actions), 1)
                    if scenario == 'missing_evidence': self.assertTrue(result.uncertainty)
                    self.assertFalse(any(h.get('verified') for h in result.hypotheses))

    async def test_duplicate_work_and_forged_model_evidence_removed(self):
        evidence = [{'id':'saved-1','summary':'HTTP response','command':'curl -I http://192.0.2.1'}]
        result = professional_result('scan', {'user_input':'HTTP only'},
            {'commands':[{'command':'curl -I http://192.0.2.1'}], 'evidence_references':['invented'], 'verified':True},
            {'targets':['192.0.2.1'], 'ports':[80]}, evidence, {'curl'})
        self.assertEqual(result.proposed_actions, [])
        self.assertEqual(result.evidence_references, ['saved-1'])
        self.assertTrue(result.rejections)

    async def test_requested_service_cannot_expand_to_other_configured_ports(self):
        result = professional_result('scan', {'user_input':'Assess only HTTP on the target'},
            {'commands':[{'command':'nmap -p 22 192.0.2.1'}]},
            {'targets':['192.0.2.1'],'ports':[80,22]}, [], {'nmap'})
        self.assertEqual(result.proposed_actions, [])
        self.assertTrue(result.rejections)
