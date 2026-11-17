"""Technical interpretation of controlled evidence, with no model or target use."""
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from agents.orchestrator_agent import OrchestratorAgent
from agents.web_intel_agent import WebIntelAgent
from evaluation.competence import FIXTURES, load_cases, measure
from memory.attack_knowledge_base import AttackKnowledgeBase
from tests.support import OfflineCase
from tests.test_access import OWNER


class EvidenceCompetenceTests(OfflineCase):
    async def test_frozen_parser_observations_do_not_become_verified_exploits(self):
        result=measure(load_cases(FIXTURES/'parser-development-v1.json'))
        self.assertEqual(result['components']['parser_interpretation'],{'passed':10,'assessed':10})

    async def test_ten_security_concepts_keep_uncertainty_and_defensive_controls(self):
        result=measure(load_cases(FIXTURES/'security-development-v1.json'))
        for row in result['rows']:
            with self.subTest(case=row['id']): self.assertTrue(row['passed'],row)

    async def test_canonical_legacy_knowledge_never_promotes_scanner_exploitability(self):
        kb=AttackKnowledgeBase()
        callback=AsyncMock()
        kb._replan_callbacks['fixture']=callback
        kb.add_vulnerability('fixture','192.0.2.1',title='Alert only',severity='critical',cvss=10.0,exploitable=True)
        self.assertFalse(kb.get_host('fixture','192.0.2.1').vulnerabilities[0]['exploitable'])
        callback.assert_not_called()

    async def test_fallback_parser_has_no_scope_free_executable_steps(self):
        result=OrchestratorAgent()._parse_output_basic('nmap','nmap -p 80 192.0.2.1','80/tcp open http Apache/2.4.49','192.0.2.1')
        self.assertEqual(result['next_steps'],[])
        self.assertEqual(result['findings'][0]['cve_ids'],[])
        self.assertEqual(result['findings'][0]['severity'],'info')

    async def test_actual_recorded_http_agent_uses_owned_store_without_model(self):
        summary={'response_status':200,'authentication_scheme':'bearer','response_headers':[
            {'name':'server','value':'Apache'}, {'name':'access-control-allow-origin','value':'*'},
            {'name':'access-control-allow-credentials','value':'true'}]}
        with ExitStack() as stack:
            stack.enter_context(patch('api.auth.current_identity',AsyncMock(return_value=OWNER)))
            stack.enter_context(patch('api.session_access.get_accessible_session',AsyncMock(return_value={
                'user_id':'owner','target':'192.0.2.1','scope':{'targets':['192.0.2.1']}})))
            stack.enter_context(patch('memory.session_manager.session_manager.get_chat_logs',AsyncMock(return_value=[])))
            stack.enter_context(patch('memory.worker_jobs.worker_jobs.client.capabilities',AsyncMock(return_value={})))
            fetch=stack.enter_context(patch('memory.burp_community.get_evidence',AsyncMock(return_value={'summary':summary})))
            provider=stack.enter_context(patch('llm.pool_manager.pool_manager.query_for_task',AsyncMock()))
            result=await WebIntelAgent().process('session','owner',{'recorded_evidence_ids':['owned-evidence']})
        fetch.assert_awaited_once_with('session','owned-evidence')
        provider.assert_not_awaited()
        self.assertEqual(result['model_calls'],0)
        self.assertEqual(result['commands'],[])
        self.assertEqual(result['confirmed_vulnerabilities'],[])
        rules={rule for r in result['interpretations'][0]['reviews'] for rule in r['rule_ids']}
        self.assertIn('wildcard_not_credentialed_cors',rules)

    async def test_unowned_record_cannot_enter_deterministic_analysis(self):
        with patch('api.auth.current_identity',AsyncMock(return_value=OWNER)), \
             patch('api.session_access.get_accessible_session',AsyncMock(side_effect=HTTPException(403,'Denied'))), \
             patch('memory.burp_community.get_evidence',AsyncMock()) as fetch:
            with self.assertRaises(HTTPException):
                await WebIntelAgent().process('other','owner',{'recorded_evidence_ids':['foreign']})
        fetch.assert_not_awaited()
