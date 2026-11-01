from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from agents.web_intel_agent import web_intel_agent
from config.cve_enricher import auto_enrich_port, CVEMatch
from tests.support import OfflineCase
from tests.test_access import OWNER, SESSION


class AgentBoundaryTests(OfflineCase):
    async def test_web_intel_restored_interface_keeps_session_authorization(self):
        result={'success':True,'content':'{"commands": [], "auth_type": "none"}'}
        with patch('api.auth.current_identity',AsyncMock(return_value=OWNER)), \
             patch('api.session_access.get_accessible_session',AsyncMock(return_value=SESSION)), \
             patch.object(web_intel_agent,'query_llm_smart',AsyncMock(return_value=result)) as provider:
            self.assertEqual((await web_intel_agent.process('engagement','owner',{'target':'192.0.2.1'}))['auth_type'],'none')
            provider.assert_awaited_once()
        with patch('api.auth.current_identity',AsyncMock(return_value=OWNER)), \
             patch('api.session_access.get_accessible_session',AsyncMock(side_effect=HTTPException(403,'Denied'))), \
             patch.object(web_intel_agent,'query_llm_smart',AsyncMock()) as provider:
            with self.assertRaises(HTTPException):await web_intel_agent.process('other','owner',{})
            provider.assert_not_awaited()

    async def test_cve_module_and_score_remain_unverified_candidates(self):
        candidate=CVEMatch(cve_id='CVE-2099-1234',cvss3=10,severity='critical',msf_module='mock/module',description='unverified service match')
        with patch('config.cve_enricher.cve_enricher.enrich_service',AsyncMock(return_value=[candidate])), \
             patch('memory.attack_knowledge_base.attack_kb.add_vulnerability') as add:
            await auto_enrich_port('test','192.0.2.1',80,'test-service','1.0')
            self.assertFalse(add.call_args.kwargs['exploitable'])
            self.assertIn('Unverified applicability',add.call_args.kwargs['description'])

    async def test_untrusted_model_arrays_are_not_accepted_as_agent_plans(self):
        self.assertIsNone(web_intel_agent.parse_json('[1,2,3]'))
