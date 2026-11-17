"""A model summary must not recommend actions rejected by shared policy."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from agents.recon_agent import ReconAgent
from tests.support import OfflineCase


class AgentPublicRejectionTests(OfflineCase):
    async def response(self, commands, summary):
        session={'user_id':'owner','target':'192.0.2.1',
                 'scope':{'targets':['192.0.2.1'],'ports':[80]}}
        model={'success':True,'content':json.dumps({'commands':commands,'suggested_response':summary})}
        with patch('api.auth.current_identity',AsyncMock(return_value=SimpleNamespace(user_id='owner'))), \
                patch('api.session_access.get_accessible_session',AsyncMock(return_value=session)), \
                patch('memory.session_manager.session_manager.get_chat_logs',AsyncMock(return_value=[])), \
                patch('memory.worker_jobs.worker_jobs.client.capabilities',AsyncMock(return_value={'tools':['curl','nmap']})), \
                patch.object(ReconAgent,'query_llm',AsyncMock(return_value=model)):
            return await ReconAgent().process('session','owner',{'target':'192.0.2.1',
                'original_objective':'Only HTTP observation on TCP80','requested_ports':[80]})

    async def test_partial_rejection_retires_misleading_execution_instructions(self):
        result=await self.response([
            {'tool':'whois','command':'whois 192.0.2.1'},
            {'tool':'curl','command':'curl -I -s --max-time 10 http://192.0.2.1:80/'}],
            'Execute all commands,including whois,then continue.')
        self.assertEqual(len(result['commands']),1)
        self.assertNotIn('Execute all',result['suggested_reply'])
        self.assertNotIn('including whois',result['suggested_reply'])
        self.assertIn('blocked',result['suggested_reply'].lower())
        self.assertTrue(result['needs_confirmation'])
        self.assertEqual(result['agent_result']['status'],'proposed')

    async def test_no_rejection_preserves_the_valid_summary(self):
        result=await self.response([{'tool':'curl',
            'command':'curl -I -s --max-time 10 http://192.0.2.1:80/'}],
            'Review the proposed bounded HTTP-header observation.')
        self.assertEqual(result['suggested_reply'],'Review the proposed bounded HTTP-header observation.')
