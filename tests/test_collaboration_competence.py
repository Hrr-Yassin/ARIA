"""Source consistency is measurable without inventing specialist collaboration."""
import json
from unittest.mock import AsyncMock, patch
from contextlib import ExitStack

from agents.correlation_agent import CorrelationAgent
from evaluation.competence import FIXTURES, load_cases, measure
from memory.analysis_review import build_handoff
from tests.support import OfflineCase
from tests.test_access import OWNER


class CollaborationCompetenceTests(OfflineCase):
    async def test_frozen_handoffs_require_attribution_and_error_detection(self):
        result=measure(load_cases(FIXTURES/'collaboration-development-v1.json'))
        for row in result['rows']:
            with self.subTest(case=row['id']): self.assertTrue(row['passed'],row)

    async def test_recent_context_retains_analyst_ids_and_filters_other_targets(self):
        entries=[{'id':'legacy-'+str(i),'agent':'vuln','content':'old','metadata':{}} for i in range(22)]
        entries += [{'id':'foreign','agent':'scan','content':'other target','metadata':{'target':'198.51.100.1'}},
                    {'id':'current','agent':'web_intel','content':'Important recent interpretation',
                     'metadata':{'target':'192.0.2.1','evidence_references':['e1'],'verified':True}}]
        handoff=build_handoff(entries,[{'id':'e1','summary':'HTTP200'}],'192.0.2.1')
        self.assertEqual(handoff['omitted_older_entries'],4)
        self.assertEqual(handoff['omitted_other_target'],1)
        self.assertEqual(handoff['claims'][-1]['id'],'current')
        self.assertFalse(handoff['claims'][-1]['verified'])
        self.assertTrue(handoff['claims'][-1]['claimed_verified'])
        self.assertIn('unverified_confirmation',{r['code'] for r in handoff['review']['issues']})

    async def test_real_correlation_entry_retains_attributed_handoff_on_provider_failure(self):
        entries=[{'id':'analyst-1','agent':'vuln','content':'Unverified claim with source attribution',
                  'metadata':{'evidence_references':['owned-evidence']}}]
        with ExitStack() as stack:
            stack.enter_context(patch('api.auth.current_identity',AsyncMock(return_value=OWNER)))
            stack.enter_context(patch('api.session_access.get_accessible_session',AsyncMock(return_value={
                'user_id':'owner','target':'192.0.2.1','scope':{'targets':['192.0.2.1']}})))
            stack.enter_context(patch('memory.session_manager.session_manager.get_chat_logs',AsyncMock(return_value=[])))
            stack.enter_context(patch('memory.worker_jobs.worker_jobs.client.capabilities',AsyncMock(return_value={})))
            stack.enter_context(patch('memory.vector_store.vector_store.get_all',return_value=entries))
            provider=stack.enter_context(patch('llm.pool_manager.pool_manager.query',AsyncMock(return_value={
                'success':False,'error':'model_budget_denied'})))
            result=await CorrelationAgent().process('session','owner',{'target':'192.0.2.1','user_input':'Challenge the supplied claims'})
        self.assertEqual(result['agent_result']['status'],'blocked')
        self.assertEqual(result['handoff_review']['claim_count'],1)
        prompt=provider.await_args.args[1]
        self.assertIn('analyst-1',prompt)
        self.assertIn('unverified_agent_assertion',prompt)
        self.assertIn('unknown_evidence_reference',prompt)
        self.assertFalse(result['handoff_review']['independent_collection_established'])
