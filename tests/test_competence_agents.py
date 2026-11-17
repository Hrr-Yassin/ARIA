"""Source-grounded software checks; no claims about model intelligence."""
from pathlib import Path
from unittest.mock import AsyncMock, patch

from agents.coordinator_agent import CoordinatorAgent
from agents.correlation_agent import CorrelationAgent
from agents.orchestrator_agent import OrchestratorAgent
from agents.vuln_agent import VulnAgent
from agents.web_intel_agent import WebIntelAgent
from evaluation.competence import FIXTURES, load_cases, measure
from tests.support import OfflineCase
from tests import test_discovery_prompt_boundaries as discovery_fixture


class CompetenceAgentTests(OfflineCase):
    async def test_frozen_http_classifications(self):
        result = measure(load_cases(FIXTURES / 'http-development-v1.json'))
        for row in result['rows']:
            with self.subTest(case=row['id']):
                self.assertTrue(row['passed'], f"expected {row['expected']!r}, actual {row['actual']!r} {row['error']}")

    async def test_vuln_incomplete_response_is_a_blocker_without_fallback_scans(self):
        result, _ = await discovery_fixture.DiscoveryPromptBoundaryTests.run_agent(self, VulnAgent, '{}')
        self.assertEqual(result['commands'], [])
        self.assertEqual(result['agent_result']['status'], 'blocked')
        self.assertIn('malformed_model_output', [r['code'] for r in result['rejections']])

    async def test_prompts_stop_requiring_unavailable_or_unsubstantiated_actions(self):
        self.assertNotIn('Tools you drive:', VulnAgent().get_system_prompt())
        self.assertNotIn('ALWAYS provide next_steps with exact commands',
                         Path('agents/orchestrator_agent.py').read_text())
        self.assertNotIn('multiple agents confirm', Path('agents/correlation_agent.py').read_text())
        self.assertNotIn('Bearer → JWT', WebIntelAgent().get_system_prompt())
        self.assertNotIn('clear bash_history', Path('agents/post_exploitation_agent.py').read_text())

    async def test_evidence_review_does_not_require_network_discovery(self):
        agent = CoordinatorAgent()
        result = agent._fast_decide('Review the saved HTTP cookie flags', [], [], [], [], 'lab', 'scope')
        self.assertIsNotNone(result)
        self.assertEqual(result['agent'], 'web_intel')

    async def test_http_secondary_entry_point_uses_public_rationale(self):
        agent = WebIntelAgent()
        with patch.object(agent, 'call_llm', AsyncMock(return_value={})) as call:
            await agent.analyze_http_traffic('session', 'owner', {'url':'http://192.0.2.1/'})
        prompt = call.await_args.kwargs['prompt']
        self.assertNotIn('reasoning_chain', prompt)
        self.assertIn('public_rationale', prompt)

    async def test_shared_guidance_requires_evidence_over_analyst_agreement(self):
        _, system = OrchestratorAgent()._ground_prompt('task', 'role')
        self.assertIn('Bearer', system)
        self.assertIn('independent', system)
        self.assertIn('unknown', system)
