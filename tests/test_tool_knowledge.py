"""Catalog provenance and prompt literacy do not confer tool authority."""
from unittest.mock import patch
import ast
from pathlib import Path

from config.tool_knowledge import catalog, for_tools
from evaluation.competence import FIXTURES, load_cases, measure
from tests.support import OfflineCase
from tests import test_discovery_prompt_boundaries as discovery_fixture
from agents.recon_agent import ReconAgent


class ToolKnowledgeTests(OfflineCase):
    async def test_catalog_distinguishes_versions_licenses_and_execution_states(self):
        rows = catalog()
        self.assertEqual(len(rows), len({r['tool'] for r in rows}))
        self.assertTrue({'nmap','curl','httpx','sqlmap','semgrep','burp','wireshark'} <= {r['tool'] for r in rows})
        for row in rows:
            for field in ('purpose','license','supported_operating_systems','input_output_formats',
                          'dependencies','resource_requirements','known_limitations','security_implications',
                          'integration_status','reference_version','version_provenance'):
                self.assertIn(field, row)
        by_name = {r['tool']:r for r in rows}
        self.assertFalse(by_name['katana']['historical_operationally_verified'])
        self.assertIn('NPSL', by_name['nmap']['license']['label'])
        self.assertIn('Proprietary', by_name['burp']['license']['label'])
        for filename,variable in (('config/tools_registry.py','TOOL_AGENT_MAP'),
                                  ('orchestrator/execution_policy.py','FLAGS')):
            for node in ast.parse(Path(filename).read_text()).body:
                if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==variable for t in node.targets):
                    self.assertLessEqual(set(ast.literal_eval(node.value)),set(by_name))

    async def test_only_advertised_tool_facts_enter_actual_prompt(self):
        _, call = await discovery_fixture.DiscoveryPromptBoundaryTests.run_agent(self, ReconAgent, '{"commands":[]}')
        _, context, _ = discovery_fixture.grounded_context(discovery_fixture.grounded_prompt(call))
        facts = context['tool_knowledge']
        self.assertEqual([f['tool'] for f in facts], ['curl','nmap'])
        self.assertTrue(all(f['runtime_version'] is None for f in facts))
        self.assertIn('not a server product version', ReconAgent()._ground_prompt('', '')[1])
        self.assertEqual(for_tools({'unknown-future-tool'}), [])

    async def test_frozen_profile_literacy_is_separate_from_model_scores(self):
        result = measure(load_cases(FIXTURES / 'tool-literacy-development-v1.json'))
        self.assertEqual(result['components']['tool_profile'], {'passed':10,'assessed':10})
        self.assertEqual(result['model_calls'],0)
        self.assertEqual(result['kind'],'deterministic_software_component')
