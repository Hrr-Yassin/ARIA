"""Incomplete model plans cannot invent actions or apparent review success."""
from evaluation.agent_plan_contracts import measure
from evaluation import agent_plan_contracts
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from tests.support import OfflineCase


class LegacyPlanContractTests(OfflineCase):
    async def test_frozen_legacy_entry_points_preserve_empty_valid_plans_and_block_missing_arrays(self):
        run=await measure()
        for row in run['rows']:
            with self.subTest(case=row['id']):
                self.assertEqual(row['actual'],row['expected'])
                if row['expected']['status']=='blocked':
                    self.assertIn('malformed_model_output',[r['code'] for r in row['public_result']['rejections']])
                    self.assertEqual(row['public_result']['agent_result']['proposed_actions'],[])

    async def test_public_uncertainty_is_retained_and_private_reasoning_is_removed(self):
        packet={'kind':'controlled_entry_point_fixture','requirement':'C15-03',
                'objective':'Explain the missing version evidence without proposing an action',
                'limitations':['Controlled software fixture only'], 'cases':[{
                    'id':'orchestrator-public-rationale','agent':'orchestrator',
                    'provider_content':json.dumps({'commands':[],
                        'public_rationale':'No product version is observed; advisory applicability remains unknown.',
                        'reasoning':'PRIVATE_FIXTURE_TRACE','suggested_response':'Need more evidence.'}),
                    'expected':{'status':'analysis','commands':[]}}]}
        with TemporaryDirectory() as directory:
            path=Path(directory)/'fixture.json';path.write_text(json.dumps(packet))
            with patch.object(agent_plan_contracts,'FIXTURE',path):run=await measure()
        public=run['rows'][0]['public_result']
        self.assertEqual(public['public_rationale'],'No product version is observed; advisory applicability remains unknown.')
        self.assertNotIn('PRIVATE_FIXTURE_TRACE',str(public))
        self.assertEqual(public['agent_result']['proposed_actions'],[])
