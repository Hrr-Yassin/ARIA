"""Twelve real software operations; synthetic worker/model execution only."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

ENABLED = os.environ.get('ARIA_INTEGRATION') == '1'


@unittest.skipUnless(ENABLED, 'requires provisioned disposable *_test database')
class ReliabilityWorkloadPostgres(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        if not (make_url(os.environ['DATABASE_URL']).database or '').endswith('_test'):
            raise RuntimeError('Disposable database required')
        subprocess.run([sys.executable, '-B', '-m', 'alembic', 'upgrade', 'head'], check=True)

    async def asyncSetUp(self):
        from memory.database_models import engine
        await engine.dispose()

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    async def test_twelve_operation_lifecycles_are_complete_and_truthful(self):
        from integration.reliability_workload import run_twelve_operations, EXPECTED
        directory = Path(os.environ.get('ARIA_RELIABILITY_ARTIFACT_DIR',
            '.local-lab/operational-reliability/manual-' + uuid.uuid4().hex[:12]))
        report = await run_twelve_operations(directory)
        (directory / 'twelve-operation-benchmark.json').write_text(json.dumps(report, indent=2) + '\n')
        self.assertTrue(report['benchmark_passed'])
        self.assertEqual(report['recorded_operations'], 12)
        self.assertEqual([op['state'] for op in report['operations']], EXPECTED)
        self.assertEqual(report['simulated_runtime_starts'], 12)
        self.assertEqual(report['actual_external_provider_calls'], 0)
        self.assertEqual(report['actual_tools_executed'], 0)
        self.assertEqual(report['counters']['preapproval_denials'], 12)
        self.assertEqual(report['counters']['duplicate_authorization_denials'], 1)
        self.assertEqual(report['counters']['dependency_denials'], 1)
        self.assertEqual(report['counters']['owner_denials'], 2)
        self.assertEqual(report['counters']['actual_agent_invocations'], 11)
        self.assertEqual(report['counters']['forbidden_network_attempts'], 0)
        self.assertEqual(report['workload_state'], 'blocked')
        self.assertEqual(report['fixture_model_accounting']['configured_selection']['provider'], 'local')
        self.assertEqual(report['fixture_model_accounting']['configured_selection']['model'], 'synthetic-fixture')
        attempts = report['fixture_model_accounting']['attempts']
        self.assertEqual(len({a['logical_request_id'] for a in attempts}), 10)
        self.assertTrue(all(a['attempt_index'] == 1 for a in attempts))
        self.assertTrue(all(a['task_run_id'] for a in attempts))
