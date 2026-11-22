"""P1 crash/restart acceptance on a fresh disposable PostgreSQL container (opt-in)."""
import json
import os
import subprocess
import sys
import unittest

ENABLED = os.environ.get('ARIA_INTEGRATION') == '1'


@unittest.skipUnless(ENABLED, 'requires rootless Podman and the cached postgres:16.6 image')
class CollaborationRestartPostgres(unittest.TestCase):
    def test_kill_recover_replan_without_duplicate_specialist_calls(self):
        run = subprocess.run([sys.executable, '-m', 'integration.collaboration_postgres'],
                             capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 0, run.stderr[-2000:])
        with open('.local-lab/p1-postgres/result.json') as handle:
            result = json.load(handle)
        checks = result['checks']
        self.assertEqual(checks['after_kill']['analysis-vuln'], 'running')
        self.assertEqual(checks['after_recover']['analysis-vuln'], 'blocked')
        self.assertTrue(checks['redelivery_duplicate'])
        self.assertTrue(checks['catalog_identity_shared'])
        self.assertEqual(checks['replans'], ['specialist_failed'])
        self.assertEqual(checks['second_restart_new_calls'], 0)
        self.assertTrue(checks['reasoning_ids_are_ledger_ids'])
        self.assertFalse(checks['reasoning_contains_raw_job_ids'])
        roles = [c['role'] for c in result['specialist_calls']]
        self.assertEqual(roles.count('web_intel'), 1)
        self.assertEqual(roles.count('correlation'), 1)
