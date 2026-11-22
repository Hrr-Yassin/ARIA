"""P4 authorization-profile acceptance on a fresh disposable PostgreSQL container (opt-in)."""
import json
import os
import subprocess
import sys
import unittest

ENABLED = os.environ.get('ARIA_INTEGRATION') == '1'


@unittest.skipUnless(ENABLED, 'requires rootless Podman and the cached postgres:16.6 image')
class ProfilesPostgres(unittest.TestCase):
    def test_profiles_persist_isolate_invalidate_and_audit(self):
        run = subprocess.run([sys.executable, '-m', 'integration.profiles_postgres'],
                             capture_output=True, text=True, timeout=600)
        self.assertEqual(run.returncode, 0, run.stderr[-2000:])
        with open('.local-lab/p4-postgres/result.json') as handle:
            result = json.load(handle)
        configure, restart = result['configure'], result['restart']
        self.assertEqual(configure['proposal_status_under_profile'], 'pending')
        self.assertEqual(restart['persisted']['revision'], 2)
        self.assertEqual(restart['stale_approval'][0], 403)
        self.assertEqual(restart['prohibited_after_restart_1'], [403, 'capability_prohibited'])
        self.assertEqual(restart['out_of_scope'], 403)
        self.assertEqual(restart['bug_bounty_without_program'], 409)
        self.assertEqual(restart['change_during_execution'], 409)
        self.assertEqual(len(restart['audit_profile_changes']), 2)
