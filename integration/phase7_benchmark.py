"""Offline Phase 7 component baseline plus named resilience acceptance tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from evaluation.benchmark import ROOT, baseline, compare, digest, freeze

SCENARIOS = {
    'restart': 'tests.test_reliability.ReliabilityTests.test_restart_blocks_unfinished_without_replay',
    'cancellation': 'tests.test_team_tasks.TeamTasks.test_cancellation_fences_late_result_and_stale_review',
    'provider_failure': 'tests.test_team_tasks.TeamTasks.test_specialist_failure_and_cancellation_are_durable',
    'storage_failure': 'tests.test_team_tasks.TeamTasks.test_storage_failure_does_not_publish',
    'duplicate_delivery': 'tests.test_team_tasks.TeamTasks.test_coordinator_duplicate_delivery_never_calls_specialist_twice',
    'scope_change': 'tests.test_program_acceptance.PolicyAcceptance.test_source_revision_suspends_and_invalidates_old_approval',
    'scope_boundary': 'tests.test_program_acceptance.PolicyAcceptance.test_exact_wildcard_path_port_and_third_party_fixture_set',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = freeze()
    results = {}
    for name, test in SCENARIOS.items():
        command = [sys.executable, '-m', 'unittest', test, '-q']
        completed = subprocess.run(command, cwd=ROOT, env={**os.environ, 'DEBUG': 'false'},
                                   capture_output=True, timeout=60)
        log = completed.stdout + completed.stderr
        results[name] = {'test': test, 'passed': completed.returncode == 0,
                         'log_sha256': hashlib.sha256(log).hexdigest()}
        if completed.returncode:
            print(log.decode(errors='replace'), file=sys.stderr)
    report = {'manifest': manifest, 'manifest_sha256': digest(manifest), 'baseline': baseline(),
              'resilience': results, 'comparison': compare([], digest(manifest)),
              'engineering_controls_passed': all(row['passed'] for row in results.values())}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n')
    print(json.dumps({'output': str(args.output), 'metrics': report['baseline']['metrics'],
                      'engineering_controls_passed': report['engineering_controls_passed']}))
    return 0 if report['engineering_controls_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
