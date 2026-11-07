"""Reproducible saved-evidence benchmark and measured workflow comparison.

Run: python -m evaluation.benchmark --output PATH [--runs measured-runs.json]
No network, database, provider, worker, or environment secrets are needed.
"""
import argparse
import base64
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
ARMS = ('manual', 'single_assistant', 'aria')
BUDGET = {'wall_seconds': 1800, 'human_seconds': 1800, 'requests': 30, 'model_cost_usd': 2.0}
TARGETS = {'precision': 1.0, 'recall': 0.8}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def cases():
    """Development controls plus held-out-shape variants, not unseen model data."""
    owner = '{"controlled_record":"private-synthetic-48","public":"hello"}'
    return [
        {'id': 'secure-denial', 'split': 'development', 'vulnerable': False, 'status': 403, 'body': '{}'},
        {'id': 'private-exposure', 'split': 'development', 'vulnerable': True, 'status': 200, 'body': owner},
        {'id': 'misleading-success', 'split': 'development', 'vulnerable': False, 'status': 200,
         'body': '{"message":"login required"}'},
        {'id': 'reordered-extra-fields', 'split': 'variant', 'vulnerable': True, 'status': 200,
         'body': '{"extra":7,"public":"hello","controlled_record":"private-synthetic-48"}'},
        {'id': 'different-private-object', 'split': 'variant', 'vulnerable': False, 'status': 200,
         'body': '{"controlled_record":"another-private-record"}'},
        {'id': 'duplicate-json-key', 'split': 'variant', 'vulnerable': False, 'status': 200,
         'body': '{"controlled_record":"private-synthetic-48","controlled_record":"public"}'},
    ]


def fixture(case):
    def capture(identity, evidence, body, status=200):
        request = b'GET /item HTTP/1.1\r\nHost: lab.test\r\n\r\n'
        response = f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{body}'.encode()
        return {'identity_id': identity, 'evidence_id': evidence, 'method': 'GET',
                'origin': 'https://lab.test', 'route': '/item', 'expired': False, 'original': {
            'method': 'GET', 'url': 'https://lab.test/item',
            'request_b64': base64.b64encode(request).decode(),
            'response_b64': base64.b64encode(response).decode()}}
    return {'identities': {key: {'active': True, 'researcher_controlled': True, 'credentials': {}} for key in ('a', 'b')},
            'objects': {'o': {'owner_identity_id': 'a', 'evidence_ids': ['e1']}},
            'permissions': {'p': {'id': 'p', 'object_id': 'o', 'identity_id': 'b',
                                  'operation': 'read', 'expected': 'deny'}},
            'captures': {'c1': capture('a', 'e1', '{"controlled_record":"private-synthetic-48","public":"hello"}'),
                         'c2': capture('b', 'e2', case['body'], case['status'])}}


def freeze():
    # Only explicit source categories from git: never inspect .env or owner artifacts.
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    paths += [str(p.relative_to(ROOT)) for p in (ROOT / 'evaluation').glob('*.py')]
    paths += ['integration/phase7_benchmark.py', 'tests/test_benchmark.py']
    hashes = {}
    for name in sorted(set(paths)):
        path = ROOT / name
        if path.is_file() and not path.is_symlink() and (name.endswith(('.py', '.js', '.cjs', '.html'))
                or name in ('requirements.txt', 'worker/requirements.txt', 'worker/Dockerfile')):
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
            'source_sha256': hashes, 'python': platform.python_version(),
            'lab': 'synthetic in-memory HTTP; no image used',
            'models': [], 'prompts': 'source hashes include agents and llm; no model calls in offline baseline',
            'tools': 'Python standard library and installed requirements',
            'installed_packages': sorted(json.loads(subprocess.check_output(
                [sys.executable, '-m', 'pip', 'list', '--format=json'], cwd=ROOT)),
                key=lambda row: row['name'].lower()),
            'budget_per_arm': BUDGET, 'targets': TARGETS, 'cases_sha256': digest(cases())}


def score(rows):
    truth = {case['id']: case['vulnerable'] for case in cases()}
    if len(rows) != len(truth) or {r['case_id'] for r in rows} != set(truth):
        raise ValueError('Each case must occur exactly once, including no-finding cases')
    for row in rows:
        if type(row['candidate']) is not bool or type(row['independently_reproduced']) is not bool:
            raise ValueError('Decisions must be booleans')
        if not row['evidence_sha256'] or any(not isinstance(h, str) or len(h) != 64
                or any(c not in '0123456789abcdef' for c in h) for h in row['evidence_sha256']):
            raise ValueError('Every decision needs attributable evidence hashes')
        if row['independently_reproduced'] and (not row['candidate']
                or not row.get('independent_reviewer') or not row.get('reproduction_evidence_sha256')):
            raise ValueError('Reproduction requires a candidate, reviewer and retained reproduction evidence')
    tp = sum(r['candidate'] and truth[r['case_id']] for r in rows)
    fp = sum(r['candidate'] and not truth[r['case_id']] for r in rows)
    positives = sum(truth.values())
    candidates = sum(r['candidate'] for r in rows)
    return {'true_positives': tp, 'false_positives': fp, 'false_negatives': positives - tp,
            'precision': tp / candidates if candidates else None, 'recall': tp / positives,
            'independent_reproduction_rate': sum(r['independently_reproduced'] for r in rows) / candidates
                if candidates else None, 'coverage': len(rows) / len(truth)}


def compare(runs, manifest_sha256):
    """Validate human-recorded measurements; never simulate missing baseline arms."""
    result = {}
    protocol = None
    for run in runs:
        arm = run['arm']
        if arm not in ARMS or arm in result or run['manifest_sha256'] != manifest_sha256:
            raise ValueError('Unknown/duplicate arm or unequal frozen starting conditions')
        if (not run['operator'] or not run['model_identifiers']
                or not isinstance(run['protocol_sha256'], str) or len(run['protocol_sha256']) != 64
                or any(c not in '0123456789abcdef' for c in run['protocol_sha256'])):
            raise ValueError('Record operator, exact model identifiers (or none), and protocol hash')
        if protocol is not None and run['protocol_sha256'] != protocol:
            raise ValueError('Comparison arms must use the same experiment protocol')
        protocol = run['protocol_sha256']
        metrics = score(run['rows'])
        for key in BUDGET:
            value = run['usage'][key]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError('Usage must be a finite nonnegative number')
        violations = run['scope_violations']
        if type(violations) is not int or violations < 0:
            raise ValueError('Record observed scope violations')
        metrics['quality_target_met'] = (metrics['precision'] is not None
            and metrics['precision'] >= TARGETS['precision'] and metrics['recall'] >= TARGETS['recall'])
        metrics.update(usage=run['usage'], within_budget=all(run['usage'][k] <= v for k, v in BUDGET.items()),
                       scope_violations=violations)
        result[arm] = metrics
    return {'arms': result, 'missing_arms': sorted(set(ARMS) - set(result)),
            'comparison_complete': set(result) == set(ARMS),
            'public_pilot_ready': False,
            'limitation': 'Measurements are human-recorded. Policy activation, participant eligibility, '
                          'live reproduction and prerequisite acceptance are separate requirements.'}


def baseline():
    from memory.application_map import ExposureReview, exposure_review
    rows = []
    started = time.monotonic()
    for case in cases():
        state = fixture(case)
        review = exposure_review(state, ExposureReview(capture_id='c2', object_id='o',
            owner_capture_id='c1', private_json_key='controlled_record', inspection_authorized=True,
            intended_visibility='restricted', observed_audience='outside', meaningful_private_content='present',
            rationale='Synthetic benchmark control; not live independent reproduction'))
        rows.append({'case_id': case['id'],
                     'candidate': review['assessment'] == 'candidate_unauthorized_disclosure',
                     'independently_reproduced': False,
                     'evidence_sha256': [digest(state['captures'][key]) for key in ('c1', 'c2')],
                     'review': review})
    return {'kind': 'deterministic saved-evidence component baseline; not a workflow comparison',
            'metrics': score(rows), 'rows': rows, 'wall_seconds': time.monotonic() - started,
            'requests': 0, 'model_cost_usd': 0, 'scope_violations': 0,
            'limitations': ['Six synthetic cases in one supported disclosure class.',
                            'Variants are public and cannot establish unseen model generalization.',
                            'No manual, single-assistant, live model or independent reproduction measurements.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runs', type=Path)
    args = parser.parse_args()
    manifest = freeze()
    report = {'manifest': manifest, 'manifest_sha256': digest(manifest), 'baseline': baseline()}
    report['comparison'] = compare(json.loads(args.runs.read_text()) if args.runs else [], report['manifest_sha256'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n')
    print(json.dumps({'output': str(args.output), 'metrics': report['baseline']['metrics'],
                      'missing_arms': report['comparison']['missing_arms']}))


if __name__ == '__main__':
    main()
