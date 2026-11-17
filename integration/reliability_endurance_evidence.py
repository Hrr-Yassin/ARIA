"""Independently reconcile terminal endurance artifacts, without network I/O.

This checks unsigned retained evidence, not a trusted clock attestation. Only a
completed exact-duration cohort can pass; checkpoints/partial runs never do.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import uuid

EXPECTED = ['completed', 'completed', 'completed', 'blocked', 'completed', 'cancelled',
            'completed', 'completed', 'completed', 'cancelled', 'completed', 'completed']
ZERO = ('duplicate_dispatches', 'lost_operations', 'unauthorized_dispatches')


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum, 'Missing or invalid integer evidence')
    return value


def number(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            'Missing or invalid measured evidence')
    return value


def identity(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value, 'Unbound evidence identity')
    return value


def load(path):
    require(path.is_file() and not path.is_symlink(), 'Missing or linked evidence artifact')
    return json.loads(path.read_text())


def validate_endurance(directory: Path, expected_seconds: int) -> dict:
    require(type(expected_seconds) is int and expected_seconds in (900, 1800, 3600, 7200, 14400, 28800),
            'An exact progressive acceptance duration is required')
    result = load(directory/'result.json')
    require(result.get('status') == 'VERIFIED' and result.get('synthetic') is True
            and result.get('application_transport') == 'in_process_ASGI', 'No terminal verified synthetic result')
    require(integer(result.get('requested_seconds')) == expected_seconds
            and number(result.get('elapsed_seconds')) >= expected_seconds, 'Requested duration was not completed')
    require(load(directory/'checkpoint.json') == result, 'Final result and checkpoint disagree')
    for key in (*ZERO, 'availability_failures', 'batch_failures', 'actual_tools_executed',
                'physical_external_provider_calls'):
        require(integer(result.get(key)) == 0, 'Failed or unresolved endurance outcome')
    manifest = load(directory/'source-manifest.json')
    require(isinstance(manifest, dict) and bool(manifest)
            and all(isinstance(v, str) and len(v) == 64 and set(v) <= set('0123456789abcdef')
                    for v in manifest.values()),
            'Source provenance is missing')
    hashes = {}

    def hashed(path):
        require(path.is_file() and not path.is_symlink(), 'Missing or linked raw artifact')
        hashes[str(path.relative_to(directory))] = hashlib.sha256(path.read_bytes()).hexdigest()

    def lines(name):
        path = directory/name
        hashed(path)
        return [json.loads(line) for line in path.read_text().splitlines()]

    batches, samples = lines('batches.jsonl'), lines('samples.jsonl')
    require(len(batches) == integer(result.get('completed_batches'), 1), 'Missing or extra batch records')
    require(len(samples) == integer(result.get('availability_samples'), 1), 'Missing or extra readiness records')
    jobs, sessions, faults = set(), set(), Counter()
    for index, batch in enumerate(batches, 1):
        require(integer(batch.get('number'), 1) == index and batch.get('passed') is True,
                'Batch order or result is invalid')
        number(batch.get('wall_seconds'))
        session_id = identity(batch.get('session_id'))
        require(session_id not in sessions, 'Duplicate batch session')
        sessions.add(session_id)
        path = directory/f'batch-{index:04d}/workload.json'
        work = load(path)
        hashed(path)
        require(work.get('synthetic') is True and work.get('benchmark_passed') is True
                and work.get('session_id') == session_id, 'Unbound or failed workload')
        require(number(work.get('wall_seconds')) == batch['wall_seconds'], 'Batch duration disagrees')
        require(integer(work.get('expected_operations')) == 12
                and integer(work.get('recorded_operations')) == 12
                and integer(work.get('simulated_runtime_starts')) == 12
                and len(work.get('operations', [])) == 12, 'Incomplete workload')
        for key in (*ZERO, 'actual_external_provider_calls', 'actual_tools_executed'):
            require(integer(work.get(key)) == 0, 'Unsafe workload result')
        require(integer(work.get('counters', {}).get('forbidden_network_attempts')) == 0,
                'Network isolation result missing or failed')
        for position, (operation, expected) in enumerate(zip(work['operations'], EXPECTED), 1):
            require(integer(operation.get('number'), 1) == position
                    and operation.get('state') == operation.get('expected_state') == expected,
                    'Operation outcome was lost or changed')
            job = identity(operation.get('job_id'))
            require(job not in jobs, 'Duplicate dispatch identity')
            jobs.add(job)
            events = operation.get('events') or []
            require(events and events[-1].get('state') == expected, 'Terminal operation event missing')
            faults[expected] += 1
    require(integer(result.get('recorded_operations')) == len(jobs) == 12 * len(batches),
            'Operation totals disagree')
    recorded_faults = result.get('expected_faults')
    require(isinstance(recorded_faults, dict) and all(type(v) is int for v in recorded_faults.values())
            and recorded_faults == dict(faults), 'Fault totals disagree')
    elapsed = [number(item.get('elapsed_seconds')) for item in samples]
    require(elapsed == sorted(elapsed) and elapsed[-1] <= result['elapsed_seconds'], 'Invalid sample order')
    connection_samples, diagnostic_errors = [], Counter()
    for item in samples:
        require(item.get('available') is True, 'Readiness result unavailable')
        number(item.get('api_readiness_wall_ms'))
        # The readiness response is measured before the separate connection
        # diagnostic. A failed diagnostic is explicitly unavailable; it cannot
        # turn an observed HTTP200 into an outage or a fabricated zero count.
        if item.get('error_type'):
            error = item['error_type']
            require(isinstance(error,str) and error.isidentifier() and len(error)<=64
                    and item.get('database_connections') is None, 'Inconsistent diagnostic failure')
            diagnostic_errors[error] += 1
        else:
            connection_samples.append(integer(item.get('database_connections'), 1))
        integer(item.get('current_rss_kb'), 1)
        require(integer(item.get('memory_available_kb')) >= 512 * 1024
                and integer(item.get('disk_available_bytes')) >= 512 * 1024 * 1024,
                'Existing resource headroom threshold failed')
    require(bool(connection_samples), 'Database connection diagnostic entirely unavailable')
    require(integer(result.get('maximum_database_connections'), 1) == max(connection_samples),
            'Connection maximum disagrees')
    number(result.get('cpu_seconds'))
    initial_rss = integer(result.get('initial_rss_kb'), 1)
    current_rss = integer(result.get('current_rss_kb'), 1)
    require(type(result.get('rss_growth_kb')) is int
            and result['rss_growth_kb'] == current_rss - initial_rss, 'RSS growth disagrees')
    legacy_rusage_peak = ('sampled_peak_rss_kb' not in result and expected_seconds == 900
                         and 'peak_rss_kb' in result)
    if legacy_rusage_peak:
        integer(result['peak_rss_kb'], 1)  # Historical ru_maxrss, not a sampled RSS maximum.
    else:
        require(integer(result.get('sampled_peak_rss_kb'), 1) == max(current_rss,
                *(sample['current_rss_kb'] for sample in samples)), 'RSS peak disagrees')
    for name in ('result.json', 'checkpoint.json', 'source-manifest.json'):
        hashed(directory/name)
    gaps = [elapsed[0], *(b-a for a,b in zip(elapsed, elapsed[1:])), result['elapsed_seconds']-elapsed[-1]]
    return {'status':'VERIFIED', 'synthetic':True, 'duration_seconds':expected_seconds,
        'elapsed_seconds':result['elapsed_seconds'], 'batches':len(batches), 'operations':len(jobs),
        'readiness_samples':len(samples), 'maximum_sample_gap_seconds':max(gaps),
        'resource_headroom_ok':True, 'sha256':hashes,
        'legacy_rusage_peak_only':legacy_rusage_peak,
        'unavailable_database_samples':sum(diagnostic_errors.values()),
        'diagnostic_error_types':dict(diagnostic_errors),
        'limitations':['Unsigned retained artifact reconciliation, not independent clock attestation.',
            'Synthetic ASGI/SQL only; no actual provider/tool/deployed availability or operational readiness claim.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--seconds', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = validate_endurance(args.directory, args.seconds)
    args.output.write_text(json.dumps(value, indent=2)+'\n')
    print(json.dumps({k:v for k,v in value.items() if k not in {'sha256','limitations'}}))
