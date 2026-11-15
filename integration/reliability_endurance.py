"""Real wall-clock synthetic endurance with disposable SQL and ASGI readiness.

The parent provisions a fresh database and keeps credentials out of arguments.
The child repeats the twelve-operation engineering workload, samples the actual
application readiness route, CPU/RSS, database connections and filesystem space.
No real provider, tool, container or target request is used. Results describe
this synthetic ASGI process, not deployed-service or graphical availability.

    python -m integration.reliability_endurance --seconds 900

Use --seconds 20 only to verify the harness; it is not a 15-minute acceptance.
Durations longer than eight hours are refused. SIGINT/SIGTERM preserve a partial
checkpoint and stop after the current harmless batch.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
import uuid


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: dict):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.chmod(0o600)
    os.replace(temporary, path)


def rss_kb():
    for line in Path('/proc/self/status').read_text().splitlines():
        if line.startswith('VmRSS:'):
            return int(line.split()[1])
    return None


def memory_available_kb():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1])
    return None


async def child_run(args) -> int:
    import httpx
    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    from config.settings import settings
    from memory.database_models import engine
    from api.main import app
    from integration.reliability_workload import run_twelve_operations
    if (os.environ.get('ARIA_INTEGRATION') != '1'
            or not (make_url(settings.DATABASE_URL).database or '').startswith('aria_reliability_')
            or not (make_url(settings.DATABASE_URL).database or '').endswith('_test')):
        raise RuntimeError('Fresh disposable reliability database required')
    directory = Path(args.output)
    started, cpu_started = time.monotonic(), time.process_time()
    stop = asyncio.Event()
    reason = {'code': ''}
    loop = asyncio.get_running_loop()
    def stopped(signum):
        reason['code'] = 'operator_cancelled'
        stop.set()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopped, signum)
    summary = {'schema': 'aria.reliability.endurance.v1', 'status': 'IN_PROGRESS',
               'synthetic': True, 'application_transport': 'in_process_ASGI',
               'requested_seconds': args.seconds, 'started_at': timestamp(), 'pid': os.getpid(),
               'completed_batches': 0, 'recorded_operations': 0, 'expected_faults': {},
               'availability_samples': 0, 'availability_failures': 0, 'batch_failures': 0,
               'physical_external_provider_calls': 0, 'actual_tools_executed': 0,
               'duplicate_dispatches': 0, 'lost_operations': 0, 'unauthorized_dispatches': 0,
               'initial_rss_kb': rss_kb(), 'source_manifest': 'source-manifest.json',
               'limitations': ['ASGI API and disposable SQL, not deployed Uvicorn/network or browser rendering availability.',
                   'Worker runtime/model/owner decisions are deterministic fixtures; no container/tool/inference occurred.',
                   'Recovery is exercised in each workload before model dispatch; hard process-crash recovery has separate integration evidence.',
                   'No short run is extrapolated into a longer tested duration.']}
    samples, batches = [], []
    def checkpoint():
        summary['elapsed_seconds'] = time.monotonic() - started
        summary['cpu_seconds'] = time.process_time() - cpu_started
        summary['current_rss_kb'] = rss_kb()
        summary['rss_growth_kb'] = (summary['current_rss_kb'] - summary['initial_rss_kb']
                                    if summary['current_rss_kb'] is not None else None)
        summary['rusage_maxrss_kb'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_values = [s['current_rss_kb'] for s in samples if s.get('current_rss_kb') is not None]
        if summary['current_rss_kb'] is not None:
            rss_values.append(summary['current_rss_kb'])
        summary['sampled_peak_rss_kb'] = max(rss_values) if rss_values else None
        if samples:
            values = [s['database_connections'] for s in samples if s.get('database_connections') is not None]
            summary['maximum_database_connections'] = max(values) if values else None
        atomic_json(directory / 'checkpoint.json', summary)
    async def sample():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://endurance-fixture') as client:
            while not stop.is_set():
                begin = time.monotonic()
                item = {'timestamp': timestamp(), 'elapsed_seconds': begin - started,
                        'current_rss_kb': rss_kb(), 'process_cpu_seconds': time.process_time() - cpu_started,
                        'database_connections': None, 'available': False}
                try:
                    response = await asyncio.wait_for(client.get('/api/ready'), timeout=10)
                    item['available'] = response.status_code == 200
                    item['api_readiness_wall_ms'] = (time.monotonic() - begin) * 1000
                    async with engine.connect() as db:
                        item['database_connections'] = await db.scalar(text(
                            'SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()'))
                except Exception as exc:
                    item['error_type'] = type(exc).__name__
                summary['availability_samples'] += 1
                if not item['available']:
                    summary['availability_failures'] += 1
                item['memory_available_kb'] = memory_available_kb()
                space = os.statvfs(directory)
                item['disk_available_bytes'] = space.f_bavail * space.f_frsize
                if ((item['memory_available_kb'] is not None and item['memory_available_kb'] < 512 * 1024)
                        or item['disk_available_bytes'] < 512 * 1024 * 1024):
                    reason['code'] = 'resource_headroom_exhausted'
                    stop.set()
                samples.append(item)
                with (directory / 'samples.jsonl').open('a') as log:
                    log.write(json.dumps(item) + '\n')
                checkpoint()
                try:
                    await asyncio.wait_for(stop.wait(), timeout=args.sample_interval)
                except asyncio.TimeoutError:
                    pass
    monitor = asyncio.create_task(sample())
    next_batch = started
    try:
        while not stop.is_set() and time.monotonic() - started < args.seconds:
            current = time.monotonic()
            remaining = args.seconds - (current - started)
            if current >= next_batch and (remaining >= 20 or not batches):
                number = len(batches) + 1
                batch_directory = directory / f'batch-{number:04d}'
                batch_directory.mkdir(mode=0o700)
                try:
                    result = await run_twelve_operations(batch_directory)
                    atomic_json(batch_directory / 'workload.json', result)
                    summary['completed_batches'] += 1
                    summary['recorded_operations'] += result['recorded_operations']
                    for operation in result['operations']:
                        state = operation['state']
                        summary['expected_faults'][state] = summary['expected_faults'].get(state, 0) + 1
                    batches.append({'number': number, 'session_id': result['session_id'],
                                    'wall_seconds': result['wall_seconds'], 'passed': result['benchmark_passed']})
                    with (directory / 'batches.jsonl').open('a') as log:
                        log.write(json.dumps(batches[-1]) + '\n')
                except Exception as exc:
                    summary['batch_failures'] += 1
                    summary['failure_type'] = type(exc).__name__
                    reason['code'] = 'workload_failure'
                    for key in ('lost_operations', 'duplicate_dispatches', 'unauthorized_dispatches'):
                        summary[key] = None  # Unresolved outcomes are not fabricated zeros.
                    stop.set()
                checkpoint()
                next_batch = max(next_batch + args.interval, time.monotonic())
            try:
                await asyncio.wait_for(stop.wait(), timeout=min(1, max(.01, remaining)))
            except asyncio.TimeoutError:
                pass
    finally:
        stop.set()
        await monitor
        checkpoint()
        summary['reason_code'] = reason['code']
        if reason['code'] == 'operator_cancelled':
            summary['status'] = 'CANCELLED'
        elif reason['code'] == 'resource_headroom_exhausted':
            summary['status'] = 'BLOCKED'
        elif (summary['batch_failures'] or summary['availability_failures']
              or summary['elapsed_seconds'] < args.seconds or not summary['completed_batches']):
            summary['status'] = 'FAILED'
        else:
            summary['status'] = 'VERIFIED' if args.seconds >= 900 else 'HARNESS_SMOKE_PASSED'
        summary['finished_at'] = timestamp()
        summary['operations_per_second'] = summary['recorded_operations'] / summary['elapsed_seconds']
        atomic_json(directory / 'checkpoint.json', summary)
        atomic_json(directory / 'result.json', summary)
        await engine.dispose()
    return 0 if summary['status'] in {'VERIFIED', 'HARNESS_SMOKE_PASSED'} else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=900)
    parser.add_argument('--interval', type=float, default=30)
    parser.add_argument('--sample-interval', type=float, default=5)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 20 <= args.seconds <= 28800 or not 15 <= args.interval <= 300 or not 1 <= args.sample_interval <= 30:
        parser.error('Use 20..28800 seconds, 15..300 batch interval and 1..30 sample interval')
    if args.child:
        return asyncio.run(child_run(args))
    from integration.reliability_services import create_database
    directory = Path('.local-lab/operational-reliability') / ('endurance-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    manifest = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                for folder in ('api', 'agents', 'memory', 'orchestrator', 'llm', 'worker', 'integration', 'config', 'security', 'security_tools')
                for p in sorted(Path(folder).rglob('*.py'))}
    atomic_json(directory / 'source-manifest.json', manifest)
    name, url = asyncio.run(create_database())
    env = {**os.environ, 'DATABASE_URL': url, 'ARIA_INTEGRATION': '1'}
    cmd = [sys.executable, '-B', '-m', 'integration.reliability_endurance', '--child',
           '--seconds', str(args.seconds), '--interval', str(args.interval),
           '--sample-interval', str(args.sample_interval), '--output', str(directory)]
    with (directory / 'console.log').open('w') as log:
        migration = subprocess.run([sys.executable, '-B', '-m', 'alembic', 'upgrade', 'head'],
                                   env=env, stdout=log, stderr=subprocess.STDOUT)
        if migration.returncode:
            print(json.dumps({'status': 'FAILED', 'stage': 'disposable_migration', 'directory': str(directory)}))
            return 1
        process = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda number, frame: process.send_signal(number))
        atomic_json(directory / 'process.json', {'parent_pid': os.getpid(), 'child_pid': process.pid,
                    'database': name, 'requested_seconds': args.seconds, 'started_at': timestamp()})
        print(json.dumps({'status': 'RUNNING', 'directory': str(directory), 'child_pid': process.pid,
                          'requested_seconds': args.seconds, 'database': name}), flush=True)
        try:
            code = process.wait(timeout=args.seconds + 120)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            atomic_json(directory / 'parent-timeout.json', {'status': 'FAILED', 'reason': 'harness_deadline_exceeded'})
            code = 1
    print(json.dumps({'status': 'FINISHED', 'exit_code': code, 'directory': str(directory)}), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
