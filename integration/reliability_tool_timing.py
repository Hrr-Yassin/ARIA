"""Opt-in timing of two bounded CLI operations on private synthetic targets.

Uses the existing WorkerLab topology/cleanup and unmodified container isolation.
The trusted fixture wraps an already policy-validated argv with an unprivileged
observer, as the existing kernel-boundary fixture does. No production adapter or
worker capability changes. No owner DB, VM, live target or model is used.

ARIA_WORKER_INTEGRATION=1 WORKER_TEST_RUNTIME=podman WORKER_TEST_IMAGE=sha256:... \
    python -m integration.reliability_tool_timing --output <new-private-directory>
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import time
import unittest

from integration.test_worker import WorkerLab
from worker.policy import prepare

OBSERVER = '''
import json, resource, subprocess, sys, time
argv = json.loads(sys.argv[1])
before = resource.getrusage(resource.RUSAGE_CHILDREN)
started = time.monotonic_ns()
result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
elapsed = (time.monotonic_ns() - started) / 1e6
after = resource.getrusage(resource.RUSAGE_CHILDREN)
stdout = result.stdout.decode(errors='replace')
print(json.dumps({'schema':'aria.fixture.tool-timing.v1', 'exit_code':result.returncode,
 'tool_wall_ms':elapsed, 'child_user_cpu_ms':(after.ru_utime-before.ru_utime)*1000,
 'child_system_cpu_ms':(after.ru_stime-before.ru_stime)*1000,
 'http_positive_control':'aria worker target' in stdout,
 'nmap_positive_control':'8080/tcp open' in stdout}),flush=True)
raise SystemExit(result.returncode)
'''


class ToolTimingLab(WorkerLab):
    async def test_in_container_cli_spans(self):
        async def observed_plan(*args):
            plan = await prepare(*args)
            return {**plan, 'argv': ['/usr/local/bin/python', '-c', OBSERVER, json.dumps(plan['argv'])]}
        self.service.planner = observed_plan
        self.tool_samples = []
        for tool in ('curl', 'nmap'):
            command = ('curl -s http://'+self.addresses[0]+':8080' if tool=='curl'
                else 'nmap -p 8080 '+self.addresses[0])
            job = self.job(command=command)
            await self.service.submit(job)
            result = await self.finished(job)
            self.assertEqual(result['state'], 'succeeded')
            sample = json.loads(result['stdout'])
            self.assertEqual(sample['schema'], 'aria.fixture.tool-timing.v1')
            self.assertEqual(sample['exit_code'], 0)
            self.assertTrue(sample['http_positive_control'] if tool=='curl' else sample['nmap_positive_control'])
            self.assertGreaterEqual(sample['tool_wall_ms'], 0)
            self.assertGreaterEqual(sample['child_user_cpu_ms'], 0)
            self.assertGreaterEqual(sample['child_system_cpu_ms'], 0)
            sample.update(tool=tool, job_id=job['job_id'], session_id=job['session_id'])
            self.tool_samples.append(sample)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if os.environ.get('ARIA_WORKER_INTEGRATION') != '1':
        parser.error('Explicit disposable-worker opt-in required')
    directory = Path(args.output)
    directory.mkdir(mode=0o700)  # Preserve earlier experiments; never overwrite.
    records = []
    class Capture(logging.Handler):
        def emit(self, record):
            try:
                data = json.loads(record.getMessage())
            except (ValueError, TypeError):
                return
            if data.get('event') in {'worker_service_admission', 'worker_runtime_stage'}:
                records.append(data)
                with (directory/'runtime-stages.jsonl').open('a') as file:
                    file.write(json.dumps(data)+'\n')
    logger = logging.getLogger('uvicorn.error')
    previous_level = logger.level
    logger.setLevel(logging.INFO)
    handler = Capture()
    logger.addHandler(handler)
    case = ToolTimingLab('test_in_container_cli_spans')
    started = time.monotonic()
    try:
        with (directory/'tests.log').open('w') as file:
            result = unittest.TextTestRunner(stream=file, verbosity=2).run(unittest.TestSuite([case]))
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
    samples = getattr(case, 'tool_samples', [])
    summary = {'status': 'VERIFIED' if result.wasSuccessful() and len(samples)==2 else 'FAILED',
        'tests_run': result.testsRun, 'errors': len(result.errors), 'failures': len(result.failures),
        'elapsed_seconds': time.monotonic()-started, 'samples': samples, 'runtime_records': len(records),
        'image': os.environ['WORKER_TEST_IMAGE'], 'runtime': os.environ.get('WORKER_TEST_RUNTIME','docker'),
        'limits': ['Isolated synthetic targets; trusted test invocation, not owner controller/live acceptance.',
            'Tool wall interval includes subprocess creation, execution and output collection.',
            'CPU values are OS-reported waited-child user/system time, not container lifecycle or inference.',
            'One sample per tool; no p95, causal performance or actual Kali deployment claim.']}
    (directory/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k!='samples'}))
    return 0 if summary['status']=='VERIFIED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
