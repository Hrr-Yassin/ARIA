"""Worker diagnostics preserve mutex, cancellation and receipt contracts."""
import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from worker.observability import admission, runtime_stage
from worker.service import WorkerService
from tests.support import OfflineCase
from tests.test_worker_server import FakeRuntime, MemoryStore, request


class WorkerObservabilityTests(OfflineCase):
    async def test_wait_and_held_time_are_separate_and_lock_released_on_failure(self):
        for fail in (False, True):
            lock = asyncio.Lock()
            with self.subTest(fail=fail), patch('worker.observability.time',
                    SimpleNamespace(monotonic_ns=iter((0, 10_000_000, 30_000_000)).__next__)), \
                 patch('worker.observability.log') as log:
                try:
                    async with admission(lock, 'submit', job_id='job', session_id='session'):
                        self.assertTrue(lock.locked())
                        if fail:
                            raise ValueError('private-exception-sentinel')
                except ValueError:
                    pass
            record = json.loads(log.info.call_args.args[0])
            self.assertFalse(lock.locked())
            self.assertEqual((record['queue_wait_ms'], record['lock_held_ms']), (10, 20))
            self.assertEqual(record['outcome'], 'failed' if fail else 'returned')
            self.assertNotIn('private-', str(record))

    async def test_cancelled_mutex_wait_never_releases_another_tasks_lock(self):
        lock = asyncio.Lock()
        await lock.acquire()
        entered = asyncio.Event()
        clock = iter((0, 5_000_000))
        def tick():
            entered.set()
            return next(clock)
        async def waiting():
            async with admission(lock, 'status', job_id='job'):
                self.fail('Cancelled waiter acquired the mutex')
        with patch('worker.observability.time', SimpleNamespace(monotonic_ns=tick)), \
             patch('worker.observability.log') as log:
            task = asyncio.create_task(waiting())
            await entered.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(lock.locked())
        lock.release()
        record = json.loads(log.info.call_args.args[0])
        self.assertEqual(record['outcome'], 'cancelled')
        self.assertEqual(record['queue_wait_ms'], 5)
        self.assertIsNone(record['lock_held_ms'])

    async def test_runtime_observation_is_content_free_and_preserves_cancelled_error(self):
        for error in (None, ValueError('private-exception'), asyncio.CancelledError()):
            with self.subTest(error=type(error).__name__), \
                 patch('worker.observability.time', SimpleNamespace(monotonic_ns=iter((0, 0)).__next__)), \
                 patch('worker.observability.log') as log:
                job = {'job_id': 'job', 'session_id': 'session', 'command': 'private-command',
                       'plan': {'protected_http': 'private-credential'}}
                try:
                    with runtime_stage(job, 'stop'):
                        if error is not None:
                            raise error
                except BaseException as caught:
                    self.assertIs(caught, error)
            record = json.loads(log.info.call_args.args[0])
            self.assertEqual(record['duration_ms'], 0)
            self.assertNotIn('private-', str(record))
            self.assertEqual(record['outcome'], 'returned' if error is None else
                'cancelled' if isinstance(error, asyncio.CancelledError) else 'failed')

    async def test_normal_lifecycle_keeps_exact_receipt_and_does_not_repeat_runtime_calls(self):
        runtime = FakeRuntime()
        planner = AsyncMock(return_value={'hosts': {}})
        service = WorkerService(MemoryStore(), runtime, ['192.0.2.0/24'], [8080], planner=planner)
        req = request()
        with patch('worker.observability.log') as log:
            initial = await service.submit(req)
            self.assertEqual(await service.submit(req), initial)
            runtime.jobs[req['job_id']].update(Status='exited', Running=False, ExitCode=0)
            terminal = await service.status(req['job_id'])
        self.assertEqual(runtime.creates, 1)
        self.assertEqual(terminal['state'], 'succeeded')
        self.assertEqual(set(terminal), {'job_id', 'session_id', 'state', 'terminated', 'exit_code', 'stdout', 'stderr'})
        records = [json.loads(call.args[0]) for call in log.info.call_args_list]
        stages = [r['stage'] for r in records if r['event']=='worker_runtime_stage']
        self.assertEqual(stages, ['create', 'start', 'inspect', 'output', 'stop'])
        self.assertTrue(all(r['duration_ms'] >= 0 for r in records if 'duration_ms' in r))
        directory = os.environ.get('ARIA_RELIABILITY_ARTIFACT_DIR')
        if directory:
            (Path(directory)/'worker-runtime-fixtures.json').write_text(json.dumps({
                'clock': 'local_monotonic', 'runtime': 'in_memory_fixture',
                'actual_containers': 0, 'actual_tools': 0, 'records': records}, indent=2)+'\n')

    async def test_denied_admission_never_observes_unstarted_runtime(self):
        runtime = FakeRuntime()
        service = WorkerService(MemoryStore(), runtime, [], [], max_jobs=0)
        from fastapi import HTTPException
        with patch('worker.observability.log') as log, self.assertRaises(HTTPException):
            await service.submit(request())
        self.assertEqual(runtime.creates, 0)
        self.assertEqual(len(log.info.call_args_list), 1)
        self.assertEqual(json.loads(log.info.call_args.args[0])['event'], 'worker_service_admission')

    async def test_broken_diagnostic_sink_preserves_admission_and_cancellation(self):
        runtime = FakeRuntime()
        service = WorkerService(MemoryStore(), runtime, [], [], planner=AsyncMock(return_value={'hosts': {}}))
        req = request()
        with patch('worker.observability.log.info', side_effect=RuntimeError('sink unavailable')):
            await service.submit(req)
            stopped = await service.cancel(req['job_id'], req['session_id'])
        self.assertEqual(stopped['state'], 'cancelled')
        self.assertTrue(stopped['terminated'])
        self.assertEqual(runtime.creates, 1)
        self.assertFalse(service.lock.locked())
