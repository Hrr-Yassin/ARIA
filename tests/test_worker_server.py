"""Worker policy and server regressions; no containers or networks required."""
import asyncio
import copy
import json
import time
import tempfile
import unittest
import uuid
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import HTTPException

from worker.app import create_app
from worker.policy import firewall, prepare
from worker.runtime import DockerRuntime
from worker.service import TERMINAL, WorkerService


def request(**changes):
    return {'job_id': str(uuid.uuid4()), 'session_id': str(uuid.uuid4()),
            'command': 'curl -I http://192.0.2.1:8080', 'timeout': 20,
            'scope': {'targets': ['192.0.2.1'], 'ports': [8080]}, **changes}


class MemoryStore:
    def __init__(self):
        self.rows = {}
        self.fail = False

    async def get(self, job_id):
        return copy.deepcopy(self.rows.get(job_id))

    async def save(self, job):
        if self.fail:
            raise RuntimeError('Storage unavailable')
        self.rows[job['job_id']] = copy.deepcopy(job)

    async def active(self):
        return [copy.deepcopy(job) for job in self.rows.values() if job['state'] not in TERMINAL]


class FakeRuntime:
    def __init__(self):
        self.jobs = {}
        self.creates = 0
        self.unavailable = False

    async def create(self, job):
        self.creates += 1
        self.jobs[job['job_id']] = {'Status': 'created', 'Running': False, 'ExitCode': 0}

    async def start(self, job):
        self.jobs[job['job_id']].update(Status='running', Running=True)

    async def inspect(self, job):
        return self.jobs.get(job['job_id'])

    async def stop(self, job):
        if self.unavailable:
            raise RuntimeError('Daemon unavailable')
        self.jobs.pop(job['job_id'], None)
        return True

    async def output(self, job):
        return 'tool output', ''


class WorkerServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store, self.runtime = MemoryStore(), FakeRuntime()
        self.service = WorkerService(self.store, self.runtime, ['192.0.2.0/24'], [8080, 443])
        self.token = 'ephemeral-worker-token-for-offline-tests'
        self.app = create_app(self.service, self.token)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url='http://worker')
        self.client.headers['Authorization'] = 'Bearer ' + self.token

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_authentication_all_routes_and_request_bounds(self):
        job = request()
        self.client.headers.clear()
        for method, path, data in [('GET', '/capabilities', None), ('POST', '/jobs', job),
                ('GET', '/jobs/' + job['job_id'], None),
                ('POST', '/jobs/' + job['job_id'] + '/cancel', {'session_id': job['session_id']})]:
            self.assertEqual((await self.client.request(method, path, json=data)).status_code, 401)
        self.client.headers['Authorization'] = 'Bearer ' + self.token
        self.assertTrue((await self.client.get('/capabilities')).json()['network_scope'])
        self.assertEqual((await self.client.post('/jobs', content=b'x' * 16385)).status_code, 413)
        for change in [{'job_id': '../escape'}, {'timeout': True}, {'timeout': 301}, {'scope': None}]:
            self.assertEqual((await self.client.post('/jobs', json={**job, **change})).status_code, 422)
        self.assertEqual(self.runtime.creates, 0)

    async def test_duplicate_and_changed_payload_across_controller_restart(self):
        job = request()
        first, second = await asyncio.gather(self.service.submit(job), self.service.submit(job))
        self.assertEqual(first, second)
        self.assertEqual(self.runtime.creates, 1)
        for change in [{'command': 'curl -I http://192.0.2.2:8080'}, {'timeout': 10},
                       {'session_id': str(uuid.uuid4())}, {'scope': {'targets': ['192.0.2.2']}}]:
            with self.assertRaises(HTTPException) as error:
                await self.service.submit({**job, **change})
            self.assertEqual(error.exception.status_code, 409)
        restored = WorkerService(self.store, self.runtime, ['192.0.2.0/24'], [8080])
        await restored.recover()
        self.assertEqual((await restored.submit(job))['state'], 'cancelled')
        self.assertEqual(self.runtime.creates, 1)

    async def test_cancel_before_submit_is_a_durable_tombstone(self):
        job = request()
        result = await self.service.cancel(job['job_id'], job['session_id'])
        self.assertTrue(result['terminated'])
        with self.assertRaises(HTTPException):
            await self.service.submit(job)
        self.assertEqual(self.runtime.creates, 0)

    async def test_unconfirmed_cancellation_survives_restart_and_wrong_session_denied(self):
        job = request()
        await self.service.submit(job)
        with self.assertRaises(HTTPException):
            await self.service.cancel(job['job_id'], str(uuid.uuid4()))
        self.runtime.unavailable = True
        result = await self.service.cancel(job['job_id'], job['session_id'])
        self.assertEqual(result['state'], 'cancel_requested')
        self.assertNotIn('terminated', result)
        await self.service.recover()
        self.assertEqual((await self.store.get(job['job_id']))['state'], 'cancel_requested')
        self.runtime.unavailable = False
        await self.service.recover()
        self.assertEqual((await self.store.get(job['job_id']))['state'], 'cancelled')

    async def test_storage_failure_denies_container_creation_and_capacity_is_bounded(self):
        self.store.fail = True
        with self.assertRaises(RuntimeError):
            await self.service.submit(request())
        self.assertEqual(self.runtime.creates, 0)
        self.store.fail = False
        self.service.max_jobs = 1
        await self.service.submit(request())
        with self.assertRaises(HTTPException) as error:
            await self.service.submit(request())
        self.assertEqual(error.exception.status_code, 429)
        self.assertEqual(self.runtime.creates, 1)

    async def test_completion_and_deadline_never_claim_unconfirmed_termination(self):
        job = request()
        await self.service.submit(job)
        self.runtime.jobs[job['job_id']].update(Status='exited', Running=False)
        result = await self.service.status(job['job_id'])
        self.assertEqual((result['state'], result['stdout'], result['exit_code']), ('succeeded', 'tool output', 0))
        self.assertNotIn(job['job_id'], self.runtime.jobs)
        later = request()
        await self.service.submit(later)
        self.store.rows[later['job_id']]['deadline'] = time.time() - 1
        self.runtime.unavailable = True
        self.assertEqual((await self.service.status(later['job_id']))['state'], 'cancel_requested')

    async def test_scope_ceiling_dns_pinning_exclusions_and_ipv6(self):
        resolver = AsyncMock(return_value=['192.0.2.1'])
        plan = await prepare('curl -I https://lab.example', {'targets': ['lab.example']},
                             ['192.0.2.0/24'], [443], resolver)
        self.assertEqual(plan['hosts'], {'lab.example': ['192.0.2.1']})
        self.assertEqual(plan['networks'], ['192.0.2.1/32'])
        resolver.return_value = ['192.0.2.1', '198.51.100.1']
        with self.assertRaises(ValueError):
            await prepare('curl -I https://lab.example', {'targets': ['lab.example']},
                          ['192.0.2.0/24'], [443], resolver)
        resolver.return_value = ['192.0.2.1']
        with self.assertRaises(ValueError):
            await prepare('curl -I https://lab.example', {'targets': ['lab.example'], 'exclusions': ['192.0.2.1']},
                          ['192.0.2.0/24'], [443], resolver)
        ipv6 = await prepare('curl -I https://[2001:db8::1]', {'targets': ['2001:db8::1']}, ['2001:db8::/64'], [443])
        self.assertIn('ip6 daddr 2001:db8::1/128', firewall(ipv6))

    async def test_unknown_tools_raw_scans_shell_and_empty_scope_are_denied(self):
        for command, scope in [('sh -c id', {'targets': ['192.0.2.1']}),
                ('nmap -sS 192.0.2.1', {'targets': ['192.0.2.1']}),
                ('nmap --script banner 192.0.2.1', {'targets': ['192.0.2.1']}),
                ('curl http://192.0.2.1; id', {'targets': ['192.0.2.1']}),
                ('curl http://192.0.2.1', {}),
                ('curl http://192.0.2.1', {'targets': ['192.0.2.1'], 'ports': [22]})]:
            with self.assertRaises(ValueError, msg=command):
                await prepare(command, scope, ['192.0.2.0/24'], [8080])
        plan = await prepare('nmap -p 8080 192.0.2.1', {'targets': ['192.0.2.1']}, ['192.0.2.0/24'], [8080])
        self.assertEqual(plan['argv'][1:4], ['-sT', '-Pn', '-n'])
        rules = firewall(plan)
        self.assertIn('policy drop', rules)
        self.assertNotIn('udp', rules)
        self.assertNotIn('iifname', rules)

    async def test_runtime_uses_restricted_container_and_never_a_shell(self):
        runtime = DockerRuntime('sha256:' + 'a' * 64)
        runtime.cli = AsyncMock(return_value=(0, b'', b''))
        job = {**request(), 'deadline': time.time() + 20,
               'plan': {'argv': ['curl', '-I', 'http://192.0.2.1'], 'networks': ['192.0.2.1/32'], 'ports': [80], 'hosts': {}}}
        await runtime.create(job)
        args = runtime.cli.call_args.args
        for flag in ['--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges=true', '--pids-limit=64', '--restart=no']:
            self.assertIn(flag, args)
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--volume', args)
        with self.assertRaises(ValueError):
            DockerRuntime('mutable:latest')
        with self.assertRaises(ValueError):
            DockerRuntime('sha256:' + 'a' * 64, 'host')

    async def test_runtime_cannot_confirm_cancellation_on_inspection_failure(self):
        runtime = DockerRuntime('sha256:' + 'a' * 64)
        runtime.cli = AsyncMock(return_value=(1, b'', b'daemon unavailable'))
        with self.assertRaises(RuntimeError):
            await runtime.stop(request())

    async def test_aria_client_sends_authoritative_scope_and_rejects_old_capabilities(self):
        from memory.worker_jobs import WorkerClient, WorkerJobs
        from tests.test_p1_workers import MemoryJobs
        captured = []
        async def handler(req):
            if req.url.path == '/capabilities':
                return httpx.Response(200, json={'protocol': 'aria-jobs-v1', 'idempotency': True, 'cancellation': True, 'network_scope': True})
            data = json.loads(req.content)
            captured.append(data)
            return httpx.Response(200, json={**data, 'state': 'succeeded', 'exit_code': 0})
        scope = {'targets': ['192.0.2.1'], 'ports': [8080]}
        context = AsyncMock(return_value={'scope': scope})
        client = WorkerClient(httpx.MockTransport(handler))
        with patch('memory.worker_jobs.settings.KALI_AGENT_URL', 'http://worker'), patch('memory.worker_jobs.settings.KALI_WORKER_PROTOCOL', 'jobs-v1'):
            jobs = WorkerJobs(MemoryJobs(), client)
            await jobs.execute('j', 'alice', 'a', 'curl http://192.0.2.1:8080', 10, authorization_check=context)
        self.assertEqual(captured[0]['scope'], scope)
        old = WorkerClient(httpx.MockTransport(lambda req: httpx.Response(200, json={
            'protocol': 'aria-jobs-v1', 'idempotency': True, 'cancellation': True})))
        with patch('memory.worker_jobs.settings.KALI_AGENT_URL', 'http://worker'):
            with self.assertRaises(ValueError):
                await old.capabilities()

    async def test_controller_file_lock_and_rejected_start_are_not_replayed(self):
        from worker.ownership import ControllerLock
        with tempfile.TemporaryDirectory() as directory:
            first, second = ControllerLock(directory), ControllerLock(directory)
            first.open()
            try:
                with self.assertRaises(RuntimeError):
                    second.open()
            finally:
                first.close()
            second.open()
            second.close()
        self.runtime.create = AsyncMock(side_effect=RuntimeError('Runtime rejected job'))
        job = request()
        result = await self.service.submit(job)
        self.assertEqual(result['state'], 'failed')
        self.assertTrue(result['terminated'])
        self.assertEqual(await self.service.submit(job), result)
        self.runtime.create.assert_awaited_once()

    async def test_unresolved_cancellation_blocks_new_jobs_for_same_session(self):
        job = request()
        await self.service.submit(job)
        self.runtime.unavailable = True
        await self.service.cancel(job['job_id'], job['session_id'])
        with self.assertRaises(HTTPException) as error:
            await self.service.submit(request(session_id=job['session_id']))
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(self.runtime.creates, 1)

    async def test_transitional_runtime_states_do_not_cancel_a_starting_job(self):
        job = request()
        await self.service.submit(job)
        for status in ['created', 'configured', 'stopping']:
            self.runtime.jobs[job['job_id']].update(Status=status, Running=False)
            self.assertEqual((await self.service.status(job['job_id']))['state'], 'running')
            self.assertIn(job['job_id'], self.runtime.jobs)
        self.runtime.jobs[job['job_id']].update(Status='exited', Running=False)
        result = await self.service.status(job['job_id'])
        self.assertEqual(result['state'], 'succeeded')
