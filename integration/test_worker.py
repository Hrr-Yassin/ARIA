"""Opt-in worker lab. Creates only disposable containers and a private network.

ARIA_WORKER_INTEGRATION=1 WORKER_TEST_RUNTIME=podman WORKER_TEST_IMAGE=sha256:...
    .venv/bin/python -m unittest integration.test_worker -v
No existing database, VM, target network or ARIA configuration is used.
"""
import asyncio
import json
import os
import secrets
import subprocess
import time
import tempfile
import unittest
import uuid
from pathlib import Path

from sqlalchemy import text

from worker.policy import prepare
from worker.runtime import DockerRuntime
from worker.service import WorkerService
from worker.store import JobStore

ENABLED = os.environ.get('ARIA_WORKER_INTEGRATION') == '1'
SERVER = """
import http.server, threading, time
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/slow': time.sleep(60)
        self.send_response(200); self.end_headers(); self.wfile.write(b'aria worker target')
    def do_HEAD(self):
        self.send_response(200); self.end_headers()
    def log_message(self, *args): pass
for port in (8080, 8081):
    threading.Thread(target=http.server.ThreadingHTTPServer(('0.0.0.0', port), Handler).serve_forever, daemon=True).start()
threading.Event().wait()
"""


@unittest.skipUnless(ENABLED, 'set ARIA_WORKER_INTEGRATION=1 for disposable container tests')
class WorkerLab(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def cli(cls, *args, input=None):
        completed = subprocess.run([cls.executable, *args], input=input, capture_output=True, timeout=60)
        if completed.returncode:
            raise RuntimeError('Disposable lab command failed: ' + completed.stderr.decode(errors='replace')[-1000:])
        return completed.stdout.decode().strip()

    @classmethod
    def setUpClass(cls):
        cls.executable = os.environ.get('WORKER_TEST_RUNTIME', 'docker')
        cls.image = os.environ['WORKER_TEST_IMAGE']
        # Validate executable/image before passing either to a subprocess.
        DockerRuntime(cls.image, executable=cls.executable)
        cls.prefix = 'aria-worker-test-' + uuid.uuid4().hex[:10]
        cls.network = cls.prefix + '-net'
        cls.containers = []
        cls.addClassCleanup(cls.cleanup)
        cls.cli('network', 'create', '--internal', cls.network)
        password = secrets.token_hex(24)
        pg = cls.prefix + '-pg'
        cls.containers.append(pg)
        cls.cli('run', '-d', '--name', pg, '--network', cls.network,
                '-p', '127.0.0.1::5432', '-e', 'POSTGRES_PASSWORD=' + password,
                '-e', 'POSTGRES_DB=aria_worker_test', 'docker.io/library/postgres:16.6')
        for _ in range(60):
            result = subprocess.run([cls.executable, 'exec', pg, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True)
            if result.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Disposable PostgreSQL did not become ready')
        schema = (Path(__file__).resolve().parents[1] / 'worker/schema.sql').read_bytes()
        cls.cli('exec', '-i', pg, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'aria_worker_test', input=schema)
        port = int(cls.cli('port', pg, '5432/tcp').splitlines()[0].rsplit(':', 1)[1])
        cls.url = f'postgresql+asyncpg://postgres:{password}@127.0.0.1:{port}/aria_worker_test'
        cls.addresses = []
        for suffix in ('allowed', 'denied'):
            name = cls.prefix + '-' + suffix
            cls.containers.append(name)
            cls.cli('run', '-d', '--name', name, '--network', cls.network,
                '--read-only', '--cap-drop=ALL', '--user=65534', '--memory=128m',
                '--pids-limit=32', '--entrypoint=/usr/local/bin/python', cls.image, '-u', '-c', SERVER)
            info = json.loads(cls.cli('inspect', name))[0]
            cls.addresses.append(info['NetworkSettings']['Networks'][cls.network]['IPAddress'])
        # Positive control: the same network can reach BOTH servers/ports before
        # the restricted job installs its firewall. A dead target cannot produce
        # a false-positive network-denial result.
        probe = 'import socket; [socket.create_connection((ip, port), timeout=1).close() for ip in ' + repr(cls.addresses) + ' for port in (8080, 8081)]'
        for _ in range(20):
            try:
                cls.cli('exec', cls.containers[-2], '/usr/local/bin/python', '-c', probe)
                break
            except RuntimeError:
                time.sleep(.25)
        else:
            raise RuntimeError('Disposable target reachability control failed')

    @classmethod
    def cleanup(cls):
        for name in reversed(cls.containers):
            subprocess.run([cls.executable, 'rm', '-f', '-v', name], capture_output=True)
        subprocess.run([cls.executable, 'network', 'rm', cls.network], capture_output=True)

    async def asyncSetUp(self):
        self.store = JobStore(self.url)
        self.addAsyncCleanup(self.close_store)
        await self.store.open()
        self.runtime = DockerRuntime(self.image, self.network, self.executable)
        await self.runtime.check()
        self.service = WorkerService(self.store, self.runtime, [self.addresses[0] + '/32'], [8080])
        await self.service.recover()

    async def close_store(self):
        await self.store.close()

    async def asyncTearDown(self):
        try:
            await self.service.recover()
        finally:
            await self.store.close()

    def job(self, **changes):
        return {'job_id': str(uuid.uuid4()), 'session_id': str(uuid.uuid4()),
                'command': 'curl -s http://' + self.addresses[0] + ':8080',
                'scope': {'targets': [self.addresses[0]], 'ports': [8080]}, 'timeout': 20, **changes}

    async def finished(self, job, timeout=30):
        async with asyncio.timeout(timeout):
            while True:
                result = await self.service.status(job['job_id'])
                if result['state'] in {'succeeded', 'failed', 'cancelled'}:
                    return result
                await asyncio.sleep(.1)

    async def test_real_http_nmap_and_persistent_idempotency(self):
        job = self.job()
        first, duplicate = await asyncio.gather(self.service.submit(job), self.service.submit(job))
        self.assertEqual(first, duplicate)
        result = await self.finished(job)
        self.assertEqual(result['state'], 'succeeded', result)
        self.assertIn('aria worker target', result['stdout'])
        await self.store.close()
        self.store = JobStore(self.url)
        await self.store.open()
        self.service = WorkerService(self.store, self.runtime, [self.addresses[0] + '/32'], [8080])
        self.assertEqual(await self.service.submit(job), result)
        self.assertIsNone(await self.runtime.inspect(job))
        nmap = self.job(command='nmap -p 8080 ' + self.addresses[0])
        await self.service.submit(nmap)
        result = await self.finished(nmap)
        self.assertEqual(result['state'], 'succeeded', result)
        self.assertIn('8080/tcp open', result['stdout'])

    async def test_kernel_network_boundary_and_privilege_drop(self):
        # Trusted test fixture deliberately bypasses tool adapters to probe the
        # actual kernel boundary independently of command validation.
        code = """
import socket, os, json, faulthandler
faulthandler.dump_traceback_later(5, exit=True)
from pathlib import Path
def connects(host, port):
    try:
        s = socket.create_connection((host, port), timeout=.7); s.close(); return True
    except OSError: return False
result = {'uid': os.getuid(), 'allowed': connects(ALLOWED, 8080),
          'denied_ip': connects(DENIED, 8080), 'denied_port': connects(ALLOWED, 8081),
          'pinned': socket.gethostbyname('pinned.test')}
status = Path('/proc/self/status').read_text()
result['caps_clear'] = 'CapEff:\t0000000000000000' in status
result['no_new_privs'] = 'NoNewPrivs:\t1' in status
try:
    Path('/opt/aria/forbidden').write_text('x'); result['root_write'] = True
except OSError: result['root_write'] = False
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); result['raw_socket'] = True
except OSError: result['raw_socket'] = False
print(json.dumps(result), flush=True)
""".replace('ALLOWED', repr(self.addresses[0])).replace('DENIED', repr(self.addresses[1]))
        async def probe(*args):
            return {'argv': ['/usr/local/bin/python', '-c', code], 'hosts': {'pinned.test': [self.addresses[0]]},
                    'networks': [self.addresses[0] + '/32'], 'ports': [8080]}
        self.service.planner = probe
        inspect = self.runtime.inspect
        transitions = []
        async def observed(job):
            state = await inspect(job)
            transitions.append(None if state is None else {key: state.get(key) for key in ('Status', 'Running', 'ExitCode', 'Error')})
            return state
        self.runtime.inspect = observed
        for attempt in range(5):
            transitions.clear()
            job = self.job()
            await self.service.submit(job)
            result = await self.finished(job)
            self.assertEqual(result['state'], 'succeeded', {'result': result, 'transitions': transitions})
            evidence = json.loads(result['stdout'])
            self.assertEqual(evidence, {'uid': 65534, 'allowed': True, 'denied_ip': False,
                'denied_port': False, 'pinned': self.addresses[0], 'caps_clear': True,
                'no_new_privs': True, 'root_write': False, 'raw_socket': False})

    async def test_cancellation_kills_descendants_and_recovery_never_replays(self):
        async def sleeper(*args):
            return {'argv': ['/usr/local/bin/python', '-u', '-c',
                'import subprocess,time; subprocess.Popen(["/usr/local/bin/python","-c","import time; time.sleep(60)"],start_new_session=True); print("descendant started",flush=True); time.sleep(60)'],
                'hosts': {}, 'networks': [self.addresses[0] + '/32'], 'ports': [8080]}
        self.service.planner = sleeper
        job = self.job()
        await self.service.submit(job)
        async with asyncio.timeout(10):
            while 'descendant started' not in (await self.runtime.output(job))[0]:
                await asyncio.sleep(.1)
        result = await self.service.cancel(job['job_id'], job['session_id'])
        self.assertEqual(result['state'], 'cancelled', result)
        self.assertTrue(result['terminated'])
        self.assertIsNone(await self.runtime.inspect(job))
        orphan = self.job()
        await self.service.submit(orphan)
        await self.store.close()
        self.store = JobStore(self.url)
        await self.store.open()
        self.service = WorkerService(self.store, self.runtime, [self.addresses[0] + '/32'], [8080])
        await self.service.recover()
        self.assertEqual((await self.service.submit(orphan))['state'], 'cancelled')
        self.assertIsNone(await self.runtime.inspect(orphan))

    async def test_deadline_works_without_controller_polling(self):
        async def sleeper(*args):
            return {'argv': ['/usr/local/bin/python', '-c', 'import time; time.sleep(60)'],
                    'hosts': {}, 'networks': [self.addresses[0] + '/32'], 'ports': [8080]}
        self.service.planner = sleeper
        job = self.job(timeout=3)
        await self.service.submit(job)
        await asyncio.sleep(4)
        state = await self.runtime.inspect(job)
        self.assertFalse(state['Running'])
        self.assertEqual(state['ExitCode'], 124)
        result = await self.service.status(job['job_id'])
        self.assertEqual(result['state'], 'cancelled')
        self.assertTrue(result['terminated'])

    async def test_database_single_owner_and_changed_id_payload(self):
        other = JobStore(self.url)
        try:
            with self.assertRaises(RuntimeError):
                await other.open()
        finally:
            await other.close()
        job = self.job()
        await self.service.submit(job)
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            await self.service.submit({**job, 'timeout': 10})

    async def test_worker_api_lifespan_with_real_storage_and_containers(self):
        import httpx
        from unittest.mock import patch
        from worker.app import create_app
        await self.store.close()
        try:
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'KALI_AGENT_TOKEN': secrets.token_hex(32), 'WORKER_DATABASE_URL': self.url,
                'WORKER_IMAGE': self.image, 'WORKER_RUNTIME': self.executable,
                'WORKER_NETWORK': self.network, 'WORKER_STATE_DIR': directory,
                'WORKER_ALLOWED_NETWORKS': json.dumps([self.addresses[0] + '/32']),
                'WORKER_ALLOWED_PORTS': '[8080]'}):
                app = create_app()
                async with app.router.lifespan_context(app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://worker') as client:
                        self.assertEqual((await client.get('/capabilities')).status_code, 401)
                        client.headers['Authorization'] = 'Bearer ' + os.environ['KALI_AGENT_TOKEN']
                        self.assertTrue((await client.get('/capabilities')).json()['network_scope'])
                        job = self.job()
                        response = await client.post('/jobs', json=job)
                        self.assertEqual(response.status_code, 200, response.text)
                        async with asyncio.timeout(30):
                            while True:
                                result = (await client.get('/jobs/' + job['job_id'])).json()
                                if result['state'] in {'succeeded', 'failed', 'cancelled'}:
                                    break
                                await asyncio.sleep(.1)
                        self.assertEqual(result['state'], 'succeeded', result)
                        self.assertIn('aria worker target', result['stdout'])
        finally:
            self.store = JobStore(self.url)
            await self.store.open()
            self.service = WorkerService(self.store, self.runtime, [self.addresses[0] + '/32'], [8080])

    async def test_lost_database_ownership_denies_dispatch(self):
        from sqlalchemy.exc import DBAPIError
        async with self.store.engine.connect() as conn:
            await conn.execute(text('SELECT pg_terminate_backend(:pid)'), {'pid': self.store.backend_pid})
            await conn.commit()
        job = self.job()
        with self.assertRaises((RuntimeError, DBAPIError)):
            await self.service.submit(job)
        self.assertIsNone(await self.runtime.inspect(job))
