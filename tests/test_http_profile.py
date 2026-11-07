"""Reviewed HTTP identity bindings and worker lifecycle without network traffic."""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch
import unittest

from cryptography.fernet import Fernet
from fastapi import HTTPException
from orchestrator.execution_policy import validate_command, PolicyError
from worker.http_profile import command_for, cipher, decode, prepare_http, public_receipt
from worker.service import WorkerService
from tests.test_worker_server import MemoryStore, FakeRuntime, request


class Store(MemoryStore):
    async def for_session(self, sid):
        return [job for job in self.rows.values() if job['session_id'] == sid]


class HttpProfile(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.key = Fernet.generate_key().decode()
        self.environment = patch.dict(os.environ, {'HTTP_REPLAY_KEY': self.key})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.spec = {'method': 'GET', 'url': 'http://192.0.2.1:8080/objects',
                     'headers': {'authorization': 'Bearer owned-account-secret'},
                     'expires_at': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}
        self.identity, self.capture = str(uuid.uuid4()), str(uuid.uuid4())
        self.command = command_for(self.identity, self.capture, self.spec)
        self.token = cipher().encrypt(json.dumps(self.spec).encode()).decode()
        self.scope = {'targets': ['192.0.2.1'], 'ports': [8080], 'web_authenticated_replay': True}

    async def test_profile_requires_explicit_permission_and_red_risk(self):
        checked = validate_command(self.command, self.scope)
        self.assertEqual(checked.risk, 'red')
        self.assertNotIn('owned-account-secret', self.command)
        self.assertEqual(decode(self.token, self.command), self.spec)
        for scope in [{**self.scope, 'web_authenticated_replay': False},
                      {**self.scope, 'targets': ['198.51.100.1']},
                      {**self.scope, 'program_policy': {'state': 'draft'}}]:
            with self.assertRaises(ValueError): validate_command(self.command, scope)

    async def test_payload_digest_method_identity_shape_and_expiry(self):
        for changes in [{'method': 'POST'}, {'url': self.spec['url'] + '?token=secret'},
                        {'url': 'http://elsewhere.test/'},
                        {'headers': {'host': 'elsewhere'}},
                        {'headers': {'authorization': 'Bearer x\r\nHost: elsewhere'}},
                        {'expires_at': '2000-01-01T00:00:00+00:00'}]:
            spec = {**self.spec, **changes}
            token = cipher().encrypt(json.dumps(spec).encode()).decode()
            with self.assertRaises(ValueError): decode(token, self.command)
            if 'headers' in changes or 'expires_at' in changes:
                with self.assertRaises(ValueError): decode(token, command_for(self.identity,self.capture,spec))

    async def test_worker_rechecks_network_ceiling_and_exact_port(self):
        with self.assertRaises(ValueError):
            await prepare_http(self.command,self.scope,['198.51.100.0/24'],[8080],self.token)
        with self.assertRaises(ValueError):
            await prepare_http(self.command,self.scope,['192.0.2.0/24'],[443],self.token)
        plan = await prepare_http(self.command,self.scope,['192.0.2.0/24'],[8080],self.token)
        self.assertEqual(plan['ports'], [8080])
        self.assertNotIn('owned-account-secret', json.dumps(plan))

    async def test_worker_duplicate_cancel_restart_and_budget(self):
        store, runtime = Store(), FakeRuntime()
        service = WorkerService(store,runtime,['192.0.2.0/24'],[8080])
        req = request(command=self.command,scope=self.scope,timeout=10,protected_http=self.token)
        first = await service.submit(req)
        self.assertEqual(await service.submit(req), first)
        self.assertEqual(runtime.creates,1)
        with self.assertRaises(HTTPException):
            await service.submit({**req,'job_id':str(uuid.uuid4())})
        with self.assertRaises(HTTPException):
            await service.submit({**req,'job_id':str(uuid.uuid4()),'command':'curl -I http://192.0.2.1:8080','protected_http':None})
        await service.recover()
        self.assertEqual((await service.submit(req))['state'],'cancelled')
        self.assertEqual(runtime.creates,1)
        with self.assertRaises(HTTPException):
            await service.submit({**req,'job_id':str(uuid.uuid4())})
        self.assertTrue(store.rows[req['job_id']]['overloaded'])

    async def test_invalid_ciphertext_and_storage_failure_never_create_runtime(self):
        store, runtime = Store(), FakeRuntime()
        service = WorkerService(store,runtime,['192.0.2.0/24'],[8080])
        req = request(command=self.command,scope=self.scope,timeout=10,protected_http='corrupted')
        with self.assertRaises(HTTPException): await service.submit(req)
        store.fail = True
        with self.assertRaises(RuntimeError): await service.submit({**req,'protected_http':self.token})
        self.assertEqual(runtime.creates,0)

    async def test_receipt_never_exposes_private_payload_or_unexpected_fields(self):
        raw = json.dumps({'profile':'aria-http-v1','status':200,'response_sha256':'a'*64,
                          'protected_response':'private-ciphertext','password':'private-secret'})
        self.assertNotIn('private',public_receipt(raw))
        self.assertNotIn('private',public_receipt('private malformed output'))

    async def test_retention_deadline_erases_terminal_private_worker_payloads(self):
        store, runtime = Store(), FakeRuntime()
        service = WorkerService(store,runtime,['192.0.2.0/24'],[8080])
        req = request(command=self.command,scope=self.scope,timeout=10,protected_http=self.token)
        await service.submit(req)
        result = await service.retention(req['job_id'],req['session_id'],'2000-01-01T00:00:00+00:00')
        self.assertTrue(result['expired'])
        job = await store.get(req['job_id'])
        self.assertEqual(job['state'],'cancelled')
        self.assertNotIn('protected_http',job)
        self.assertNotIn('protected_http',job['plan'])
        self.assertEqual(job['stdout'],'')
        with self.assertRaises(HTTPException):
            await service.retention(req['job_id'],str(uuid.uuid4()),'2000-01-01T00:00:00+00:00')

    async def test_private_key_mount_permissions_and_cleanup(self):
        import stat
        from worker.runtime import DockerRuntime
        runtime= DockerRuntime('sha256:'+'a'*64)
        runtime.cli=AsyncMock(return_value=(0,b'',b''))
        runtime.inspect=AsyncMock(return_value=None)
        job=request(plan={'hosts':{},'protected_http':self.token,'argv':[]},deadline=9999999999)
        original_umask=os.umask(0o077)
        try:
            await runtime.create(job)
        finally:
            os.umask(original_umask)
        try:
            directory=runtime.key_directory(job)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((directory/'key').stat().st_mode),0o444)
            self.assertNotIn(self.key,repr(runtime.cli.call_args))
        finally:
            await runtime.stop(job)
        self.assertFalse(directory.exists())

    async def test_timeout_and_credential_bearing_urls_fail_before_dispatch(self):
        store,runtime=Store(),FakeRuntime()
        service=WorkerService(store,runtime,['192.0.2.0/24'],[8080])
        with self.assertRaises(HTTPException):
            await service.submit(request(command=self.command,scope=self.scope,timeout=11,protected_http=self.token))
        self.assertEqual(runtime.creates,0)
        spec={**self.spec,'url':self.spec['url']+'/owned-account-secret'}
        token=cipher().encrypt(json.dumps(spec).encode()).decode()
        with self.assertRaises(ValueError):
            decode(token,command_for(self.identity,self.capture,spec))
