"""Agent -> authorization ledger -> jobs-v1 ASGI worker -> receipt -> parser.

Every runtime is mocked. These tests prove communication contracts, not installed
binaries or container isolation. All DNS, providers and model calls stay blocked.
"""
import asyncio
import copy
import json
import time
import uuid
from unittest.mock import AsyncMock, patch
import httpx
from fastapi import HTTPException

from tests.support import OfflineCase
from tests.test_tool_adapters import fixture, profile
from tests.test_execution import MemoryStore as AuthorizationStore
from tests.test_p1_workers import MemoryJobs
from tests.test_worker_server import MemoryStore, FakeRuntime
from security_tools.adapters import ADAPTERS, encode
from security_tools.service import ToolOperations
from memory.execution_authorization import ExecutionAuthorization
from memory.worker_jobs import WorkerJobs, WorkerClient
from worker.service import WorkerService
from worker.app import create_app


class WorkerStore(MemoryStore):
    async def for_session(self, session_id):
        return [copy.deepcopy(j) for j in self.rows.values() if j['session_id']==session_id]


class FixtureRuntime(FakeRuntime):
    def __init__(self, raw):
        super().__init__();self.raw=raw;self.complete=True
    async def start(self, job):
        await super().start(job)
        if self.complete:self.jobs[job['job_id']].update(Status='exited',Running=False)
    async def output(self, job):
        return self.raw,''


class AdapterContractTests(OfflineCase):
    async def setup_tool(self, name):
        data=fixture(name);self.data=data;self.sid=str(uuid.uuid4())
        self.runtime=FixtureRuntime(data['stdout']);self.worker_store=WorkerStore()
        self.worker=WorkerService(self.worker_store,self.runtime,['192.0.2.0/24'],[8080,443],profiles={name:profile(name)})
        self.remote=httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(self.worker,'fixture-token')),base_url='http://worker',headers={'Authorization':'Bearer fixture-token'})
        self.addAsyncCleanup(self.remote.aclose)
        self.sent=[]
        async def transport(req):
            if req.method=='POST' and req.url.path=='/jobs':self.sent.append(json.loads(req.content))
            response=await self.remote.request(req.method,req.url.path,content=req.content)
            return httpx.Response(response.status_code,json=response.json())
        async def context(user,session):
            if user!='owner' or session!=self.sid:raise HTTPException(403,'Denied')
            return {'scope':self.data['scope'],'owner_id':'owner'}
        self.jobs=WorkerJobs(MemoryJobs(),WorkerClient(httpx.MockTransport(transport)),context)
        self.authorizations=AuthorizationStore()
        self.auth=ExecutionAuthorization(self.authorizations,context)
        self.bridge=ToolOperations(self.auth,self.jobs)
        for p in (patch('config.settings.settings.KALI_AGENT_URL','http://worker'),
                  patch('config.settings.settings.KALI_WORKER_PROTOCOL','jobs-v1'),
                  patch('memory.execution_authorization.worker_jobs',self.jobs),
                  patch('worker.policy.resolve',AsyncMock(return_value=['192.0.2.1']))):
            p.start();self.addCleanup(p.stop)
        return data

    async def proposal(self):
        proposal=await self.bridge.propose('owner',self.sid,self.data['request'])
        if proposal['status']=='pending':await self.auth.decide('owner',self.sid,proposal['id'],'approve')
        return proposal

    async def test_profiles_default_to_unavailable(self):
        await self.setup_tool('httpx');self.worker.profiles={}
        view=(await self.remote.get('/capabilities')).json()
        self.assertEqual(view['typed_adapters'],{})
        proposal=await self.proposal()
        with self.assertRaises(HTTPException): await self.bridge.execute('owner',self.sid,self.data['request'],proposal['id'])
        self.assertEqual(self.runtime.creates,0)

    async def test_agent_cannot_use_custom_executor_or_legacy_transport(self):
        await self.setup_tool('httpx');proposal=await self.proposal()
        executor=AsyncMock()
        with self.assertRaises(HTTPException): await self.auth.execute('owner',self.sid,proposal['command'],action_id=proposal['id'],timeout=10,executor=executor)
        executor.assert_not_awaited()
        with patch('config.settings.settings.KALI_WORKER_PROTOCOL','legacy-execute'):
            with self.assertRaises(HTTPException): await self.auth.execute('owner',self.sid,proposal['command'],action_id=proposal['id'],timeout=10)
        self.assertEqual(self.runtime.creates,0)

    async def test_api_requires_identity_and_uses_typed_bridge(self):
        from api.main import app
        from api.auth import get_current_user
        from tests.test_access import OWNER
        await self.setup_tool('httpx')
        payload={'session_id':self.sid,'operation':self.data['request']}
        self.assertEqual((await self.client.post('/api/tool-operations/proposals',json=payload)).status_code,401)
        app.dependency_overrides[get_current_user]=lambda:OWNER
        self.addCleanup(app.dependency_overrides.clear)
        with patch('api.routers.tool_operations.tool_operations',self.bridge):
            response=await self.client.post('/api/tool-operations/proposals',json=payload)
            self.assertEqual(response.status_code,200)
            executed=await self.client.post('/api/tool-operations/execute',json={**payload,'action_id':response.json()['id']})
            self.assertEqual(executed.status_code,200)
            self.assertEqual(executed.json()['output']['error'],'none')
            denied=await self.client.post('/api/tool-operations/proposals',json={**payload,'session_id':'foreign'})
            self.assertEqual(denied.status_code,403)


def make_contract(name, check):
    async def test(self):
        data=await self.setup_tool(name)
        if check=='roundtrip':
            proposal=await self.proposal()
            result=await self.bridge.execute('owner',self.sid,data['request'],proposal['id'])
            self.assertEqual(result['state'],'succeeded',result)
            self.assertEqual(result['output']['error'],'none',result)
            self.assertEqual(len(result['output']['observations']),1)
            self.assertTrue(result['provenance']['receipt_verified'])
            self.assertIsNone(result['provenance']['tool_version'])
            self.assertEqual(self.sent[0]['scope'],data['scope'])
            self.assertEqual(self.runtime.creates,1)
            self.assertEqual(self.authorizations.records[proposal['id']].status,'consumed')
            with self.assertRaises(HTTPException):await self.bridge.execute('owner',self.sid,data['request'],proposal['id'])
            self.assertEqual(self.runtime.creates,1)
        elif check=='unauthorized':
            with self.assertRaises(HTTPException):await self.bridge.propose('intruder',self.sid,data['request'])
            proposal=await self.proposal()
            data['scope']['targets']=['198.51.100.1'];data['scope']['artifact_sha256']=[]
            with self.assertRaises(HTTPException):await self.bridge.execute('owner',self.sid,data['request'],proposal['id'])
            self.assertEqual(self.runtime.creates,0)
        elif check=='cancellation':
            command=encode(data['request']);jid=str(uuid.uuid4())
            job={'job_id':jid,'session_id':self.sid,'command':command,'scope':data['scope'],'timeout':ADAPTERS[name].timeout}
            self.runtime.complete=False
            await self.worker.submit(job)
            with self.assertRaises(HTTPException):await self.worker.cancel(jid,str(uuid.uuid4()))
            self.runtime.unavailable=True
            self.assertEqual((await self.worker.cancel(jid,self.sid))['state'],'cancel_requested')
            self.runtime.unavailable=False
            self.assertEqual((await self.worker.cancel(jid,self.sid))['state'],'cancelled')
            self.assertEqual((await self.worker.submit(job))['state'],'cancelled')
            self.assertEqual(self.runtime.creates,1)
        elif check=='malformed_receipt':
            proposal=await self.proposal();self.runtime.raw='{broken'
            result=await self.bridge.execute('owner',self.sid,data['request'],proposal['id'])
            self.assertEqual(result['output']['error'],'invalid_output')
            self.assertEqual(result['output']['observations'],[])
            # A verified receipt proves provenance, not a valid scanner result.
            self.assertTrue(result['provenance']['receipt_verified'])
            with self.assertRaises(HTTPException):await self.jobs.verify_receipt('owner',self.sid,proposal['id'],'tampered','',0)
        elif check=='worker_timeout':
            job={'job_id':str(uuid.uuid4()),'session_id':self.sid,'command':encode(data['request']),
                 'scope':data['scope'],'timeout':ADAPTERS[name].timeout}
            self.runtime.complete=False
            await self.worker.submit(job)
            self.worker_store.rows[job['job_id']]['deadline']=time.time()-1
            result=await self.worker.status(job['job_id'])
            self.assertEqual(result['state'],'cancelled')
            self.assertTrue(result['terminated'])
        elif check=='unavailable':
            self.worker.profiles={}
            job={'job_id':str(uuid.uuid4()),'session_id':self.sid,'command':encode(data['request']),
                 'scope':data['scope'],'timeout':ADAPTERS[name].timeout}
            with self.assertRaises(HTTPException):await self.worker.submit(job)
            self.assertEqual(self.runtime.creates,0)
    return test

for name in ADAPTERS:
    for check in ('roundtrip','unauthorized','cancellation','malformed_receipt','worker_timeout','unavailable'):
        setattr(AdapterContractTests,f'test_{name}_{check}',make_contract(name,check))

class AdapterReceiptTests(OfflineCase):
    setup_tool = AdapterContractTests.setup_tool
    # Keep extra cases separate from the generated per-tool matrix.
    async def test_attestation_binding_is_required_for_terminal_evidence(self):
        from security_tools.adapters import sha256,contract_digest
        await self.setup_tool('httpx')
        job={'job_id':'fixture-job','session_id':self.sid,'state':'running',
             'adapter_request_sha256':sha256(encode(self.data['request'])),
             'adapter_registry_sha256':contract_digest(),'adapter_capability':ADAPTERS['httpx'].capability}
        await self.jobs.store.create(job)
        stamp={'request_sha256':job['adapter_request_sha256'],'registry_sha256':contract_digest(),
               'capability':job['adapter_capability'],'image_id':'sha256:'+'c'*64,
               'declared_tool_version':'1.0.0','binary_sha256':'b'*64}
        receipt={'job_id':job['job_id'],'session_id':self.sid,'state':'succeeded','exit_code':0,'stdout':'fixture','stderr':'','adapter_attestation':stamp}
        for field in ('request_sha256','registry_sha256','capability'):
            changed={**receipt,'adapter_attestation':{**stamp,field:'d'*64}}
            with self.assertRaises(ValueError):await self.jobs.record_snapshot(job,changed)
            self.assertEqual((await self.jobs.store.get(job['job_id']))['state'],'running')
        await self.jobs.record_snapshot(job,receipt)
        self.assertTrue(await self.jobs.verify_receipt('owner',self.sid,job['job_id'],'fixture','',0))

    async def test_recovery_does_not_reparse_commands_under_changed_adapter_revision(self):
        await self.setup_tool('httpx');self.runtime.complete=False
        job={'job_id':str(uuid.uuid4()),'session_id':self.sid,'scope':self.data['scope'],
             'command':encode(self.data['request']),'timeout':15}
        await self.worker.submit(job)
        with patch('security_tools.adapters.contract_digest',return_value='f'*64):
            await self.worker.recover()
            restored=await self.worker.status(job['job_id'])
        self.assertEqual(restored['state'],'cancelled')
        self.assertEqual(self.runtime.creates,1)

    async def test_worker_admission_rate_concurrency_and_total_budget(self):
        await self.setup_tool('httpx');self.runtime.complete=False
        def job():return {'job_id':str(uuid.uuid4()),'session_id':self.sid,'scope':self.data['scope'],
                          'command':encode(self.data['request']),'timeout':15}
        first=job();await self.worker.submit(first)
        with self.assertRaises(HTTPException) as error:await self.worker.submit(job())
        self.assertEqual(error.exception.status_code,429)
        self.runtime.jobs[first['job_id']].update(Status='exited',Running=False)
        await self.worker.status(first['job_id'])
        with self.assertRaises(HTTPException) as error:await self.worker.submit(job())
        self.assertEqual(error.exception.status_code,429)
        self.worker_store.rows[first['job_id']]['admitted_at']=time.time()-5
        for index in range(19):
            record={**job(),'state':'succeeded','admitted_at':time.time()-5}
            await self.worker_store.save(record)
        with self.assertRaises(HTTPException) as error:await self.worker.submit(job())
        self.assertEqual(error.exception.status_code,429)
        self.assertEqual(self.runtime.creates,1)
