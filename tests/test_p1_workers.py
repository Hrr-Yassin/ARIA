import asyncio
import copy
from unittest.mock import AsyncMock, patch
import httpx
from fastapi import HTTPException
from memory.worker_jobs import WorkerJobs, WorkerClient, TERMINAL
from agents.autonomous_engine import AutonomousEngine, SessionRunState
from tests.support import OfflineCase


class MemoryJobs:
    def __init__(self):self.rows={};self.fenced=set();self.epochs={};self.lock=asyncio.Lock()
    async def create(self,job):
        async with self.lock:
            if job['session_id'] in self.fenced:raise HTTPException(409,'Fenced')
            if job['job_id'] in self.rows:raise ValueError('Duplicate job')
            if any(j['session_id']==job['session_id'] and (j['state'] in {'unknown','cancel_requested'} or j.get('cancel_requested')) for j in self.rows.values()):
                raise HTTPException(409,'Unresolved cancellation')
            self.rows[job['job_id']]=copy.deepcopy(job)
    async def fence(self,sid,resume=False):
        async with self.lock:
            if resume:
                if sid in self.fenced and any(j['session_id']==sid and j['state'] not in TERMINAL for j in self.rows.values()):
                    raise HTTPException(409,'Unresolved')
                self.fenced.discard(sid)
            else:
                self.fenced.add(sid);self.epochs[sid]=self.epochs.get(sid,0)+1
    async def get(self,jid):return copy.deepcopy(self.rows.get(jid))
    async def update(self,jid,values,expected=None):
        async with self.lock:
            row=self.rows[jid]
            if expected is None or row['state'] in expected:row.update(values,revision=row.get('revision',0)+1)
            return copy.deepcopy(row)
    async def list(self,sid=None):return [copy.deepcopy(j) for j in self.rows.values() if sid is None or j['session_id']==sid]


class MockWorker:
    def __init__(self):
        self.started=asyncio.Event();self.release=asyncio.Event();self.submits=0;self.cancels=0;self.ack=True
    async def capabilities(self):return {'tools':['inert']}
    async def submit(self,job,command,timeout):
        self.submits+=1;self.started.set()
        return {'job_id':job['job_id'],'session_id':job['session_id'],'state':'running'}
    async def status(self,job):
        await self.release.wait()
        return {'job_id':job['job_id'],'session_id':job['session_id'],'state':'succeeded','exit_code':0,'stdout':'mock'}
    async def cancel(self,job):
        self.cancels+=1
        if not self.ack:raise RuntimeError('unavailable')
        return {'job_id':job['job_id'],'session_id':job['session_id'],'state':'cancelled','terminated':True}


class WorkerTests(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.url=patch('memory.worker_jobs.settings.KALI_AGENT_URL','http://worker.invalid');self.url.start()
        self.store=MemoryJobs();self.worker=MockWorker()
        async def context(uid,sid):
            if uid!='alice' or sid!='a':raise HTTPException(403,'Denied')
            return {'owner_id':'alice'}
        self.jobs=WorkerJobs(self.store,self.worker,context)
    async def asyncTearDown(self):
        self.url.stop();await super().asyncTearDown()

    async def test_unadvertised_tool_never_dispatches(self):
        self.worker.capabilities = AsyncMock(return_value={'tools': ['curl']})
        with self.assertRaises(HTTPException) as error:
            await self.jobs.execute('job1', 'alice', 'a', 'inert mock command', 10)
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(self.worker.submits, 0)

    async def test_autonomous_goal_blocks_missing_or_malformed_capabilities(self):
        engine = AutonomousEngine()
        context = {'owner_id': 'alice', 'scope': {'targets': ['192.0.2.1']}, 'auth_revision': 0}
        for caps, reason in [({'tools': ['curl']}, 'capability_unavailable'),
                             ({'tools': 'curl,nmap'}, 'worker_unavailable')]:
            with self.subTest(caps=caps), \
                 patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value=context)), \
                 patch('agents.autonomous_engine.worker_jobs.client.capabilities', AsyncMock(return_value=caps)), \
                 patch.object(engine, '_run_loop', AsyncMock()) as run:
                result = await engine.start('a', 'alice', goal='discovery')
                self.assertEqual(result['reason_code'], reason)
                run.assert_not_awaited()
                engine._runs.pop('a', None)

    async def test_cancel_requires_owner_and_acknowledgement_under_race(self):
        task=asyncio.create_task(self.jobs.execute('job1','alice','a','inert mock command',10))
        await self.worker.started.wait()
        with self.assertRaises(HTTPException):await self.jobs.cancel_session('bob','a')
        self.assertEqual(self.worker.cancels,0)
        result=await self.jobs.cancel_session('alice','a')
        self.assertEqual((result['cancelled'],result['pending']),(1,0))
        self.worker.release.set()
        final=await task
        self.assertEqual(final['status'],'cancelled');self.assertEqual(final['exit_code'],-1)
        self.assertEqual(self.worker.submits,1)

    async def test_disconnect_unknown_state_survives_restart_and_blocks_new_jobs(self):
        self.worker.ack=False
        task=asyncio.create_task(self.jobs.execute('job1','alice','a','inert mock command',10))
        await self.worker.started.wait();task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual((await self.store.get('job1'))['state'],'unknown')
        with self.assertRaises(HTTPException):await self.jobs.execute('job2','alice','a','inert mock command',10)
        restored=WorkerJobs(self.store,MockWorker(),self.jobs.context_loader)
        result=await restored.recover()
        self.assertEqual(result[0]['state'],'cancelled')
        self.assertEqual(restored.client.submits,0)
        self.assertEqual(self.worker.submits,1)
        with self.assertRaises(HTTPException):await restored.status('bob','a','job1')

    async def test_deadline_cancels_remote_job_and_never_claims_success(self):
        with self.assertRaises(HTTPException) as error:
            await self.jobs.execute('job1','alice','a','inert mock command',0)
        self.assertEqual(error.exception.status_code,504)
        self.assertEqual((await self.store.get('job1'))['state'],'cancelled')
        self.assertEqual(self.worker.cancels,1)

    async def test_recovery_cancels_prepared_job_without_dispatch(self):
        await self.store.create({'job_id':'job1','session_id':'a','user_id':'alice','state':'prepared','endpoint':'http://worker.invalid','revision':0})
        result=await self.jobs.recover()
        self.assertEqual(result[0]['state'],'cancelled')
        self.assertEqual(self.worker.submits,0);self.assertEqual(self.worker.cancels,0)

    async def test_worker_contract_rejects_wrong_session_and_unconfirmed_termination(self):
        job={'job_id':'j','session_id':'a'}
        for data in [{'job_id':'j','session_id':'b','state':'running'},
                     {'job_id':'j','session_id':'a','state':'cancelled','terminated':False}]:
            with self.assertRaises(ValueError):WorkerClient.snapshot(data,job)
        seen=[]
        async def handler(request):
            seen.append(request)
            if request.url.path=='/capabilities':return httpx.Response(200,json={'protocol':'aria-jobs-v1','idempotency':True,'cancellation':True,'network_scope':True})
            return httpx.Response(200,json={'job_id':'j','session_id':'a','state':'running'})
        client=WorkerClient(httpx.MockTransport(handler))
        await client.capabilities();await client.submit(job,'inert mock command',10)
        self.assertEqual([r.url.path for r in seen],['/capabilities','/jobs'])
        self.assertTrue(all('Authorization' in r.headers for r in seen))

    async def test_same_target_events_and_subscribers_are_isolated(self):
        engine=AutonomousEngine()
        a=SessionRunState('a','alice','goal','192.0.2.1','expert');b=SessionRunState('b','bob','goal','192.0.2.1','expert')
        engine._runs={'a':a,'b':b}
        await engine._on_replan_event({'host':'192.0.2.1'},session_id='b',run_id=b.run_id)
        self.assertEqual(a.activity_log,[]);self.assertEqual(len(b.activity_log),1)
        one=engine.stream_events('a');two=engine.stream_events('a')
        t1=asyncio.create_task(anext(one));t2=asyncio.create_task(anext(two));await asyncio.sleep(0)
        await engine._emit(a,{'type':'test'})
        self.assertEqual(await t1,await t2)
        await one.aclose();await two.aclose()

    async def test_concurrent_start_stop_and_restart_own_their_tasks(self):
        engine=AutonomousEngine();entered=asyncio.Event()
        async def run(state):
            try:entered.set();await asyncio.Event().wait()
            finally:state.active=False
        context={'owner_id':'alice','scope':{'targets':['192.0.2.1']},'auth_revision':0}
        with patch('agents.autonomous_engine.execution_authorization._context',AsyncMock(return_value=context)), \
             patch('agents.autonomous_engine.worker_jobs.client.capabilities',AsyncMock(return_value={'tools':['curl','nmap']})), \
             patch.object(engine,'_write_decision_log',AsyncMock()),patch.object(engine,'_run_loop',side_effect=run), \
             patch('agents.autonomous_engine.worker_jobs.cancel_session',AsyncMock(return_value={'cancelled':0,'pending':0,'jobs':[]})):
            results=await asyncio.gather(engine.start('a','alice'),engine.start('a','alice'))
            self.assertEqual(sorted(r['status'] for r in results),['already_running','started'])
            await entered.wait();old=engine._runs['a']
            self.assertEqual((await engine.request_stop('a','alice'))['status'],'stopped')
            self.assertTrue(engine._tasks['a'].done())
            self.assertEqual((await engine.start('a','alice'))['status'],'started')
            self.assertNotEqual(engine._runs['a'].run_id,old.run_id)
            await engine.shutdown()

    async def test_revoking_one_principal_does_not_cancel_other_users_jobs(self):
        for uid,sid,jid in [('alice','a','one'),('bob','b','two')]:
            await self.store.create({'job_id':jid,'session_id':sid,'user_id':uid,'state':'running','endpoint':'http://worker.invalid','protocol':'jobs-v1','revision':0})
        result=await self.jobs.revoke_principal('alice')
        self.assertEqual(result['cancelled'],1)
        self.assertEqual((await self.store.get('two'))['state'],'running')
        self.assertEqual(self.worker.cancels,1)

    async def test_revocation_during_capability_check_prevents_submission(self):
        calls=0
        async def authorize():
            nonlocal calls
            calls+=1
            if calls>1:raise HTTPException(403,'Revoked')
        with self.assertRaises(HTTPException) as error:
            await self.jobs.execute('job1','alice','a','inert mock command',10,authorization_check=authorize)
        self.assertEqual(error.exception.status_code,403)
        self.assertEqual(self.worker.submits,0)
        self.assertEqual((await self.store.get('job1'))['state'],'cancelled')

    async def test_batch_cancellation_intent_survives_request_cancellation(self):
        entered=asyncio.Event();release=asyncio.Event()
        async def cancel(job):
            entered.set();await release.wait()
            return {'job_id':job['job_id'],'session_id':job['session_id'],'state':'cancelled','terminated':True}
        self.worker.cancel=cancel
        for jid in ['one','two']:
            await self.store.create({'job_id':jid,'session_id':'a','user_id':'alice','state':'running','endpoint':'http://worker.invalid','protocol':'jobs-v1','revision':0})
        request=asyncio.create_task(self.jobs.cancel_session('alice','a'))
        await entered.wait();request.cancel()
        with self.assertRaises(asyncio.CancelledError):await request
        self.assertTrue(all(j['cancel_requested'] for j in await self.store.list('a')))
        release.set();await self.jobs.drain_cleanup()
        self.assertTrue(all(j['state']=='cancelled' for j in await self.store.list('a')))

    async def test_receipt_verifies_session_hash_exit_status_and_owner(self):
        import hashlib
        await self.store.create({'job_id':'receipt','session_id':'a','user_id':'alice','state':'succeeded','exit_code':0,
          'output_hash':hashlib.sha256(b'mock output').hexdigest(),'stderr_hash':hashlib.sha256(b'').hexdigest()})
        self.assertTrue(await self.jobs.verify_receipt('alice','a','receipt','mock output','',0))
        for uid,output in [('bob','mock output'),('alice','fabricated')]:
            with self.assertRaises(HTTPException):await self.jobs.verify_receipt(uid,'a','receipt',output,'',0)

    async def test_fence_requires_explicit_resume_and_invalidates_old_approvals(self):
        from memory.execution_authorization import ExecutionAuthorization
        from tests.test_execution import MemoryStore
        async def context(uid,sid):
            if uid!='alice':raise HTTPException(403,'Denied')
            return {'owner_id':'alice','scope':{'targets':['192.0.2.1']},'worker_epoch':self.store.epochs.get('a',0),'worker_blocked':'a' in self.store.fenced}
        sink=AsyncMock(return_value={'exit_code':0})
        authorization=ExecutionAuthorization(MemoryStore(),context,sink)
        proposal=await authorization.propose('alice','a','nmap 192.0.2.1')
        await self.jobs.cancel_session('alice','a')
        with self.assertRaises(HTTPException):await self.jobs.resume_session('bob','a')
        with self.assertRaises(HTTPException):await authorization.execute('alice','a',proposal.command,action_id=proposal.id)
        await self.jobs.resume_session('alice','a')
        with self.assertRaises(HTTPException):await authorization.execute('alice','a',proposal.command,action_id=proposal.id)
        await authorization.execute('alice','a','nmap 192.0.2.1')
        sink.assert_awaited_once()

    async def test_oversized_worker_response_is_stopped_during_streaming(self):
        yielded=0
        class Stream(httpx.AsyncByteStream):
            async def __aiter__(self):
                nonlocal yielded
                for _ in range(1000):
                    yielded+=1
                    yield b'x'*65536
        async def handler(request):return httpx.Response(200,stream=Stream())
        client=WorkerClient(httpx.MockTransport(handler))
        with self.assertRaises(ValueError):await client.request('GET','/jobs/example')
        self.assertLess(yielded,20)
