"""Disposable SQL + real isolated authenticated worker acceptance; no owner DB.
ARIA_PHASE3=1 WORKER_TEST_RUNTIME=podman WORKER_TEST_IMAGE=sha256:... \
  .venv/bin/python -m integration.phase3_mapping
"""
import asyncio
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.local-lab/phase3'
SERVER = '''
import http.server, threading, json, time
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        account = {'Bearer owned-a':'a','Bearer owned-b':'b'}.get(self.headers.get('Authorization'))
        if self.path == '/slow': time.sleep(60)
        if self.path == '/redirect':
            self.send_response(302); self.send_header('Location','http://excluded.invalid/'); self.end_headers(); return
        body = json.dumps({'owner':account,'object':'object-'+str(account)}).encode()
        if self.path == '/large': body = b'x'*40000
        self.send_response(200 if account else 401)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)))
        self.end_headers();self.wfile.write(body)
    def do_HEAD(self):
        self.send_response(200); self.end_headers()
    def log_message(self,*args): pass
for port in (8080,8081):
    threading.Thread(target=http.server.ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever,daemon=True).start()
threading.Event().wait()
'''


async def acceptance(lab):
    import httpx
    from fastapi import HTTPException
    from config.settings import settings
    from memory.database_models import User, PentestSession, ChatLog, DecisionLog, async_session, engine
    from memory.application_map import ApplicationMap, IdentityInput, RequestInput, CaptureInput, ComparisonInput, ObjectInput, WorkflowInput, PermissionInput, DataPolicy, Change, now
    from memory.burp_community import import_pair
    from memory.execution_authorization import execution_authorization
    from memory.worker_jobs import worker_jobs
    from worker.app import create_app
    from worker.runtime import DockerRuntime
    from worker.service import WorkerService
    from worker.store import JobStore
    from worker.http_profile import cipher
    from sqlalchemy import select
    worker_store = JobStore(lab.url)
    await worker_store.open()
    class DiagnosticRuntime(DockerRuntime):
        async def output(self, job):
            stdout, stderr = await super().output(job)
            if stderr:
                diagnostic = OUTPUT / 'runtime-errors.log'
                diagnostic.write_text(stderr)
                diagnostic.chmod(0o600)
            return stdout, stderr
    service = WorkerService(worker_store, DiagnosticRuntime(lab.image,lab.network,lab.executable),
                            [lab.addresses[0]+'/32'],[8080])
    worker_jobs.client.transport = httpx.ASGITransport(app=create_app(service,settings.KALI_AGENT_TOKEN))
    owner, sid = str(uuid.uuid4()), str(uuid.uuid4())
    first_sid = sid
    async with async_session() as db:
        db.add(User(id=owner,username='phase3-'+owner,password_hash='unused'))
        await db.flush()
        db.add(PentestSession(id=sid,user_id=owner,target=lab.addresses[0],scope={
            'targets':[lab.addresses[0]],'ports':[8080],'web_authenticated_replay':True,'web_request_budget':20}))
        await db.commit()
    mapping = ApplicationMap()
    revision = 0
    checks = {}
    jobs = []
    async def identity(account):
        nonlocal revision
        value=await mapping.change(sid,owner,'identities',IdentityInput(expected_revision=revision,
            label='Owned '+account,role='member',researcher_controlled=True,
            credentials={'authorization':'Bearer owned-'+account}))
        revision=value['revision'];return value['id']
    async def capture(identity_id, account, path='/objects'):
        nonlocal revision
        url='http://'+lab.addresses[0]+':8080'+path
        raw=('GET '+path+' HTTP/1.1\r\nHost: '+lab.addresses[0]+':8080\r\nAuthorization: Bearer owned-'+account+'\r\n\r\n').encode()
        baseline=b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'+json.dumps({'owner':account,'object':'object-'+account}).encode()
        original={'url':url,'request_b64':base64.b64encode(raw).decode(),'response_b64':base64.b64encode(baseline).decode()}
        pair={'digest':uuid.uuid4().hex,'summary':{'method':'GET','endpoint':path},'authenticated':True,'original':original}
        eid=(await import_pair(sid,pair))['evidence_id']
        value=await mapping.change(sid,owner,'captures',CaptureInput(expected_revision=revision,identity_id=identity_id,evidence_id=eid))
        revision=value['revision'];return value['id']
    async def run(identity_id, capture_id, timeout=10):
        proposal=await mapping.replay_proposal(sid,owner,identity_id,capture_id)
        await execution_authorization.decide(owner,sid,proposal['action_id'],'approve')
        result=await execution_authorization.execute(owner,sid,proposal['command'],tool='aria-http',
                                                     action_id=proposal['action_id'],timeout=timeout)
        return proposal,result
    try:
        a,b=await identity('a'),await identity('b')
        ca,cb=await capture(a,'a'),await capture(b,'b')
        pending=await mapping.replay_proposal(sid,owner,a,ca)
        try:
            await execution_authorization.execute(owner,sid,pending['command'],tool='aria-http',action_id=pending['action_id'],timeout=10)
        except HTTPException as exc: assert exc.status_code==403
        else: raise AssertionError('Pending approval executed')
        await execution_authorization.decide(owner,sid,pending['action_id'],'reject')
        try:
            await execution_authorization.execute(owner,sid,pending['command'],tool='aria-http',action_id=pending['action_id'],timeout=10)
        except HTTPException as exc: assert exc.status_code==403
        else: raise AssertionError('Rejected approval executed')
        assert not await worker_store.for_session(sid)
        checks['pending_and_rejected_approvals_never_dispatch']='passed'
        for identity_id,capture_id,account in [(a,ca,'a'),(b,cb,'b')]:
            proposal,result=await run(identity_id,capture_id)
            jobs.append(result['job_id'])
            assert result['exit_code']==0,result
            assert 'owned-' not in json.dumps(result)
            assert 'protected_response' not in result['stdout']
            comparison=await mapping.replay_comparison(sid,owner,result['job_id'])
            assert comparison['equivalent'],comparison
            job=await worker_jobs.store.get(result['job_id'])
            private=json.loads(cipher(settings.HTTP_REPLAY_KEY).decrypt(job['protected_response'].encode()))
            body=base64.b64decode(private['response_b64']).partition(b'\r\n\r\n')[2]
            assert json.loads(body)['owner']==account
            try:
                await execution_authorization.execute(owner,sid,proposal['command'],tool='aria-http',action_id=proposal['action_id'],timeout=10)
            except HTTPException: pass
            else: raise AssertionError('Consumed approval replayed')
            await asyncio.sleep(1.1)
        checks['two_authenticated_accounts_and_private_evidence']='passed'
        checks['shared_approval_one_use_and_semantic_comparison']='passed'
        restored=await ApplicationMap().view(sid,owner)
        assert len(restored['identities'])==2 and len(restored['captures'])==2
        assert 'owned-' not in json.dumps(restored)
        try: await mapping.view(sid,str(uuid.uuid4()))
        except HTTPException: pass
        else: raise AssertionError('Foreign owner access')
        checks['sql_restart_and_owner_isolation']='passed'
        view = await mapping.view(sid,owner)
        revision=view['revision']
        object_row=await mapping.change(sid,owner,'objects',ObjectInput(expected_revision=revision,
            label='Owned document',owner_identity_id=a,evidence_ids=[view['captures'][ca]['evidence_id']]))
        revision=object_row['revision']
        for kind in ('sharing','invitation','export','account_settings'):
            row=await mapping.change(sid,owner,'workflows',WorkflowInput(expected_revision=revision,label=kind,
                kind=kind,evidence_ids=[view['captures'][ca]['evidence_id'],view['captures'][cb]['evidence_id']],
                before='Owned private state',after='Human-observed transition'))
            revision=row['revision']
        row=await mapping.change(sid,owner,'permissions',PermissionInput(expected_revision=revision,
            object_id=object_row['id'],identity_id=b,operation='read',expected='deny',
            rationale='Private object owned by first account',evidence_ids=[view['captures'][ca]['evidence_id']]))
        revision=row['revision']
        checks['owned_objects_workflows_and_expected_permissions']='passed'
        # Real model admission is exercised, with no physical provider call.
        from llm.engagement_budget import engagement_context, model_accounting
        token=engagement_context.set({'session_id':sid,'owner':owner})
        try:
            try: await model_accounting.reserve(owner,'groq','fixture','Metadata','')
            except HTTPException as exc: assert exc.status_code==403
            else: raise AssertionError('Default-deny provider sharing bypassed')
            policy=await mapping.change(sid,owner,'policy',DataPolicy(expected_revision=revision,
                retention_days=7,provider_sharing='redacted_metadata'))
            revision=policy['revision']
            try: await model_accounting.reserve(owner,'groq','fixture','Reflected owned-a secret','')
            except HTTPException as exc: assert exc.status_code==403 and 'credential' in exc.detail
            else: raise AssertionError('Registered credential reached model admission')
        finally:
            engagement_context.reset(token)
        checks['provider_default_deny_and_registered_secret_guard']='passed'
        if os.environ.get('ARIA_PHASE3_BROWSER')=='1':
            from orchestrator.browser_mapping import browser_mapping
            settings.BROWSER_MAPPING_ENABLED=True
            try:
                for identity_id,capture_id in [(a,ca),(b,cb)]:
                    current=await mapping.view(sid,owner)
                    draft=await mapping.change(sid,owner,'requests',RequestInput(expected_revision=current['revision'],
                        identity_id=identity_id,method='GET',url='http://'+lab.addresses[0]+':8080/objects'))
                    proposal=await mapping.replay_proposal(sid,owner,identity_id,draft['id'])
                    await execution_authorization.decide(owner,sid,proposal['action_id'],'approve')
                    image=await browser_mapping.preview(owner,sid,identity_id,proposal['action_id'])
                    assert image.startswith(b'\x89PNG'), 'Missing browser screenshot'
                    (OUTPUT/('browser-'+identity_id+'.png')).write_bytes(image)
                    await asyncio.sleep(1.1)
                contexts=[browser_mapping.pool.slots[(owner,sid,key)].context for key in (a,b)]
                assert contexts[0] is not contexts[1]
                await contexts[0].add_cookies([{'name':'account','value':'first','url':'http://'+lab.addresses[0]+':8080'}])
                assert not await contexts[1].cookies()
                view=await mapping.view(sid,owner)
                observed=[capture for capture in view['captures'].values() if capture.get('attribution')=='authenticated_worker_receipt']
                assert len(observed)==2 and {capture['identity_id'] for capture in observed}=={a,b}
                checks['real_browser_to_approved_worker_and_endpoint_catalog']='passed'
            finally:
                await browser_mapping.close()
            revision=(await mapping.view(sid,owner))['revision']
        # Redirects return an observation without contacting the excluded host.
        cr=await capture(a,'a','/redirect');_,redirect=await run(a,cr)
        assert json.loads(redirect['stdout'])['status']==302
        checks['redirect_not_followed']='passed'
        await asyncio.sleep(1.1)
        # Bounded response failure stops the engagement; use a slow request first.
        slow=await capture(a,'a','/slow')
        proposal=await mapping.replay_proposal(sid,owner,a,slow)
        await execution_authorization.decide(owner,sid,proposal['action_id'],'approve')
        task=asyncio.create_task(execution_authorization.execute(owner,sid,proposal['command'],tool='aria-http',action_id=proposal['action_id'],timeout=10))
        for _ in range(100):
            job=await worker_store.get(proposal['action_id'])
            if job and job['state']=='running': break
            await asyncio.sleep(.1)
        else: raise AssertionError('Slow worker did not run')
        await worker_jobs.cancel_session(owner,sid)
        result=await task
        assert result['status']=='cancelled',result
        remote=await worker_store.get(proposal['action_id'])
        assert remote['terminated'] is True
        checks['running_cancellation_confirmed']='passed'
        count=len(await worker_store.for_session(sid))
        await service.recover()
        assert len(await worker_store.for_session(sid))==count
        checks['restart_no_duplicate_execution']='passed'
        # Retention expires map copies and source captures, and the authenticated
        # worker retention RPC clears its terminal encrypted request/response.
        from datetime import timedelta
        from unittest.mock import patch
        with patch('memory.application_map.now',return_value=now()+timedelta(days=100)):
            expired=await mapping.view(sid,owner)
            assert all(not item['active'] for item in expired['identities'].values())
            assert all(item['expired'] for item in expired['captures'].values())
        async with async_session() as db:
            source=await db.get(ChatLog,restored['captures'][ca]['evidence_id'])
            assert 'protected_original' not in source.data
        for job_id in jobs:
            await service.retention(job_id,sid,'2000-01-01T00:00:00+00:00')
            remote=await worker_store.get(job_id)
            assert not remote.get('protected_http') and not remote['plan'].get('protected_http')
            assert remote['stdout']==''
        checks['map_source_and_worker_private_evidence_expiry']='passed'
        for path in ('/large','/slow'):
            sid=str(uuid.uuid4())
            revision=0
            async with async_session() as db:
                db.add(PentestSession(id=sid,user_id=owner,target=lab.addresses[0],scope={
                    'targets':[lab.addresses[0]],'ports':[8080],'web_authenticated_replay':True,'web_request_budget':20}))
                await db.commit()
            controlled=await identity('a')
            selected=await capture(controlled,'a',path)
            if path=='/large':
                _,bounded=await run(controlled,selected)
                assert bounded['exit_code']!=0 and 'protected_response' not in bounded['stdout']
                remote=await worker_store.get(bounded['job_id'])
                assert remote['overloaded'] is True
                try: await run(controlled,selected)
                except HTTPException: pass
                else: raise AssertionError('Overload/unknown-result stop was bypassed')
                checks['oversized_response_and_stop_on_unknown_result']='passed'
            else:
                proposal=await mapping.replay_proposal(sid,owner,controlled,selected)
                await execution_authorization.decide(owner,sid,proposal['action_id'],'approve')
                try:
                    bounded=await execution_authorization.execute(owner,sid,proposal['command'],tool='aria-http',
                        action_id=proposal['action_id'],timeout=2)
                    assert bounded['status']=='cancelled' or (bounded['status']=='failed' and bounded['exit_code']==124),bounded
                except HTTPException as exc:
                    assert exc.status_code==504,exc
                remote=await worker_store.get(proposal['action_id'])
                assert remote['terminated'] is True and (remote['state']=='cancelled' or
                    (remote['state']=='failed' and remote['exit_code']==124)),remote
                checks['deadline_terminates_slow_authenticated_request']='passed'
        async with async_session() as db:
            first=await db.get(PentestSession,first_sid)
            metadata=dict(first.metadata_);metadata.pop('application_mapping',None)
            first.metadata_=metadata
            await db.commit()
        await mapping.purge_expired()
        async with async_session() as db:
            first=await db.get(PentestSession,first_sid)
            assert first.metadata_['application_mapping'] is True
        checks['startup_retention_and_existing_map_consent_reconciliation']='passed'
        return {'status':'passed','checks':checks,'worker_image':lab.image,'schema_revision':'0003',
                'live_model_calls':0,'owner_data_accessed':False,'target':'disposable internal synthetic HTTP server'}
    finally:
        await service.recover()
        await worker_store.close()
        await engine.dispose()


def main():
    if os.environ.get('ARIA_PHASE3')!='1':
        raise SystemExit('Set ARIA_PHASE3=1 for a fresh disposable lab')
    from integration import test_worker
    test_worker.SERVER=SERVER
    lab=test_worker.WorkerLab
    OUTPUT.mkdir(parents=True,exist_ok=True)
    (OUTPUT/'worker.json').write_text(json.dumps({'status':'running'}))
    try:
        lab.setUpClass()
        from sqlalchemy.engine import make_url
        from cryptography.fernet import Fernet
        lab.cli('exec',lab.containers[0],'createdb','-U','postgres','aria_phase3_test')
        url=make_url(lab.url).set(database='aria_phase3_test').render_as_string(hide_password=False)
        os.environ.update(DATABASE_URL=url,DEBUG='false',SECRET_KEY=secrets.token_hex(32),
            FERNET_KEY=Fernet.generate_key().decode(),HTTP_REPLAY_KEY=Fernet.generate_key().decode(),
            KALI_AGENT_TOKEN=secrets.token_hex(32),KALI_AGENT_URL='http://phase3-worker',KALI_WORKER_PROTOCOL='jobs-v1',
            BURP_COMMUNITY_ENABLED='false',ARIA_EMBEDDING_MODEL_PATH='',REDIS_URL='redis://127.0.0.1:1/15')
        with (OUTPUT/'migrations.log').open('w') as log:
            subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,check=True,stdout=log,stderr=log)
            subprocess.run([sys.executable,'-m','alembic','check'],cwd=ROOT,check=True,stdout=log,stderr=log)
        result=asyncio.run(acceptance(lab))
        (OUTPUT/'worker.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(result))
    except BaseException as exc:
        (OUTPUT/'worker.json').write_text(json.dumps({'status':'failed','error_type':type(exc).__name__},indent=2))
        raise
    finally:
        if hasattr(lab,'containers') and hasattr(lab,'network'):
            lab.cleanup()


if __name__=='__main__':main()
