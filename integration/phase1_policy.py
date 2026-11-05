"""Opt-in synthetic SQL/real-container Phase 1 acceptance. Never reads owner data."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.local-lab/phase1'


async def acceptance(lab):
    import httpx
    from sqlalchemy import select
    from api.main import app
    from api.auth import hash_password
    from memory.database_models import User, PentestSession, async_session, engine
    from memory.execution_authorization import execution_authorization
    from memory.worker_jobs import worker_jobs
    from worker.store import JobStore
    from worker.service import WorkerService
    from worker.runtime import DockerRuntime
    from worker.app import create_app
    from config.settings import settings
    store = JobStore(lab.url)
    await store.open()
    service = WorkerService(store, DockerRuntime(lab.image, lab.network, lab.executable),
                            [lab.addresses[0] + '/32'], [8080])
    worker_jobs.client.transport = httpx.ASGITransport(app=create_app(service, settings.KALI_AGENT_TOKEN))
    password = secrets.token_hex(20)
    owner, other = str(uuid.uuid4()), str(uuid.uuid4())
    async with async_session() as db:
        db.add_all([User(id=owner, username='phase1-owner', password_hash=hash_password(password)),
                    User(id=other, username='phase1-other', password_hash=hash_password(password))])
        await db.commit()
    checks = {}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://synthetic') as client:
            async def call(method,path,expected=200,**kwargs):
                response = await client.request(method,path,**kwargs)
                assert response.status_code == expected, (path,response.status_code,response.text[:200])
                return response.json()
            login = await call('POST','/api/login',json={'username':'phase1-owner','password':password})
            client.headers['Authorization']='Bearer '+login['token']
            session = await call('POST','/api/session/new',json={'target':lab.addresses[0],'name':'Phase 1 synthetic program'})
            sid = session['session_id']
            base = '/api/programs/'+sid
            target = lab.addresses[0]
            text=(f'In scope:\nhttp://{target}:8080/api\nExclusions:\n/api/private and all third parties excluded\n'
                  'Eligible issue classes:\nHTTP observations\nAccount requirements:\nOwned synthetic accounts only\n'
                  'Automation restrictions:\nAutomated GET/HEAD observations allowed: maximum 2 requests, concurrency 1, interval 1 second\n'
                  'Prerequisites:\nLocal lab research with synthetic data only\n')
            snapshot = await call('POST',base+'/import-text',json={'name':'Local lab program','source_url':'https://example.test/policy','text':text,'program_type':'disclosure_only'})
            await call('POST',base+'/'+snapshot['id']+'/activate',expected=409,json={'review_id':'absent','confirm':True})
            rules=[]
            for category, values in snapshot['rules'].items():
                for value in values:
                    rules.append({'category':category,'quote':value['quote'],'start':value['start'],'interpretation':value['quote']})
            indices={rule['category']:i for i,rule in enumerate(rules)}
            asset={'host':target,'path':'/api','ports':[8080],'schemes':['http'],'source_rule':indices['included_assets']}
            execution={'assets':[asset],'exclusions':[{**asset,'path':'/api/private','source_rule':indices['exclusions']}],
                       'third_party_exclusions':[],'automation':'allowed','accounts_confirmed':True,
                       'prerequisites_confirmed':True,'permission_confirmed':True,'eligible_classes':['http_observation'],
                       'max_requests':2,'concurrency':1,'min_interval_seconds':1,
                       'automation_source_rule':indices['automation_restrictions'],'budget_source_rule':indices['automation_restrictions'],
                       'accounts_source_rule':indices['account_requirements'],'prerequisites_source_rule':indices['prerequisites'],
                       'classes_source_rule':indices['eligible_issue_classes'],'exclusions_source_rule':indices['exclusions']}
            review=await call('POST',base+'/'+snapshot['id']+'/review',json={'content_sha256':snapshot['content_sha256'],'rules':rules,'decision':'reviewed','note':'Synthetic review','execution':execution})
            await call('POST',base+'/'+snapshot['id']+'/activate',json={'review_id':review['id'],'confirm':True})
            checks['human_review_activation']='passed'
            for command in [f'curl http://{target}:8080/api/private', f'curl -L http://{target}:8080/api',f'curl http://{target}:8081/api',f'nmap {target}']:
                await call('POST','/api/execution/proposals',expected=403,json={'session_id':sid,'command':command})
            checks['scope_negative_fixtures']='passed'
            command=f'curl -I http://{target}:8080/api'
            stale=await execution_authorization.propose(owner,sid,command,require_approval=True)
            await execution_authorization.decide(owner,sid,stale.id,'approve')
            proposal=await execution_authorization.propose(owner,sid,command,require_approval=True)
            await execution_authorization.decide(owner,sid,proposal.id,'approve')
            receipt=await call('POST','/api/kali/execute',json={'session_id':sid,'command':command,'action_id':proposal.id})
            assert 'ARIA_HTTP_STATUS:200' in receipt['stdout']
            checks['real_worker_policy_receipt']='passed'
            await asyncio.sleep(1.1)
            # Import suspends authoritative SQL scope; old approved action cannot dispatch.
            new=await call('POST',base+'/import-text',json={'name':'Updated local program','source_url':'https://example.test/policy','text':text})
            assert new['revision']==2 and new['execution_suspended']
            await call('POST','/api/kali/execute',expected=403,json={'session_id':sid,'command':command,'action_id':stale.id})
            checks['revision_suspension_stale_approval']='passed'
            # Re-activation preserves the existing traffic reservation.
            review2=await call('POST',base+'/'+new['id']+'/review',json={'content_sha256':new['content_sha256'],'rules':rules,'decision':'reviewed','note':'Revalidated synthetic review','execution':execution})
            await call('POST',base+'/'+new['id']+'/activate',json={'review_id':review2['id'],'confirm':True})
            concurrent=await asyncio.gather(*(client.post('/api/kali/execute',json={'session_id':sid,'command':command}) for _ in range(2)))
            assert sorted(response.status_code for response in concurrent)==[200,429], [response.text for response in concurrent]
            receipt2=next(response.json() for response in concurrent if response.status_code==200)
            assert 'ARIA_HTTP_STATUS:200' in receipt2['stdout']
            checks['shared_concurrent_admission']='passed'
            await asyncio.sleep(1.1)
            await call('POST','/api/kali/execute',expected=429,json={'session_id':sid,'command':command})
            async with async_session() as db:
                saved=(await db.execute(select(PentestSession).where(PentestSession.id==sid))).scalar_one()
                assert saved.metadata_['program_requests_used']==2
            checks['durable_budget_across_policy_revisions']='passed'
            fit=await call('POST',base+'/'+new['id']+'/fit',json={'technical_fit':'good','basis':'Synthetic owned HTTP lab'})
            assert fit['score']==2 and 'accessible_accounts' in fit['unknown']
            catalog=await call('GET','/api/programs/catalog')
            assert len(catalog['programs'])==1
            checks['catalog_unknowns']='passed'
            login2=await call('POST','/api/login',json={'username':'phase1-other','password':password})
            client.headers['Authorization']='Bearer '+login2['token']
            await call('GET',base+'/history',expected=404)
            assert (await call('GET','/api/programs/catalog'))['programs']==[]
            checks['owner_isolation']='passed'
            # Expired backoff must not clear the durable API stop, even with a
            # fresh store instance and an otherwise exhausted request budget.
            import time
            from fastapi import HTTPException
            from memory.worker_jobs import SQLJobStore
            async with async_session() as db:
                saved=(await db.execute(select(PentestSession).where(PentestSession.id==sid))).scalar_one()
                saved.metadata_={**saved.metadata_, 'program_overloaded':True,
                                 'program_backoff_until':time.time()-86400}
                scope=saved.scope
                await db.commit()
            try:
                await SQLJobStore().create({'job_id':str(uuid.uuid4()),'session_id':sid,
                                           'user_id':owner,'scope':scope})
                raise AssertionError('Expired backoff cleared the durable stop')
            except HTTPException as error:
                assert error.status_code==429 and 'stopped after overload' in error.detail
            checks['expired_backoff_durable_stop']='passed'
            # Independently persist the worker stop after a real container goes
            # missing; a recreated controller must deny another job.
            job={'job_id':str(uuid.uuid4()),'session_id':str(uuid.uuid4()),
                 'command':command,'scope':scope,'timeout':20}
            await service.submit(job)
            stored=await store.get(job['job_id'])
            assert await service.runtime.stop(stored)
            await service.status(job['job_id'])
            assert (await store.get(job['job_id']))['overloaded']
            restored=WorkerService(store,service.runtime,service.ceiling,service.allowed_ports)
            await restored.recover()
            try:
                await restored.submit({**job,'job_id':str(uuid.uuid4())})
                raise AssertionError('Recreated worker cleared the durable stop')
            except HTTPException as error:
                assert error.status_code==429 and 'stopped after overload' in error.detail
            checks['missing_container_worker_stop']='passed'
            return {'status':'passed','checks':checks,'owner_data_accessed':False,
                    'schema_revision':'0003','worker_image':lab.image,'live_models':False}
    finally:
        await store.close()
        await engine.dispose()


def main():
    if os.environ.get('ARIA_PHASE1')!='1':
        raise SystemExit('Set ARIA_PHASE1=1 for an isolated synthetic lab')
    OUTPUT.mkdir(parents=True,exist_ok=True)
    from integration.test_worker import WorkerLab
    WorkerLab.setUpClass()
    try:
        from sqlalchemy.engine import make_url
        from cryptography.fernet import Fernet
        pg=WorkerLab.containers[0]
        WorkerLab.cli('exec',pg,'createdb','-U','postgres','aria_phase1_test')
        app_url=make_url(WorkerLab.url).set(database='aria_phase1_test').render_as_string(hide_password=False)
        os.environ.update(DATABASE_URL=app_url,DEBUG='false',SECRET_KEY=secrets.token_hex(32),
                          FERNET_KEY=Fernet.generate_key().decode(),KALI_AGENT_TOKEN=secrets.token_hex(32),
                          KALI_AGENT_URL='http://phase1-worker',KALI_WORKER_PROTOCOL='jobs-v1',
                          BURP_COMMUNITY_ENABLED='false',ARIA_EMBEDDING_MODEL_PATH='',REDIS_URL='redis://127.0.0.1:1/15')
        with (OUTPUT/'migrations.log').open('w') as log:
            subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,check=True,stdout=log,stderr=log)
        report=asyncio.run(acceptance(WorkerLab))
        manifest={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
                  for directory in ('api','memory','orchestrator','worker','security','web','tests','integration')
                  for path in sorted((ROOT/directory).rglob('*')) if path.suffix in {'.py','.js','.css','.html','.cjs'}}
        report['source_revision']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        report['working_tree_changes']=True
        report['source_manifest_sha256']=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
        (OUTPUT/'source-manifest.json').write_text(json.dumps(manifest,indent=2))
        (OUTPUT/'result.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report))
    finally:
        WorkerLab.cleanup()


if __name__=='__main__':main()
