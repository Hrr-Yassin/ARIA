"""Opt-in Phase 2 acceptance: fresh SQL + isolated worker, mocked model responses."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.local-lab/phase2'


async def acceptance(lab):
    import httpx
    from fastapi import HTTPException
    from sqlalchemy import select
    from api.main import app
    from api.auth import hash_password
    from config.settings import settings
    from memory.database_models import User, UserAPIKey, DecisionLog, async_session, engine
    from memory.execution_authorization import execution_authorization
    from memory.worker_jobs import worker_jobs
    from memory.team_tasks import TeamStore, team_store
    from llm.engagement_budget import model_accounting, engagement_context
    from llm.pool_manager import pool_manager
    from worker.store import JobStore
    from worker.service import WorkerService
    from worker.runtime import DockerRuntime
    from worker.app import create_app
    store=JobStore(lab.url)
    await store.open()
    service=WorkerService(store,DockerRuntime(lab.image,lab.network,lab.executable),[lab.addresses[0]+'/32'],[8080])
    worker_jobs.client.transport=httpx.ASGITransport(app=create_app(service,settings.KALI_AGENT_TOKEN))
    owner,other=str(uuid.uuid4()),str(uuid.uuid4())
    password=secrets.token_hex(20)
    async with async_session() as db:
        db.add_all([User(id=owner,username='phase2-owner',password_hash=hash_password(password)),
                    User(id=other,username='phase2-other',password_hash=hash_password(password))])
        await db.commit()
        db.add(UserAPIKey(user_id=owner,provider='groq',encrypted_key=pool_manager.encrypt_key('synthetic-never-sent'),requests_limit=50))
        await db.commit()
    checks={}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://synthetic') as client:
            async def call(method,path,expected=200,**kwargs):
                response=await client.request(method,path,**kwargs)
                assert response.status_code==expected,(path,response.status_code,response.text[:300])
                return response.json()
            login=await call('POST','/api/login',json={'username':'phase2-owner','password':password})
            client.headers['Authorization']='Bearer '+login['token']
            sid=(await call('POST','/api/session/new',json={'target':lab.addresses[0], 'scope':{'targets':[lab.addresses[0]],'ports':[8080]}}))['session_id']
            base='/api/team/'+sid
            command='curl -I http://'+lab.addresses[0]+':8080/api'
            proposal=await execution_authorization.propose(owner,sid,command,require_approval=True)
            await execution_authorization.decide(owner,sid,proposal.id,'approve')
            receipt=await call('POST','/api/kali/execute',json={'session_id':sid,'command':command,'action_id':proposal.id})
            assert receipt['exit_code']==0
            evidence=(await call('POST',base+'/evidence',json={'request_id':str(uuid.uuid4()),'source_kind':'worker','source_id':receipt['job_id']}))['data']
            eid=evidence['id']
            assert evidence['hashes']['output_hash']
            checks['real_worker_evidence_catalog']='passed'
            limits={'max_calls':10,'max_tokens':500000,'max_cost_microusd':1000000,
                    'tariffs':[{'provider':'groq','model':'llama-3.3-70b-versatile','microusd_per_million':1000000}]}
            await call('PUT',base+'/model-budget',json=limits)
            spec={'owner_role':'web_intel','objective':'Describe saved HTTP evidence, preserve uncertainty',
                  'expected_output':'Evidence-linked observations', 'completion_criteria':['No unverified vulnerability claim'],
                  'evidence_inputs':[eid]}
            body={'request_id':str(uuid.uuid4()),'task':spec}
            first=await call('POST',base+'/tasks',json=body)
            assert (await call('POST',base+'/tasks',json=body))['duplicate']
            tid=first['entity_id']
            second=await call('POST',base+'/tasks',json={'request_id':str(uuid.uuid4()),'task':{**spec,'owner_role':'correlation','dependencies':[tid]}})
            tid2=second['entity_id']
            await call('POST',base+'/tasks/'+tid2+'/run',expected=409,json={'request_id':str(uuid.uuid4())})
            provider=SimpleProvider(eid)
            with patch.dict('llm.pool_manager.PROVIDER_CLIENTS',{'groq':MagicMock(return_value=provider)}):
                run_id=str(uuid.uuid4())
                deliveries=await asyncio.gather(*(client.post(base+'/tasks/'+tid+'/run',json={'request_id':run_id}) for _ in range(2)))
                assert all(response.status_code==200 for response in deliveries)
                results=[response.json() for response in deliveries]
                assert sum(bool(result['duplicate']) for result in results)==1
                analyzed=next(result for result in results if result['data']['state']=='awaiting_review')
                assert analyzed['data']['result']['evidence_references']==[eid]
                assert (await call('POST',base+'/tasks/'+tid+'/run',json={'request_id':run_id}))['duplicate']
                assert provider.query.await_count==1
                await call('POST',base+'/tasks/'+tid+'/transition',json={'request_id':str(uuid.uuid4()),'expected_revision':analyzed['data']['revision'],'state':'completed','reason':'Reviewed observation; no vulnerability proven'})
                interrupted=str(uuid.uuid4())
                await team_store.claim(sid,owner,tid2,interrupted)
                await TeamStore().recover()
                view=await TeamStore().view(sid,owner)
                states={t['id']:t for t in view['tasks']}
                assert states[tid]['state']=='completed' and states[tid2]['state']=='blocked'
                assert (await call('POST',base+'/tasks/'+tid2+'/run',json={'request_id':interrupted}))['duplicate']
                assert provider.query.await_count==1
                await call('POST',base+'/tasks/'+tid2+'/transition',json={'request_id':str(uuid.uuid4()),'expected_revision':states[tid2]['revision'],'state':'queued','reason':'Inspected after restart'})
                await call('POST',base+'/tasks/'+tid2+'/run',json={'request_id':str(uuid.uuid4())})
                assert provider.query.await_count==2
            checks['multi_task_restart_no_replay']='passed'
            checks['typed_specialist_evidence_and_review']='passed'
            hypothesis=(await call('POST',base+'/knowledge',json={'request_id':str(uuid.uuid4()),'kind':'hypothesis','text':'Possible exposure','evidence_references':[eid],'uncertainty':'HTTP success does not prove disclosure'}))['entity_id']
            await call('POST',base+'/knowledge',json={'request_id':str(uuid.uuid4()),'kind':'observation','text':'Rejected hypothesis without account controls','evidence_references':[eid],'uncertainty':'Accounts missing','disposition':'rejected','contradicts':[hypothesis]})
            await call('POST',base+'/coverage',json={'request_id':str(uuid.uuid4()),'key':'authorization','question':'Are objects isolated?','feature':'API objects','status':'blocked','gap_reason':'Two-account testing is Phase 3','evidence_references':[]})
            view=await call('GET',base)
            assert len(view['knowledge'])==2 and view['coverage'][0]['status']=='blocked'
            event_view=await call('GET',base+'/events?after=0')
            assert event_view['cursor']==view['cursor']
            checks['coverage_contradictions_durable_events']='passed'
            budget=await call('GET',base+'/model-budget')
            assert budget['usage']['calls']==2 and budget['usage']['reported_tokens']==40
            assert budget['usage']['unknown_cost_calls']==2
            # Fresh store instances race on the same SQL engagement row.
            await call('PUT',base+'/model-budget',json={**limits,'max_calls':3})
            token=engagement_context.set({'session_id':sid,'owner':owner})
            try:
                attempts=await asyncio.gather(*(model_accounting.reserve(owner,'groq','llama-3.3-70b-versatile','test','') for _ in range(2)),return_exceptions=True)
                assert sum(isinstance(item,dict) for item in attempts)==1
                assert sum(isinstance(item,HTTPException) and item.status_code==429 for item in attempts)==1
            finally:
                engagement_context.reset(token)
            checks['shared_sql_model_budget_and_unknown_cost']='passed'
            # Other owner cannot read events/catalog/budgets or mutate tasks.
            login2=await call('POST','/api/login',json={'username':'phase2-other','password':password})
            client.headers['Authorization']='Bearer '+login2['token']
            for suffix in ('','/events','/model-budget'):
                await call('GET',base+suffix,expected=404)
            await call('POST',base+'/tasks',expected=404,json={'request_id':str(uuid.uuid4()),'task':spec})
            checks['owner_isolation']='passed'
            # Catalog lookups must also reject source IDs from another engagement
            # belonging to the same user, not just other-owner access.
            client.headers['Authorization']='Bearer '+login['token']
            sid_other=(await call('POST','/api/session/new',json={'target':lab.addresses[0]}))['session_id']
            await call('POST','/api/team/'+sid_other+'/evidence',expected=404,
                       json={'request_id':str(uuid.uuid4()),'source_kind':'worker','source_id':receipt['job_id']})
            async with async_session() as db:
                jobs=(await db.execute(select(DecisionLog).where(DecisionLog.session_id==sid,DecisionLog.decision_type=='worker_job'))).scalars().all()
                assert len(jobs)==1
            checks['specialists_never_dispatch_tools']='passed'
            return {'status':'passed','checks':checks,'live_model_calls':0,'mocked_provider_calls':2,
                    'owner_data_accessed':False,'schema_revision':'0003','worker_image':lab.image}
    finally:
        await store.close()
        await engine.dispose()


class SimpleProvider:
    def __init__(self,evidence_id):
        self.query=AsyncMock(return_value={'success':True,'content':json.dumps({'commands':[],
            'findings':[{'description':'HTTP response observed; no vulnerability established','evidence_references':[evidence_id]}],
            'correlations':[{'finding':'A successful response does not prove a vulnerability','evidence_references':[evidence_id]}]}),
            'tokens_used':20})


def main():
    if os.environ.get('ARIA_PHASE2')!='1':
        raise SystemExit('Set ARIA_PHASE2=1 for a new disposable synthetic lab')
    from integration.test_worker import WorkerLab
    OUTPUT.mkdir(parents=True,exist_ok=True)
    WorkerLab.setUpClass()
    try:
        from sqlalchemy.engine import make_url
        from cryptography.fernet import Fernet
        WorkerLab.cli('exec',WorkerLab.containers[0],'createdb','-U','postgres','aria_phase2_test')
        url=make_url(WorkerLab.url).set(database='aria_phase2_test').render_as_string(hide_password=False)
        os.environ.update(DATABASE_URL=url,DEBUG='false',SECRET_KEY=secrets.token_hex(32),
            FERNET_KEY=Fernet.generate_key().decode(),KALI_AGENT_TOKEN=secrets.token_hex(32),
            KALI_AGENT_URL='http://phase2-worker',KALI_WORKER_PROTOCOL='jobs-v1',
            BURP_COMMUNITY_ENABLED='false',ARIA_EMBEDDING_MODEL_PATH='',REDIS_URL='redis://127.0.0.1:1/15')
        with (OUTPUT/'migrations.log').open('w') as log:
            subprocess.run([sys.executable,'-m','alembic','upgrade','head'],cwd=ROOT,check=True,stdout=log,stderr=log)
            subprocess.run([sys.executable,'-m','alembic','check'],cwd=ROOT,check=True,stdout=log,stderr=log)
        report=asyncio.run(acceptance(WorkerLab))
        manifest={str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest()
                  for directory in ('api','agents','memory','orchestrator','llm','worker','security','web','tests','integration')
                  for path in sorted((ROOT/directory).rglob('*')) if path.suffix in {'.py','.js','.css','.html','.cjs'}}
        report.update(source_revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
            working_tree_changes=True,source_manifest_sha256=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest())
        (OUTPUT/'source-manifest.json').write_text(json.dumps(manifest,indent=2))
        (OUTPUT/'result.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report))
    finally:
        WorkerLab.cleanup()


if __name__=='__main__':main()
