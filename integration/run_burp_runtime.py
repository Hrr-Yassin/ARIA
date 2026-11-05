"""Official Community runtime + real SQL + bounded, authorized TCP80 lab requests.
Requires aria_test already migrated. Does not modify owner DB or browser certificates.
"""
import asyncio
import base64
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path
import httpx
from sqlalchemy.engine import make_url
from config.settings import settings

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.local-lab/burp-runtime'


async def main():
    if os.environ.get('ARIA_BURP_RUNTIME')!='1': raise SystemExit('Set ARIA_BURP_RUNTIME=1 for bounded isolated-lab validation')
    settings.DATABASE_URL=make_url(settings.DATABASE_URL).set(database='aria_test').render_as_string(hide_password=False)
    settings.REDIS_URL=make_url(settings.REDIS_URL).set(database='15').render_as_string(hide_password=False)
    OUTPUT.mkdir(mode=0o700,exist_ok=True)
    token_file=OUTPUT/'connector-token'
    if not token_file.exists(): token_file.write_text(secrets.token_hex(32)); token_file.chmod(0o600)
    token=token_file.read_text().strip(); settings.BURP_CONNECTOR_TOKEN=token
    settings.BURP_COMMUNITY_ENABLED=True
    settings.BURP_CONNECTOR_URL='http://127.0.0.1:17777'
    config=OUTPUT/'project.json'
    config.write_text(json.dumps({'proxy':{'request_listeners':[{'certificate_mode':'per_host','custom_tls_protocols':[],'use_custom_tls_protocols':False,'enable_http2':False,'listen_mode':'loopback_only','listener_port':18081,'running':True}]}}))
    environment={**os.environ,'ARIA_BURP_CONNECTOR_TOKEN':token,'ARIA_BURP_TARGETS':'192.168.77.20',
        'ARIA_BURP_STATE_FILE':str(OUTPUT/'jobs.properties'),'ARIA_BURP_SET_SCOPE':'1'}
    command=['java','-Xmx768m','-Djava.awt.headless=true','-Djava.util.prefs.userRoot='+str(OUTPUT/'prefs'),
        '-cp',str(ROOT/'.local-lab/burpsuite-community-2025.2.jar')+':'+str(ROOT/'burp-community/build/aria-community.jar'),
        'burp.StartBurp','--use-defaults','--disable-auto-update','--data-dir='+str(OUTPUT/'data'),
        '--config-file='+str(config),'--developer-extension-class-name=aria.CommunityExtension']
    results={}; process=None; target_requests=0
    log=(OUTPUT/'runtime.log').open('w')
    try:
        if os.environ.get("ARIA_BURP_EXTERNAL")!="1":
            process=subprocess.Popen(command,cwd=ROOT,env=environment,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.PIPE)
            if os.environ.get("ARIA_ACCEPT_BURP_EULA")=="1":
                process.stdin.write(b"y\n"); process.stdin.flush()
        async with httpx.AsyncClient(timeout=3,trust_env=False,headers={'Authorization':'Bearer '+token}) as client:
            for _ in range(120):
                if process is not None and process.poll() is not None: raise RuntimeError('Community runtime exited; see redacted runtime log')
                try:
                    response=await client.get('http://127.0.0.1:17777/capabilities')
                    if response.status_code==200: break
                except httpx.HTTPError: pass
                await asyncio.sleep(.5)
            else: raise RuntimeError('Community connector did not become ready; runtime or initial licensing may need attention')
            caps=response.json(); assert caps['edition']=='COMMUNITY' and caps['scanner'] is False and caps['active_replay'] is True,caps
            results['official_community_extension_load']='passed'; print('Official Community extension ready',flush=True)
            proxy_port=18081  # Explicit isolated listener; readiness may lag extension initialization.
            for _ in range(60):
                try:
                    reader,writer=await asyncio.open_connection('127.0.0.1',proxy_port); writer.close(); await writer.wait_closed(); break
                except OSError: await asyncio.sleep(.25)
            else: raise RuntimeError('Isolated proxy listener did not become ready')
            async with httpx.AsyncClient(proxy='http://127.0.0.1:18081',timeout=15,trust_env=False) as proxy:
                target_requests+=1
                captured=await proxy.get('http://192.168.77.20/?aria_validation='+uuid.uuid4().hex)
                assert captured.status_code in {200,301,302,403,404}
            results['real_proxy_capture']='passed'
            from memory.database_models import User,PentestSession,async_session,engine
            from api.auth import TokenData
            from api.routers.burp import proxy_history,import_history_selection,CaptureSelection,repeater
            from memory.web_actions import web_actions
            uid,sid=str(uuid.uuid4()),str(uuid.uuid4())
            async with async_session() as db:
                db.add(User(id=uid,username='burp-runtime-'+uid,password_hash='unused')); await db.flush()
                db.add(PentestSession(id=sid,user_id=uid,target='192.168.77.20',scope={'targets':['192.168.77.20'],'ports':[80],
                    'web_authenticated_replay':True,'web_mutations':True,'web_request_budget':5})); await db.commit()
            user=TokenData(user_id=uid,username='burp-runtime',role='pentester',skill_level='expert')
            history=await proxy_history(sid,user); assert history['captures']
            selection=CaptureSelection(capture_ids=[history['captures'][-1]['capture_id']])
            first=await import_history_selection(sid,selection,user)
            second=await import_history_selection(sid,selection,user)
            eid=first['imported'][0]['evidence_id']
            assert second['imported'][0]['evidence_id']==eid and second['imported'][0]['duplicate']
            results['selected_import_and_duplicates']='passed'
            assert (await repeater(sid,eid,user))['network_request_sent'] is False
            results['real_repeater_staging']='passed'
            denied=await web_actions.propose(sid,uid,eid)
            await web_actions.decide(sid,uid,denied['action_id'],'reject')
            try: await web_actions.execute(sid,uid,denied['action_id'])
            except Exception as error: assert getattr(error,'status_code',None)==403
            else: raise AssertionError('Rejected replay was executable')
            results['rejected_replay_no_dispatch']='passed'
            for mutation in [None,{'method':'HEAD','path':'/?aria_fixture=approved','headers':{'Authorization':'Bearer synthetic-transport-fixture'}}]:
                proposal=await web_actions.propose(sid,uid,eid,mutation)
                await web_actions.decide(sid,uid,proposal['action_id'],'approve')
                result=await web_actions.execute(sid,uid,proposal['action_id']); target_requests+=1
                for _ in range(100):
                    result=await web_actions.status(sid,uid,proposal['action_id'])
                    if result['state'] in {'completed','failed','cancelled_after_dispatch'}: break
                    await asyncio.sleep(.15)
                assert result['state']=='completed',result
                assert result['result']['comparison']['response_bytes']>0
                assert 'synthetic-transport-fixture' not in json.dumps(result)
                assert (await web_actions.execute(sid,uid,proposal['action_id']))['state']=='completed'
            results['approved_exact_replay_and_bounded_mutation']='passed'
            results['response_comparison_and_one_use']='passed'
            cancelled=await web_actions.propose(sid,uid,eid)
            assert (await web_actions.cancel(sid,uid,cancelled['action_id']))['state']=='cancelled'
            results['cancel_before_dispatch']='passed'
            await engine.dispose()
            print('Native capture, import, Repeater, exact replay and mutation passed',flush=True)
    except Exception as exc:
        results['runtime']='blocked: '+str(exc)
        raise
    finally:
        if process is not None:
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        if process is not None and process.stdin is not None: process.stdin.close()
        log.close()
        (OUTPUT/'report.json').write_text(json.dumps({'results':results,'target':'192.168.77.20','port':80,
            'target_request_upper_bound':target_requests,'live_model_calls':0,'live_model_tokens':0,
            'limitations':['Synthetic Authorization tests credential transport; no valid authenticated account or gained access is claimed.',
                'Running cancellation/deadlines verified separately with the JVM controlled sender fixture.']},indent=2))
    print(json.dumps(results,indent=2))


if __name__=='__main__': asyncio.run(main())
