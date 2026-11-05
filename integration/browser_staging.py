"""Real Firefox + full API + restored staging SQL + native Community.
Only the isolated TCP80 target receives bounded HTTP requests. No model calls.
"""
import asyncio
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
import httpx
import sys
sys.path.append(str(Path(__file__).resolve().parents[1]/'.local-lab/browser-venv/lib/python3.11/site-packages'))
from playwright.async_api import async_playwright, expect
from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from config.settings import settings

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.local-lab/upgrade-stage'
BASE='http://127.0.0.1:17004'

async def main():
    if os.environ.get('ARIA_STAGING_BROWSER')!='1': raise SystemExit('Set ARIA_STAGING_BROWSER=1 for isolated full-application validation')
    metadata=json.loads((OUTPUT/'metadata.json').read_text())
    name=metadata['database']
    assert name.startswith('aria_upgrade_') and name.endswith('_test')
    engine=create_async_engine(make_url(settings.DATABASE_URL).set(database=name))
    # Copied unresolved jobs belong to the original deployment. Fence only the copy
    # before lifespan recovery can contact a worker about an inherited job ID.
    async with engine.begin() as db:
        rows=(await db.execute(text("SELECT id,metadata FROM decision_logs WHERE decision_type='worker_job'"))).all()
        isolated=0
        for ident,data in rows:
            if data.get('state') not in {'succeeded','failed','cancelled'}:
                data={**data,'state':'failed','staging_original_state':data.get('state'),'error':'Inherited job fenced in staging; no worker cancellation or replay'}
                await db.execute(text('UPDATE decision_logs SET metadata=CAST(:data AS jsonb) WHERE id=:id'),{'id':ident,'data':json.dumps(data)})
                isolated+=1
    await engine.dispose()
    runtime=ROOT/'.local-lab/burp-runtime'; token=(runtime/'connector-token').read_text().strip()
    environment={**os.environ,'ARIA_BURP_CONNECTOR_TOKEN':token,'ARIA_BURP_TARGETS':'192.168.77.20',
        'ARIA_BURP_STATE_FILE':str(OUTPUT/'native-jobs.properties'),'ARIA_BURP_SET_SCOPE':'1'}
    native=['java','-Xmx768m','-Djava.awt.headless=true','-Djava.util.prefs.userRoot='+str(runtime/'prefs'),'-cp',str(ROOT/'.local-lab/burpsuite-community-2025.2.jar')+':'+str(ROOT/'burp-community/build/aria-community.jar'),'burp.StartBurp','--use-defaults','--disable-auto-update','--data-dir='+str(OUTPUT/'burp-data'),'--config-file='+str(runtime/'project.json'),'--developer-extension-class-name=aria.CommunityExtension']
    logs=[(OUTPUT/'api.log').open('w'),(OUTPUT/'native.log').open('w')]
    children=[]; results={'inherited_job_isolation':{'status':'passed','copied_jobs_fenced':isolated}}; errors=[]
    try:
        children.append(subprocess.Popen(native,cwd=ROOT,env=environment,stdout=logs[1],stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL))
        children.append(subprocess.Popen([str(ROOT/'.venv/bin/python'),'-B','-m','uvicorn','integration.staging_server:app','--host','127.0.0.1','--port','17004','--log-level','warning'],cwd=ROOT,stdout=logs[0],stderr=subprocess.STDOUT))
        async with httpx.AsyncClient(timeout=2,trust_env=False) as client:
            for _ in range(160):
                if any(p.poll() is not None for p in children): raise RuntimeError('Staging process exited; inspect private logs')
                try:
                    api=await client.get(BASE+'/api/health')
                    burp=await client.get('http://127.0.0.1:17777/capabilities',headers={'Authorization':'Bearer '+token})
                    if api.status_code==200 and burp.status_code==200: break
                except httpx.HTTPError: pass
                await asyncio.sleep(.25)
            else: raise RuntimeError('Staging readiness timeout')
        results['full_app_startup_revision_0003']='passed'
        async with async_playwright() as pw:
            with tempfile.TemporaryDirectory(prefix='aria-staging-firefox-') as profile:
                context=await pw.firefox.launch_persistent_context(profile,headless=True,viewport={'width':1440,'height':1000},accept_downloads=True)
                page=await context.new_page(); page.on('pageerror',lambda exc:errors.append(str(exc)))
                try:
                    login=dict(line.split(': ',1) for line in (ROOT/'.local-lab/login.txt').read_text().splitlines())
                    await page.goto(BASE+'/login'); await page.locator('#username').fill(login['Username']); await page.locator('#password').fill(login['Password']); await page.locator('#login-btn').click(); await page.wait_for_url(BASE+'/')
                    token=await page.evaluate("localStorage.getItem('pentestai_token')"); headers={'Authorization':'Bearer '+token}
                    async def api(path,method='get',data=None):
                        response=await getattr(context.request,method)(BASE+path,headers=headers,**({'data':data} if data is not None else {}))
                        assert response.ok,f'{method} {path}: {response.status}'
                        return await response.json()
                    sessions=(await api('/api/session/list'))['sessions']
                    original=0
                    for session in sessions:
                        if session['name'].startswith('Browser HTTP test') or session['name']=='Metasploitable manual test':
                            await page.locator('.session-item',has_text=session['name']).click()
                            saved=await api('/api/session/'+session['session_id']+'/restore')
                            assert saved['logs']
                            await expect(page.locator('#messages')).to_contain_text(next(x['content'].strip()[:60] for x in saved['logs'] if x['content'].strip()))
                            original+=1
                    assert original==4
                    results['owner_four_histories_on_new_backend']='passed'
                    session=await api('/api/session/new','post',{'name':'Full staging Community workflow','target':'192.168.77.20','scope':{'targets':['192.168.77.20'],'ports':[80],'web_authenticated_replay':True,'web_mutations':True,'web_request_budget':5}})
                    sid=session['session_id']; await page.evaluate('(sid)=>localStorage.setItem("current_session",sid)',sid); await page.reload()
                    await expect(page.locator('#session-name')).to_have_text('Full staging Community workflow')
                    # Provider-free observation via the real shared approval and worker path.
                    proposal=await api('/api/execution/proposals','post',{'session_id':sid,'command':'curl -I --max-time 10 http://192.168.77.20:80/','tool':'curl'})
                    if proposal['status']=='pending':
                        await api('/api/execution/'+proposal['action_id']+'/decision','post',{'session_id':sid,'decision':'approve'})
                    result=await api('/api/kali/execute','post',{'session_id':sid,'command':proposal['command'],'tool':'curl','action_id':proposal['action_id']})
                    assert result.get('exit_code')==0,result
                    results['real_worker_approved_observation']='passed'
                    for _ in range(60):
                        try:
                            async with httpx.AsyncClient(proxy='http://127.0.0.1:18081',timeout=10,trust_env=False) as proxy:
                                captured=await proxy.get('http://192.168.77.20/?aria_stage='+uuid.uuid4().hex)
                            break
                        except httpx.ConnectError: await asyncio.sleep(.25)
                    else: raise RuntimeError('Proxy listener unavailable')
                    await page.locator('[data-tab="burp"]').click()
                    await expect(page.locator('#tab-burp input[type=checkbox]').last).to_be_visible()
                    await page.locator('#tab-burp input[type=checkbox]').last.check()
                    await page.get_by_role('button',name='Import selected Proxy captures').click()
                    await expect(page.get_by_role('button',name='Stage in Repeater')).to_be_visible()
                    await page.get_by_role('button',name='Stage in Repeater').click(); await expect(page.locator('#toast-container')).to_contain_text('Request staged')
                    results['native_browser_capture_import_repeater']='passed'
                    async def reject(dialog): await dialog.dismiss()
                    page.once('dialog',reject); await page.get_by_role('button',name='Review exact replay').click()
                    await page.wait_for_timeout(200)
                    actions=await api('/api/burp/'+sid+'/replays'); assert actions['actions'][-1]['state']=='rejected'
                    async def approve(dialog): await dialog.accept()
                    page.once('dialog',approve); await page.get_by_role('button',name='Review exact replay').click()
                    await expect(page.locator('#tab-burp')).to_contain_text('completed',timeout=20000)
                    results['native_browser_rejection_approved_replay_comparison']='passed'
                    # Exercise JSON mutation editor and a second explicit confirmation.
                    async def mutate(dialog): await dialog.accept('{"method":"HEAD","path":"/?aria_stage_mutation=approved"}')
                    page.once('dialog',mutate)
                    await page.get_by_role('button',name='Review request changes').click()
                    page.once('dialog',approve)
                    await expect(page.locator('#tab-burp')).to_contain_text('HEAD',timeout=20000)
                    actions=await api('/api/burp/'+sid+'/replays')
                    for _ in range(80):
                        actions=await api('/api/burp/'+sid+'/replays')
                        if sum(x['state']=='completed' for x in actions['actions'])==2: break
                        await asyncio.sleep(.2)
                    assert sum(x['state']=='completed' for x in actions['actions'])==2,actions
                    results['native_browser_approved_mutation']='passed'
                    for fmt in ['html','markdown','latex','pdf']:
                        report=await api('/api/report/generate','post',{'session_id':sid,'format':fmt})
                        response=await context.request.get(BASE+'/api/report/download/'+report['filename'],headers=headers)
                        assert response.ok and len(await response.body())>100
                    await page.reload(); await expect(page.get_by_role('link',name='Download report')).to_have_count(4)
                    results['four_real_report_formats_download_restore']='passed'
                    for tab in ['hosts','findings','shells','creds','timeline','decisions','playbooks','burp']:
                        await page.locator('[data-tab="'+tab+'"]').click(); await page.wait_for_timeout(100)
                    assert not errors,errors
                    results['all_intel_tabs_and_javascript']='passed'
                    await page.screenshot(path=str(OUTPUT/'full-browser.png'),full_page=True)
                finally: await context.close()
    except Exception as exc:
        results['harness']='failed: '+str(exc); raise
    finally:
        for process in reversed(children):
            process.terminate()
            try: process.wait(timeout=8)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        for log in logs: log.close()
        (OUTPUT/'browser-report.json').write_text(json.dumps({'results':results,'javascript_errors':errors,'live_model_calls':0,'target':'192.168.77.20','port':80,'target_request_ceiling':4,'environment':'real API, staged PostgreSQL, Firefox, worker and official Community runtime'},indent=2))
    print(json.dumps(results,indent=2))

if __name__=='__main__': asyncio.run(main())
