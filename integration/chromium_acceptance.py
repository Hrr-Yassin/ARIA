"""Visible Chromium acceptance against real local services; no fixture routes.

ARIA_CHROMIUM_ACCEPTANCE=1 PLAYWRIGHT_BROWSERS_PATH=/tmp/aria-playwright-browsers \
.local-lab/browser-venv/bin/python integration/chromium_acceptance.py
User selected blocked autonomous acceptance only; no model tariffs are added.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
from datetime import datetime, timezone
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://localhost:7000'
TARGET = '192.168.77.20'

AUDIT = r'''
import asyncio, hashlib, json, sys
from pathlib import Path
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine
from dotenv import dotenv_values
from memory.database_models import async_session, engine, PentestSession, DecisionLog
async def main():
    sid=sys.argv[1]
    async with async_session() as db:
        session=await db.get(PentestSession,sid)
        rows=(await db.execute(select(DecisionLog).where(DecisionLog.session_id==sid))).scalars().all()
        jobs=[r.metadata_ for r in rows if r.decision_type=='worker_job']
        data={'session_id':sid,'scope':session.scope,'worker_jobs':jobs,
              'model_usage':(session.metadata_ or {}).get('model_usage',{}),
              'model_attempt_count':sum(r.decision_type=='model_attempt' for r in rows),
              'authorizations':[{'id':r.id,'status':r.human_decision,'command':r.action_taken} for r in rows if r.decision_type=='execution_authorization']}
    await engine.dispose()
    worker=create_async_engine(dotenv_values('.local-lab/worker.env')['WORKER_DATABASE_URL'])
    async with worker.connect() as conn:
        receipts=await conn.scalars(text("SELECT record FROM aria_worker_jobs WHERE record->>'session_id'=:sid"),{'sid':sid})
        data['independent_worker_receipts']=[{'job_id':r['job_id'],'state':r['state'],'exit_code':r.get('exit_code'),
            'terminated':r.get('terminated'),'stdout_sha256':hashlib.sha256(r.get('stdout','').encode()).hexdigest(),
            'has_open_tcp80':'80/tcp' in r.get('stdout','') and 'open' in r.get('stdout',''),
            'plan':r.get('plan')} for r in receipts]
    await worker.dispose()
    print(json.dumps(data,default=str))
asyncio.run(main())
'''

async def main():
    if os.environ.get('ARIA_CHROMIUM_ACCEPTANCE') != '1':
        raise SystemExit('Set ARIA_CHROMIUM_ACCEPTANCE=1 to use real local services')
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out=ROOT/'.local-lab/chromium-acceptance'/stamp
    out.mkdir(parents=True,mode=0o700)
    report={'started_utc':stamp,'base':BASE,'headless':False,'browser':'Chromium',
            'mocked_routes':False,'target':TARGET,'tests':[],'javascript_errors':[],
            'console_errors':[],'network':[],'autonomous_policy':'blocked flow only; no paid calls'}
    login=dict(line.split(': ',1) for line in (ROOT/'.local-lab/login.txt').read_text().splitlines())
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(headless=False,slow_mo=200)
        context=await browser.new_context(viewport={'width':1440,'height':1000})
        page=await context.new_page()
        page.set_default_timeout(20000)
        page.on('pageerror',lambda exc:report['javascript_errors'].append(str(exc)[:500]))
        page.on('console',lambda msg:report['console_errors'].append(msg.text[:400]) if msg.type=='error' else None)
        page.on('response',lambda r:report['network'].append({'method':r.request.method,'path':r.url.removeprefix(BASE).split('?')[0],'status':r.status,'request_id':r.headers.get('x-request-id')}) if r.url.startswith(BASE) else None)
        page.on('requestfailed',lambda r:report['network'].append({'method':r.method,'path':r.url.split('?')[0],'failed':r.failure}) if r.url.startswith(BASE) else None)
        sid=None
        headers=None
        def save():
            (out/'report.json').write_text(json.dumps(report,indent=2,default=str))
        async def evidence(name,data):
            (out/(name+'.json')).write_text(json.dumps(data,indent=2,default=str))
        async def screenshot(name):
            await page.screenshot(path=str(out/(name+'.png')),full_page=True)
        async def get(path):
            response=await context.request.get(BASE+path,headers=headers)
            assert response.ok, (path,response.status)
            return await response.json()
        async def audit(name,session_id=None):
            proc=await asyncio.create_subprocess_exec(str(ROOT/'.venv/bin/python'),'-c',AUDIT,session_id or sid,cwd=ROOT,
                env={**os.environ,'DEBUG':'false'},stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            stdout,stderr=await proc.communicate()
            assert proc.returncode==0, stderr.decode()[-1000:]
            data=json.loads(stdout)
            await evidence(name,data)
            return data
        async def check(name,action):
            try:
                detail=await action()
                result={'test':name,'status':'passed','evidence':detail}
            except Exception as exc:
                result={'test':name,'status':'failed','error':type(exc).__name__+': '+str(exc)[:1200]}
            report['tests'].append(result)
            await screenshot(str(len(report['tests'])).zfill(2)+'-'+name)
            save()
            print(json.dumps(result),flush=True)
            return result['status']=='passed'
        try:
            async def login_ui():
                nonlocal headers
                await page.goto(BASE+'/login')
                await expect(page.get_by_label('Username')).to_be_visible()
                await page.get_by_label('Username').fill(login['Username'])
                await page.get_by_label('Password').fill(login['Password'])
                async with page.expect_response(lambda r:r.url.endswith('/api/login')) as pending:
                    await page.locator('#login-btn').click()
                response=await pending.value
                assert response.ok, 'Login HTTP '+str(response.status)
                await page.wait_for_url(BASE+'/')
                await expect(page.locator('#send-button')).to_be_visible()
                headers={'Authorization':'Bearer '+await page.evaluate("localStorage.getItem('pentestai_token')")}
                return {'login_http':response.status}
            if not await check('login',login_ui):raise RuntimeError('Login prerequisite failed')
            async def cancel_creation():
                before=await get('/api/session/list')
                page.once('dialog',lambda d:d.dismiss())
                await page.locator('#new-session-btn').click()
                after=await get('/api/session/list')
                assert before['total']==after['total']
                return {'session_count_unchanged':after['total']}
            await check('cancel-new-target',cancel_creation)
            async def new_target():
                nonlocal sid
                page.once('dialog',lambda d:d.accept(TARGET))
                async with page.expect_response(lambda r:r.url.endswith('/api/session/new')) as pending:
                    await page.locator('#new-session-btn').click()
                response=await pending.value
                assert response.ok
                created=await response.json();sid=created['session_id'];report['session_id']=sid
                await expect(page.locator('#target-value')).to_have_text(TARGET)
                persisted=await get('/api/session/'+sid)
                assert persisted['target']==TARGET and persisted['scope']['targets']==[TARGET]
                await evidence('created-session',persisted)
                return {'session_id':sid,'persisted_scope':persisted['scope']}
            if not await check('create-authorized-lab-target',new_target):raise RuntimeError('Target prerequisite failed')
            async def worker():
                await page.locator('#settings-button').click()
                await expect(page.locator('#execution-capabilities')).to_contain_text('Worker online')
                health=await get('/api/kali/health');assert health['status']=='online'
                await page.locator('#risk-threshold').select_option('green_only')
                await page.locator('#max-steps').fill('2')
                await page.locator('#settings-close').click()
                return health
            await check('configure-conservative-execution',worker)
            async def exclusion():
                await page.locator('#user-input').fill('scan http but do not scan ssh')
                async with page.expect_response(lambda r:r.url.endswith('/api/v8/input')) as pending:
                    await page.locator('#send-button').click()
                result=await (await pending.value).json()
                assert not result.get('commands'),result
                assert 'exclusion' in result.get('suggested_reply','')
                data=await audit('exclusion-ledger');assert not data['worker_jobs']
                await evidence('exclusion-response',result)
                return {'commands':0,'jobs':0}
            await check('ambiguous-exclusion-does-not-dispatch',exclusion)
            async def plan():
                await page.locator('#user-input').fill('scan http port 80 only')
                async with page.expect_response(lambda r:r.url.endswith('/api/v8/input')) as pending:
                    await page.locator('#send-button').click()
                result=await (await pending.value).json()
                commands=result.get('commands',[])
                assert len(commands)==1,result
                command=commands[0]['command']
                assert '-p 80 ' in command and TARGET in command and '-sT' in command and '-sC' not in command
                await evidence('tcp80-plan',result)
                await expect(page.locator('.cmd-btn-run').last).to_be_visible()
                data=await audit('plan-ledger');assert not data['worker_jobs']
                return {'command':command,'dispatch_before_run':0}
            if not await check('request-bounded-tcp80-probe',plan):raise RuntimeError('Probe plan prerequisite failed')
            async def execute():
                async with page.expect_response(lambda r:r.url.endswith('/api/kali/execute'),timeout=90000) as pending:
                    await page.locator('.cmd-btn-run').last.click()
                    await screenshot('probe-in-progress')
                response=await pending.value
                result=await response.json();await evidence('execution-response',result)
                assert response.ok and result.get('exit_code')==0,result
                assert '80/tcp' in result.get('stdout','') and 'open' in result.get('stdout','')
                await expect(page.locator('#messages')).to_contain_text('80/tcp')
                data=await audit('execution-ledger')
                receipts=data['independent_worker_receipts']
                assert len(receipts)==1 and receipts[0]['state']=='succeeded' and receipts[0]['terminated']
                assert receipts[0]['job_id']==result['job_id'] and receipts[0]['has_open_tcp80']
                assert receipts[0]['stdout_sha256']==hashlib.sha256(result['stdout'].encode()).hexdigest()
                assert data['worker_jobs'][0]['state']=='succeeded'
                return {'job_id':result['job_id'],'exit_code':0,'worker_output_matches_api':True,'receipt':'execution-ledger.json'}
            await check('execute-real-probe-and-correlate-worker-receipt',execute)
            async def restore():
                await expect(page.locator('#send-button')).to_be_enabled()
                await page.reload()
                await expect(page.locator('#target-value')).to_have_text(TARGET)
                await expect(page.locator('#messages')).to_contain_text('80/tcp')
                history=await get('/api/session/'+sid+'/restore')
                assert any('80/tcp' in row.get('content','') for row in history['logs'])
                await evidence('restored-history',history)
                return {'persisted_output':True,'message_count':len(history['logs'])}
            await check('reload-restores-real-output',restore)
            async def findings():
                await page.locator('[data-tab="hosts"]').click()
                hosts=await get('/api/pentest/'+sid+'/kb-snapshot')
                await evidence('kb-snapshot',hosts)
                await screenshot('hosts-after-probe')
                await page.locator('[data-tab="findings"]').click()
                data=await get('/api/findings/'+sid);await evidence('findings',data)
                assert data.get('findings'), 'Expected the saved service observation'
                assert all(f['severity']=='info' for f in data['findings']), 'Open ports must not be classified as vulnerabilities'
                assert all(not h.get('vulnerabilities') for h in hosts.get('hosts',[])), 'Open port became a KB vulnerability'
                await expect(page.locator('#tab-findings')).to_be_visible()
                await page.locator('[data-tab="decisions"]').click()
                decisions=await get('/api/pentest/'+sid+'/decision-log');await evidence('decision-log',decisions)
                assert any(row['type']=='worker_job' for row in decisions['entries'])
                return {'findings_total':data.get('total'),'hosts_count':len(hosts.get('hosts',[])),'decision_records':decisions.get('count'),'vulnerability_claim':'No finding claimed from an open port'}
            await check('inspect-hosts-findings-and-audit',findings)
            async def auto_blocked():
                before=await audit('before-autonomous')
                await page.locator('#settings-button').click()
                await page.locator('#max-steps').focus()
                await page.locator('#max-steps').press('Home')
                await page.locator('#max-steps').press('ArrowRight')
                await expect(page.locator('#max-steps')).to_have_value('2')
                await page.locator('#settings-close').click()
                await page.locator('#goal-select').select_option('http_check')
                async with page.expect_response(lambda r:'/autonomous/start' in r.url) as pending:
                    await page.locator('#auto-button').click()
                response=await pending.value;assert response.ok
                await evidence('autonomous-start',{'request':response.request.post_data_json,'response':await response.json()})
                for _ in range(120):
                    status=await get('/api/pentest/'+sid+'/autonomous/status')
                    if not status.get('active'):break
                    await asyncio.sleep(.5)
                else:raise AssertionError('Autonomous blocked flow did not terminate')
                await evidence('autonomous-status',status)
                assert response.request.post_data_json['max_steps']==2, 'Step budget not transmitted'
                assert status.get('run_state')=='blocked',status
                assert not status.get('successful_steps') and not status.get('evidence_job_ids')
                after=await audit('after-autonomous')
                assert len(after['worker_jobs'])==len(before['worker_jobs'])
                assert after['model_attempt_count']==0 and not after['model_usage'].get('calls',0)
                await expect(page.locator('#auto-label')).to_have_text('Auto mode')
                await expect(page.locator('#auto-log-counter')).to_have_text('step 0 / 2')
                return {'state':status['run_state'],'reason_code':status.get('reason_code'),'reason':status.get('reason'),'physical_model_calls':0,'new_worker_jobs':0}
            await check('autonomous-blocks-without-paid-model-calls',auto_blocked)
            async def inspect_reports():
                await page.locator('#settings-button').click()
                await page.locator('#reports-refresh').click()
                await expect(page.locator('#reports-status')).to_contain_text('Loaded')
                await page.locator('#team-refresh').click()
                await expect(page.locator('#team-status')).to_contain_text('Saved event')
                return {'report_status':await page.locator('#reports-status').inner_text(),'team_status':await page.locator('#team-status').inner_text()}
            await check('inspect-real-report-and-evidence-workspaces',inspect_reports)
            await page.locator('#settings-close').click()
            async def url_target():
                url='http://'+TARGET
                page.once('dialog',lambda d:d.accept(url))
                async with page.expect_response(lambda r:r.url.endswith('/api/session/new')) as pending:
                    await page.locator('#new-session-btn').click()
                response=await pending.value
                assert response.ok
                created=await response.json()
                report['url_session_id']=created['session_id']
                await expect(page.locator('#target-value')).to_have_text(url)
                await page.locator('#user-input').fill('scan http port 80 only')
                async with page.expect_response(lambda r:r.url.endswith('/api/v8/input')) as pending:
                    await page.locator('#send-button').click()
                result=await (await pending.value).json()
                await evidence('url-target-plan',result)
                commands=result.get('commands',[])
                assert len(commands)==1, 'URL target did not produce a bounded plan'
                import shlex
                argv=shlex.split(commands[0]['command'])
                assert argv[-1]==TARGET, 'Nmap received a URL instead of its host: '+argv[-1]
                async with page.expect_response(lambda r:r.url.endswith('/api/kali/execute'),timeout=90000) as pending:
                    await page.locator('.cmd-btn-run').last.click()
                response=await pending.value
                receipt=await response.json()
                await evidence('url-execution-response',receipt)
                assert response.ok and receipt.get('exit_code')==0, receipt
                assert '80/tcp' in receipt.get('stdout','')
                ledger=await audit('url-worker-ledger',created['session_id'])
                independent=ledger['independent_worker_receipts']
                assert len(independent)==1 and independent[0]['state']=='succeeded'
                assert independent[0]['job_id']==receipt['job_id'] and independent[0]['has_open_tcp80']
                assert independent[0]['stdout_sha256']==hashlib.sha256(receipt['stdout'].encode()).hexdigest()
                await page.locator('.session-item').filter(has_text=created['name']).first.wait_for()
                return {'session_id':created['session_id'],'target':url,'nmap_host':argv[-1],'job_id':receipt['job_id'],'worker_output_matches_api':True}
            await check('url-target-produces-host-based-scan',url_target)
            async def switch_back():
                sessions=await get('/api/session/list')
                original=next(s for s in sessions['sessions'] if s['session_id']==sid)
                await page.locator('.session-item').filter(has_text=original['name']).first.click()
                await expect(page.locator('#target-value')).to_have_text(TARGET)
                await expect(page.locator('#messages')).to_contain_text('80/tcp')
                await expect(page.locator('#auto-log-counter')).to_have_text('step 0 / 2')
                return {'session_id':sid,'restored_original_probe':True}
            await check('switch-back-restores-original-engagement',switch_back)
            await page.locator('[data-tab="findings"]').click()
            await screenshot('final-workspace')
            report['final_audit']=await audit('final-ledger')
        finally:
            report['finished_utc']=datetime.now(timezone.utc).isoformat()
            save()
            print('EVIDENCE_DIRECTORY='+str(out),flush=True)
            # Gracefully close only this new acceptance browser, never personal browsers.
            await browser.close()
    if any(test['status']=='failed' for test in report['tests']):raise SystemExit(1)

if __name__=='__main__':asyncio.run(main())
