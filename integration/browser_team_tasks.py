"""Synthetic Firefox acceptance for durable team controls; no live model or jobs."""
import asyncio
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
from playwright.async_api import async_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.local-lab/phase2-browser'
BASE='http://127.0.0.1:17003'


async def main():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    view={'tasks':[],'evidence':[],'knowledge':[],'coverage':[],'cursor':0}
    budget={'limits':{'max_calls':20,'max_tokens':200000,'max_cost_microusd':1000000,'tariffs':[]},'usage':{},'attempts':[]}
    requests=[]; errors=[]
    objective='<img src=x onerror=alert(1)> Review saved evidence'
    async def fixture(route):
        path=route.request.url.split(BASE)[-1].split('?')[0]
        method=route.request.method
        body=route.request.post_data_json if method in {'POST','PUT'} else None
        requests.append({'path':path,'method':method})
        data={}
        if path=='/api/session/list':
            data={'sessions':[{'session_id':sid,'name':name,'target':'app.example.test','phase':'scope'} for sid,name in [('a','First engagement'),('b','Second engagement')]]}
        elif path in {'/api/session/a','/api/session/b'}:
            sid=path.rsplit('/',1)[1];data={'session_id':sid,'name':'First engagement' if sid=='a' else 'Second engagement','target':'app.example.test','phase':'scope'}
        elif path.endswith('/restore'):data={'logs':[],'has_more':False}
        elif path.endswith('/autonomous/status'):data={'active':False}
        elif path.endswith('/kb-snapshot'):data={'hosts':[],'timeline':[]}
        elif path=='/api/capabilities':data={'worker':{'status':'online','available_tools':['curl','nmap']}}
        elif path.endswith('/model-budget'):
            if method=='PUT':
                assert body['tariffs'][0]['microusd_per_million']==1000000
                assert body['max_cost_microusd']==1000000
                budget['limits']=body
            data=budget
        elif path=='/api/team/a':data=view
        elif path=='/api/team/b':data={'tasks':[],'evidence':[],'knowledge':[],'coverage':[],'cursor':0}
        elif path.endswith('/events'):data={'events':[],'cursor':view['cursor']}
        elif path=='/api/team/a/tasks':
            task={**body['task'],'id':'task-a','state':'queued','revision':1,'result':None}
            view['tasks'].append(task);view['cursor']+=1;data={'data':task}
        elif path.endswith('/tasks/task-a/run'):
            task=view['tasks'][0];task.update(state='awaiting_review',revision=2,result={'uncertainty':['No vulnerability is proven'],'evidence_references':[]})
            view['cursor']+=1;data={'data':task}
        elif path.endswith('/tasks/task-a/transition'):
            assert body['state']=='completed' and body['expected_revision']==2
            view['tasks'][0].update(state='completed',revision=3)
            view['cursor']+=1;data={'data':view['tasks'][0]}
        elif path.endswith('/evidence') and method=='POST':
            assert body['source_kind']=='worker' and body['source_id']=='worker-receipt'
            view['evidence'].append({'id':'evidence-a','summary':'HTTP response observation','trust':'untrusted_observation'})
            view['cursor']+=1;data={'data':view['evidence'][0]}
        elif path.endswith('/coverage') and method=='POST':
            assert body['status']=='blocked' and body['gap_reason']
            view['coverage'].append(body);view['cursor']+=1;data={'data':body}
        elif path.endswith('/knowledge') and method=='POST':
            assert body['uncertainty'] and body['disposition']=='rejected'
            view['knowledge'].append(body);view['cursor']+=1;data={'data':body}
        await route.fulfill(status=200,content_type='application/json',body=json.dumps(copy.deepcopy(data)))
    command=[str(ROOT/'.venv/bin/python'),'-B','-c',"import tests; import uvicorn; uvicorn.run('api.main:app',host='127.0.0.1',port=17003,lifespan='off',log_level='warning')"]
    with (OUTPUT/'server.log').open('w') as log,tempfile.TemporaryDirectory(prefix='aria-team-browser-') as profile:
        server=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try:urllib.request.urlopen(BASE,timeout=1).close();break
                except OSError:await asyncio.sleep(.1)
            else:raise RuntimeError('Synthetic browser server failed to start')
            async with async_playwright() as pw:
                context=await pw.firefox.launch_persistent_context(profile,headless=True,viewport={'width':1440,'height':1100})
                await context.route('**/api/**',fixture)
                page=await context.new_page()
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.on('dialog',lambda dialog:asyncio.create_task(dialog.accept('Reviewed synthetic result')))
                await page.goto(BASE+'/login')
                await page.evaluate("localStorage.setItem('pentestai_token','synthetic');localStorage.setItem('current_session','a')")
                await page.goto(BASE)
                await page.locator('#settings-button').click()
                await page.locator('#team-refresh').click()
                await expect(page.locator('#team-status')).to_contain_text('Saved event 0')
                await page.get_by_text('Create a task',exact=True).click()
                await page.locator('#team-objective').fill(objective)
                await page.locator('#team-create').click()
                await expect(page.locator('#team-tasks')).to_contain_text(objective)
                assert await page.locator('#team-tasks img').count()==0
                await page.get_by_role('button',name='Delegate analysis',exact=True).click()
                await expect(page.locator('#team-tasks')).to_contain_text('awaiting_review')
                await page.screenshot(path=str(OUTPUT/'task-awaiting-review.png'),full_page=True)
                await page.get_by_role('button',name='Mark reviewed and complete',exact=True).click()
                await expect(page.locator('#team-tasks')).to_contain_text('completed')
                await page.get_by_text('Evidence catalog',exact=True).click()
                await page.locator('#team-source-id').fill('worker-receipt')
                await page.locator('#team-catalog').click()
                await expect(page.locator('#team-evidence')).to_contain_text('evidence-a')
                await page.get_by_text('Coverage and gaps',exact=True).click()
                for name,value in [('team-coverage-key','auth'),('team-question','Are accounts isolated?'),('team-feature','API'),('team-gap','Account testing is Phase 3')]:
                    await page.locator('#'+name).fill(value)
                await page.locator('#team-coverage-state').select_option('blocked')
                await page.locator('#team-save-coverage').click()
                await expect(page.locator('#team-coverage')).to_contain_text('Account testing is Phase 3')
                await page.get_by_text('Observations and hypotheses',exact=True).click()
                await page.locator('#team-knowledge-text').fill('Rejected unsupported finding')
                await page.locator('#team-uncertainty').fill('No reproduction evidence')
                await page.locator('#team-disposition').select_option('rejected')
                await page.locator('#team-save-knowledge').click()
                await expect(page.locator('#team-knowledge')).to_contain_text('Rejected unsupported finding')
                await page.get_by_text('Shared model budget',exact=True).click()
                await page.locator('#team-model-name').fill('synthetic-model')
                await page.locator('#team-model-rate').fill('1')
                await page.locator('#team-save-budget').click()
                await expect(page.locator('#team-model-usage')).to_contain_text('synthetic-model')
                await page.locator('#team-panel').screenshot(path=str(OUTPUT/'team-ledger.png'))
                # Old engagement cards must not mutate the newly selected one.
                view['tasks'][0].update(state='queued',revision=4,result=None)
                await page.locator('#team-refresh').click()
                await expect(page.get_by_role('button',name='Delegate analysis',exact=True)).to_be_visible()
                old_action=await page.get_by_role('button',name='Delegate analysis',exact=True).element_handle()
                await page.locator('#settings-close').click()
                await page.get_by_text('Second engagement',exact=True).click()
                await page.locator('#settings-button').click()
                count=len([r for r in requests if r['path'].endswith('/run')])
                await expect(page.locator('#team-tasks')).to_be_empty()
                await old_action.evaluate('(el)=>el.click()')
                assert len([r for r in requests if r['path'].endswith('/run')])==count
                assert not any(r['path']=='/api/kali/execute' for r in requests)
                assert not errors,errors
                await context.close()
            report={'status':'passed','checks':['saved_tasks','source_xss','delegation_and_human_review','evidence_catalog','coverage_gaps','rejected_observations','model_budget','session_switch_guard','no_tool_dispatch'],'page_errors':errors}
            (OUTPUT/'result.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
        finally:
            server.terminate();server.wait(timeout=10)


if __name__=='__main__':asyncio.run(main())
