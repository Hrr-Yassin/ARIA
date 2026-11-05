"""Firefox acceptance of the program-policy UI with synthetic API fixtures only."""
import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
from playwright.async_api import async_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'.local-lab/phase1-browser'
BASE='http://127.0.0.1:17002'


async def main():
    snapshot=json.loads(subprocess.check_output([str(ROOT/'.venv/bin/python'),'-c',
        'import tests, json; from tests.program_fixtures import policy_fixture; print(json.dumps(policy_fixture()[0]))'],cwd=ROOT))
    snapshot['source_text']+='\n<img src=x onerror=alert(1)>\n'
    history=[]
    requests=[]
    errors=[]
    OUTPUT.mkdir(parents=True,exist_ok=True)
    async def fixture(route):
        path=route.request.url.split(BASE)[-1].split('?')[0]
        body=route.request.post_data_json if route.request.method=='POST' else None
        requests.append({'path':path,'method':route.request.method})
        data={};code=200
        if path=='/api/session/list':data={'sessions':[{'session_id':'a','name':'Synthetic program','target':'app.example.test','phase':'scope'}]}
        elif path.endswith('/restore'):data={'logs':[],'has_more':False}
        elif path=='/api/session/a':data={'session_id':'a','name':'Synthetic program','target':'app.example.test','phase':'scope'}
        elif path.endswith('/autonomous/status'):data={'active':False}
        elif path.endswith('/kb-snapshot'):data={'hosts':[],'timeline':[]}
        elif path=='/api/capabilities':data={'worker':{'status':'online','available_tools':['curl','nmap']}}
        elif path=='/api/programs/a/history':data={'history':history}
        elif path=='/api/programs/catalog':data={'programs':[{'name':'Synthetic program','program_type':'disclosure_only','score':2,'unknown':['accessible_accounts'], 'fit':{'participation_eligibility':'unknown','basis':'Synthetic fit'},'prerequisites':snapshot['rules']['prerequisites']}]}
        elif path=='/api/programs/a/import-text':
            assert body['program_type']=='disclosure_only'
            history.append({'id':snapshot['id'],'type':'program_policy_snapshot','data':snapshot})
            data=snapshot
        elif path=='/api/programs/a/import-page':code,data=422,{'detail':'Public policy retrieval failed; use manual text import'}
        elif path.endswith('/review'):
            if body['decision']=='rejected':
                assert body['rules']==[] and body['execution'] is None
                data={'id':'rejected-review','decision':'rejected'}
            else:
                assert len(body['rules'])==6 and body['execution']['automation']=='allowed'
                assert all(snapshot['source_text'][r['start']:r['start']+len(r['quote'])]==r['quote'] for r in body['rules'])
                data={'id':'review','decision':'reviewed'}
        elif path.endswith('/activate'):
            assert body=={'review_id':'review','confirm':True}
            data={'state':'active'}
        elif path.endswith('/fit'):
            assert body['technical_fit']=='good' and body['participation_eligibility']=='unknown'
            data={'score':2}
        await route.fulfill(status=code,content_type='application/json',body=json.dumps(data))
    command=[str(ROOT/'.venv/bin/python'),'-B','-c',
             "import tests; import uvicorn; uvicorn.run('api.main:app',host='127.0.0.1',port=17002,lifespan='off',log_level='warning')"]
    with (OUTPUT/'server.log').open('w') as log,tempfile.TemporaryDirectory(prefix='aria-policy-browser-') as profile:
        server=subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen(BASE,timeout=1).close();break
                except OSError:await asyncio.sleep(.1)
            else:raise RuntimeError('Synthetic server did not start')
            async with async_playwright() as pw:
                context=await pw.firefox.launch_persistent_context(profile,headless=True,viewport={'width':1440,'height':1000})
                await context.route('**/api/**',fixture)
                page=await context.new_page()
                page.on('pageerror',lambda exc:errors.append(str(exc)))
                page.on('dialog',lambda dialog:asyncio.create_task(dialog.accept()))
                await page.goto(BASE+'/login')
                await page.evaluate("localStorage.setItem('pentestai_token','synthetic');localStorage.setItem('current_session','a')")
                await page.goto(BASE)
                await page.locator('#settings-button').click()
                await page.locator('#program-refresh').click()
                await expect(page.locator('#program-status')).to_contain_text('Import a policy')
                await page.get_by_text('Import official program policy',exact=True).click()
                await page.locator('#program-name').fill('Synthetic program')
                await page.locator('#program-url').fill('https://example.test/policy')
                await page.locator('#program-type').select_option('disclosure_only')
                await page.locator('#program-text').fill(snapshot['source_text'])
                await page.locator('#program-import-page').click()
                await expect(page.locator('#program-status')).to_contain_text('manual text import')
                await page.locator('#program-import-text').click()
                await expect(page.locator('#program-status')).to_contain_text('Revision 1')
                await page.get_by_text('Review and activate current policy',exact=True).click()
                await expect(page.locator('#program-source')).to_contain_text('<img src=x onerror=alert(1)>')
                assert await page.locator('#program-source img').count()==0
                for category in snapshot['rules']:
                    await page.locator('#program-interpretation-'+category).fill('Checked exact source and applicable limits')
                await page.locator('#program-assets').fill('app.example.test | /api | 443 | https')
                await page.locator('#program-exclusions').fill('app.example.test | /api/private | 443 | https')
                await page.locator('#program-automation').select_option('allowed')
                for key in ('accounts','prerequisites','permission'):await page.locator('#program-'+key).check()
                await page.locator('#program-note').fill('Synthetic human review')
                await page.locator('#program-review').click()
                await expect(page.locator('#program-status')).to_contain_text('Explicit activation is still required')
                await page.locator('#program-activate').click()
                await expect(page.locator('#program-status')).to_contain_text('Policy activated')
                await page.locator('#program-status').scroll_into_view_if_needed()
                await page.screenshot(path=str(OUTPUT/'policy-activated.png'),full_page=True)
                await page.get_by_text('Assess program fit',exact=True).click()
                await page.locator('#program-fit-technical_fit').select_option('good')
                await page.locator('#program-fit-basis').fill('Synthetic owned lab experience')
                await page.locator('#program-fit-save').click()
                await expect(page.locator('#program-catalog')).to_contain_text('Participation: unknown')
                await page.locator('#program-catalog').scroll_into_view_if_needed()
                await page.screenshot(path=str(OUTPUT/'program-shortlist.png'),full_page=True)
                await page.locator('#program-note').fill('Reject after synthetic review')
                await page.locator('#program-reject').click()
                await expect(page.locator('#program-status')).to_contain_text('Policy rejected')
                assert not errors,errors
                await context.close()
            (OUTPUT/'result.json').write_text(json.dumps({'status':'passed','checks':['manual_import','fetch_fallback','source_xss','source_linked_review','explicit_activation','fit_unknowns','human_rejection'],'page_errors':errors,'requests':requests},indent=2))
            print('Phase 1 Firefox acceptance passed: seven checks; no page errors')
        finally:
            server.terminate();server.wait(timeout=10)


if __name__=='__main__':asyncio.run(main())
