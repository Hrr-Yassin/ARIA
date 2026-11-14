"""Chromium acceptance with real HTTP/SQL persistence and no paid inference.

Run with .venv/bin/python -m integration.openrouter_budget_browser.
Creates a guarded disposable *_test PostgreSQL database, mocks only provider
discovery there, and preserves the real 7002 engagement's existing approval.
Screenshots and sanitized results are private; no browser trace stores credentials.
"""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import asyncpg
import httpx
from playwright.async_api import async_playwright, expect
from sqlalchemy import select
from sqlalchemy.engine import make_url

from config.settings import settings
from memory.database_models import async_session, engine, PentestSession, User, ChatLog

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / '.local-lab/openrouter-activation'
REAL_SID = '1f2e2cd2-c37d-4c00-a1ba-5134705f89dd'


async def workspace(browser, base, token, sid, name):
    context = await browser.new_context(viewport={'width': 1500, 'height': 1100})
    # Real acceptance must never submit approval, tool execution or inference.
    if base.endswith(':7002'):
        async def deny_mutations(route):
            request = route.request
            if request.method not in {'GET', 'HEAD'}:
                await route.abort()
            else:
                await route.continue_()
        await context.route('**/api/**', deny_mutations)
    page = await context.new_page()
    await page.goto(base + '/login')
    await page.evaluate('([token,sid])=>{localStorage.setItem("pentestai_token",token);localStorage.setItem("current_session",sid)}', [token, sid])
    await page.goto(base)
    await page.locator('.session-item').filter(has_text=name).first.click()
    await page.locator('#settings-button').click()
    await page.locator('#team-refresh').click()
    await expect(page.locator('#team-status')).to_contain_text('Saved event')
    await page.get_by_text('Shared model budget', exact=True).click()
    return context, page


async def browser_api(page, path, method='GET', body=None):
    return await page.evaluate('''async ([path,method,body])=>{
      const r=await fetch(path,{method,headers:{Authorization:'Bearer '+localStorage.getItem('pentestai_token'),
        'Content-Type':'application/json'},...(body===null?{}:{body:JSON.stringify(body)})});
      return {status:r.status,data:await r.json()};}''', [path, method, body])


async def main():
    OUT.mkdir(parents=True, exist_ok=True)
    report = {'chromium_sandbox': True, 'paid_inference_calls': 0, 'checks': []}
    # Existing private bearer token is used only in memory and browser storage.
    token = json.loads((ROOT / '.local-lab/intelligence/auth.json').read_text())['token']
    async with async_session() as db:
        session = await db.get(PentestSession, REAL_SID)
        real_name = session.name
        real_metadata = dict(session.metadata_ or {})
    admin_url = make_url(settings.DATABASE_URL)
    db_name = 'aria_budget_' + uuid.uuid4().hex[:10] + '_test'
    connection = await asyncpg.connect(admin_url.set(drivername='postgresql').render_as_string(hide_password=False))
    await connection.execute('CREATE DATABASE "' + db_name + '"')
    await connection.close()
    fixture_url = admin_url.set(database=db_name).render_as_string(hide_password=False)
    env = {**os.environ, 'DATABASE_URL': fixture_url, 'ARIA_BUDGET_FIXTURE': '1'}
    report['fixture_database'] = db_name
    with (OUT / 'fixture-server.log').open('w') as log:
        subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'], cwd=ROOT, env=env, stdout=log, stderr=log, check=True)
        # Seed only synthetic identities and an empty engagement in the test DB.
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
        from api.auth import create_token
        test_engine = create_async_engine(fixture_url)
        factory = async_sessionmaker(test_engine, expire_on_commit=False)
        sid, owner, source = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
        async with factory() as db:
            user = User(id=owner, username='budget-fixture', password_hash='unused')
            db.add(user); await db.flush()
            other = User(id=str(uuid.uuid4()), username='other-budget-owner', password_hash='unused')
            db.add(other); await db.flush()
            db.add(PentestSession(id=sid, user_id=owner, name='Synthetic budget acceptance', target='192.0.2.2', scope={'targets':['192.0.2.2']}))
            await db.flush()
            db.add(ChatLog(id=source,session_id=sid,role='tool_output',msg_type='synthetic_lab',
                content='Synthetic owner control; no target was contacted.'))
            await db.commit()
            test_token = create_token(owner, user.username, user.role.value, user.skill_level.value)
            other_token = create_token(other.id, other.username, other.role.value, other.skill_level.value)
        server = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'integration.openrouter_budget_fixture:app', '--host', '127.0.0.1', '--port', '17012', '--lifespan', 'off'], cwd=ROOT, env=env, stdout=log, stderr=log)
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                for _ in range(100):
                    try:
                        if (await client.get('http://127.0.0.1:17012/')).is_success: break
                    except httpx.HTTPError: pass
                    await asyncio.sleep(.1)
                else: raise RuntimeError('Fixture did not start')
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, chromium_sandbox=True)
                try:
                    ctx, page = await workspace(browser, 'http://127.0.0.1:17012', test_token, sid, 'Synthetic budget acceptance')
                    await expect(page.locator('#team-save-budget')).to_be_disabled()
                    report['checks'].append('missing tariff blocks approval in UI')
                    # Server also rejects a forged tariff even if a client bypasses UI.
                    forged={'max_calls':1,'max_tokens':200000,'max_cost_microusd':2000000,'tariffs':[{'provider':'openrouter','model':settings.OPENROUTER_MODEL,'microusd_per_million':1}]}
                    assert (await browser_api(page, '/api/team/'+sid+'/model-budget', 'PUT', forged))['status']==409
                    await browser_api(page, '/_fixture/'+sid+'/failure', 'POST')
                    await page.locator('#team-refresh-tariff').click()
                    await expect(page.locator('#team-status')).to_contain_text('Mock provider unavailable')
                    await expect(page.locator('#team-save-budget')).to_be_disabled()
                    report['checks'].append('provider failure visible and approval blocked')
                    await browser_api(page, '/_fixture/'+sid+'/ok', 'POST')
                    await page.locator('#team-refresh-tariff').click()
                    await expect(page.locator('#team-refresh-tariff')).to_be_disabled()
                    await expect(page.locator('#team-status')).to_contain_text('Tariff verified')
                    await expect(page.locator('#team-effective-tariff')).to_contain_text('output $0.18/M')
                    await page.locator('#team-model-calls').fill('1')
                    await page.locator('#team-model-cost').fill('2')
                    # Invalid data must be rejected by the real API and shown in UI.
                    await page.locator('#team-model-tokens').fill('-1')
                    await page.locator('#team-save-budget').click()
                    await expect(page.locator('#team-status')).to_contain_text('greater than or equal to 0')
                    await page.locator('#team-model-tokens').fill('200000')
                    await page.locator('#team-save-budget').click()
                    await expect(page.locator('#team-budget-approval')).to_contain_text('Saved approval: $2.00')
                    await page.locator('#team-panel').screenshot(path=str(OUT/'synthetic-approved.png'))
                    await page.reload()
                    await page.locator('#settings-button').click()
                    await page.locator('#team-refresh').click()
                    await expect(page.locator('#team-budget-approval')).to_contain_text('Saved approval: $2.00')
                    report['checks'].append('browser approval persists $2 ceiling after reload')
                    assert (await browser_api(page, '/_fixture/'+sid+'/call', 'POST'))['status']==200
                    assert (await browser_api(page, '/_fixture/'+sid+'/call', 'POST'))['status']==429
                    ledger=(await browser_api(page, '/api/team/'+sid+'/model-budget'))['data']
                    assert ledger['usage']['calls']==1 and ledger['usage']['reported_cost_microusd']==1
                    report['checks'].append('SQL reservation settlement and call ceiling enforced')
                    await page.get_by_text('Shared model budget', exact=True).click()
                    await page.locator('#team-model-calls').fill('20')
                    await page.locator('#team-model-cost').fill('0.000001')
                    await page.locator('#team-save-budget').click()
                    await expect(page.locator('#team-budget-approval')).to_contain_text('Saved approval')
                    assert (await browser_api(page, '/_fixture/'+sid+'/call', 'POST'))['status']==429
                    retained=(await browser_api(page, '/api/team/'+sid+'/model-budget'))['data']
                    assert retained['usage']==ledger['usage']
                    report['checks'].append('cost ceiling denies further reservations; lowering limits retains usage')
                    # Unknown and altered quotes are rejected by the actual API.
                    invalid={**retained['limits'], 'tariffs':[dict(retained['limits']['tariffs'][0])]}
                    invalid['tariffs'][0]['model']='unknown/model'
                    assert (await browser_api(page, '/api/team/'+sid+'/model-budget','PUT',invalid))['status']==409
                    invalid['tariffs'][0]={**retained['limits']['tariffs'][0], 'microusd_per_million':1}
                    assert (await browser_api(page, '/api/team/'+sid+'/model-budget','PUT',invalid))['status']==409
                    async with httpx.AsyncClient(trust_env=False, headers={'Authorization':'Bearer '+other_token}) as outsider:
                        for suffix,method in [('/model-budget','GET'),('/model-budget','PUT'),('/model-tariff/refresh','POST')]:
                            result=await outsider.request(method,'http://127.0.0.1:17012/api/team/'+sid+suffix,
                                **({'json':retained['limits']} if method=='PUT' else {}))
                            assert result.status_code in (403,404)
                    report['checks'].append('unknown model and altered price rejected; other owner denied read refresh and approval')
                    await browser_api(page, '/_fixture/'+sid+'/stale', 'POST')
                    assert (await browser_api(page, '/_fixture/'+sid+'/call', 'POST'))['status']==409
                    await page.locator('#team-refresh').click()
                    await expect(page.locator('#team-save-budget')).to_be_disabled()
                    report['checks'].append('stale tariff blocks UI and backend')
                    catalog=await browser_api(page, '/api/team/'+sid+'/evidence', 'POST',
                        {'request_id':str(uuid.uuid4()),'source_kind':'chat','source_id':source})
                    assert catalog['status']==200, catalog
                    ref=catalog['data']['data']['id']
                    candidate={'title':'Synthetic ownership investigation <img>',
                        'claim':'A controlled outsider may read an owner object',
                        'supporting_evidence':[ref],'alternative_explanations':['The response may be generic public content'],
                        'prerequisites':['Two controlled identities'],'validation_strategy':'Compare original private content under both identities',
                        'positive_controls':['Owner can read the object'],'negative_controls':['Missing object has no private content'],
                        'confidence':.2,'uncertainty':['Independent reproduction pending']}
                    created=await browser_api(page, '/api/team/'+sid+'/research/hypotheses', 'POST',
                        {'request_id':str(uuid.uuid4()),'hypothesis':candidate})
                    assert created['status']==200, created
                    await page.locator('#team-refresh').click()
                    await page.get_by_text('Persistent research',exact=True).click()
                    await expect(page.locator('#team-research')).to_contain_text(candidate['title'])
                    await expect(page.locator('#team-research')).to_contain_text('Unverified research.')
                    assert await page.locator('#team-research img').count()==0
                    await page.locator('#team-research').screenshot(path=str(OUT/'synthetic-research.png'))
                    await page.reload()
                    await page.locator('#settings-button').click()
                    await page.locator('#team-refresh').click()
                    await expect(page.locator('#team-research')).to_contain_text(candidate['title'])
                    report['checks'].append('research API and UI persist hypothesis evidence controls history and render untrusted text safely')
                    await ctx.close()

                    ctx, page = await workspace(browser, 'http://127.0.0.1:7002', token, REAL_SID, real_name)
                    await expect(page.locator('#team-model-provider')).to_have_value('openrouter')
                    await expect(page.locator('#team-model-name')).to_have_value(settings.OPENROUTER_MODEL)
                    expected = 'Saved approval: $2.00' if real_metadata.get('model_budget_approved_at') else 'Pending owner approval'
                    await expect(page.locator('#team-budget-approval')).to_contain_text(expected)
                    await page.locator('#team-panel').screenshot(path=str(OUT/'real-current-budget.png'))
                    await page.reload()
                    await page.locator('#settings-button').click()
                    await page.locator('#team-refresh').click()
                    await expect(page.locator('#team-budget-approval')).to_contain_text(expected)
                    budget=(await browser_api(page, '/api/team/'+REAL_SID+'/model-budget'))['data']
                    assert budget['approved_at'] == real_metadata.get('model_budget_approved_at')
                    assert budget['limits'] == real_metadata.get('model_limits', budget['limits'])
                    report['real_tariff']=budget['tariff_quotes'][settings.OPENROUTER_MODEL]
                    report['checks'].append('real persisted tariff and approval survive UI reload; all real mutations blocked')
                    await ctx.close()
                finally: await browser.close()
            report['status']='passed'
        finally:
            server.terminate(); server.wait(timeout=15)
            await test_engine.dispose()
            await engine.dispose()
            (OUT/'browser-result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__': asyncio.run(main())
