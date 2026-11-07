"""Opt-in real-deployment UI review; no model calls or target execution.

ARIA_LIVE_REVIEW=1 .local-lab/browser-venv/bin/python integration/browser_live_review.py
Creates one labelled engagement through the UI; keeps artifacts private.
"""
import asyncio
import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://127.0.0.1:7000'
OUT = ROOT / '.local-lab/live-review-2026-11-07'

async def main():
    if os.environ.get('ARIA_LIVE_REVIEW') != '1':
        raise SystemExit('Set ARIA_LIVE_REVIEW=1 to test the running deployment')
    OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    login = dict(line.split(': ', 1) for line in (ROOT / '.local-lab/login.txt').read_text().splitlines())
    results, errors, failures = [], [], []
    async with async_playwright() as pw:
        browser = await pw.firefox.launch(headless=True)
        context = await browser.new_context(viewport={'width':1440,'height':1000})
        page = await context.new_page()
        page.set_default_timeout(12000)
        page.on('pageerror', lambda exc: errors.append(str(exc)[:200]))
        page.on('response', lambda response: failures.append({'status':response.status,'path':response.url.split('?')[0]}) if response.status >= 500 else None)
        async def check(name, action):
            try:
                detail = await action()
                results.append({'test':name, 'status':'passed', 'detail':detail})
            except Exception as exc:
                results.append({'test':name, 'status':'failed', 'detail':str(exc)[:700]})
                await page.screenshot(path=str(OUT / ('failure-'+str(len(results))+'.png')), full_page=True)
            print(json.dumps(results[-1]), flush=True)
        try:
            async def login_flow():
                await page.goto(BASE+'/login')
                await page.locator('#username').fill(login['Username'])
                await page.locator('#password').fill(login['Password'])
                await page.locator('#login-btn').click()
                await page.wait_for_url(BASE+'/')
                await expect(page.locator('#send-button')).to_be_visible()
            await check('real login and workspace', login_flow)
            async def create():
                async def target(dialog): await dialog.accept('https://example.invalid')
                page.once('dialog', target)
                await page.locator('#new-session-btn').click()
                await expect(page.locator('#session-name')).to_contain_text('Session ')
                sid = await page.evaluate("localStorage.getItem('current_session')")
                assert sid
                return {'session_id':sid, 'target':'https://example.invalid', 'execution':False}
            await check('create engagement through native prompt', create)
            async def reload():
                name = await page.locator('#session-name').inner_text()
                await page.reload()
                await expect(page.locator('#session-name')).to_have_text(name)
                await expect(page.locator('#messages')).to_contain_text('No saved messages')
            await check('reload preserves new engagement and empty history', reload)
            async def tabs():
                for tab in ['hosts','findings','shells','creds','timeline','decisions','playbooks','burp']:
                    await page.locator('[data-tab="'+tab+'"]').click()
                    await expect(page.locator('#tab-'+tab)).to_be_visible()
                await page.screenshot(path=str(OUT/'workspace-desktop.png'), full_page=True)
            await check('all eight intelligence tabs', tabs)
            async def settings():
                await page.locator('#settings-button').click()
                await expect(page.locator('#execution-capabilities')).not_to_contain_text('Checking')
                return await page.locator('#execution-capabilities').inner_text()
            await check('settings and live worker capabilities', settings)
            for button, status in [('team-refresh','team-status'),('reports-refresh','reports-status'),('program-refresh','program-status')]:
                async def load(button=button,status=status):
                    async with page.expect_response(lambda r: '/api/' in r.url and r.request.method=='GET' and r.status==200):
                        await page.locator('#'+button).click()
                    await page.wait_for_timeout(600)
                    text = await page.locator('#'+status).inner_text()
                    assert not any(word in text.lower() for word in ['failed','error','unavailable']), text
                    return text
                await check(button+' real saved data', load)
            async def mobile():
                await page.set_viewport_size({'width':390,'height':844})
                await page.screenshot(path=str(OUT/'settings-mobile.png'), full_page=True)
                sizes = await page.evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth})')
                assert sizes['scroll'] <= sizes['width'], sizes
                await page.locator('#settings-close').click()
                await page.screenshot(path=str(OUT/'workspace-mobile.png'), full_page=True)
                sizes = await page.evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth})')
                assert sizes['scroll'] <= sizes['width'], sizes
            await check('390px mobile settings and workspace overflow', mobile)
            async def logout():
                await page.set_viewport_size({'width':1440,'height':1000})
                await page.locator('#settings-button').click()
                await page.locator('#logout-button').click()
                await page.wait_for_url(re.compile(re.escape(BASE) + r'/login(?:\.html)?$'))
                assert not await page.evaluate("localStorage.getItem('pentestai_token')")
                await page.goto(BASE+'/')
                await page.wait_for_url(re.compile(re.escape(BASE) + r'/login(?:\.html)?$'))
            await check('sign out clears token and protects workspace', logout)
        finally:
            await browser.close()
            report={'date':datetime.now(timezone.utc).isoformat(), 'base':BASE,'browser':'Firefox','tests':results,'javascript_errors':errors,'server_errors':failures,'model_calls':0,'target_requests':0}
            (OUT/'report.json').write_text(json.dumps(report,indent=2))
    if errors or failures or any(r['status']=='failed' for r in results):
        raise SystemExit(1)

if __name__ == '__main__':
    asyncio.run(main())
