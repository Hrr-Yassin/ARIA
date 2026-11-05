"""Real Firefox, synthetic API fixtures, disposable server/profile; no lab execution.
Run: .local-lab/browser-venv/bin/python integration/browser_reliability.py
Artifacts: .local-lab/reliability-browser/ (screenshots, requests and result JSON).
"""
import asyncio
import json
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.local-lab/reliability-browser'
BASE = 'http://127.0.0.1:17001'


async def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    results, requests, errors = {}, [], []
    sessions = [{'session_id': key, 'name': name, 'target':'192.0.2.1', 'phase':'scope'}
        for key, name in [('a','Saved Alpha'),('b','Saved Beta'),('c','Empty legacy'),('d','Retry history')]]
    failed = True
    slow = False
    worker_status = 'online'
    async def fixture(route):
        nonlocal failed, slow
        path = route.request.url.split(BASE)[-1].split('?')[0]
        requests.append({'method':route.request.method, 'path':path})
        data = {}
        status = 200
        if path == '/api/session/list': data = {'sessions':sessions}
        elif path == '/api/capabilities':
            if worker_status == 'error':
                status, data = 503, {'detail':'fixture unavailable'}
            else:
                data = {'worker':{'status':worker_status, 'available_tools':['curl','nmap'] if worker_status == 'online' else []}}
        elif path.startswith('/api/session/'):
            sid = path.split('/')[3]
            session = next((s for s in sessions if s['session_id'] == sid), {})
            data = session
            if path.endswith('/restore'):
                if sid == 'a' and slow: await asyncio.sleep(0.4)
                if sid == 'd' and failed:
                    status, data = 503, {'detail':'fixture database unavailable'}
                else:
                    data = {'logs':[] if sid == 'c' else [{'role':'user','content':session['name']+' prompt'},
                        {'role':'assistant','content':session['name']+' response'}], 'has_more':False}
        elif path.endswith('/autonomous/status'): data = {'active':False}
        elif path.endswith('/kb-snapshot'): data = {'hosts':[], 'timeline':[]}
        await route.fulfill(status=status, content_type='application/json', body=json.dumps(data))

    command = [str(ROOT/'.venv/bin/python'), '-B', '-c',
        "import tests; import uvicorn; uvicorn.run('api.main:app', host='127.0.0.1', port=17001, lifespan='off', log_level='warning')"]
    with (OUTPUT/'server.log').open('w') as log, tempfile.TemporaryDirectory(prefix='aria-firefox-') as profile:
        server = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(BASE, timeout=1): break
                except OSError: await asyncio.sleep(0.1)
            else: raise RuntimeError('Disposable server did not start')
            async with async_playwright() as pw:
                async def open_profile():
                    context = await pw.firefox.launch_persistent_context(profile, headless=True, viewport={'width':1440,'height':1000})
                    await context.route('**/api/**', fixture)
                    page = await context.new_page()
                    page.on('pageerror', lambda exc: errors.append(str(exc)))
                    page.on('request', lambda req: requests.append({'method':req.method,'path':req.url.split(BASE)[-1]}) if '/static/' in req.url else None)
                    return context, page
                context, page = await open_profile()
                await page.goto(BASE+'/login')
                await page.evaluate("localStorage.setItem('pentestai_token','synthetic-fixture'); localStorage.setItem('current_session','a')")
                await page.goto(BASE)
                await expect(page.locator('#messages')).to_contain_text('Saved Alpha response')
                for worker_status, expected in [('online','curl, nmap'), ('not_configured','not configured'),
                                                ('unreachable','unreachable'), ('error','could not be loaded')]:
                    await page.locator('#settings-button').click()
                    await expect(page.locator('#execution-capabilities')).to_contain_text(expected)
                    await expect(page.locator('#settings-panel')).to_contain_text('Tools mentioned by agents are proposals')
                    await page.screenshot(path=str(OUTPUT/('capabilities-'+worker_status+'.png')), full_page=True)
                    await page.locator('#settings-close').click()
                results['capability_availability_and_failure_states'] = 'passed'
                results['fresh_profile_history'] = 'passed'
                await page.screenshot(path=str(OUTPUT/'fresh-history.png'), full_page=True)
                await page.locator('.session-item', has_text='Saved Beta').click()
                await expect(page.locator('#messages')).to_contain_text('Saved Beta response')
                await expect(page.locator('#messages')).not_to_contain_text('Saved Alpha')
                results['session_isolation'] = 'passed'
                await page.locator('.session-item', has_text='Empty legacy').click()
                await expect(page.locator('#messages')).to_contain_text('No saved messages')
                results['empty_history_visible'] = 'passed'
                await page.screenshot(path=str(OUTPUT/'empty-history.png'), full_page=True)
                await page.locator('.session-item', has_text='Retry history').click()
                await expect(page.locator('#messages')).to_contain_text('History could not be loaded')
                await page.screenshot(path=str(OUTPUT/'failed-history.png'), full_page=True)
                failed = False
                await page.get_by_role('button', name='History could not be loaded. Click to retry.').click()
                await expect(page.locator('#messages')).to_contain_text('Retry history response')
                results['history_failure_retry'] = 'passed'
                slow = True
                await page.locator('.session-item', has_text='Saved Alpha').click()
                await page.locator('.session-item', has_text='Saved Beta').click()
                await expect(page.locator('#messages')).to_contain_text('Saved Beta response')
                await page.wait_for_timeout(600)
                await expect(page.locator('#messages')).not_to_contain_text('Saved Alpha')
                results['stale_restore_ignored'] = 'passed'
                await page.reload()
                await expect(page.locator('#messages')).to_contain_text('Saved Beta response')
                results['refresh_history'] = 'passed'
                await context.close()
                context, page = await open_profile()
                await page.goto(BASE)
                await expect(page.locator('#messages')).to_contain_text('Saved Beta response')
                results['warm_profile_browser_restart'] = 'passed'
                await page.screenshot(path=str(OUTPUT/'warm-history.png'), full_page=True)
                await context.close()
            assets = [r['path'] for r in requests if '/static/' in r['path']]
            assert assets and all('?v=' in path for path in assets), assets
            results['content_hash_asset_urls'] = 'passed'
            assert not errors, errors
            results['javascript_errors'] = 'passed'
        except Exception as exc:
            results['harness'] = 'failed: '+str(exc)
            raise
        finally:
            server.terminate()
            server.wait(timeout=10)
            report = {'environment':'real Firefox; mocked API; disposable server and browser profiles',
                'results':results, 'page_errors':errors, 'live_model_calls':0, 'live_model_tokens':0,
                'limitations':['No database outage integration', 'No active lab scan', 'No Burp integration',
                    'Cache-warmed browser tested; an actual two-build deployment upgrade remains untested']}
            (OUTPUT/'report.json').write_text(json.dumps(report, indent=2))
            (OUTPUT/'requests.json').write_text(json.dumps(requests, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__': asyncio.run(main())
