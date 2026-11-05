"""Read-only history audit on the owner's running deployment (login plus GETs).
Never submits prompts, proposals, scans, settings changes, or session mutations.
"""
import asyncio
import json
import tempfile
from pathlib import Path
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT/'.local-lab/owner-history-audit'
BASE = 'http://127.0.0.1:7000'


async def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    login = dict(line.split(': ', 1) for line in (ROOT/'.local-lab/login.txt').read_text().splitlines())
    results, requests, errors = [], [], []
    async with async_playwright() as pw:
        with tempfile.TemporaryDirectory(prefix='aria-owner-history-') as profile:
            for profile_state in ['fresh', 'cache_warmed']:
                context = await pw.firefox.launch_persistent_context(profile, headless=True, viewport={'width':1440,'height':1000})
                page = await context.new_page()
                page.on('pageerror', lambda exc: errors.append(str(exc)))
                page.on('request', lambda req: requests.append({'method':req.method,'path':req.url.split(BASE)[-1].split('?')[0]}))
                try:
                    if profile_state == 'fresh':
                        await page.goto(BASE+'/login')
                        await page.locator('#username').fill(login['Username'])
                        await page.locator('#password').fill(login['Password'])
                        await page.locator('#login-btn').click()
                        await page.wait_for_url(BASE+'/')
                    else: await page.goto(BASE)
                    token = await page.evaluate("localStorage.getItem('pentestai_token')")
                    headers = {'Authorization':'Bearer '+token}
                    response = await context.request.get(BASE+'/api/session/list', headers=headers)
                    assert response.ok
                    sessions = (await response.json())['sessions']
                    selected = [s for s in sessions if s['name'].startswith('Browser HTTP test') or s['name']=='Metasploitable manual test']
                    assert selected
                    for index, session in enumerate(selected):
                        sid = session['session_id']
                        restore = await context.request.get(BASE+'/api/session/'+sid+'/restore', headers=headers)
                        assert restore.ok
                        logs = (await restore.json())['logs']
                        await page.locator('.session-item', has_text=session['name']).click()
                        await expect(page.locator('#session-name')).to_have_text(session['name'])
                        if logs:
                            # Assert saved text appears; do not put contents in the report.
                            for entry in logs:
                                if entry.get('content', '').strip():
                                    await expect(page.locator('#messages')).to_contain_text(entry['content'].strip()[:60])
                                    break
                        else: await expect(page.locator('#messages')).to_contain_text('No saved messages')
                        await page.locator('#messages').evaluate("e => Promise.all(e.getAnimations({subtree:true}).map(a => a.finished.catch(() => {})))")
                        await page.screenshot(path=str(OUTPUT/f'{profile_state}-{index}.png'), full_page=True)
                        results.append({'profile':profile_state, 'session_id':sid, 'name':session['name'],
                            'saved_messages':len(logs), 'rendering':'passed' if logs else 'empty state passed'})
                    await page.reload()
                    await expect(page.locator('#session-name')).to_have_text(selected[-1]['name'])
                    assert not errors, errors
                finally:
                    await context.close()
    (OUTPUT/'report.json').write_text(json.dumps({'results':results,'javascript_errors':errors,
        'live_model_calls':0,'mutations':'login only; all application reads',
        'limitation':'Running backend was not restarted or migrated; new backend deployment remains unverified here.'},indent=2))
    (OUTPUT/'requests.json').write_text(json.dumps(requests, indent=2))
    print(json.dumps({'sessions_checked':len(results), 'javascript_errors':errors}, indent=2))


if __name__ == '__main__': asyncio.run(main())
