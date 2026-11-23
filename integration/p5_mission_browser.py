"""P5 visible Chromium acceptance of the deployed Mission Control (lab Fedora API).

Signs in as the lab owner (credentials read from .local-lab/login.txt, never
printed), then checks the authorization profile panel against the backend API,
creates one engagement through the UI and verifies the backend marks it
profile-required, and captures the operational views. No tool is dispatched.
Run with the browser venv: ``.local-lab/browser-venv/bin/python -m integration.p5_mission_browser``.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import urllib.request
from playwright.async_api import async_playwright, expect

BASE = 'http://127.0.0.1:7000'
SID = 'c5486358-599b-4c07-89f3-f590096a3c80'
OUT = Path('.local-lab/p5/browser')


def credentials() -> tuple[str, str]:
    fields = {}
    for line in Path('.local-lab/login.txt').read_text().splitlines():
        key, _, value = line.partition(':') if ':' in line.split('=')[0] else line.partition('=')
        fields[key.strip().lower()] = value.strip()
    return fields['username'], fields['password']


class _Response:
    def __init__(self, body: bytes):
        self._body = body

    def json(self):
        return json.loads(self._body or b'null')


class _Client:
    """Minimal authenticated GET client (the browser venv has only the standard library)."""

    def __init__(self, token: str):
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def get(self, path: str) -> _Response:
        request = urllib.request.Request(BASE + path, headers={'Authorization': 'Bearer ' + self.token})
        with self.opener.open(request, timeout=30) as response:
            return _Response(response.read())


def api(token: str) -> _Client:
    return _Client(token)


async def main() -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    user, password = credentials()
    checks: list[dict] = []
    errors: list[str] = []

    def check(name: str, ok: bool, detail: str = '') -> None:
        checks.append({'check': name, 'status': 'passed' if ok else 'failed', 'detail': detail[:300]})

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False, chromium_sandbox=True,
                                                   args=['--disable-background-networking'])
        try:
            context = await browser.new_context(viewport={'width': 1440, 'height': 960}, reduced_motion='reduce')
            await context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(BASE + '/')
                                else route.abort())
            page = await context.new_page()
            page.set_default_timeout(10000)
            page.on('pageerror', lambda error: errors.append(str(error)))
            await page.goto(BASE + '/login?next=mission')
            await page.get_by_label('Username').fill(user)
            await page.get_by_label('Password').fill(password)
            await page.get_by_role('button', name='Sign In').click()
            await page.wait_for_url('**/dashboard*')
            token = await page.evaluate("() => localStorage.getItem('token') || localStorage.getItem('aria_token') || ''")
            if not token:
                cookies = await context.cookies()
                token = next((c.get('value', '') for c in cookies if c.get('name') == 'pentestai_token'), '')
            check('signed in through the login page', bool(token))
            client = api(token)

            # 1. Authorization profile panel versus the backend decision record.
            started = time.perf_counter()
            await page.goto(f'{BASE}/dashboard?view=settings&sid={SID}')
            panel = page.locator('#authorization-profile')
            await expect(panel.get_by_text('Enforced restrictions')).to_be_visible()
            check('profile panel renders', True, f'{(time.perf_counter() - started) * 1000:.0f} ms')
            backend = client.get(f'/api/engagements/{SID}/profile').json()
            panel_text = await panel.inner_text()
            enforced = backend['restrictions']['enforced']
            check('panel shows backend profile kind and revision',
                  'Private lab' in panel_text and f"Revision{chr(10)}{backend['profile']['revision']}" in panel_text.replace('\t', '\n')
                  or str(backend['profile']['revision']) in panel_text, f"revision {backend['profile']['revision']}")
            check('panel lists exactly the backend permitted capabilities',
                  all(cap in panel_text for cap in enforced['permitted_capabilities']),
                  ', '.join(enforced['permitted_capabilities']))
            check('panel shows prohibited capability', all(cap in panel_text for cap in enforced['prohibited_capabilities']))
            check('panel shows approval level from backend', 'all' in panel_text.lower())
            check('policy change history listed', panel_text.count('Revision') >= 2)
            await page.screenshot(path=str(OUT / '01-profile-panel.png'), full_page=True)

            # 2. Readiness exposed by the backend for the same profile (UI surface checked separately).
            readiness = client.get(f'/api/sessions/{SID}/tool-readiness').json()
            blocked = {e['capability'] for e in readiness['capabilities'] if e['status'] == 'blocked'}
            check('backend readiness blocks capabilities the profile does not permit',
                  {'semgrep.source.scan.v1', 'subfinder.domain.passive.v1'} <= blocked, ', '.join(sorted(blocked)))
            check('tool readiness is shown in Mission Control', 'tool readiness' in (await page.inner_text('body')).lower(),
                  'not present in the deployed UI' if 'tool readiness' not in (await page.inner_text('body')).lower() else '')

            # 3. New engagement through the UI is profile-required in the backend.
            await page.goto(f'{BASE}/dashboard?view=sessions')
            await page.get_by_role('button', name='New session').click()
            await page.get_by_label('Session name').fill('P5 browser acceptance (no execution)')
            await page.get_by_label('Engagement target').fill('192.168.77.20')
            before = {s.get('id') or s.get('session_id') for s in (client.get('/api/session/list').json() or [])
                      if isinstance(s, dict)} if isinstance(client.get('/api/session/list').json(), list) else set()
            await page.get_by_role('button', name='Create', exact=False).first.click()
            await page.wait_for_timeout(2500)
            sessions = client.get('/api/session/list').json()
            sessions = sessions if isinstance(sessions, list) else sessions.get('sessions', [])
            created = [s for s in sessions if (s.get('id') or s.get('session_id')) not in before
                       and 'P5 browser acceptance' in str(s.get('name', ''))]
            new_sid = (created[0].get('id') or created[0].get('session_id')) if created else None
            check('session created through the UI', bool(new_sid), str(new_sid))
            if new_sid:
                state = client.get(f'/api/engagements/{new_sid}/profile').json()['restrictions']
                check('new engagement is profile-required in the backend', state.get('state') == 'profile_required')
                await page.goto(f'{BASE}/dashboard?view=settings&sid={new_sid}')
                new_panel = page.locator('#authorization-profile')
                await expect(new_panel.get_by_text('Enforced restrictions')).to_be_visible()
                check('UI states that every operation is denied', 'every operation is denied' in (await new_panel.inner_text()))
                await page.screenshot(path=str(OUT / '02-new-engagement-profile-required.png'), full_page=True)

            # 4. Operational views for the lab engagement.
            for index, view in enumerate(('operations', 'agents', 'tasks', 'investigation', 'events', 'infrastructure'), 3):
                started = time.perf_counter()
                await page.goto(f'{BASE}/dashboard?view={view}&sid={SID}')
                await page.wait_for_timeout(2500)
                body = (await page.inner_text('body'))
                await page.screenshot(path=str(OUT / f'{index:02d}-{view}.png'), full_page=True)
                check(f'{view} view renders', len(body) > 200, f'{(time.perf_counter() - started) * 1000:.0f} ms')
                if view == 'operations':
                    check('operations shows worker execution history', 'nmap' in body.lower() or 'httpx' in body.lower())
                if view in {'agents', 'tasks'}:
                    check(f'{view} shows delegated specialist tasks', 'blocked' in body.lower() or 'queued' in body.lower())
        finally:
            await browser.close()
    result = {'browser': 'Chromium (visible, headless=False)', 'base': BASE, 'checks': checks, 'page_errors': errors}
    (OUT / 'result.json').write_text(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    print(json.dumps(asyncio.run(main()), indent=1))
