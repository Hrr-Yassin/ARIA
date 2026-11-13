"""Phase A browser review. Real local APIs; only normal login mutates account state.

ARIA_PHASE_A_REVIEW=1 .local-lab/browser-venv/bin/python integration/phase_a_design_review.py
Empty/error responses are injected only in separate test browser contexts.
Reports/screenshots stay in ignored .local-lab; credentials are never reported.
"""
from __future__ import annotations
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get('ARIA_BASE_URL', 'http://127.0.0.1:7000').rstrip('/')
OUT = ROOT / '.local-lab' / 'phase-a-review' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')

async def main():
    if os.environ.get('ARIA_PHASE_A_REVIEW') != '1':
        raise SystemExit('Set ARIA_PHASE_A_REVIEW=1 to inspect the real local deployment')
    OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = {'browser': 'Chromium', 'real_api_integration': True,
              'mutations': ['normal owner login'], 'checks': [], 'screenshots': [],
              'test_only_fault_injection': ['empty session list', 'session list HTTP 503']}
    def check(name, passed, detail=None):
        report['checks'].append({'name': name, 'passed': bool(passed), 'detail': detail})
        print(json.dumps({'check': name, 'passed': bool(passed)}), flush=True)
    async def capture(page, name):
        await page.screenshot(path=str(OUT / (name + '.png')), full_page=True)
        report['screenshots'].append(str((OUT / (name + '.png')).relative_to(ROOT)))
    async def layout(page, name):
        result = await page.evaluate("""() => ({
          overflow: document.documentElement.scrollWidth > innerWidth + 1,
          foundation: getComputedStyle(document.body).getPropertyValue('--aria-bg').trim(),
          background: getComputedStyle(document.body).backgroundColor,
          font: getComputedStyle(document.body).fontFamily,
          main: document.querySelectorAll('main').length,
          overflowElements: [...document.querySelectorAll('body *')].filter(e => {
            const r = e.getBoundingClientRect();
            return r.width > 0 && r.right > innerWidth + 2 && getComputedStyle(e).position !== 'fixed';
          }).slice(0, 6).map(e => e.id || e.className || e.tagName)
        })""")
        check(name + '-layout', not result['overflow'] and result['foundation'] == '#090d14' and result['main'] == 1, result)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(viewport={'width': 1440, 'height': 1000})
        page = await context.new_page()
        page.set_default_timeout(15000)
        errors = []
        context.on('page', lambda p: p.on('pageerror', lambda error: errors.append(type(error).__name__)))
        page.on('pageerror', lambda error: errors.append(type(error).__name__))
        try:
            # Public review specimen contains no account or operational reads.
            api_requests = []
            page.on('request', lambda request: api_requests.append(request.url) if '/api/' in request.url else None)
            await page.goto(BASE + '/static/design-system.html', wait_until='networkidle')
            await layout(page, 'specimen-desktop')
            await capture(page, 'foundation-desktop-1440')
            check('specimen-no-api-requests', not api_requests)
            before = await page.locator('.aria-table td').first.evaluate('(el) => getComputedStyle(el).paddingTop')
            await page.locator('#density').select_option('compact')
            after = await page.locator('.aria-table td').first.evaluate('(el) => getComputedStyle(el).paddingTop')
            check('density-affects-record-padding', before == '14px' and after == '9px', {'before': before, 'after': after})
            await page.locator('#density').select_option('comfortable')
            await page.locator('[data-token="--aria-primary"]').click()
            check('token-inspection', '--aria-primary: #a2bbff' in await page.locator('#token-readout').inner_text())
            await page.locator('summary').focus()
            await page.keyboard.press('Enter')
            check('keyboard-disclosure', await page.locator('details').get_attribute('open') is not None)
            focus = await page.locator('summary').evaluate('(el) => getComputedStyle(el).outlineStyle')
            check('visible-keyboard-focus', focus == 'solid', focus)
            await page.locator('#motion').check()
            check('explicit-motion-off', await page.locator('html').get_attribute('data-motion') == 'off')
            await page.locator('#motion').uncheck()
            await page.emulate_media(reduced_motion='reduce')
            motion = await page.locator('.aria-button').evaluate('(el) => getComputedStyle(el).transitionDuration')
            check('reduced-motion', motion == '0s', motion)
            await page.emulate_media(reduced_motion='no-preference', forced_colors='active')
            colors = await page.locator('.aria-input').first.evaluate('(el) => getComputedStyle(el).borderTopStyle')
            check('forced-colors-control-boundary', colors == 'solid')
            await page.emulate_media(forced_colors='none')
            contrast = await page.evaluate("""() => {
              const s = getComputedStyle(document.documentElement);
              const lum = token => {
                const hex = s.getPropertyValue(token).trim().slice(1);
                const c = [0,2,4].map(i => parseInt(hex.slice(i,i+2),16)/255).map(x => x <= .04045 ? x/12.92 : ((x+.055)/1.055)**2.4);
                return c[0]*.2126+c[1]*.7152+c[2]*.0722;
              };
              const ratio = (a,b) => (Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);
              const result = [];
              for (const text of ['--aria-text','--aria-secondary','--aria-muted','--aria-primary','--aria-telemetry','--aria-success','--aria-warning','--aria-danger','--aria-unknown'])
                for (const bg of ['--aria-bg','--aria-surface','--aria-raised']) result.push({text,bg,ratio:ratio(text,bg),minimum:4.5});
              result.push({text:'--aria-on-primary',bg:'--aria-primary',ratio:ratio('--aria-on-primary','--aria-primary'),minimum:4.5});
              for (const bg of ['--aria-bg','--aria-surface','--aria-raised']) result.push({text:'--aria-border-strong',bg,ratio:ratio('--aria-border-strong',bg),minimum:3});
              return result;
            }""")
            report['contrast'] = contrast
            check('foundation-contrast', all(pair['ratio'] >= pair['minimum'] for pair in contrast), [p for p in contrast if p['ratio'] < p['minimum']])
            for width in (390, 320):
                await page.set_viewport_size({'width': width, 'height': 844})
                await page.evaluate('scrollTo(0, 0)')
                await layout(page, 'specimen-' + str(width))
                await capture(page, 'foundation-mobile-' + str(width))
            await page.set_viewport_size({'width': 1440, 'height': 1000})
            await page.goto(BASE + '/login')
            await layout(page, 'login-desktop')
            await page.locator('#login-btn').click()
            check('login-empty-error', await page.locator('#error-msg').is_visible())
            await capture(page, 'login-desktop-1440')
            await page.set_viewport_size({'width': 390, 'height': 844})
            await layout(page, 'login-mobile')
            await capture(page, 'login-mobile-390')
            denied = await context.request.get(BASE + '/api/session/list')
            check('session-api-requires-auth', denied.status == 401, {'status': denied.status})
            source = ROOT / '.local-lab' / 'login.txt'
            credentials = dict(line.split(': ', 1) for line in source.read_text().splitlines())
            await page.locator('#username').fill(credentials['Username'])
            await page.locator('#password').fill(credentials['Password'])
            await page.locator('#login-btn').click()
            await page.wait_for_url(BASE + '/')
            token = await page.evaluate("localStorage.getItem('pentestai_token')")
            check('real-owner-login', bool(token))
            headers = {'Authorization': 'Bearer ' + token}
            response = await context.request.get(BASE + '/api/session/list', headers=headers)
            sessions = (await response.json()).get('sessions', [])
            check('real-session-api', response.ok, {'status': response.status, 'count': len(sessions)})
            if sessions:
                sid = sessions[0]['session_id']
                campaign = await context.request.get(BASE + '/api/pentest/' + sid + '/campaign', headers=headers)
                check('campaign-response-contract', campaign.status in (200, 404), {'status': campaign.status, 'expected_absence': campaign.status == 404})
            for width, size in ((1440, 'desktop'), (390, 'mobile')):
                await page.set_viewport_size({'width': width, 'height': 1000 if width == 1440 else 844})
                await page.goto(BASE + '/')
                await page.wait_for_timeout(800)
                await layout(page, 'workspace-' + size)
                await capture(page, 'workspace-' + size + '-' + str(width))
                await page.locator('#settings-button').click()
                check('settings-' + size, await page.locator('#settings-panel').is_visible())
                await page.wait_for_function("!document.getElementById('execution-capabilities').textContent.includes('Checking')", timeout=10000)
                await capture(page, 'settings-' + size + '-' + str(width))
                await page.goto(BASE + '/dashboard')
                await page.wait_for_selector('body[data-dashboard-ready="true"]')
                await layout(page, 'dashboard-' + size)
                await capture(page, 'dashboard-' + size + '-' + str(width))
            admin_probe = await context.request.get(BASE + '/api/admin/users', headers=headers)
            if admin_probe.status == 200:
                for width, size in ((1440, 'desktop'), (390, 'mobile')):
                    await page.set_viewport_size({'width': width, 'height': 1000 if width == 1440 else 844})
                    await page.goto(BASE + '/admin')
                    await page.wait_for_timeout(600)
                    await layout(page, 'admin-' + size)
                    await page.get_by_role('button', name='Users', exact=True).focus()
                    await page.keyboard.press('Enter')
                    check('admin-keyboard-' + size, 'active' in (await page.locator('#sec-users').get_attribute('class') or '') and 'active' in (await page.get_by_role('button', name='Users', exact=True).get_attribute('class') or ''))
                    await capture(page, 'admin-' + size + '-' + str(width))
            else:
                check('admin-role-boundary', admin_probe.status == 403, {'status': admin_probe.status, 'admin_visual_review': 'not available for this principal'})
            storage = await context.storage_state()
            # Isolated browser-only fault injection; no production files or records change.
            for scenario in ('empty', 'error'):
                fault = await browser.new_context(storage_state=storage, viewport={'width': 390, 'height': 844})
                async def route_list(route):
                    await route.fulfill(status=200 if scenario == 'empty' else 503, content_type='application/json', body=json.dumps({'sessions': [], 'total': 0} if scenario == 'empty' else {'detail': 'Test-only source unavailable'}))
                await fault.route('**/api/session/list', route_list)
                screen = await fault.new_page()
                await screen.goto(BASE + '/dashboard')
                await screen.wait_for_selector('body[data-dashboard-ready="true"]')
                if scenario == 'empty':
                    passed = await screen.locator('#engagement-select').is_disabled()
                else:
                    passed = await screen.locator('#data-warning').is_visible()
                check('test-only-' + scenario + '-state', passed)
                await capture(screen, 'dashboard-test-only-' + scenario)
                await fault.close()
            check('no-page-errors', not errors, {'count': len(errors)})
        except Exception as exc:
            check('browser-workflow', False, {'error_type': type(exc).__name__, 'message': str(exc)[:250]})
            await capture(page, 'failure')
        finally:
            await browser.close()
    report['failed'] = sum(not item['passed'] for item in report['checks'])
    (OUT / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'report': str((OUT / 'report.json').relative_to(ROOT)), 'checks': len(report['checks']), 'failed': report['failed']}), flush=True)
    return 1 if report['failed'] else 0

if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
