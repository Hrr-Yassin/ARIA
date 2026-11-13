"""Visible dashboard acceptance against the real owner deployment.

Run with the existing browser virtual environment:
    ARIA_DASHBOARD_ACCEPTANCE=1 .local-lab/browser-venv/bin/python integration/dashboard_screenshots.py

Set ARIA_DASHBOARD_SESSION_ID to pin an engagement. Otherwise the script selects
the listed engagement with the most recorded findings. It never creates a
campaign, starts a run, changes a budget or submits a report. The only mutation
is the normal owner login required by the application.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get('ARIA_BASE_URL', 'http://127.0.0.1:7000').rstrip('/')
STAMP = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
OUT = ROOT / '.local-lab' / 'dashboard-review' / STAMP
HEADLESS = os.environ.get('ARIA_DASHBOARD_HEADFUL') != '1'
EXPECTED_404_FRAGMENTS = ('/campaign',)


def login_values() -> dict[str, str]:
    source = ROOT / '.local-lab' / 'login.txt'
    if not source.exists():
        raise SystemExit('Missing private local login file: .local-lab/login.txt')
    return dict(line.split(': ', 1) for line in source.read_text().splitlines())


def is_expected_404(url: str) -> bool:
    return any(fragment in url for fragment in EXPECTED_404_FRAGMENTS)


async def pick_engagement(context, token: str) -> tuple[str, dict]:
    headers = {'Authorization': 'Bearer ' + token}
    response = await context.request.get(BASE + '/api/session/list', headers=headers)
    if not response.ok:
        raise RuntimeError('Session list HTTP ' + str(response.status))
    sessions = (await response.json()).get('sessions', [])
    pinned = os.environ.get('ARIA_DASHBOARD_SESSION_ID', '').strip()
    if pinned:
        return pinned, {'pinned': True, 'session_count': len(sessions)}

    best = None
    best_score = -1
    for session in sessions:
        sid = session.get('session_id')
        if not sid:
            continue
        finding_total = 0
        task_total = 0
        try:
            findings = await context.request.get(BASE + '/api/findings/' + sid, headers=headers)
            if findings.ok:
                finding_total = int((await findings.json()).get('total') or 0)
            team = await context.request.get(BASE + '/api/team/' + sid, headers=headers)
            if team.ok:
                task_total = len((await team.json()).get('tasks') or [])
        except Exception:
            continue
        score = finding_total * 10 + min(task_total, 20)
        if score > best_score:
            best = sid
            best_score = score
            best_meta = {
                'pinned': False,
                'session_count': len(sessions),
                'selected_findings': finding_total,
                'selected_tasks': task_total,
                'selected_name': session.get('name', ''),
                'selected_target': session.get('target', ''),
            }
    if not best:
        raise RuntimeError('No engagements are available to inspect')
    return best, best_meta


async def main() -> int:
    if os.environ.get('ARIA_DASHBOARD_ACCEPTANCE') != '1':
        raise SystemExit('Set ARIA_DASHBOARD_ACCEPTANCE=1 to use the real local deployment')
    OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    credentials = login_values()
    report = {
        'started_utc': STAMP,
        'base': BASE,
        'browser': 'Chromium',
        'headless': HEADLESS,
        'mocked_routes': False,
        'mutations': ['owner login'],
        'checks': [],
        'screenshots': [],
        'console_errors': [],
        'page_errors': [],
        'network_errors': [],
    }
    checks = report['checks']

    def record(name: str, passed: bool, detail=None, error=None):
        checks.append({
            'name': name,
            'status': 'passed' if passed else 'failed',
            'detail': detail,
            'error': error,
        })
        print(json.dumps({'check': name, 'status': checks[-1]['status']}), flush=True)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=HEADLESS, slow_mo=0 if HEADLESS else 80)
        context = await browser.new_context(viewport={'width': 1440, 'height': 1000})
        page = await context.new_page()
        page.set_default_timeout(25000)
        page.on('console', lambda message: report['console_errors'].append(message.text[:500])
                if message.type == 'error' else None)
        page.on('pageerror', lambda error: report['page_errors'].append(str(error)[:1000]))
        page.on('response', lambda response: report['network_errors'].append({
            'status': response.status, 'url': response.url.split('?')[0],
        }) if response.url.startswith(BASE) and response.status >= 400 else None)
        page.on('requestfailed', lambda request: report['network_errors'].append({
            'failed': True, 'url': request.url.split('?')[0],
            'reason': str(request.failure),
        }) if request.url.startswith(BASE) else None)

        # ── Login (real UI) ─────────────────────────────────────────────
        try:
            await page.goto(BASE + '/login')
            await page.get_by_label('Username').fill(credentials['Username'])
            await page.get_by_label('Password').fill(credentials['Password'])
            await page.locator('#login-btn').click()
            await page.wait_for_url(BASE + '/')
            token = await page.evaluate("localStorage.getItem('pentestai_token')")
            record('owner-login', bool(token), {'landing': '/'})
        except Exception as exc:  # noqa: BLE001
            record('owner-login', False, error=type(exc).__name__ + ': ' + str(exc)[:500])
            await browser.close()
            report['finished_utc'] = datetime.now(timezone.utc).isoformat()
            (OUT / 'report.json').write_text(json.dumps(report, indent=2))
            return 1

        sid, selection = await pick_engagement(context, token)
        report['session_id'] = sid
        report['selection'] = selection
        headers = {'Authorization': 'Bearer ' + token}
        expected_total = 0
        findings_response = await context.request.get(BASE + '/api/findings/' + sid, headers=headers)
        if findings_response.ok:
            expected_total = int((await findings_response.json()).get('total') or 0)
        record('select-real-engagement', True, {'session_id': sid, **selection})

        await page.evaluate("sid => localStorage.setItem('current_session', sid)", sid)
        await page.goto(BASE + '/dashboard')
        try:
            await page.wait_for_selector('body[data-dashboard-ready="true"]', timeout=25000)
            await page.wait_for_timeout(900)
            record('dashboard-ready', True, {'url': page.url})
        except Exception as exc:  # noqa: BLE001
            record('dashboard-ready', False, error=type(exc).__name__ + ': ' + str(exc)[:500])
            await page.screenshot(path=str(OUT / 'dashboard-failure.png'), full_page=True)
            await browser.close()
            report['finished_utc'] = datetime.now(timezone.utc).isoformat()
            (OUT / 'report.json').write_text(json.dumps(report, indent=2))
            return 1

        # ── Desktop invariants ──────────────────────────────────────────
        desktop = await page.evaluate("""() => ({
          title: document.getElementById('engagement-title')?.textContent,
          target: document.getElementById('hero-target')?.textContent,
          findings: document.getElementById('metric-findings')?.textContent,
          tasks: document.getElementById('metric-tasks')?.textContent,
          evidence: document.getElementById('metric-evidence')?.textContent,
          calls: document.getElementById('metric-calls')?.textContent,
          campaign: document.getElementById('campaign-body')?.innerText || '',
          campaignState: document.getElementById('campaign-state')?.textContent,
          worker: document.getElementById('rail-worker')?.dataset.state,
          workerLabel: document.getElementById('rail-worker-label')?.textContent,
          graphNodes: document.querySelectorAll('.graph-node').length,
          timelineItems: document.querySelectorAll('.timeline-item').length,
          overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
          warningHidden: document.getElementById('data-warning')?.hidden,
          unlabeled: [...document.querySelectorAll('button, a, select, [tabindex="0"]')]
            .filter(el => !((el.getAttribute('aria-label') || el.textContent || '').trim()))
            .map(el => el.id || el.className || el.tagName),
        })""")
        report['desktop'] = desktop
        record('desktop-no-horizontal-overflow', not desktop['overflow'],
               {'scroll_width': await page.evaluate('document.documentElement.scrollWidth'),
                'inner_width': 1440})
        record('real-finding-count', desktop['findings'] == str(expected_total),
               {'displayed': desktop['findings'], 'api_total': expected_total})
        record('real-campaign-state', (desktop['campaignState'] or '') != '',
               {'state': desktop['campaignState'], 'panel_has_empty_state': 'No supervised campaign' in desktop['campaign']})
        record('worker-state-present', desktop['worker'] in {'online', 'offline', 'unknown'},
               {'state': desktop['worker'], 'label': desktop['workerLabel']})
        record('graph-rendered', desktop['graphNodes'] >= 1, {'nodes': desktop['graphNodes']})
        record('timeline-rendered', desktop['timelineItems'] >= 1, {'items': desktop['timelineItems']})
        record('interactive-elements-labeled', not desktop['unlabeled'], {'unlabeled': desktop['unlabeled']})
        record('no-visible-warning', bool(desktop['warningHidden']))

        # ── Interactions ────────────────────────────────────────────────
        try:
            findings_nodes = await page.locator('.graph-node-finding circle').count()
            if findings_nodes:
                await page.locator('.graph-node-finding circle').first.click()
                await page.wait_for_timeout(200)
                detail = await page.locator('#graph-detail').inner_text()
                selected = await page.locator('.graph-node.is-selected').count()
                record('graph-node-selection', selected == 1 and 'Finding' in detail,
                       {'selected': selected, 'detail_chars': len(detail)})
            else:
                record('graph-node-selection', True, {'skipped': 'no finding nodes'})
        except Exception as exc:  # noqa: BLE001
            record('graph-node-selection', False, error=type(exc).__name__ + ': ' + str(exc)[:500])

        try:
            await page.locator('#evidence-tab-catalog').click()
            selected = await page.locator('#evidence-tab-catalog').get_attribute('aria-selected')
            body_text = await page.locator('#evidence-body').inner_text()
            await page.locator('#evidence-tab-findings').click()
            record('evidence-tabs', selected == 'true' and bool(body_text), {'catalog_selected': selected})
        except Exception as exc:  # noqa: BLE001
            record('evidence-tabs', False, error=type(exc).__name__ + ': ' + str(exc)[:500])

        try:
            await page.locator('#evidence-tab-findings').focus()
            await page.keyboard.press('ArrowRight')
            selected = await page.locator('#evidence-tab-catalog').get_attribute('aria-selected')
            await page.keyboard.press('ArrowLeft')
            record('evidence-tabs-keyboard', selected == 'true', {'arrow_selected': selected})
        except Exception as exc:  # noqa: BLE001
            record('evidence-tabs-keyboard', False, error=type(exc).__name__ + ': ' + str(exc)[:500])

        # Reset to the findings view before the screenshot.
        try:
            await page.locator('#evidence-tab-findings').click()
            await page.locator('#graph-detail').scroll_into_view_if_needed()
            await page.evaluate('window.scrollTo(0, 0)')
            await page.evaluate('document.activeElement && document.activeElement.blur()')
            await page.wait_for_timeout(200)
        except Exception:
            pass
        desktop_path = OUT / 'dashboard-desktop-1440.png'
        await page.screenshot(path=str(desktop_path), full_page=True)
        report['screenshots'].append(str(desktop_path.relative_to(ROOT)))
        record('desktop-screenshot', True, {'path': str(desktop_path.relative_to(ROOT))})

        # ── Mobile ──────────────────────────────────────────────────────
        storage = await context.storage_state()
        mobile_context = await browser.new_context(
            viewport={'width': 390, 'height': 844}, storage_state=storage)
        mobile = await mobile_context.new_page()
        mobile.set_default_timeout(25000)
        mobile_console = []
        mobile_errors = []
        mobile.on('console', lambda message: mobile_console.append(message.text[:500])
                  if message.type == 'error' else None)
        mobile.on('pageerror', lambda error: mobile_errors.append(str(error)[:1000]))
        await mobile.goto(BASE + '/dashboard')
        await mobile.wait_for_selector('body[data-dashboard-ready="true"]', timeout=25000)
        await mobile.wait_for_timeout(800)
        mobile_data = await mobile.evaluate("""() => {
          const svg = document.getElementById('graph-svg');
          const svgRect = svg.getBoundingClientRect();
          const labels = [...document.querySelectorAll('.graph-node text')].map(node => {
            const rect = node.getBoundingClientRect();
            return {
              text: node.textContent,
              inside: rect.left >= svgRect.left - 2 && rect.right <= svgRect.right + 2
                && rect.top >= svgRect.top - 2 && rect.bottom <= svgRect.bottom + 2,
            };
          });
          const timeline = document.getElementById('timeline-body');
          const picker = document.querySelector('.engagement-picker').getBoundingClientRect();
          return {
            overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
            innerWidth: window.innerWidth,
            scrollWidth: document.documentElement.scrollWidth,
            railHeight: Math.round(document.querySelector('.rail').getBoundingClientRect().height),
            topbarTop: Math.round(document.querySelector('.topbar').getBoundingClientRect().top),
            pickerWidth: Math.round(picker.width),
            labelsOutside: labels.filter(label => !label.inside),
            timelineScrolls: timeline.scrollHeight > timeline.clientHeight,
            bodyHeight: document.body.scrollHeight,
          };
        }""")
        report['mobile'] = mobile_data
        record('mobile-no-horizontal-overflow', not mobile_data['overflow'], mobile_data)
        record('mobile-two-row-header', mobile_data['topbarTop'] >= mobile_data['railHeight']
               and mobile_data['pickerWidth'] >= 330, mobile_data)
        record('graph-labels-inside-svg', not mobile_data['labelsOutside'],
               {'outside': mobile_data['labelsOutside']})
        record('mobile-timeline-scrolls', mobile_data['timelineScrolls'], {
            'body_height': mobile_data['bodyHeight'],
        })
        mobile_path = OUT / 'dashboard-mobile-390.png'
        await mobile.screenshot(path=str(mobile_path), full_page=True)
        report['screenshots'].append(str(mobile_path.relative_to(ROOT)))
        record('mobile-screenshot', True, {'path': str(mobile_path.relative_to(ROOT))})
        report['mobile_console_errors'] = mobile_console
        report['mobile_page_errors'] = mobile_errors
        record('mobile-no-page-errors', not mobile_errors, {'count': len(mobile_errors)})
        await mobile_context.close()

        # ── Error surfaces ──────────────────────────────────────────────
        unexpected_network = [
            item for item in report['network_errors']
            if item.get('failed') or not is_expected_404(item.get('url', ''))
        ]
        repeatable_console = [
            text for text in report['console_errors']
            if not (text.startswith('Failed to load resource') and '404' in text)
        ]
        report['unexpected_network_errors'] = unexpected_network
        record('no-page-errors', not report['page_errors'], {'count': len(report['page_errors'])})
        record('no-unexpected-network-errors', not unexpected_network,
               {'unexpected': unexpected_network})
        record('no-unexpected-console-errors', not repeatable_console,
               {'console': repeatable_console, 'expected_404s': len(report['network_errors']) - len(unexpected_network)})
        await browser.close()

    report['finished_utc'] = datetime.now(timezone.utc).isoformat()
    (OUT / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    failed = [check for check in checks if check['status'] != 'passed']
    print(json.dumps({
        'report': str((OUT / 'report.json').relative_to(ROOT)),
        'screenshots': report['screenshots'],
        'checks': len(checks),
        'failed': len(failed),
    }, indent=2), flush=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(asyncio.run(main()))
