"""Visible Chromium black-box run against the authorized local HTTP target.

This run honors the user's no-paid-model-calls constraint. Run with:
PLAYWRIGHT_BROWSERS_PATH=/tmp/aria-playwright-browsers \
  .local-lab/browser-venv/bin/python integration/aria_http_autonomy_benchmark.py
"""
import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
BASE = 'http://localhost:7000'
TARGET = '192.168.77.20'
OUT = ROOT / '.local-lab/aria-http-autonomy-benchmark'


async def main():
    OUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    creds = dict(line.split(': ', 1) for line in (ROOT / '.local-lab/login.txt').read_text().splitlines())
    record = {
        'mode': 'visible Chromium; actual ARIA UI; no route mocks',
        'target': TARGET,
        'paid_model_calls_authorized': False,
        'events': [], 'network': [], 'console_errors': [], 'page_errors': [], 'screenshots': [],
    }
    stop_at = None

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False, slow_mo=150)
        context = await browser.new_context(viewport={'width': 1440, 'height': 1000})
        page = await context.new_page()
        page.set_default_timeout(20000)
        page.on('console', lambda msg: record['console_errors'].append(msg.text[:500]) if msg.type == 'error' else None)
        page.on('pageerror', lambda err: record['page_errors'].append(str(err)[:500]))
        page.on('response', lambda resp: record['network'].append({'method': resp.request.method, 'path': resp.url.removeprefix(BASE).split('?')[0], 'status': resp.status}) if resp.url.startswith(BASE) else None)
        page.on('request', lambda req: record.update({'timer_start_utc': datetime.now(timezone.utc).isoformat(), 'timer_start_monotonic': time.monotonic()} ) if 'timer_start_monotonic' not in record and req.method == 'POST' and '/autonomous/start' in req.url else None)

        async def save(name):
            path = OUT / f'{name}.png'
            await page.screenshot(path=str(path), full_page=True)
            record['screenshots'].append(str(path.relative_to(ROOT)))
            (OUT / 'run.json').write_text(json.dumps(record, indent=2, default=str))

        try:
            await page.goto(BASE + '/login')
            await page.get_by_label('Username').fill(creds['Username'])
            await page.get_by_label('Password').fill(creds['Password'])
            async with page.expect_response(lambda r: r.url.endswith('/api/login')) as login_resp:
                await page.locator('#login-btn').click()
            record['login_status'] = (await login_resp.value).status
            await page.wait_for_url(BASE + '/')
            await expect(page.locator('#send-button')).to_be_visible()
            await save('01-dashboard')

            # Create a fresh engagement through the native UI, scoped only to the authorized target.
            page.once('dialog', lambda d: d.accept(TARGET))
            async with page.expect_response(lambda r: r.url.endswith('/api/session/new')) as create_resp:
                await page.locator('#new-session-btn').click()
            create = await (await create_resp.value).json()
            record['session_id'] = create.get('session_id')
            record['created_target'] = create.get('target', TARGET)
            await expect(page.locator('#target-value')).to_have_text(TARGET)
            await save('02-target-created')

            # Select ordinary autonomous discovery, with the normal conservative risk policy.
            await page.locator('#settings-button').click()
            await page.locator('#goal-select').select_option('discovery')
            await page.locator('#max-steps').fill('12')
            await page.locator('#risk-threshold').select_option('green_only')
            await save('03-discovery-configured')
            await page.locator('#settings-close').click()

            # Timer origin is recorded from the browser's actual POST request event.
            async with page.expect_response(lambda r: '/autonomous/start' in r.url, timeout=30000) as start_resp:
                await page.locator('#auto-button').click()
            response = await start_resp.value
            record['start_http_status'] = response.status
            record['start_response'] = await response.json()
            start_time = record.get('timer_start_monotonic')
            if start_time is None:
                raise RuntimeError('Autonomous start POST was observed without timer origin')
            record['timer_start_monotonic'] = start_time
            stop_at = start_time + 900
            record['timer_deadline_monotonic'] = stop_at
            record['elapsed_seconds_at_start_response'] = time.monotonic() - start_time
            await save('04-run-started')

            # Observe only. If the UI becomes terminal/blocked, record actual duration and finish.
            while time.monotonic() < stop_at:
                await page.wait_for_timeout(1000)
                status = await page.locator('#auto-label').inner_text()
                record['last_ui_status'] = status
                elapsed = time.monotonic() - start_time
                if int(elapsed) in {60, 120, 300, 600, 840}:
                    await save(f'milestone-{int(elapsed)}s')
                resp = record['start_response'] if isinstance(record['start_response'], dict) else {}
                state = str(resp.get('run_state', resp.get('status', ''))).lower()
                if state in {'blocked', 'completed', 'failed', 'cancelled', 'stopped'}:
                    record['early_terminal_state'] = state
                    break
                if 'RUNNING' not in status.upper() and elapsed > 5:
                    # The visible run ended or blocked; preserve it without restarting.
                    record['early_terminal_state'] = status
                    break
            record['timer_end_monotonic'] = time.monotonic()
            record['elapsed_seconds'] = record['timer_end_monotonic'] - start_time
            record['deadline_reached'] = record['timer_end_monotonic'] >= stop_at
            await save('05-final-ui')
        except Exception as exc:
            record['error'] = type(exc).__name__ + ': ' + str(exc)[:1500]
            await save('error-state')
        finally:
            record['finished_utc'] = datetime.now(timezone.utc).isoformat()
            (OUT / 'run.json').write_text(json.dumps(record, indent=2, default=str))
            await context.close()
            await browser.close()
    print(json.dumps(record, indent=2, default=str))


if __name__ == '__main__':
    asyncio.run(main())
