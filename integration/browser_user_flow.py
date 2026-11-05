"""Opt-in real Firefox flow. Run with the lab's separate browser venv.

Uses existing saved login, creates its own scoped session, executes only HTTP/TCP80
checks against Metasploitable, and leaves screenshots/report in ignored local lab.
"""
import asyncio
import json
import os
import time
import subprocess
from pathlib import Path
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[1]

async def main():
    if os.environ.get('ARIA_BROWSER_LAB') != '1':
        raise SystemExit('Set ARIA_BROWSER_LAB=1 to run against the isolated lab')
    output = ROOT / '.local-lab/browser-results'
    output.mkdir(mode=0o700, exist_ok=True)
    login = dict(line.split(': ', 1) for line in (ROOT / '.local-lab/login.txt').read_text().splitlines())
    report, errors = {}, []
    async with async_playwright() as pw:
        browser = await pw.firefox.launch(headless=os.environ.get('ARIA_BROWSER_HEADED') != '1')
        context = await browser.new_context(viewport={'width':1440,'height':1000})
        page = await context.new_page()
        page.on('pageerror', lambda exc: errors.append(str(exc)[:200]))
        sid = None
        headers = None
        try:
            await page.goto('http://localhost:7000/login')
            await page.locator('#username').fill(login['Username'])
            await page.locator('#password').fill(login['Password'])
            await page.locator('#login-btn').click()
            await page.wait_for_url('http://localhost:7000/')
            await expect(page.locator('#send-button')).to_be_visible()
            report['login'] = 'passed'
            token = await page.evaluate("localStorage.getItem('pentestai_token')")
            headers = {'Authorization': 'Bearer ' + token}
            # Fixture establishes a narrow engagement before browser actions.
            response = await context.request.post('http://localhost:7000/api/session/new', headers=headers,
                data={'target':'192.168.77.20','name':'Browser HTTP test '+str(int(time.time())),
                      'scope':{'targets':['192.168.77.20'],'ports':[80],'exclusions':[]}})
            assert response.ok
            session = await response.json()
            sid = session['session_id']
            await page.evaluate('(sid)=>localStorage.setItem("current_session",sid)', sid)
            await page.reload()
            await expect(page.locator('#session-name')).to_contain_text('Browser HTTP test')
            await page.locator('#user-input').fill('scan http port')
            async with page.expect_response(lambda r: '/api/v8/input' in r.url) as pending:
                await page.locator('#send-button').click()
            plan = await (await pending.value).json()
            assert len(plan['commands']) == 1 and '-p 80 ' in plan['commands'][0]['command']
            assert '-sC' not in plan['commands'][0]['command']
            report['scoped_plan'] = 'passed'
            async with page.expect_response(lambda r: '/api/kali/execute' in r.url, timeout=60000) as pending:
                await page.locator('.cmd-btn-run').last.click()
            response = await pending.value
            assert response.ok, 'Execution endpoint failed'
            result = await response.json()
            assert result['exit_code'] == 0, 'Real scan failed'
            await expect(page.locator('#messages')).to_contain_text('80/tcp', timeout=30000)
            await page.locator('#messages .msg').last.evaluate('(e)=>Promise.all(e.getAnimations().map(a=>a.finished))')
            await page.screenshot(path=str(output / 'manual-output.png'), full_page=True)
            report['manual_run_output'] = 'passed'
            await page.reload()
            await expect(page.locator('#messages')).to_contain_text('scan http port')
            await expect(page.locator('#messages')).to_contain_text('80/tcp')
            await page.screenshot(path=str(output / 'restored-history.png'), full_page=True)
            report['refresh_history'] = 'passed'
            health = await context.request.get('http://localhost:7000/api/kali/health', headers=headers)
            assert (await health.json())['status'] == 'online'
            report['worker_health'] = 'passed'
            # API negative cases use the same authenticated browser context; no execution.
            denied = await context.request.post('http://localhost:7000/api/execution/proposals', headers=headers,
                data={'session_id':sid,'tool':'curl','command':'curl -I http://192.168.77.1'})
            assert denied.status == 403
            report['out_of_scope_denied'] = 'passed (browser API)'
            proposal = await context.request.post('http://localhost:7000/api/execution/proposals', headers=headers,
                data={'session_id':sid,'tool':'curl','command':'curl -X POST http://192.168.77.20'})
            approval = await proposal.json()
            assert approval['status'] == 'pending'
            rejected = await context.request.post('http://localhost:7000/api/execution/'+approval['action_id']+'/decision', headers=headers,
                data={'session_id':sid,'decision':'reject'})
            assert (await rejected.json())['status'] == 'rejected'
            report['approval_rejection'] = 'passed (browser API; not dispatched)'
            # A persisted test-only card exercises the actual native confirm UI.
            fixture = """
import asyncio, os
from memory.session_manager import session_manager
from memory.database_models import engine
async def main():
    await session_manager.add_chat_log(os.environ['ARIA_BROWSER_SESSION'], 'assistant',
        'Approval rejection test fixture: dismiss the confirmation; do not execute.', 'plan',
        {'commands':[{'tool':'curl', 'command':'curl -X POST http://192.168.77.20',
                      'purpose':'Test rejection only', 'risk_color':'red'}]})
    await engine.dispose()
asyncio.run(main())
"""
            subprocess.run([str(ROOT / '.venv/bin/python'), '-c', fixture], cwd=ROOT,
                           env={**os.environ, 'ARIA_BROWSER_SESSION':sid}, check=True, capture_output=True)
            await page.reload()
            await expect(page.locator('#messages')).to_contain_text('Approval rejection test fixture')
            executions = []
            page.on('request', lambda request: executions.append(1) if request.url.endswith('/api/kali/execute') else None)
            page.once('dialog', lambda dialog: asyncio.create_task(dialog.dismiss()))
            async with page.expect_response(lambda response: '/decision' in response.url) as pending:
                await page.locator('.cmd-btn-run').last.click()
            decision = await (await pending.value).json()
            assert decision['status'] == 'rejected'
            assert not executions, 'Rejected UI command was dispatched'
            report['approval_rejection_ui'] = 'passed (real dialog dismissed; fixture card; no dispatch)'
            await page.screenshot(path=str(output / 'approval-rejection.png'), full_page=True)

            await page.locator('#settings-button').click()
            slider = page.locator('#max-steps')
            await slider.focus()
            await slider.press('Home')
            await slider.press('ArrowRight')
            await page.locator('#settings-close').click()
            await page.locator('#goal-select').select_option('http_check')
            async with page.expect_response(lambda r: '/autonomous/start' in r.url) as pending:
                await page.locator('#auto-button').click()
            started = await pending.value
            assert started.ok
            assert started.request.post_data_json['max_steps'] == 2
            report['auto_start_budget'] = 'passed'
            # Wait for a completed real HTTP check, then start again and exercise Stop.
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                status = await context.request.get('http://localhost:7000/api/pentest/'+sid+'/autonomous/status', headers=headers)
                data = await status.json()
                if not data.get('active'):
                    break
                await asyncio.sleep(.25)
            else:
                raise AssertionError('Autonomous cycle did not end')
            await page.screenshot(path=str(output / 'autonomous-cycle.png'), full_page=True)
            decisions = await context.request.get('http://localhost:7000/api/pentest/'+sid+'/decision-log', headers=headers)
            decision_data = await decisions.json()
            assert 'auto_execute' in json.dumps(decision_data) and 'HTTP/1.1 200' in json.dumps(decision_data), 'Autonomous HTTP success receipt missing'
            report['auto_cycle'] = 'passed (real HTTP 200 decision record)'
            await page.reload()
            await page.locator('#goal-select').select_option('http_check')
            await page.locator('#auto-button').click()
            await expect(page.locator('#auto-button')).to_have_attribute('data-state','on')
            async with page.expect_response(lambda r: '/autonomous/stop' in r.url) as pending:
                await page.locator('#auto-button').click()
            stop = await (await pending.value).json()
            assert stop.get('pending', 0) == 0
            report['auto_stop'] = 'passed'
            report['browser_errors'] = errors
            assert not errors, 'Browser JavaScript error'
        except Exception as exc:
            report['failure'] = type(exc).__name__ + ': ' + str(exc)[:400]
            await page.screenshot(path=str(output / 'failure.png'), full_page=True)
            raise
        finally:
            if sid and headers:
                await context.request.post('http://localhost:7000/api/pentest/'+sid+'/autonomous/stop', headers=headers)
            (output / 'report.json').write_text(json.dumps(report, indent=2))
            print(json.dumps(report, indent=2))
            await browser.close()

if __name__ == '__main__':
    asyncio.run(main())
