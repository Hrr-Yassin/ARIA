"""Visible Chromium acceptance on the real app and fresh synthetic PostgreSQL.

Uses normal graphical login/navigation/start controls, never request API writes
or browser route mocks. Setup creates fixture records before serving the app.
Worker is unconfigured and a zero-call validation budget forbids inference.
No owner credentials, database, Redis, worker or service is modified. No trace,
video or authenticated storage state is recorded. Only sanitized screenshots
and closed diagnostic fields are retained. Chromium sandboxing is mandatory.

    python -m integration.reliability_visible --visible
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def manifest():
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ('api', 'agents', 'memory', 'orchestrator', 'llm', 'config', 'security', 'web',
                       'integration', 'worker', 'security_tools')
        for p in sorted((ROOT / folder).rglob('*'))
        if p.is_file() and p.suffix in {'.py', '.js', '.html', '.css'}}


async def prepare(directory):
    from sqlalchemy import select
    from config.settings import settings
    from memory.database_models import PentestSession, User, async_session, engine
    from api.auth import hash_password
    from integration.reliability_workload import run_twelve_operations
    if not os.environ.get('ARIA_RELIABILITY_BROWSER'):
        raise RuntimeError('Disposable browser fixture guard is required')
    result = await run_twelve_operations(directory / 'fixture')
    from memory.research import research_store
    await research_store.ingest_review(result['session_id'],
        result['fixture_model_accounting']['attempts'][0]['owner'], 'visible-synthetic-research',
        {'hypotheses': [{'description': 'A synthetic saved observation requires independent controls.',
            'evidence_job_ids': [result['operations'][0]['job_id']],
            'validation_criterion': 'Compare controlled synthetic observations before accepting a claim.',
            'confidence': .1}]})
    async with async_session() as db:
        session = await db.get(PentestSession, result['session_id'])
        owner = await db.get(User, session.user_id)
        owner.username = os.environ['ARIA_BROWSER_USERNAME']
        owner.display_name = 'Synthetic reliability operator'
        owner.password_hash = hash_password(os.environ['ARIA_BROWSER_PASSWORD'])
        session.name = 'Synthetic reliability: twelve engineering operations'
        await db.commit()
    (directory / 'fixture.json').write_text(json.dumps({
        'session_id': result['session_id'], 'benchmark_passed': result['benchmark_passed'],
        'recorded_operations': result['recorded_operations'],
        'model_calls_before_gui': result['fixture_model_accounting']['usage']['calls'],
        'actual_tools_executed': result['actual_tools_executed']}, indent=2) + '\n')
    await engine.dispose()


def guarded_app():
    from sqlalchemy.engine import make_url
    from config.settings import settings
    database = make_url(settings.DATABASE_URL).database or ''
    if (os.environ.get('ARIA_RELIABILITY_BROWSER') != '1'
            or not database.startswith('aria_reliability_') or not database.endswith('_test')
            or settings.KALI_AGENT_URL):
        raise RuntimeError('Fresh disposable browser database and disabled worker required')
    from api.main import app
    from llm.validation_budget import ValidationBudget, current_budget
    @app.middleware('http')
    async def forbid_generation(request, call_next):
        token = current_budget.set(ValidationBudget(max_calls=0, max_tokens=0))
        try:
            return await call_next(request)
        finally:
            current_budget.reset(token)
    if os.environ.get('ARIA_RELIABILITY_STREAM') == '1':
        from integration.reliability_stream import configure_fixture
        configure_fixture(app, Path(os.environ['ARIA_RELIABILITY_OUTPUT']))
    return app


async def browser_acceptance(base, directory, username, password):
    from playwright.async_api import async_playwright, expect
    result = {'headless': False, 'chromium_sandbox': True,
              'real_application': True, 'fixture_data': True,
              'api_interaction_substitutions': False, 'route_mocks': False,
              'checks': [], 'screenshots': [], 'page_error_types': [],
              'limitations': ['Disposable synthetic deployment, not owner deployment or live laboratory acceptance.',
                             'Worker deliberately unavailable; no tool or provider may run.']}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False, chromium_sandbox=True)
        result['browser_version'] = browser.version
        context = await browser.new_context(viewport={'width': 1600, 'height': 1100})
        page = await context.new_page()
        page.set_default_timeout(20000)
        page.on('pageerror', lambda exc: result['page_error_types'].append(type(exc).__name__))
        async def screenshot(name, locator=None):
            path = directory / name
            if locator is None:
                await page.screenshot(path=path, full_page=True, animations='disabled')
            else:
                await locator.screenshot(path=path, animations='disabled')
            result['screenshots'].append(name)
        try:
            await page.goto(base + '/login')
            await page.locator('#username').fill(username)
            await page.locator('#password').fill(password)
            await page.locator('#login-btn').click()
            await page.wait_for_url(base + '/')
            result['checks'].append('real_graphical_login')
            fixture = json.loads((directory / 'fixture.json').read_text())
            await page.locator('.session-item', has_text='Synthetic reliability: twelve').click()
            await expect(page.locator('#session-name')).to_have_text('Synthetic reliability: twelve engineering operations')
            objective = 'Retain the authorized objective and explain the unavailable isolated worker.'
            await page.locator('#user-input').fill(objective)
            await page.locator('#auto-button').click()
            await expect(page.locator('#auto-log-lines')).to_contain_text('Worker capability discovery failed')
            result['checks'].append('worker_blocker_after_ui_start')
            await screenshot('workspace-worker-blocked.png')
            await page.reload()
            await expect(page.locator('#auto-log-lines')).to_contain_text('Worker capability discovery failed')
            result['checks'].append('blocker_survives_reload')
            await page.locator('a[href="/dashboard"]').click()
            await page.wait_for_url(base + '/dashboard')
            await page.wait_for_function("document.body.dataset.dashboardReady === 'true'")
            await expect(page.locator('#hero-note')).to_contain_text(objective)
            await expect(page.locator('#campaign-body')).to_contain_text('worker_unavailable')
            await expect(page.locator('#campaign-body')).to_contain_text('Operator action')
            await expect(page.locator('#metric-tasks')).to_have_text('12')
            await expect(page.locator('#phase-readiness')).to_have_text('Unavailable')
            if await page.locator('#phase-readiness-meter').get_attribute('aria-valuenow') is not None:
                raise AssertionError('Unknown readiness must not expose a numeric percentage')
            result['checks'].extend(['dashboard_exact_objective', 'safe_blocker_details', 'all_twelve_tasks_visible'])
            await screenshot('dashboard-overview.png')
            await screenshot('dashboard-blocker.png', page.locator('#campaign-panel'))
            await screenshot('dashboard-agent-tasks.png', page.locator('#agents-panel'))
            await page.locator('#evidence-tab-catalog').click()
            await expect(page.locator('#evidence-tab-catalog')).to_have_attribute('aria-selected', 'true')
            await expect(page.locator('#evidence-body')).to_contain_text('Unverified hypothesis')
            result['checks'].append('graphical_evidence_catalog_navigation')
            await screenshot('dashboard-evidence.png', page.locator('#evidence-panel'))
            result['navigation_timings_ms'] = await page.evaluate("""() => {
              const n = performance.getEntriesByType('navigation')[0];
              return n ? {response_end:n.responseEnd, dom_content_loaded:n.domContentLoadedEventEnd,
                          load_event_end:n.loadEventEnd} : null;
            }""")
            result['browser_measurements'] = await page.evaluate("""() => performance.getEntriesByType('measure')
              .filter(e => e.name.startsWith('aria.')).map(e => ({name:e.name,duration_ms:e.duration,detail:e.detail}))""")
            if not any(m['name'] == 'aria.dashboard.dom_update' for m in result['browser_measurements']):
                raise AssertionError('Actual dashboard DOM update was not measured')
            if not any(m['name'] == 'aria.http.headers' and m['detail'].get('request_id')
                       and m['detail'].get('server_handler_ms') is not None for m in result['browser_measurements']):
                raise AssertionError('Correlated server/browser request timing unavailable')
            result['checks'].append('graphical_dashboard_navigation')
            if result['page_error_types']:
                raise RuntimeError('JavaScript errors during visible acceptance')
            result['status'] = 'VERIFIED'
        except Exception as exc:
            result['status'] = 'FAILED'
            result['error_type'] = type(exc).__name__
            # Login failures must not produce credential-bearing screenshots.
            if not await page.locator('#password').count():
                await screenshot('visible-failure.png')
        finally:
            await context.close()
            await browser.close()
    return result


async def inspect_owner(session_id):
    """Read the existing owner GUI; never start a run or change its controls."""
    from playwright.async_api import async_playwright, expect
    if not session_id:
        raise ValueError('An explicit existing owner session is required')
    directory = ROOT / '.local-lab/operational-reliability' / ('owner-visible-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    result = {'status': 'IN_PROGRESS', 'headless': False, 'chromium_sandbox': True,
        'purpose': 'read-only existing owner budget/capability inspection',
        'mutations': ['normal owner login only'], 'model_requests_started': 0,
        'worker_operations_started': 0, 'owner_deployment_modified': False,
        'session_id': session_id, 'directory': str(directory.relative_to(ROOT))}
    credentials = dict(line.split(': ', 1) for line in (ROOT / '.local-lab/login.txt').read_text().splitlines())
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False, chromium_sandbox=True)
        context = await browser.new_context(viewport={'width': 1600, 'height': 1100})
        page = await context.new_page()
        page.set_default_timeout(20000)
        captures = set()
        async def capture(response):
            path = response.url.split('?', 1)[0]
            if not response.ok:
                return
            if path.endswith('/' + session_id + '/model-budget'):
                body = await response.json()
                result['budget'] = {'approved_at': body.get('approved_at'),
                    'limits': {k: (body.get('limits') or {}).get(k) for k in ('max_calls', 'max_tokens', 'max_cost_microusd', 'tariffs')},
                    'usage': {k: (body.get('usage') or {}).get(k) for k in ('calls', 'reserved_tokens', 'reported_tokens',
                        'reserved_cost_microusd', 'reported_cost_microusd', 'unknown_usage_calls', 'unknown_cost_calls', 'stopped', 'stop_reason')}}
            elif path.endswith('/' + session_id + '/autonomous/status'):
                body = await response.json()
                result['run'] = {k: body.get(k) for k in ('run_id', 'run_state', 'reason_code', 'active', 'model_calls', 'steps_taken')}
            elif path.endswith('/api/capabilities'):
                body = await response.json()
                worker = body.get('worker') or {}
                result['worker'] = {k: worker.get(k) for k in ('status', 'available_tools', 'protocol')}
        def response_seen(response):
            task = asyncio.create_task(capture(response))
            captures.add(task)
            task.add_done_callback(captures.discard)
        page.on('response', response_seen)
        try:
            response = await page.goto('http://127.0.0.1:7000/login')
            result['server_build'] = response.headers.get('x-aria-build')
            await page.locator('#username').fill(credentials['Username'])
            await page.locator('#password').fill(credentials['Password'])
            await page.locator('#login-btn').click()
            await page.wait_for_url('http://127.0.0.1:7000/')
            await page.locator('a[href="/dashboard"]').click()
            await page.wait_for_url('http://127.0.0.1:7000/dashboard')
            await page.locator('#engagement-select').select_option(session_id)
            await expect(page.locator('#hero-target')).to_have_text('192.168.77.20')
            await expect(page.locator('#budget-body')).to_contain_text('Engagement ceiling')
            if captures:
                await asyncio.gather(*list(captures), return_exceptions=True)
            await page.screenshot(path=directory / 'owner-budget-inspection.png', full_page=True,
                animations='disabled', mask=[page.locator('#account-name'), page.locator('#account-initial')])
            result['status'] = 'VERIFIED' if 'budget' in result else 'FAILED'
        except Exception as exc:
            result.update(status='BLOCKED', error_type=type(exc).__name__)
        finally:
            await context.close()
            await browser.close()
    (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return 0 if result['status'] == 'VERIFIED' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--visible', action='store_true')
    parser.add_argument('--stream', action='store_true', help='Measure passive synthetic WebSocket events through the real UI')
    parser.add_argument('--prepare', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output')
    parser.add_argument('--inspect-owner', action='store_true', help='Read-only graphical inspection of the original owner deployment')
    parser.add_argument('--owner-session')
    args = parser.parse_args()
    if args.inspect_owner:
        return asyncio.run(inspect_owner(args.owner_session))
    if args.prepare:
        asyncio.run(prepare(Path(args.output)))
        return 0
    if not args.visible:
        parser.error('--visible is required; headless acceptance is unsupported')
    directory = ROOT / '.local-lab/operational-reliability' / ('visible-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    result = {'status': 'IN_PROGRESS', 'started_at': datetime.now(timezone.utc).isoformat(),
              'owner_deployment_modified': False, 'directory': str(directory.relative_to(ROOT))}
    result['head'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    server = None
    try:
        if not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            result.update(status='BLOCKED', reason_code='graphical_session_unavailable')
            return 1
        from integration.reliability_services import create_database
        name, url = asyncio.run(create_database())
        result['database'] = name
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        username, password = 'reliability-' + uuid.uuid4().hex[:12], secrets.token_urlsafe(32)
        env = {**os.environ, 'DATABASE_URL': url, 'ARIA_INTEGRATION': '1',
               'ARIA_RELIABILITY_BROWSER': '1', 'ARIA_BROWSER_USERNAME': username,
               'ARIA_RELIABILITY_STREAM': '1' if args.stream else '0', 'ARIA_RELIABILITY_OUTPUT': str(directory),
               'ARIA_BROWSER_PASSWORD': password, 'SECRET_KEY': secrets.token_urlsafe(48),
               'KALI_AGENT_TOKEN': secrets.token_urlsafe(48), 'KALI_AGENT_URL': '',
               'REDIS_URL': 'redis://127.0.0.1:1/0', 'LLM_ROUTING': 'local',
               'LOCAL_LLM_MODEL': '', 'LOCAL_LLM_URL': 'http://127.0.0.1:1/v1',
               'ALLOWED_ORIGINS': json.dumps([base]),
               'BURP_COMMUNITY_ENABLED': 'false', 'BURP_CONNECTOR_TOKEN': '',
               'REPORT_OUTPUT_DIR': str(directory / 'reports')}
        source = manifest()
        (directory / 'source-manifest.json').write_text(json.dumps(source, indent=2) + '\n')
        with (directory / 'setup.log').open('w') as log:
            subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'],
                           env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            subprocess.run([sys.executable, '-m', 'integration.reliability_visible', '--prepare',
                            '--output', str(directory)], env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        with (directory / 'server.log').open('w') as log:
            server = subprocess.Popen([sys.executable, '-m', 'uvicorn',
                'integration.reliability_visible:guarded_app', '--factory', '--host', '127.0.0.1',
                '--port', str(port), '--workers', '1'], env=env, stdout=log, stderr=subprocess.STDOUT)
            import httpx
            with httpx.Client(trust_env=False, timeout=1) as client:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise RuntimeError('Disposable application startup failed')
                    try:
                        if client.get(base + '/api/ready').status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(.1)
                else:
                    raise TimeoutError('Disposable application readiness deadline')
            if args.stream:
                from integration.reliability_stream import browser_acceptance as acceptance
            else:
                acceptance = browser_acceptance
            result.update(asyncio.run(acceptance(base, directory, username, password)))
        result['source_unchanged_during_acceptance'] = source == manifest()
        if not result['source_unchanged_during_acceptance']:
            result['status'] = 'FAILED'
        return 0 if result['status'] == 'VERIFIED' else 1
    except Exception as exc:
        result.update(status='BLOCKED', error_type=type(exc).__name__)
        return 1
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        result['finished_at'] = datetime.now(timezone.utc).isoformat()
        (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
