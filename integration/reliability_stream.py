"""Passive graphical event timing on the guarded disposable deployment only.

Fixture events exercise the real authenticated stream and frontend. They start
no engine loop, model, authorization proposal or worker job. Browser and server
intervals remain in their own clock domains; no end-to-end latency is inferred.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
from unittest.mock import patch

OBJECTIVE = 'Measure synthetic event delivery only; no model, worker or target execution.'


def configure_fixture(app, directory: Path) -> None:
    """Called only after reliability_visible.guarded_app has checked isolation."""
    from agents.autonomous_engine import SessionRunState, autonomous_engine
    from api.routers import pentest
    from memory.database_models import PentestSession, async_session
    from memory.knowledge_store import scope_identity_digest
    from config.settings import settings
    import os
    from sqlalchemy.engine import make_url
    database = make_url(settings.DATABASE_URL).database or ''
    if (os.environ.get('ARIA_RELIABILITY_BROWSER') != '1' or settings.KALI_AGENT_URL
            or not database.startswith('aria_reliability_') or not database.endswith('_test')):
        raise RuntimeError('Isolated browser fixture and disabled worker required')
    original_lifespan = app.router.lifespan_context
    original_log = pentest.log
    original_stream = autonomous_engine.stream_events
    connected = asyncio.Event()

    class SendLog:
        def __getattr__(self, name):
            return getattr(original_log, name)
        def info(self, event, **fields):
            if event == 'autonomous_websocket_send':
                with (directory/'websocket-sends.jsonl').open('a') as file:
                    file.write(json.dumps(fields)+'\n')
            original_log.info(event, **fields)

    @asynccontextmanager
    async def lifespan(application):
        async with original_lifespan(application):
            fixture = json.loads((directory/'fixture.json').read_text())
            sid = fixture['session_id']
            async with async_session() as db:
                session = await db.get(PentestSession, sid)
                owner, target, scope = session.user_id, session.target, session.scope
            state = SessionRunState(sid, owner, 'discovery', target, 'expert', owner_id=owner,
                objective=OBJECTIVE, scope_digest=scope_identity_digest(scope, target))
            autonomous_engine._runs[sid] = state
            autonomous_engine._approvals[sid] = {}
            async def stream(session_id):
                if session_id == sid:
                    connected.set()  # Router has already authenticated/authorized this subscriber.
                async for event in original_stream(session_id):
                    yield event
            async def produce():
                try:
                    await asyncio.wait_for(connected.wait(), timeout=45)
                    for number in range(1, 4):
                        await autonomous_engine._emit(state, {'type': 'auto_activity', 'status': 'running',
                            'action': f'Synthetic telemetry event {number}; no operation executed',
                            'telemetry_fixture': True})
                        await asyncio.sleep(.1)
                    state.run_state, state.active = 'blocked', False
                    state.reason_code = 'synthetic_measurement_complete'
                    state.reason = 'Synthetic telemetry complete; discovery was not executed.'
                    await autonomous_engine._emit(state, {'type': 'auto_complete', 'status': 'blocked',
                        'reason_code': state.reason_code, 'action': state.reason, 'telemetry_fixture': True})
                finally:
                    state.active = False
            with patch.object(autonomous_engine, 'stream_events', side_effect=stream), \
                 patch.object(pentest, 'log', SendLog()):
                producer = asyncio.create_task(produce())
                try:
                    yield
                finally:
                    if not producer.done():
                        producer.cancel()
                    await asyncio.gather(producer, return_exceptions=True)
    app.router.lifespan_context = lifespan


async def browser_acceptance(base: str, directory: Path, username: str, password: str) -> dict:
    from playwright.async_api import async_playwright, expect
    result = {'status': 'IN_PROGRESS', 'headless': False, 'chromium_sandbox': True,
        'fixture_data': True, 'api_interaction_substitutions': False, 'route_mocks': False,
        'page_error_types': [], 'checks': [], 'screenshots': [],
        'limitations': ['Passive synthetic events, no engine/model/worker execution.',
            'Server send and browser event/microtask/frame intervals are separate clocks; no wire latency.']}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False, chromium_sandbox=True)
        result['browser_version'] = browser.version
        page = await browser.new_page(viewport={'width': 1600, 'height': 1100})
        page.set_default_timeout(20000)
        page.on('pageerror', lambda error: result['page_error_types'].append(type(error).__name__))
        await page.add_init_script("""(() => {
          const Native = window.WebSocket;
          window.fixtureMessages = [];
          window.WebSocket = class extends Native {
            constructor(...args) {
              super(...args);
              this.addEventListener('message', message => {
                let data;
                try { data = JSON.parse(message.data); } catch { return; }
                if (!data.telemetry_fixture || window.fixtureMessages.length >= 20) return;
                const start = performance.now();
                const sample = {run_id:data.run_id, session_id:data.session_id,
                  event_sequence:data.event_sequence, received_browser_ms:start};
                window.fixtureMessages.push(sample);
                queueMicrotask(() => {sample.observer_microtask_ms = performance.now() - start;});
                requestAnimationFrame(() => requestAnimationFrame(() => {
                  sample.frame_opportunity_ms = performance.now() - start;
                }));
              });
            }
          };
        })();""")
        try:
            await page.goto(base+'/login')
            await page.locator('#username').fill(username)
            await page.locator('#password').fill(password)
            await page.locator('#login-btn').click()
            await page.wait_for_url(base+'/')
            await page.locator('.session-item', has_text='Synthetic reliability: twelve').click()
            await expect(page.locator('#target-value')).to_have_text('192.0.2.1')
            await expect(page.locator('#auto-label')).to_have_text('AUTONOMOUS — BLOCKED')
            await page.wait_for_function('window.fixtureMessages.length === 4 && window.fixtureMessages.every(m => Number.isFinite(m.frame_opportunity_ms))')
            result['browser_events'] = await page.evaluate('window.fixtureMessages')
            sends = [json.loads(line) for line in (directory/'websocket-sends.jsonl').read_text().splitlines()]
            result['server_sends'] = sends
            assert len(sends) == 4 and len({s['websocket_stream_id'] for s in sends}) == 1
            assert all(s['outcome'] == 'succeeded' and s['websocket_asgi_send_ms'] >= 0 for s in sends)
            key = lambda event: (event['session_id'], event['run_id'], event['event_sequence'])
            assert [key(e) for e in sends] == [key(e) for e in result['browser_events']]
            assert len({key(e) for e in sends}) == 4
            assert not result['page_error_types']
            result['checks'] = ['graphical_login_and_session_selection', 'real_owned_stream_delivery',
                'four_distinct_ordered_events', 'server_browser_identity_correlation', 'truthful_blocked_terminal']
            await page.screenshot(path=directory/'stream-workspace.png', animations='disabled')
            result['screenshots'].append('stream-workspace.png')
            result['status'] = 'VERIFIED'
        except Exception as error:
            result.update(status='FAILED', error_type=type(error).__name__)
        finally:
            await browser.close()
    return result
