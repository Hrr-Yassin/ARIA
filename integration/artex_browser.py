"""Visible Chromium observations against loopback FastAPI with synthetic records."""
import argparse
import asyncio
import hashlib
import json
import re
from statistics import median
from contextlib import ExitStack
from pathlib import Path
from time import perf_counter
from unittest.mock import patch

import psutil
from playwright.async_api import async_playwright, expect
from integration.mission_browser import METRICS, current, loopback_server, sign_in, with_staged_dashboard
from integration.mission_fixture import ALPHA, BETA, TASK2, Fixture, settings


async def run(assets: Path, output: Path, baseline: bool, existing_suite: bool, telemetry: bool = False) -> None:
    output.mkdir(parents=True, exist_ok=True)
    fixture = Fixture(current=True)
    if telemetry:
        fixture.stream_pulses = asyncio.Queue()
    app = with_staged_dashboard(fixture, assets)

    async def captures(sid, owner, before, limit):
        fixture.owner(sid, owner)
        rows = [] if sid != ALPHA else [{'id': 'controlled-http', 'destination': 'http://records.example.test',
            'source': 'burp_community_selected_history',
            'method': 'GET', 'response_status': 200, 'response_content_type': 'application/json',
            'response_body_bytes': 42, 'request_content_type': None, 'imported_at': '2026-11-19T09:00:00Z'}]
        return {'schema_version': 'aria.mission.traffic.v1', 'session_id': sid, 'captures': rows, 'next_before': None}

    async def capture(sid, owner, capture_id):
        captures_page = await captures(sid, owner, None, 1)
        saved = next(row for row in captures_page['captures'] if row['id'] == capture_id)
        return {'schema_version': 'aria.mission.traffic.capture.v1', 'session_id': sid, 'capture': saved,
                'request': {'headers': [], 'preview': {'state': 'historical_metadata'}},
                'response': {'headers': [], 'preview': {'state': 'historical_metadata'}}}

    large_fixture = False

    async def team(sid, owner):
        snapshot = await fixture.team(sid, owner)
        if large_fixture and sid == ALPHA:
            snapshot['evidence'].extend({'id': f'generated-{index:04}', 'source_kind': 'chat', 'source_id': f'import-{index:04}',
                'source_timestamp': '2026-11-19T09:00:00Z', 'trust': 'untrusted_observation'}
                for index in range(1200))
        return snapshot

    errors = []
    checks = {}
    samples = []
    with ExitStack() as stack:
        for mock in fixture.patches():
            stack.enter_context(mock)
        if not baseline:
            stack.enter_context(patch('memory.traffic_observations.retained_traffic', side_effect=captures))
            stack.enter_context(patch('memory.traffic_observations.retained_capture', side_effect=capture))
            if not existing_suite:
                stack.enter_context(patch('memory.team_tasks.team_store.view', side_effect=team))
        async with loopback_server(app) as base, async_playwright() as playwright:
            settings.ALLOWED_ORIGINS.append(base)
            browser = await playwright.chromium.launch(headless=False, chromium_sandbox=True,
                                                       args=['--disable-background-networking'])
            try:
                context = await browser.new_context(viewport={'width': 1440, 'height': 960}, reduced_motion='reduce')
                await context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else route.abort())
                page = await context.new_page()
                page.set_default_timeout(7500)
                page.on('pageerror', lambda error: errors.append(str(error)))
                if existing_suite:
                    result = await current(browser, base, output, fixture)
                    result.update(browser=browser.version, headless=False, fixture='Synthetic owner-scoped records')
                    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                    if result['pageErrors'] or any(item['status'] != 'passed' for item in result['checks']):
                        raise SystemExit(1)
                    return
                await sign_in(page, base, mission=True)
                navigation = page.get_by_role('navigation', name='Mission Control sections')
                for _ in range(5):
                    start = perf_counter()
                    await page.goto(base + '/dashboard?sid=' + ALPHA)
                    await expect(page.get_by_label('Current session')).to_have_value(ALPHA)
                    await expect(page.get_by_text('Admission blocked', exact=True)).to_be_visible()
                    samples.append({'readyMs': 1000 * (perf_counter() - start), **await page.evaluate(METRICS)})
                await page.screenshot(path=output / 'overview.png')
                if not baseline:
                    async def check(name, operation):
                        try:
                            checks[name] = await operation() or {'status': 'passed'}
                        except Exception as error:
                            checks[name] = {'status': 'failed', 'error': str(error)[:1000]}
                            await page.screenshot(path=output / (name + '-failed.png'))
                            dialog = page.get_by_role('dialog')
                            if await dialog.is_visible():
                                await page.get_by_role('button', name='Close inspector').click()

                    async def graphs():
                        start = perf_counter()
                        await navigation.get_by_role('link', name='Exploration Graph', exact=True).click()
                        graph = page.get_by_role('group', name='Exploration Graph', exact=True)
                        await expect(graph.locator('.graph-node').first).to_be_visible()
                        elapsed = 1000 * (perf_counter() - start)
                        await expect(graph.locator('[data-kind="Depends on"]')).to_have_count(1)
                        frames = await graph.evaluate('''async svg => {
                            const scene = svg.querySelector('g')
                            const values = []
                            let prev = performance.now()
                            for (let index = 0; index < 30; index += 1) {
                              await new Promise(requestAnimationFrame)
                              const now = performance.now()
                              values.push(now - prev)
                              prev = now
                              scene.setAttribute('transform', 'translate(' + index + ', 0)')
                            }
                            return values
                        }''')
                        await page.get_by_role('button', name='Zoom in', exact=True).click()
                        await page.get_by_role('button', name='Fit graph', exact=True).click()
                        await page.screenshot(path=output / 'exploration.png')
                        node = graph.get_by_role('button', name='Review evidence freshness, Task, blocked')
                        await node.focus()
                        await node.press('Enter')
                        inspector = page.get_by_role('dialog')
                        await expect(inspector.get_by_text('Task:' + TASK2, exact=True)).to_be_visible()
                        await inspector.get_by_role('button', name='References · Depends on · Review imported service inventory').click()
                        await expect(inspector.get_by_role('heading', name='Review imported service inventory')).to_be_visible()
                        await inspector.get_by_role('button', name='Close inspector').click()
                        await page.get_by_label('Search graph').fill('does-not-exist')
                        await expect(page.get_by_text('No records match these filters.')).to_be_visible()
                        await page.get_by_label('Search graph').fill('')
                        await page.get_by_label('Record type').select_option('Evidence')
                        await expect(graph.locator('.graph-node')).to_have_count(1)
                        await navigation.get_by_role('link', name='Asset Graph', exact=True).click()
                        asset = page.get_by_role('group', name='Asset Graph', exact=True)
                        await expect(asset.locator('.graph-node').first).to_be_visible()
                        await page.screenshot(path=output / 'asset.png')
                        await page.get_by_text('Visible node groups', exact=True).click()
                        await page.get_by_role('checkbox', name='Evidence', exact=True).uncheck()
                        await expect(asset.locator('[data-node^="Evidence:"]')).to_have_count(0)
                        await page.get_by_role('checkbox', name='Evidence', exact=True).check()
                        await expect(asset.locator('[data-node^="Evidence:"]')).to_have_count(1)
                        return {'status': 'passed', 'explorationReadyMs': elapsed, 'graphFrameMedianMs': median(frames[1:]),
                                'graphFrameSamples': len(frames) - 1}

                    async def task_views():
                        await navigation.get_by_role('link', name='Tasks', exact=True).click()
                        await expect(page.get_by_role('table').get_by_text('Review evidence freshness')).to_be_visible()
                        for value in ('board', 'timeline'):
                            await page.get_by_label('Task layout').select_option(value)
                            await expect(page.get_by_role('button', name='Review evidence freshness', exact=False)).to_be_visible()
                        await page.get_by_label('Task layout').select_option('dependencies')
                        await expect(page.get_by_role('group', name='Agent assignments and recorded dependencies')).to_be_visible()
                        await navigation.get_by_role('link', name='Communication', exact=True).click()
                        await page.get_by_role('button', name='Review evidence freshness', exact=False).click()
                        await expect(page.get_by_role('dialog').get_by_role('heading', name='Revision 3')).to_be_visible()
                        await expect(page.get_by_role('group', name='Recorded dependency roles at claim')).to_be_visible()
                        await page.screenshot(path=output / 'communication.png')
                        await page.get_by_role('button', name='Close inspector').click()

                    async def traffic():
                        await navigation.get_by_role('link', name='Traffic', exact=True).click()
                        await page.get_by_role('button', name='GET http://records.example.test', exact=False).click()
                        inspector = page.get_by_role('dialog')
                        await expect(inspector.get_by_text('application/json', exact=True)).to_be_visible()
                        await page.screenshot(path=output / 'traffic.png')
                        await inspector.get_by_role('button', name='Close inspector').click()
                        await page.get_by_label('Search capture page').fill('404')
                        await expect(page.get_by_text('0 of 1 captures on page 1')).to_be_visible()
                        await page.get_by_label('Current session').select_option(BETA)
                        await expect(page.get_by_text('0 of 0 captures on page 1')).to_be_visible()
                        await expect(page.get_by_role('button', name='GET http://records.example.test', exact=False)).to_have_count(0)
                        await page.set_viewport_size({'width': 390, 'height': 844})
                        await page.screenshot(path=output / 'traffic-mobile.png')
                        assert await page.evaluate('document.documentElement.scrollWidth') <= 390

                    async def events():
                        await page.get_by_label('Current session').select_option(ALPHA)
                        await page.set_viewport_size({'width': 1440, 'height': 960})
                        await navigation.get_by_role('link', name='Events', exact=True).click()
                        await page.get_by_label('Event source').select_option('model')
                        await expect(page.get_by_role('button', name='Model attempt reserved', exact=False).first).to_be_visible()
                        await page.get_by_role('button', name='Replay retained events').click()
                        await expect(page.get_by_text('Retained record 1 / 15', exact=False)).to_be_visible()
                        await page.get_by_role('button', name='Exit replay').click()

                    async def event_delivery():
                        await page.get_by_label('Event source').select_option('team')
                        await expect(page.get_by_text('Run stream connected', exact=True)).to_be_visible(timeout=15000)
                        await expect(page.get_by_text('3 retained records.', exact=False)).to_be_visible()
                        measurements = []
                        for sequence in range(4, 9):
                            predicate = lambda reply: reply.ok and f'team_after={sequence - 1}' in reply.url
                            async with page.expect_response(predicate):
                                start = perf_counter()
                                fixture.extra_team = sequence - 3
                                fixture.stream_pulses.put_nowait(sequence)
                            await expect(page.get_by_text(f'{sequence} retained records.', exact=False)).to_be_visible()
                            measurements.append(round(1000 * (perf_counter() - start), 3))
                        return {'status': 'passed', 'websocket_to_visible_event_ms': measurements}

                    async def api_diagnostics():
                        await navigation.get_by_role('link', name='Tasks', exact=True).click()
                        await expect(page.get_by_text('Review evidence freshness', exact=True).first).to_be_visible()
                        await navigation.get_by_role('link', name='Infrastructure', exact=True).click()
                        await page.get_by_role('button', name='Simple mode', exact=True).click()
                        card = page.locator('section.card').filter(has=page.get_by_role('heading', name='API diagnostics', exact=True))
                        await expect(card.get_by_text('/api/team/' + ALPHA, exact=True)).to_be_visible()
                        route = base + '/api/ready'

                        async def transport_failure(intercepted):
                            await intercepted.abort('failed')

                        fixture.faults['/api/health'] = (500, {'detail': 'Synthetic application error'})
                        await page.route(route, transport_failure)
                        try:
                            await page.get_by_role('button', name='Refresh', exact=True).click()
                            for label in ('HTTP 5xx responses', 'Transport failures'):
                                value = card.get_by_text(label, exact=True).locator('xpath=following-sibling::dd[1]')
                                await expect(value).to_have_text('1')
                            value = card.get_by_text('Round-trip p95', exact=True).locator('xpath=following-sibling::dd[1]')
                            await expect(value).to_have_text(re.compile(r'^\d+\.\d ms$'))
                        finally:
                            fixture.faults.pop('/api/health')
                            await page.unroute(route, transport_failure)
                        await page.screenshot(path=output / 'api-diagnostics.png')
                        await page.get_by_label('Current session').select_option(BETA)
                        await expect(card.get_by_text('/api/team/' + ALPHA, exact=True)).to_have_count(0)
                        await page.get_by_label('Current session').select_option(ALPHA)
                        await page.get_by_role('button', name='Advanced mode', exact=True).click()

                    async def large_graph():
                        nonlocal large_fixture
                        large_fixture = True
                        try:
                            await navigation.get_by_role('link', name='Asset Graph', exact=True).click()
                            await page.get_by_role('button', name='Refresh', exact=True).click()
                            await page.get_by_label('Record type').select_option('Evidence')
                            await expect(page.get_by_text('1–80 of 1201 records', exact=True)).to_be_visible()
                            graph = page.get_by_role('group', name='Asset Graph', exact=True)
                            await expect(graph.locator('.graph-node')).to_have_count(80)
                            await page.get_by_role('button', name='Next records', exact=True).click()
                            await expect(page.get_by_text('81–160 of 1201 records', exact=True)).to_be_visible()
                            assert len(set(await graph.locator('.graph-node').evaluate_all(
                                'nodes => nodes.map(node => node.dataset.node)'))) == 80
                            bounds = await graph.bounding_box()
                            assert bounds is not None
                            pan = graph.locator('g').first
                            transform = await pan.get_attribute('transform')
                            await page.mouse.move(bounds['x'] + 16, bounds['y'] + 20)
                            await page.mouse.down()
                            await page.mouse.move(bounds['x'] + 68, bounds['y'] + 35, steps=12)
                            await page.mouse.up()
                            assert await pan.get_attribute('transform') != transform
                            cdp = await browser.new_browser_cdp_session()
                            before = {item['id']: item['cpuTime'] for item in (await cdp.send('SystemInfo.getProcessInfo'))['processInfo']}
                            started = perf_counter()
                            frames = await graph.evaluate('''async svg => {
                                const scene = svg.querySelector('g')
                                const original = scene.getAttribute('transform')
                                const values = []
                                let prev = performance.now()
                                for (let step = 0; step < 60; step += 1) {
                                  await new Promise(requestAnimationFrame)
                                  const now = performance.now()
                                  values.push(now - prev)
                                  prev = now
                                  scene.setAttribute('transform', 'translate(' + step + ', 10)')
                                }
                                scene.setAttribute('transform', original)
                                return values
                            }''')
                            end = (await cdp.send('SystemInfo.getProcessInfo'))['processInfo']
                            wall = perf_counter() - started
                            cpu = sum(max(0, item['cpuTime'] - before[item['id']])
                                      for item in end if item['id'] in before)
                            rss = 0
                            for process in end:
                                try:
                                    rss += psutil.Process(process['id']).memory_info().rss
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    rss = None
                                    break
                            await cdp.detach()
                            await page.get_by_label('Search graph').fill('generated-1199')
                            await expect(graph.locator('.graph-node')).to_have_count(1)
                            return {'status': 'passed', 'retainedNodes': 1201, 'mountedNodes': 80,
                                    'frameMedianMs': median(frames[1:]), 'frameSamples': len(frames) - 1,
                                    'browserCpuPercent': 100 * cpu / wall, 'browserSummedRssBytes': rss}
                        finally:
                            large_fixture = False

                    await check('graphs', graphs)
                    await check('task_views', task_views)
                    await check('traffic', traffic)
                    await check('events', events)
                    if telemetry:
                        await check('event_delivery', event_delivery)
                        await check('api_diagnostics', api_diagnostics)
                    await check('large_graph', large_graph)
                result = {'stage': 'baseline' if baseline else 'candidate', 'fixture': 'Synthetic owner-scoped records',
                          'browser': browser.version, 'headless': False, 'checks': checks, 'samples': samples,
                          'pageErrors': errors, 'assets': {str(path.relative_to(assets)): hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in assets.rglob('*') if path.is_file()}}
                (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                if errors or any(item['status'] != 'passed' for item in checks.values()):
                    raise SystemExit(1)
            finally:
                await browser.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--existing-suite', action='store_true')
    parser.add_argument('--telemetry', action='store_true')
    arguments = parser.parse_args()
    asyncio.run(run(arguments.assets, arguments.output, arguments.baseline, arguments.existing_suite, arguments.telemetry))
