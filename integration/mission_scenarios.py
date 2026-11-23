"""Representative Mission Control browser journeys over disposable fixture stores."""
from __future__ import annotations

import asyncio
from hashlib import sha256
import re
from time import perf_counter
from zipfile import ZipFile
from io import BytesIO

from PIL import Image, ImageChops

from playwright.async_api import expect

from integration.mission_browser import METRICS, sign_in
from integration.mission_fixture import ALPHA, BETA, FOREIGN, JOB, OLDER_CAMPAIGN, PENDING_REVIEW, REPORT, REPORT_DIGEST, REPORT_FILES

READY = '[data-mission-ready="true"]'


async def scenarios(page, base, out, fixture, errors):
    checks = []
    samples = []
    changes = []
    renderers = []
    files = []
    app = page.locator("#mission-content")
    nav = page.get_by_role("navigation", name="Mission Control sections")
    picker = page.get_by_label("Current session", exact=True)
    dialog = page.get_by_role("dialog")
    screenshot = lambda path: page.screenshot(path=out / path)
    saved_stream = fixture.current
    fixture.current = False

    async def check(name, run):
        started = perf_counter()
        row = {'name': name, 'status': 'passed'}
        try:
            await run()
        except Exception as exc:
            row.update(status='failed', error=f'{type(exc).__name__}: {exc}'[:1300])
            try:
                await screenshot('failure-' + str(len(checks) + 1) + '.png')
            except Exception:
                pass
        row['durationMs'] = round((perf_counter() - started) * 1000, 2)
        checks.append(row)
        print(f'{row["status"]:6s}  {name}', flush=True)
        if 'error' in row:
            print(row['error'], flush=True)

    async def snap(name):
        await screenshot(name)
        files.append(name)

    async def go(name):
        await nav.get_by_role("link", name=name, exact=True).click()
        await expect(page.locator('#mission-title')).to_have_text('Mission Control' if name == 'Overview' else name)

    async def refresh():
        await page.get_by_role('button', name='Refresh', exact=True).click()
        await expect(page.locator(READY)).to_have_count(1)

    async def select(sid):
        await picker.select_option(sid)
        await expect(picker).to_have_value(sid)
        await expect(page.locator(READY)).to_have_count(1)

    async def close():
        await page.get_by_role('button', name='Close inspector', exact=True).click()
        await expect(dialog).to_have_count(0)

    async def login():
        await sign_in(page, base, mission=True)
        await expect(page.locator(READY)).to_have_count(1)
        await expect(nav).to_be_visible()
        await expect(picker).to_have_value(ALPHA)
        await expect(app.get_by_text('Review retained service inventory', exact=True)).to_be_visible()

    async def cold_load():
        for _ in range(5):
            started = perf_counter()
            await page.goto(base + '/dashboard?sid=' + ALPHA)
            await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
            await expect(page.locator(READY)).to_have_count(1)
            samples.append({'readyMs': round((perf_counter() - started) * 1000, 2), **await page.evaluate(METRICS)})
        await snap('overview-desktop.png')

    async def visual_repeatability():
        before = (out / 'overview-desktop.png').read_bytes()
        await page.reload()
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
        await expect(page.locator(READY)).to_have_count(1)
        await page.evaluate('document.fonts.ready')
        after = await page.screenshot()
        exact = sha256(after).digest() == sha256(before).digest()
        first, second = (Image.open(BytesIO(blob)).convert('RGB') for blob in (before, after))
        assert first.size == second.size
        difference = ImageChops.difference(first, second)
        changed = sum(pixel != (0, 0, 0) for pixel in difference.get_flattened_data())
        largest = max(high for _, high in difference.getextrema())
        # GPU raster rounding can vary by 1–2 colour levels on curved edges.
        # Retain exact-match and difference measures; reject shape/text changes.
        assert largest <= 2 and changed <= first.width * first.height * .0001, (changed, largest)
        changes.append({'overviewRefreshVisualMatch': True, 'overviewRefreshPixelMatch': exact,
                        'overviewChangedPixels': changed, 'overviewMaxChannelDifference': largest,
                        'screenshotSHA256': sha256(after).hexdigest()})

    async def list_sessions():
        await go('Sessions')
        await page.get_by_label('Search name or target').fill('Quarterly')
        await expect(app.get_by_text('1 of 2 sessions')).to_be_visible()
        await page.get_by_label('Session status').select_option('active')
        await app.get_by_role('button', name='Quarterly controls review', exact=False).click()
        await expect(picker).to_have_value(BETA)
        await expect(app.get_by_role('heading', name='Quarterly controls review')).to_be_visible()

    async def restore():
        await page.reload()
        await expect(picker).to_have_value(BETA)
        await expect(app.get_by_role('heading', name='Quarterly controls review')).to_be_visible()
        await expect(app.get_by_text('Admission undetermined', exact=True)).to_be_visible()
        await expect(app.get_by_text('Unknown / 20', exact=True)).to_be_visible()

    async def create():
        await go('Sessions')
        await app.get_by_role('button', name='New session').click()
        await dialog.get_by_label('Session name').fill('New review records')
        await dialog.get_by_label('Engagement target').fill('new-review.example.test')
        await dialog.get_by_role('button', name='Create session').click()
        await expect(app.get_by_role('heading', name='New review records')).to_be_visible()
        assert any(item['name'] == 'New review records' for item in fixture.sessions.values())

    async def switching():
        started = perf_counter()
        await select(ALPHA)
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
        changes.append({'selectionMs': round((perf_counter() - started) * 1000, 2)})
        path = '/api/mission/' + BETA + '/accounting'
        fixture.delays[path] = 0.7
        await picker.select_option(BETA)
        await expect(app.get_by_role('heading', name='Quarterly controls review')).to_be_visible()
        await picker.select_option(ALPHA)
        await expect(app.get_by_role('heading', name='Service inventory review')).to_be_visible()
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
        await asyncio.sleep(0.75)
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
        fixture.delays.pop(path, None)

    async def workspace():
        href = await page.get_by_role('link', name='Research workspace').get_attribute('href')
        assert href == '/dashboard?view=workspace&sid=' + ALPHA, href
        await page.get_by_role('link', name='Research workspace').click()
        frame = page.frame_locator('iframe.workspace-frame')
        await expect(frame.locator('#workspace-main')).to_be_visible()
        await expect(frame.get_by_text('Retained fixture note for ' + ALPHA, exact=True)).to_be_visible()
        await expect(frame.get_by_role('button', name='Toggle autonomous mode')).to_be_enabled()
        draft = frame.get_by_role('textbox', name='Message or autonomous objective')
        await draft.click()
        await draft.press_sequentially('Unsent operator draft; no model request', delay=1)
        await expect(draft).to_have_value('Unsent operator draft; no model request')
        await refresh()
        await page.get_by_role('button', name='Simple mode', exact=True).click()
        await expect(draft).to_have_value('Unsent operator draft; no model request')
        await page.get_by_role('button', name='Advanced mode', exact=True).click()
        assert await page.evaluate("localStorage.getItem('current_session')") == ALPHA
        await select(BETA)
        await expect(frame.get_by_text('Retained fixture note for ' + BETA, exact=True)).to_be_visible()
        await expect(frame.get_by_text('Retained fixture note for ' + ALPHA, exact=True)).to_have_count(0)
        await expect(frame.get_by_role('textbox', name='Message or autonomous objective')).to_have_value('')
        await select(ALPHA)
        await expect(frame.get_by_text('Retained fixture note for ' + ALPHA, exact=True)).to_be_visible()
        await snap('workspace-integrated.png')
        await page.set_viewport_size({'width': 390, 'height': 844})
        await expect(frame.get_by_role('textbox', name='Message or autonomous objective')).to_be_visible()
        assert await frame.locator('html').evaluate('node => node.scrollWidth <= window.innerWidth'), 'Embedded workspace overflows'
        await page.set_viewport_size({'width': 1440, 'height': 960})
        await go('Overview')
        await expect(page.locator('iframe.workspace-frame')).to_have_count(0)
        await expect(picker).to_have_value(ALPHA)

    async def scope():
        await app.get_by_role('button', name='Inspect scope').click()
        await expect(dialog.get_by_text('records.example.test', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('443', exact=True)).to_be_visible()
        await page.keyboard.press('Escape')
        await expect(dialog).to_have_count(0)

    async def graph():
        await go('Agents')
        graph = app.get_by_role('group', name='Agent assignments and recorded dependencies')
        await expect(graph).to_be_visible()
        await graph.get_by_role('button', name='Correlation, Agent, blocked').click()
        await expect(dialog.get_by_role('heading', name='Correlation')).to_be_visible()
        await dialog.get_by_role('button', name='Review evidence freshness', exact=False).click()
        await expect(dialog.get_by_text('Awaiting current service inventory', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('The inventory export may be stale.', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('A second reference to the same inventory is not independent.', exact=True)).to_be_visible()
        await dialog.get_by_role('button', name='Inspect task history', exact=True).click()
        await expect(dialog.get_by_role('heading', name='Revision 3')).to_be_visible()
        await expect(dialog.get_by_text('fixture-review-run', exact=True)).to_have_count(2)
        await expect(dialog.get_by_text('fixture-origin-run', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('Evidence prepared for review', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('Recorded when the review request was prepared. Provider delivery is unknown.',
                                        exact=True)).to_be_visible()
        await expect(dialog.get_by_text('A second reference to the same inventory is not independent.', exact=True)).to_be_visible()
        await snap('task-history.png')
        await close()
        await graph.get_by_role('button', name='Review evidence freshness, Task, blocked').click()
        await dialog.get_by_role('button', name='Recorded status and service timestamp', exact=False).click()
        await expect(dialog.get_by_text('Simulated fixture', exact=True)).to_be_visible()
        await close()
        await app.get_by_role('button', name='Zoom in', exact=True).click()
        await app.get_by_role('button', name='Fit graph', exact=True).click()
        await app.get_by_label('Task state').select_option('blocked')
        await expect(graph.get_by_role('button', name='Review evidence freshness, Task, blocked')).to_be_visible()
        await expect(graph.get_by_role('button', name='Review imported service inventory, Task, completed')).to_have_count(0)
        await app.get_by_label('Task state').select_option('')
        await snap('agents-desktop.png')

    async def events_and_replay():
        await go('Events')
        await app.get_by_label('Event source').select_option('team')
        await expect(app.get_by_text('3 retained records.', exact=False)).to_be_visible()
        await app.get_by_role('button', name='Replay retained events').click()
        await expect(app.get_by_label('Historical replay position')).to_be_visible()
        await expect(app.get_by_text('Retained record 1 / 3', exact=False)).to_be_visible()
        await app.get_by_role('button', name='Exit replay').click()
        await app.get_by_label('Event source').select_option('')
        await app.get_by_label('Search events').fill('fixture-task-2')
        await expect(app.get_by_text('1 retained record.', exact=False)).to_be_visible()
        await app.get_by_label('Search events').fill('')

    async def advanced_and_renderers():
        await page.get_by_role('button', name='Simple mode').click()
        await expect(page.locator('html')).to_have_attribute('data-mode', 'advanced')
        await expect(app.get_by_role('heading', name='Operational stages')).to_be_visible()
        await app.get_by_role('heading', name='Activity density').scroll_into_view_if_needed()
        await expect(app.locator('[data-renderer="Canvas 2D"]')).to_have_count(1)
        await app.get_by_label('Renderer').select_option('gpu')
        await expect(app.locator('.density')).to_have_attribute('data-renderer', re.compile(r'^(PixiJS|Canvas 2D)'))
        await expect(app.locator('.density .subtle')).to_contain_text(re.compile(r'^(PixiJS|GPU unavailable)'))
        renderer = await app.locator('.density').get_attribute('data-renderer')
        assert renderer
        renderers.append(renderer)
        if renderer == 'Canvas 2D':
            await expect(app.get_by_text('GPU unavailable', exact=False)).to_be_visible()
        else:
            await expect(app.locator('.density canvas')).to_be_visible()
        await app.get_by_role('heading', name='Event relationships').scroll_into_view_if_needed()
        await expect(app.get_by_role('group', name='Retained event relationships')).to_be_visible()
        await snap('event-relationships.png')
        return renderer

    async def renderer_fallback():
        await app.get_by_role('heading', name='Activity density').scroll_into_view_if_needed()
        await app.get_by_label('Renderer').select_option('canvas')
        await expect(app.locator('.density')).to_have_attribute('data-renderer', 'Canvas 2D')
        await page.evaluate("""() => {
          const base = HTMLCanvasElement.prototype.getContext;
          window.fixtureCanvasContext = base;
          HTMLCanvasElement.prototype.getContext = function (kind, ...args) {
            if (kind === 'webgl' || kind === 'webgl2' || kind === 'experimental-webgl') return null;
            return base.call(this, kind, ...args);
          };
        }""")
        try:
            await app.get_by_label('Renderer').select_option('gpu')
            await expect(app.locator('.density .subtle')).to_contain_text('GPU unavailable')
            await expect(app.locator('.density')).to_have_attribute('data-renderer', 'Canvas 2D')
        finally:
            await page.evaluate("""() => {
              HTMLCanvasElement.prototype.getContext = window.fixtureCanvasContext;
              delete window.fixtureCanvasContext;
            }""")

    async def retained_topology():
        fixture.current = saved_stream
        try:
            await go('Investigation')
            await refresh()
            await app.get_by_role('heading', name='Recorded topology', exact=True).scroll_into_view_if_needed()
            await expect(app.get_by_role('group', name='Recorded host topology')).to_be_visible()
            await app.get_by_role('heading', name='Application topology', exact=True).scroll_into_view_if_needed()
            visual = app.get_by_role('group', name='Recorded application map evidence')
            await expect(visual).to_be_visible()
            await expect(visual.locator('[data-kind="Evidence reference"]')).to_have_count(1)
            await snap('application-topology.png')
        finally:
            fixture.current = False

    async def commands():
        await go('Operations')
        await app.get_by_role('button', name='Curl', exact=False).filter(has_text='HTTP 200').click()
        await expect(dialog.get_by_text('HTTP status 200', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('fixture-private-marker', exact=False)).to_have_count(0)
        await close()
        await app.get_by_role('button', name=JOB, exact=False).click()
        await expect(dialog.get_by_text('Output SHA-256', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('Failed', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('httpx.http.probe.v1', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('1.7.1', exact=True)).to_be_visible()
        await close()

    async def frozen_replay():
        await go('Events')
        await app.get_by_label('Event source').select_option('team')
        await app.get_by_role('button', name='Replay retained events').click()
        await expect(app.get_by_text('Retained record 1 / 3', exact=False)).to_be_visible()
        fixture.extra_team = 1
        try:
            await refresh()
            await expect(app.get_by_text('Retained record 1 / 3', exact=False)).to_be_visible()
            await app.get_by_label('Search events').fill('no-matching-event')
            await expect(app.get_by_text('No events match the current filters.', exact=True)).to_be_visible()
            await expect(app.get_by_role('button', name='Exit replay')).to_be_enabled()
            await app.get_by_label('Search events').fill('')
            await app.get_by_role('button', name='Exit replay').click()
            await expect(app.get_by_text('4 retained records.', exact=False)).to_be_visible()
            await app.get_by_role('button', name='Replay retained events').click()
            key = f'/api/mission/{ALPHA}/events'
            fixture.faults[key] = (403, {'detail': 'Test session access revoked'})
            try:
                await refresh()
                await expect(app.get_by_text('Access was denied.', exact=False)).to_be_visible()
                await expect(app.get_by_role('button', name='Exit replay')).to_have_count(0)
                await expect(app.get_by_role('region', name='Event timeline')).to_have_count(0)
            finally:
                fixture.faults.pop(key, None)
        finally:
            fixture.extra_team = 0
            await page.reload()
        await expect(page.locator(READY)).to_have_count(1)

    async def campaign_archive():
        await go('Events')
        choices = app.get_by_label('Campaign timeline')
        await expect(choices.locator(f'option[value="{OLDER_CAMPAIGN}"]')).to_have_count(0)
        await app.get_by_role('button', name='Load earlier campaigns').click()
        await expect(choices.locator(f'option[value="{OLDER_CAMPAIGN}"]')).to_have_count(1)
        route = f'/api/mission/{ALPHA}/campaigns/{OLDER_CAMPAIGN}/events'
        fixture.faults[route] = (503, {'detail': 'Fixture archive unavailable'})
        try:
            await choices.select_option(OLDER_CAMPAIGN)
            await expect(app.get_by_role('button', name='Retry campaign snapshot')).to_be_visible()
            await expect(app.get_by_text('0 retained records.', exact=False)).to_have_count(0)
        finally:
            fixture.faults.pop(route, None)
        await app.get_by_role('button', name='Retry campaign snapshot').click()
        await expect(app.get_by_text('Campaign snapshot', exact=True)).to_be_visible()
        await expect(app.get_by_text('Earlier campaign events are outside retention', exact=True)).to_be_visible()
        await expect(app.get_by_text('50 retained records.', exact=False)).to_be_visible()
        await expect(app.get_by_role('button', name='Campaign completed', exact=False)).to_be_visible()
        await expect(app.get_by_role('button', name='Cancel campaign')).to_have_count(0)
        await app.get_by_role('button', name='Replay retained events').click()
        await expect(app.get_by_text('Retained record 1 / 50', exact=False)).to_be_visible()
        await app.get_by_role('button', name='Exit replay').click()
        await choices.select_option('')
        await expect(app.get_by_text('Campaign snapshot', exact=True)).to_have_count(0)
        await expect(app.get_by_role('button', name='Campaign completed', exact=False)).to_have_count(0)

    async def evidence():
        await go('Investigation')
        await app.get_by_role('button', name='Recorded status and service timestamp', exact=False).click()
        await expect(dialog.get_by_text(JOB, exact=True)).to_be_visible()
        await close()
        await app.get_by_role('button', name='Inventory timestamp is stale', exact=False).click()
        await expect(dialog.get_by_text('Candidate', exact=True)).to_be_visible()
        await close()
        await snap('investigation-desktop.png')

    async def report():
        await app.get_by_role('button', name='Inventory evidence review', exact=False).click()
        await expect(dialog.get_by_text('Retained inventory review fixture', exact=False)).to_be_visible()
        await close()

    async def report_export():
        await app.get_by_role('button', name='Inventory evidence review', exact=False).click()
        await expect(dialog.get_by_text(REPORT_DIGEST, exact=True)).to_be_visible()
        download_button = dialog.get_by_role('button', name='Download signed ZIP')
        path = f'/api/report/{ALPHA}/drafts/{REPORT}/export'
        fixture.faults[path] = (409, {'detail': 'Fixture evidence expired'})
        try:
            await download_button.click()
            await expect(dialog.get_by_role('status')).to_have_text('The server declined the operation in its current state.')
        finally:
            fixture.faults.pop(path, None)
        fixture.export_digest = '0' * 64
        try:
            await download_button.click()
            await expect(dialog.get_by_role('status')).to_have_text('The exported package did not match the signed preview.')
        finally:
            fixture.export_digest = REPORT_DIGEST
        async with page.expect_download() as pending_download:
            await download_button.click()
        download = await pending_download.value
        assert download.suggested_filename == f'aria-report-{REPORT}.zip'
        with ZipFile(await download.path()) as archive:
            assert {name: archive.read(name).decode() for name in archive.namelist()} == REPORT_FILES
        await close()
        await app.get_by_role('button', name='Unsigned controls draft', exact=False).click()
        await expect(dialog.get_by_text('Awaiting report sign-off', exact=True)).to_be_visible()
        await expect(dialog.get_by_role('button', name='Download signed ZIP')).to_have_count(0)
        await close()

    async def charts():
        await go('Analytics')
        await expect(page.locator(READY)).to_have_count(1)
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
        await expect(app.get_by_text('3,926 tokens available · 8,192 minimum reservation', exact=True)).to_be_visible()
        await expect(app.get_by_text('1 · 6.7%', exact=True)).to_have_count(2)
        await app.get_by_label('Model', exact=True).select_option('fixture-reviewed')
        await page.evaluate('new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))')
        await app.get_by_role('heading', name='Token usage', exact=True).scroll_into_view_if_needed()
        await expect(app.locator('[data-renderer="echarts"]').first).to_be_visible()
        await snap('analytics-desktop.png')

    async def projected_accounting():
        route = base + '/api/mission/' + ALPHA + '/accounting'
        async with page.expect_response(lambda response: response.url == route) as received:
            await refresh()
        response = await received.value
        assert response.ok
        assert 'fixture-private-accounting-metadata' not in await response.text()
        data = await response.json()
        assert len(data['attempts']) == 15 and data['omitted_attempts'] == 1
        await expect(app.get_by_text('1 record could not be attributed', exact=False)).to_be_visible()
        attempts = app.get_by_role('region', name='Model attempts')
        await attempts.get_by_role('button', name='fixture-reviewed', exact=False).first.click()
        await expect(dialog.get_by_text('Timeout', exact=True).first).to_be_visible()
        await close()

    async def infrastructure():
        await go('Infrastructure')
        await expect(app.get_by_text('Unreachable', exact=True).first).to_be_visible()
        await expect(app.locator('.infra-row').get_by_text('PostgreSQL', exact=True)).to_be_visible()
        await expect(app.locator('.infra-row').get_by_text('Redis', exact=True)).to_be_visible()
        typed_httpx = app.get_by_role('button', name='httpx', exact=False)
        await expect(typed_httpx).to_contain_text('Version unknown')
        fixture.worker_up = True
        await refresh()
        await expect(app.locator('.infra-row').get_by_text('Online', exact=True)).to_be_visible()
        await expect(typed_httpx).to_contain_text('Declared version 1.7.1')
        await typed_httpx.click()
        await expect(dialog.get_by_text('httpx.http.probe.v1', exact=True)).to_be_visible()
        await expect(dialog.get_by_text('Unverified by the capability probe', exact=True)).to_be_visible()
        await snap('typed-worker-profile.png')
        await close()
        fixture.worker_typed_profile = False
        await refresh()
        await expect(typed_httpx).to_contain_text('Not Advertised', ignore_case=True)
        await expect(typed_httpx).to_contain_text('Version unknown')
        await app.get_by_role('heading', name='Reported infrastructure connections').scroll_into_view_if_needed()
        await expect(app.get_by_role('group', name='Reported infrastructure connections')).to_be_visible()

    async def pending_and_rejection():
        fixture.current = saved_stream
        await go('Operations')
        await refresh()
        await expect(app.get_by_text('Expired', exact=True)).to_be_visible()
        assert await app.get_by_role('button', name='Reject proposal', exact=True).count() == 1
        await app.get_by_role('button', name='Reject proposal', exact=True).click()
        await dialog.get_by_role('button', name='Reject proposal', exact=True).click()
        await expect(app.get_by_text('Request acknowledged.', exact=False)).to_be_visible()
        await expect(app.get_by_role('button', name='Reject proposal', exact=True)).to_have_count(0)
        assert fixture.rejections == 1

    async def authorization_history():
        journal = app.get_by_role('region', name='Authorization history')
        await journal.get_by_role('button', name='Rejection recorded', exact=False).click()
        await expect(dialog.get_by_text('Durable authorization journal', exact=True)).to_be_visible()
        await expect(dialog.get_by_text(PENDING_REVIEW, exact=True)).to_be_visible()
        await close()
        await go('Events')
        await app.get_by_label('Event source').select_option('authorization')
        await app.get_by_label('Search events').fill(PENDING_REVIEW)
        await expect(app.get_by_text('2 retained records.', exact=False)).to_be_visible()
        await app.get_by_role('button', name='Replay retained events').click()
        await app.get_by_label('Historical replay position').press('End')
        await expect(app.get_by_text('Retained record 2 / 2', exact=False)).to_be_visible()
        await app.get_by_role('heading', name='Event relationships').scroll_into_view_if_needed()
        graph = app.get_by_role('group', name='Retained event relationships')
        await expect(graph.locator('[data-kind="Recorded authorization"]')).to_have_count(1)
        await app.get_by_role('button', name='Exit replay').click()
        search = app.get_by_label('Search events')
        await search.press('ControlOrMeta+a')
        await search.press('Backspace')
        await expect(search).to_have_value('')
        await app.get_by_label('Event source').select_option('')
        await go('Operations')

    async def cancellation():
        await go('Operations')
        await app.get_by_role('button', name='Cancel campaign', exact=True).click()
        await dialog.get_by_role('button', name='Cancel campaign', exact=True).click()
        await expect(app.get_by_text('Campaign · Cancelling', exact=True)).to_be_visible()
        await expect(app.get_by_text('Campaign · Cancelled', exact=True)).to_have_count(0)

    async def pause_containment():
        saved = fixture.campaign_state
        path = '/api/pentest/' + ALPHA + '/campaign/pause'
        try:
            fixture.campaign_state = 'running'
            await go('Operations')
            await refresh()
            await app.get_by_role('button', name='Pause campaign', exact=True).click()
            fixture.faults[path] = (409, {'detail': {'code': 'campaign_conflict'}})
            await dialog.get_by_role('button', name='Pause campaign', exact=True).click()
            await expect(page.get_by_role('status').filter(has_text='The server declined')).to_be_visible()
            assert fixture.pause_requests == 0
            await expect(app.get_by_text('Campaign · Running', exact=True)).to_be_visible()
            fixture.faults.pop(path)
            await app.get_by_role('button', name='Pause campaign', exact=True).click()
            await dialog.get_by_role('button', name='Pause campaign', exact=True).click()
            await expect(app.get_by_text('Campaign · Pausing', exact=True)).to_be_visible()
            assert fixture.pause_requests == 1
            await expect(app.get_by_role('button', name='Pause campaign', exact=True)).to_have_count(0)
            await expect(app.get_by_text('Campaign · Paused', exact=True)).to_have_count(0)
            await snap('containment-pausing.png')
            fixture.campaign_state = 'paused'
            await refresh()
            await expect(app.get_by_text('Campaign · Paused', exact=True)).to_be_visible()
        finally:
            fixture.campaign_state = saved
            fixture.faults.pop(path, None)

    async def stop_containment():
        path = '/api/pentest/' + BETA + '/autonomous/stop'
        try:
            fixture.bounded_state = {'active': True, 'run_state': 'executing'}
            fixture.web_pending = 1
            await select(BETA)
            await app.get_by_role('button', name='Stop bounded run', exact=True).click()
            fixture.delays[path] = 0.5
            async with page.expect_response(lambda response: response.url.endswith(path)) as stopped:
                await dialog.get_by_role('button', name='Stop bounded run', exact=True).click()
                await expect(app.get_by_role('button', name='Stop bounded run', exact=True)).to_be_disabled()
            payload = await (await stopped.value).json()
            assert payload['status'] == 'cancellation_pending' and payload['pending'] == 1, payload
            await expect(app.get_by_text('Stop acknowledged. 1 cancellation(s) remain unconfirmed.', exact=False)).to_be_visible()
            await expect(app.get_by_role('button', name='Stop bounded run', exact=True)).to_have_count(0)
            assert fixture.stop_requests == 1
            await page.reload()
            await expect(app.get_by_text('Web replay termination remains unconfirmed.', exact=False)).to_be_visible()
            await expect(app.get_by_role('button', name='Stop bounded run', exact=True)).to_have_count(0)
            fixture.web_summary_unavailable = True
            await refresh()
            await expect(app.get_by_text('Stored web replay state is unavailable.', exact=False)).to_be_visible()
            await expect(app.get_by_role('heading', name='Worker receipts', exact=True)).to_be_visible()
            fixture.web_summary_unavailable = False
            await refresh()
            await expect(app.get_by_text('Web replay termination remains unconfirmed.', exact=False)).to_be_visible()
            await snap('containment-stop-pending.png')
            # Changing sessions while a mutation is in flight must not place its
            # acknowledgement or refreshed records in the newly selected session.
            fixture.bounded_state = {'active': True, 'run_state': 'executing'}
            await refresh()
            await app.get_by_role('button', name='Stop bounded run', exact=True).click()
            await dialog.get_by_role('button', name='Stop bounded run', exact=True).click()
            await select(ALPHA)
            await asyncio.sleep(0.65)
            await expect(app.get_by_text('Stop acknowledged.', exact=False)).to_have_count(0)
            await expect(app.get_by_text('Campaign · Paused', exact=True)).to_be_visible()
        finally:
            fixture.bounded_state = None
            fixture.web_pending = 0
            fixture.web_summary_unavailable = False
            fixture.delays.pop(path, None)
            await select(ALPHA)

    async def resume_control():
        await go('Operations')
        await refresh()
        await app.get_by_role('button', name='Resume campaign', exact=True).click()
        await expect(dialog.get_by_text('The server may schedule execution', exact=False)).to_be_visible()
        await page.keyboard.press('Escape')
        assert fixture.resume_requests == 0
        await app.get_by_role('button', name='Resume campaign', exact=True).click()
        await dialog.get_by_role('button', name='Resume campaign', exact=True).click()
        await expect(app.get_by_text('Campaign · Scheduled', exact=True)).to_be_visible()
        assert fixture.resume_requests == 1
        fixture.campaign_state = 'paused'
        await refresh()

    async def mutation_read_race():
        path = base + '/api/pentest/' + BETA + '/autonomous/status'
        captured, release = asyncio.Event(), asyncio.Event()

        async def hold_old_status(route):
            response = await route.fetch()
            captured.set()
            await release.wait()
            await route.fulfill(response=response)

        fixture.bounded_state = {'active': True, 'run_state': 'executing'}
        try:
            await select(BETA)
            await page.route(path, hold_old_status, times=1)
            await page.get_by_role('button', name='Refresh', exact=True).click()
            await asyncio.wait_for(captured.wait(), 5)
            await app.get_by_role('button', name='Stop bounded run', exact=True).click()
            async with page.expect_response(lambda response: response.url.endswith('/autonomous/stop')):
                await dialog.get_by_role('button', name='Stop bounded run', exact=True).click()
            release.set()
            await expect(app.get_by_text('Bounded run · Cancelled', exact=True)).to_be_visible()
            await expect(app.get_by_role('button', name='Stop bounded run', exact=True)).to_have_count(0)
        finally:
            release.set()
            await page.unroute(path, hold_old_status)
            fixture.bounded_state = None
            await select(ALPHA)

    async def reconnect():
        connections = fixture.stream_count
        fixture.stream_disconnects = 1
        await go('Events')
        await expect(app.get_by_text('Run stream connected', exact=True)).to_be_visible(timeout=15000)
        assert fixture.stream_count >= connections + 2
        await expect(app.get_by_text('Run stream reported an event gap', exact=True)).to_be_visible()
        await app.get_by_label('Event source').select_option('campaign')
        await expect(app.get_by_text('3 retained records.', exact=False)).to_be_visible()
        await expect(app.get_by_text('Campaign cancel requested', exact=True)).to_be_visible()
        search = app.get_by_label('Search events')
        await search.fill('campaign')
        await search.press('ControlOrMeta+a')
        fixture.add_operation('campaign_health_alert', 'cancelling', 'Fixture campaign update')
        await page.get_by_role('button', name='Refresh', exact=True).dispatch_event('click')
        await expect(app.get_by_text('4 retained records.', exact=False)).to_be_visible()
        assert await search.evaluate('input => [input.selectionStart, input.selectionEnd]') == [0, 8]
        await search.press('Backspace')
        await expect(search).to_have_value('')
        await app.get_by_label('Event source').select_option('')
        await app.get_by_role('button', name='Tasks', exact=False).first.click()
        await expect(dialog.get_by_text('Sequence', exact=True)).to_be_visible()
        await close()

    async def catch_up_retained_events():
        path = base + '/api/mission/' + ALPHA + '/events?'
        cursors = []
        saved_current = fixture.current

        def track(request):
            if request.url.startswith(path):
                match = re.search(r'[?&]team_after=(\d+)', request.url)
                if match:
                    cursors.append(int(match.group(1)))

        try:
            fixture.current = False
            await page.reload()
            await expect(page.locator(READY)).to_have_count(1)
            await app.get_by_label('Event source').select_option('team')
            await expect(app.get_by_text('3 retained records.', exact=False)).to_be_visible()
            page.on('request', track)
            fixture.extra_team = 230
            await refresh()
            await expect(app.get_by_text('203 retained records.', exact=False)).to_be_visible()
            await expect(app.get_by_text('Team · Available · newer records pending', exact=True)).to_be_visible()
            assert cursors == [3, 53, 103, 153], cursors
            await refresh()
            await expect(app.get_by_text('233 retained records.', exact=False)).to_be_visible()
            await expect(app.get_by_text('Team · Available · newer records pending', exact=True)).to_have_count(0)
            assert cursors == [3, 53, 103, 153, 203], cursors

            async def stalled_cursor(route):
                response = await route.fetch()
                body = await response.json()
                assert body['team']['cursor'] == 233
                body['team']['has_more'] = True
                await route.fulfill(response=response, json=body)

            await page.route(re.compile(re.escape(path)), stalled_cursor, times=1)
            await refresh()
            await expect(app.get_by_text('An event source did not advance its cursor.', exact=False)).to_be_visible()
            await expect(app.get_by_text('233 retained records.', exact=False)).to_be_visible()
            assert cursors == [3, 53, 103, 153, 203, 233], cursors
            await refresh()
            await expect(app.get_by_text('An event source did not advance its cursor.', exact=False)).to_have_count(0)
        finally:
            page.remove_listener('request', track)
            fixture.extra_team = 0
            fixture.current = saved_current
            await page.reload()

    async def windowed_history():
        fixture.extra_team = 600
        try:
            await page.reload()
            await expect(page.locator(READY)).to_have_count(1)
            await app.get_by_label('Event source').select_option('team')
            await expect(app.get_by_text('50 retained records.', exact=False)).to_be_visible()
            history = app.get_by_role('button', name='Load older team events')
            for count in [150, 250, 350, 450, 550, 603]:
                await history.click()
                await expect(app.get_by_text(f'{count} retained records.', exact=False)).to_be_visible()
            listing = app.get_by_role('region', name='Event timeline')
            mounted = await listing.locator('.record').count()
            assert mounted < 25, mounted
            scrolling = await listing.evaluate('''async root => {
                const frames = []; let previous;
                for (let index = 0; index < 90; index++) {
                    const now = await new Promise(requestAnimationFrame);
                    if (previous !== undefined) frames.push(now - previous);
                    previous = now;
                    root.scrollTop = index * (root.scrollHeight - root.clientHeight) / 89;
                }
                frames.sort((a, b) => a - b);
                return {timelineScrollFps: 1000 * frames.length / frames.reduce((a, b) => a + b, 0),
                    timelineScrollFrameP95Ms: frames[Math.floor(frames.length * .95)],
                    timelineScrollFrames: frames.length, timelineScrollMountedRows: root.querySelectorAll('.record').length};
            }''')
            changes.append(scrolling)
            started = perf_counter()
            await listing.focus()
            await page.keyboard.press('End')
            await expect(listing.locator('[data-position="602"]')).to_be_focused()
            changes.append({'virtualListRecords': 603, 'mountedRecords': mounted,
                            'jumpToLastMs': round((perf_counter() - started) * 1000, 2)})
        finally:
            fixture.extra_team = 0
            await page.reload()

    async def preferences():
        await go('Settings')
        await app.get_by_label('Theme', exact=True).select_option('light')
        await app.get_by_label('Accent colour').select_option('teal')
        await app.get_by_label('Layout density').select_option('compact')
        await expect(page.locator('html')).to_have_attribute('data-theme', 'light')
        await expect(page.locator('html')).to_have_attribute('data-accent', 'teal')
        await page.reload()
        await expect(page.locator('html')).to_have_attribute('data-density', 'compact')
        await expect(page.get_by_role('button', name='Advanced mode')).to_be_visible()
        await app.get_by_label('Theme', exact=True).select_option('system')
        await expect(page.locator('html')).to_have_attribute('data-theme', 'light')
        await snap('settings-light.png')

    async def panel_preferences():
        await go('Overview')
        await app.get_by_role('button', name='Collapse Model budget', exact=True).click()
        await expect(app.get_by_role('button', name='Expand Model budget')).to_have_attribute('aria-expanded', 'false')
        await page.reload()
        await expect(app.get_by_role('button', name='Expand Model budget')).to_be_visible()
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_hidden()
        await app.get_by_role('button', name='Expand Model budget').click()
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
        await go('Settings')
        width = app.get_by_label('Inspector width')
        await width.press('End')
        await expect(width).to_have_value('700')
        await page.reload()
        await expect(app.get_by_label('Inspector width')).to_have_value('700')
        await go('Overview')
        await app.get_by_role('button', name='Inspect scope').click()
        assert abs((await dialog.bounding_box())['width'] - 700) <= 2
        await close()
        await go('Operations')
        await expect(app.get_by_role('button', name='Collapse Execution state and containment')).to_have_count(0)
        await expect(app.get_by_role('button', name='Collapse Pending proposals')).to_have_count(0)

    async def responsive():
        await go('Overview')
        for width, height in [(1024, 768), (768, 1024), (390, 844), (320, 720)]:
            await page.set_viewport_size({'width': width, 'height': height})
            result = await page.evaluate(METRICS)
            assert result['width'] <= width + 1, (width, result['width'])
            if width in {768, 390}:
                await snap('overview-' + str(width) + '.png')
        await page.set_viewport_size({'width': 1440, 'height': 960})

    async def keyboard():
        await page.reload()
        await expect(page.locator(READY)).to_have_count(1)
        await page.keyboard.press('Tab')
        await expect(page.get_by_role('link', name='Skip to mission content')).to_be_focused()
        await page.keyboard.press('Enter')
        await expect(app).to_be_focused()
        await app.get_by_role('button', name='Inspect scope').focus()
        await page.keyboard.press('Enter')
        await expect(dialog).to_be_visible()
        await page.keyboard.press('Escape')
        await expect(app.get_by_role('button', name='Inspect scope')).to_be_focused()

    async def partial_errors():
        await go('Overview')
        path = '/api/mission/' + ALPHA + '/accounting'
        fixture.faults[path] = (500, {'detail': 'fixture-private-exception'})
        await refresh()
        await expect(app.get_by_text('Stale data', exact=True)).to_be_visible()
        await expect(app.get_by_text('fixture-private-exception', exact=False)).to_have_count(0)
        fixture.faults[path] = (200, {'attempts': 'invalid schema'})
        await refresh()
        await expect(app.get_by_text('The API record did not match its expected schema.', exact=True)).to_be_visible()
        fixture.faults[path] = (403, {'detail': 'fixture-private-denial'})
        await refresh()
        await expect(app.get_by_text('Access was denied.', exact=True)).to_be_visible()
        await expect(app.get_by_text('Admission blocked', exact=True)).to_have_count(0)
        fixture.faults.pop(path)
        await refresh()
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()
        response = await page.request.get(base + '/api/mission/' + FOREIGN + '/events')
        assert response.status == 403, response.status
        response = await page.request.get(base + '/api/mission/missing-fixture/events')
        assert response.status == 404, response.status

    async def network_loss():
        await page.context.set_offline(True)
        try:
            await refresh()
            await expect(app.get_by_text('The API could not be reached.', exact=True).first).to_be_visible()
        finally:
            await page.context.set_offline(False)
        await refresh()
        await expect(app.get_by_text('Admission blocked', exact=True)).to_be_visible()

    async def revocation():
        fixture.epoch = 1
        await page.get_by_role('button', name='Refresh', exact=True).click()
        await page.wait_for_url('**/login?next=mission')
        await expect(page.get_by_label('Username')).to_be_visible()
        assert await page.evaluate("localStorage.getItem('pentestai_token')") is None

    async def no_client_errors():
        assert errors == [], errors

    for name, test in [
        ('Login and normal dashboard routing', login), ('Repeated initial loading and API volume', cold_load),
        ('Settled overview remains visually stable after refresh', visual_repeatability),
        ('Session search, status filter and selection', list_sessions), ('Refresh restores selected session and unknown usage', restore),
        ('Session creation through FastAPI', create), ('Rapid session switching fences late data', switching),
        ('Integrated workspace preserves drafts and follows the shared session', workspace), ('Scope inspector and keyboard dismissal', scope),
        ('Agent graph inspection, filtering and zoom', graph), ('Source-aware event search and retained replay', events_and_replay),
        ('Frozen replay under live arrivals, empty filters and access revocation', frozen_replay),
        ('Retained campaign archive, paging and retention gaps', campaign_archive),
        ('Advanced mode, SVG event graph, Canvas and GPU fallback', advanced_and_renderers),
        ('Explicit loss of WebGL falls back to Canvas', renderer_fallback),
        ('Recorded host and application topology', retained_topology),
        ('Sanitized command output and worker receipt inspection', commands), ('Investigation evidence and verification state', evidence),
        ('Protected professional report preview', report), ('Signed report download, stale denial and manifest mismatch', report_export),
        ('Budget blocker and ECharts analytics', charts),
        ('Allowlisted accounting payload and retained timeout inspection', projected_accounting),
        ('Worker outage, recovery and service readiness', infrastructure), ('Pending proposal rejection and expiry', pending_and_rejection),
        ('Durable authorization journal and action correlation', authorization_history),
        ('Pause conflict, pending acknowledgement and confirmed recovery', pause_containment),
        ('Stop retains pending web cancellation and fences session changes', stop_containment),
        ('Resume requires confirmation and shows the server scheduling state', resume_control),
        ('Post-stop reconciliation retires a pre-mutation in-flight response', mutation_read_race),
        ('Campaign cancellation remains pending until confirmed', cancellation),
        ('WebSocket disconnect, reconnect and deduplicated event refresh', reconnect),
        ('Forward event catch-up follows cursors within a bounded refresh', catch_up_retained_events),
        ('Older event pages and 603-record windowed timeline', windowed_history),
        ('Themes, accent, density and detail persistence', preferences),
        ('Persistent panel collapse and keyboard inspector resizing', panel_preferences),
        ('Desktop, tablet and two mobile viewports', responsive),
        ('Keyboard bypass, dialog focus and focus restoration', keyboard),
        ('HTTP 403/404/500 and malformed response handling', partial_errors), ('Offline connection and refresh recovery', network_loss),
        ('Session revocation redirects on 401', revocation), ('No uncaught client errors', no_client_errors)
    ]:
        await check(name, test)
    return {'checks': checks, 'samples': samples, 'interaction': changes, 'renderers': renderers, 'screenshots': files, 'pageErrors': errors,
            'socketConnections': fixture.stream_count, 'rejections': fixture.rejections}
