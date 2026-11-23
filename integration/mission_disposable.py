"""Verify Mission Control read contracts against a fresh rootless PostgreSQL container.

Uses a cached image, a random loopback port, and a disposable container. Existing
databases and Redis are outside the fixture. Provider and worker APIs are never used.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter
from uuid import NAMESPACE_URL, uuid4, uuid5

PODMAN = '/usr/bin/podman'
IMAGE = 'docker.io/library/postgres:16.6'
DB = 'aria_mission_test'
ROLE = 'aria_fixture'
HAR_FIXTURE = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures' / 'mission-synthetic.har'


def command(*args, env=None, check=True):
    return subprocess.run([PODMAN, *args], check=check, capture_output=True, text=True, env=env)


async def browser_har_catalog(page, inspector, sid: str, output: Path) -> dict:
    from playwright.async_api import expect
    from sqlalchemy import select, update
    from memory.database_models import ChatLog, DecisionLog, async_session
    from security.har import HAR_CAPTURE_TYPE

    path = f'/api/team/{sid}/evidence'
    async with async_session() as db:
        capture_id, original = (await db.execute(select(ChatLog.id, ChatLog.content).where(
            ChatLog.session_id == sid, ChatLog.msg_type == HAR_CAPTURE_TYPE,
            ChatLog.data['summary']['url'].as_string() == 'https://records.example.test'))).one()
        captured = (ChatLog.id == capture_id, ChatLog.session_id == sid)
        await db.execute(update(ChatLog).where(*captured).values(content='Synthetic substituted metadata'))
        await db.commit()
    catalog_events = select(DecisionLog.metadata_).where(
        DecisionLog.session_id == sid, DecisionLog.decision_type == 'team_event',
        DecisionLog.metadata_['collection'].as_string() == 'evidence',
        DecisionLog.metadata_['data']['source_id'].as_string() == capture_id)

    def catalog_response(response):
        return response.url.endswith(path) and response.request.method == 'POST'

    catalog = inspector.get_by_role('button', name='Add capture metadata to evidence')
    try:
        async with page.expect_response(catalog_response) as pending:
            await catalog.click()
        denied = await pending.value
        assert denied.status == 409, f'Catalog status for substituted metadata was {denied.status}'
        await expect(inspector.get_by_text('Saved HAR capture failed integrity validation', exact=False)).to_be_visible()
        await page.screenshot(path=output / 'postgres-har-catalog-denied.png')
        async with async_session() as db:
            assert (await db.execute(catalog_events)).first() is None
    finally:
        async with async_session() as db:
            await db.execute(update(ChatLog).where(*captured).values(content=original))
            await db.commit()

    async with page.expect_response(catalog_response) as pending:
        await catalog.click()
    accepted = await pending.value
    assert accepted.status == 200, f'Catalog status for bound metadata was {accepted.status}'
    await expect(inspector.get_by_text('Capture metadata cataloged', exact=False)).to_be_visible()
    async with async_session() as db:
        event = (await db.execute(catalog_events)).scalar_one()
        assert isinstance(event, dict)
        evidence = event['data']
    assert evidence['source_id'] == capture_id and evidence['trust'] == 'untrusted_observation'
    assert evidence['hashes']['content_sha256'] == hashlib.sha256(original.encode()).hexdigest()
    assert 'Quarterly inventory sample' not in evidence['summary']

    await page.reload()
    await expect(page.get_by_label('Current session')).to_have_value(sid)
    await page.get_by_role('navigation').get_by_role('link', name='Traffic', exact=True).click()
    await page.get_by_role('button', name='POST https://records.example.test', exact=False).first.click()
    await expect(inspector.get_by_role('link', name='Open Investigation')).to_be_visible()
    return {'rejectedStatus': denied.status, 'acceptedStatus': accepted.status,
            'rejectedWrites': 0, 'storedEvidenceDigest': evidence['hashes']['content_sha256'], 'visibleAfterReload': True}


async def database_browser(app, sid, password, proposal_id, archived_id, output, finding_id, assets):
    from playwright.async_api import async_playwright, expect
    from starlette.responses import JSONResponse
    from integration.mission_browser import loopback_server, sources, with_staged_dashboard

    review_path = f'/api/team/{sid}/findings/{finding_id}/review'
    upload_path = f'/api/mission/{sid}/traffic/import-har'
    catalog_path = f'/api/team/{sid}/evidence'
    data_policy_path = f'/api/application-map/{sid}/data-policy'
    writes = {('POST', '/api/login'), ('POST', review_path), ('POST', upload_path), ('POST', catalog_path),
              ('PUT', data_policy_path)}

    async def readonly(scope, receive, send):
        if scope['type'] == 'http' and scope['method'] not in {'GET', 'HEAD'} and (
                scope['method'], scope['path']) not in writes:
            response = JSONResponse({'detail': 'Write outside retained review fixture'}, status_code=405)
            return await response(scope, receive, send)
        if scope['type'] == 'websocket':
            return await send({'type': 'websocket.close', 'code': 1008})
        return await app(scope, receive, send)

    dashboard = with_staged_dashboard(readonly, assets) if assets else readonly
    async with loopback_server(dashboard) as base, async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False, chromium_sandbox=True,
            args=['--disable-background-networking'])
        try:
            context = await browser.new_context(viewport={'width': 1440, 'height': 960}, reduced_motion='reduce')
            await context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else route.abort())
            page = await context.new_page()
            errors = []
            console_errors = []
            failed_http: Counter[int] = Counter()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('console', lambda message: console_errors.append(message.text) if message.type == 'error' else None)
            page.on('response', lambda response: failed_http.update([response.status]) if response.status >= 400 else None)
            await page.goto(base + '/login?next=mission')
            await page.get_by_label('Username').fill('mission-fixture')
            await page.get_by_label('Password').fill(password)
            await page.get_by_role('button', name='Sign In').click()
            await expect(page.get_by_label('Current session')).to_have_value(sid)
            await expect(page.get_by_text('Admission blocked', exact=True)).to_be_visible()
            policy_write = await page.evaluate('''async path => {
              const bearer = localStorage.getItem('pentestai_token');
              const response = await fetch(path, {method: 'PUT', headers: {
                'Authorization': 'Bearer ' + bearer, 'Content-Type': 'application/json'
              }, body: JSON.stringify({expected_revision: 0, retention_days: 7, provider_sharing: 'deny'})});
              const receipt = await response.json();
              return {status: response.status, revision: receipt.revision};
            }''', data_policy_path)
            assert policy_write == {'status': 200, 'revision': 1}, policy_write
            await page.reload()
            await expect(page.get_by_label('Current session')).to_have_value(sid)
            await page.get_by_role('navigation').get_by_role('link', name='Analytics', exact=True).click()
            await expect(page.get_by_text('Application data policy denies provider sharing.', exact=False)).to_be_visible()
            attempts = page.get_by_role('region', name='Model attempts')
            await attempts.get_by_role('button', name='fixture-reviewed', exact=False).click()
            await expect(page.get_by_role('dialog').get_by_text('Timeout', exact=True).first).to_be_visible()
            await expect(page.get_by_text('fixture-private-diagnostic', exact=False)).to_have_count(0)
            await page.get_by_role('button', name='Close inspector').click()
            await page.get_by_role('navigation').get_by_role('link', name='Operations', exact=True).click()
            await expect(page.get_by_text('Web replay termination remains unconfirmed.', exact=False)).to_be_visible()
            await page.reload()
            await expect(page.get_by_text('Web replay termination remains unconfirmed.', exact=False)).to_be_visible()
            journal = page.get_by_role('region', name='Authorization history')
            await journal.get_by_role('button', name='Rejection recorded', exact=False).click()
            await expect(page.get_by_role('dialog').get_by_text(proposal_id, exact=True)).to_be_visible()
            await expect(page.get_by_text('fixture-private-command')).to_have_count(0)
            assert not errors, errors
            screenshot = output / 'postgres-authorization.png'
            await page.screenshot(path=screenshot)
            await page.get_by_role('button', name='Close inspector').click()
            await page.get_by_role('navigation').get_by_role('link', name='Events', exact=True).click()
            await page.get_by_label('Campaign timeline').select_option(archived_id)
            await expect(page.get_by_text('Campaign snapshot', exact=True)).to_be_visible()
            await expect(page.get_by_role('button', name='Campaign completed', exact=False)).to_be_visible()
            await expect(page.get_by_role('button', name='Campaign cancelled', exact=False)).to_have_count(0)
            await page.get_by_role('button', name='Replay retained events').click()
            await expect(page.get_by_text('Retained record 1 / 1', exact=False)).to_be_visible()
            archive = screenshot.with_name('postgres-campaign-replay.png')
            await page.screenshot(path=archive)
            assert not errors, errors
            nav = page.get_by_role('navigation')
            type_picker = page.get_by_label('Record type')
            for reload_page in (False, True):
                if reload_page:
                    await page.reload()
                else:
                    await nav.get_by_role('link', name='Exploration Graph', exact=True).click()
                await type_picker.select_option('Task')
                graph = page.get_by_role('group', name='Exploration Graph', exact=True)
                await expect(graph.locator('[data-kind="Depends on"]')).to_have_count(1)
                await graph.get_by_role('button', name='Retained inventory review, Task, blocked', exact=True).press('Enter')
                await expect(page.get_by_role('dialog').get_by_text('Evidence:retained-inventory', exact=False).first).to_be_visible()
                await page.get_by_role('button', name='Close inspector').click()
            graph_capture = output / 'postgres-exploration.png'
            await page.screenshot(path=graph_capture)
            checkpoint_picker = page.get_by_label('Team checkpoint')
            await checkpoint_picker.select_option('11')
            await expect(page.get_by_text('Saved checkpoint #11', exact=False)).to_be_visible()
            await type_picker.select_option('Finding')
            graph = page.get_by_role('group', name='Exploration Graph', exact=True)
            await expect(graph.get_by_role('button', name='Concurrent synthetic review, Finding, observation')).to_be_visible()
            await expect(graph.get_by_role('button', name='Synthetic review candidate', exact=False)).to_have_count(0)
            checkpoint_capture = output / 'postgres-checkpoint.png'
            await page.screenshot(path=checkpoint_capture)
            await type_picker.select_option('Task')
            await graph.get_by_role('button', name='Retained inventory review, Task, blocked', exact=True).press('Enter')
            checkpoint_dialog = page.get_by_role('dialog')
            await checkpoint_dialog.get_by_role('button', name='References · Depends on', exact=False).click()
            await expect(checkpoint_dialog.get_by_text('Task:task-9', exact=True)).to_be_visible()
            await checkpoint_dialog.get_by_role('button', name='Close inspector').click()
            await page.get_by_label('Current session').select_option(label='Second owned fixture')
            await expect(checkpoint_picker).to_have_value('')
            await checkpoint_picker.select_option('3')
            await expect(page.get_by_text('There are missing or ambiguous ledger sequences in this history.')).to_be_visible()
            await expect(page.get_by_text('1 unreadable graph records.')).to_be_visible()
            await expect(graph.get_by_role('button', name='Concurrent synthetic review', exact=False)).to_have_count(0)
            await page.get_by_label('Current session').select_option(sid)
            await expect(checkpoint_picker).to_have_value('')
            await expect(graph.get_by_role('button', name='Concurrent synthetic review, Finding, rejected')).to_be_visible()
            await nav.get_by_role('link', name='Traffic', exact=True).click()
            await page.get_by_role('button', name='GET http://records.example.test', exact=False).first.click()
            await expect(page.get_by_role('dialog').get_by_text('application/json', exact=True)).to_be_visible()
            await expect(page.get_by_text('fixture-private-path', exact=False)).to_have_count(0)
            traffic_capture = output / 'postgres-traffic.png'
            await page.screenshot(path=traffic_capture)
            await page.get_by_role('button', name='Close inspector').click()
            await page.get_by_role('button', name='Import HAR', exact=True).click()
            await page.get_by_label('HAR file').set_input_files(HAR_FIXTURE)
            await page.get_by_label('Include reviewed body previews').check()
            await page.get_by_role('button', name='Save archive', exact=True).click()
            await expect(page.get_by_text('2 imported · 0 already saved · 0 skipped', exact=True)).to_be_visible()
            await page.get_by_role('button', name='Save archive', exact=True).click()
            await expect(page.get_by_text('0 imported · 2 already saved · 0 skipped', exact=True)).to_be_visible()
            await page.get_by_role('button', name='Close inspector').click()
            await page.get_by_label('Capture source').select_option('sanitized_har_import')
            await page.get_by_role('button', name='POST https://records.example.test', exact=False).first.click()
            inspector = page.get_by_role('dialog')
            body_preview = inspector.get_by_label('Response body preview')
            await expect(body_preview).to_contain_text('Quarterly inventory sample')
            preview_text = await body_preview.text_content()
            assert preview_text is not None
            preview_data = json.loads(preview_text)
            assert preview_data['echo'] == ['[REDACTED]'] * 6
            await expect(inspector.get_by_label('Request body preview')).to_contain_text('synthetic inventory')
            await expect(body_preview.locator('em')).to_have_count(0)
            await expect(inspector.get_by_text('42.5 ms', exact=True)).to_be_visible()
            await expect(inspector.get_by_text('fixture-har-private-', exact=False)).to_have_count(0)
            har_capture = output / 'postgres-har-inspection.png'
            await page.screenshot(path=har_capture)
            await page.set_viewport_size({'width': 390, 'height': 844})
            assert await inspector.evaluate('node => node.scrollWidth <= node.clientWidth')
            request_panel = await inspector.get_by_role('heading', name='Request', exact=True).bounding_box()
            response_panel = await inspector.get_by_role('heading', name='Response', exact=True).bounding_box()
            assert request_panel is not None and response_panel is not None
            assert response_panel['y'] > request_panel['y']
            await page.set_viewport_size({'width': 1440, 'height': 960})
            catalog_checks = await browser_har_catalog(page, inspector, sid, output)
            await page.get_by_role('button', name='Close inspector').click()
            await page.get_by_role('button', name='GET https://notes.example.test', exact=False).first.click()
            await expect(inspector.get_by_label('Response body preview')).to_contain_text('Archived inventory note')
            await expect(inspector.get_by_text('fixture-har-private-', exact=False)).to_have_count(0)
            await page.get_by_role('button', name='Close inspector').click()
            started = perf_counter()
            await nav.get_by_role('link', name='Asset Graph', exact=True).click()
            asset = page.get_by_role('group', name='Asset Graph', exact=True)
            notes = asset.get_by_role('button', name='GET https://notes.example.test, Traffic record, observed', exact=True)
            await expect(notes).to_be_visible()
            asset_ready_ms = round(1000 * (perf_counter() - started), 3)
            await expect(asset.locator('[data-node="Application:http://records.example.test"]')).to_have_count(1)
            await expect(asset.locator('[data-node="Domain:records.example.test"]')).to_have_count(1)
            await expect(asset.locator('[data-node^="Endpoint:https://notes.example.test"]')).to_have_count(0)
            await asset.locator('[data-node="HTTP capture:mapped-inventory"]').press('Enter')
            await inspector.get_by_role('button', name='References · Mapped from saved capture', exact=False).click()
            await expect(inspector.get_by_text('Mission Traffic', exact=True)).to_be_visible()
            await expect(inspector.get_by_role('button', name='References · Cataloged capture source', exact=False)).to_be_visible()
            await expect(inspector.get_by_text('fixture-private-path', exact=False)).to_have_count(0)
            await page.get_by_role('button', name='Close inspector').click()
            await notes.press('Enter')
            await page.set_viewport_size({'width': 390, 'height': 844})
            assert await inspector.evaluate('node => node.scrollWidth <= node.clientWidth')
            await page.set_viewport_size({'width': 1440, 'height': 960})
            asset_capture = output / 'postgres-retained-assets.png'
            await page.screenshot(path=asset_capture)
            await inspector.get_by_role('button', name='Open saved HTTP inspection').click()
            await expect(inspector.get_by_label('Response body preview')).to_contain_text('Archived inventory note')
            await page.get_by_label('Current session').select_option(label='Second owned fixture')
            await expect(inspector).not_to_be_visible()
            await expect(asset.get_by_role('button', name='Second owned fixture, Engagement, recorded', exact=True)).to_be_visible()
            await expect(notes).to_have_count(0)
            await page.get_by_label('Current session').select_option(sid)
            await expect(notes).to_be_visible()
            await nav.get_by_role('link', name='Investigation', exact=True).click()
            await page.get_by_label('Search findings').fill('synthetic review')
            await page.get_by_role('button', name='Synthetic review candidate', exact=False).click()
            inspector = page.get_by_role('dialog')
            submit = inspector.get_by_role('button', name='Record review disposition')
            await expect(submit).to_be_disabled()
            await inspector.get_by_label('Review decision').select_option('inconclusive')
            await inspector.get_by_label('Review reason').fill('The synthetic observation has no independent corroboration.')
            await expect(submit).to_be_disabled()
            await inspector.get_by_label('Smallest missing validation').fill('Independent fixture record.')
            await submit.click()
            await expect(inspector.get_by_text('Review recorded at revision 2.', exact=True)).to_be_visible()
            await page.get_by_role('button', name='Close inspector').click()
            await page.reload()
            await page.get_by_label('Review state').select_option('inconclusive')
            await page.get_by_role('button', name='Synthetic review candidate', exact=False).click()
            await inspector.get_by_text('Finding revision history', exact=True).click()
            await expect(inspector.get_by_role('heading', name='Revision 2', exact=True)).to_be_visible()
            await expect(inspector.get_by_role('heading', name='Revision 1', exact=True)).to_be_visible()
            await expect(inspector.get_by_text('Independent fixture record.', exact=True).last).to_be_visible()
            review_capture = output / 'postgres-evidence-review.png'
            await page.screenshot(path=review_capture)
            assert not errors, errors
            await context.close()
            fingerprints = sources('after')
            if assets:
                fingerprints = {name: digest for name, digest in fingerprints.items() if not name.startswith('web/static/mission/')}
                fingerprints.update({'staged/' + str(path.relative_to(assets)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in assets.rglob('*') if path.is_file()})
            return {'browser': browser.version, 'headless': False, 'checks': ['Login against migrated PostgreSQL',
                'Durable budget denial and model attempt redaction', 'Durable authorization detail and redaction',
                'Authenticated application data policy update is visible in admission accounting',
                'Pending web replay state survives reload without contacting the connector',
                'Older campaign snapshot and replay', 'Reconstructed task dependency and missing evidence after browser reload',
                'Earlier team checkpoint restored saved state and dependency links, disclosed gaps, and cleared on session switch',
                'Durable allowlisted Burp metadata in the inspector',
                'Sanitized archive import, duplicate acknowledgment, JSON and text body previews, and mobile inspection',
                'Catalog rejects substituted HAR metadata and records the restored projection once',
                'Asset Graph links saved traffic and catalog records, deduplicates origins, and scopes inspection to the engagement',
                'Owner-only finding disposition and immutable revisions after reload'],
                'screenshot': screenshot.name, 'archiveScreenshot': archive.name, 'graphScreenshot': graph_capture.name,
                'trafficScreenshot': traffic_capture.name, 'reviewScreenshot': review_capture.name,
                'harScreenshot': har_capture.name, 'checkpointScreenshot': checkpoint_capture.name,
                'assetScreenshot': asset_capture.name, 'retainedAssetReadyMs': asset_ready_ms, 'sourceHashes': fingerprints,
                'harCatalogIntegrity': catalog_checks, 'applicationDataPolicy': {**policy_write, 'denialVisibleAfterReload': True},
                'pageErrors': len(errors), 'httpErrors': dict(failed_http), 'consoleErrors': console_errors}
        finally:
            await browser.close()


async def snapshot_readback(payload):
    """Read durable IDs from a fresh API process with application startup disabled."""
    import tests
    import httpx
    from config.settings import settings

    settings.DATABASE_URL = payload['url']
    settings.KALI_AGENT_URL = ''
    settings.FERNET_KEY = payload['fixture_fernet']
    from api.main import app
    from memory.database_models import engine

    sid = payload['sid']
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1') as client:
            login = await client.post('/api/login', json={'username': 'mission-fixture', 'password': payload['password']})
            login.raise_for_status()
            headers = {'Authorization': 'Bearer ' + login.json()['token']}
            ledger = await client.get(f'/api/team/{sid}', headers=headers)
            ledger.raise_for_status()
            captures = await client.get(f'/api/mission/{sid}/traffic', headers=headers)
            captures.raise_for_status()
            inspection = await client.get(f'/api/mission/{sid}/traffic/captures/{payload["har_id"]}', headers=headers)
            inspection.raise_for_status()
            body = inspection.json()['response']['preview']
            assert body['state'] == 'available'
            checkpoint = await client.get(f'/api/mission/{sid}/exploration/checkpoint?sequence=11', headers=headers)
            checkpoint.raise_for_status()
            return {'tasks': sorted((row['id'], row['state'], row['revision']) for row in ledger.json()['tasks']),
                    'captures': [row['id'] for row in captures.json()['captures']],
                    'preview_sha256': hashlib.sha256(body['text'].encode()).hexdigest(), 'checkpoint': checkpoint.json()}
    finally:
        await engine.dispose()


async def verify_har_storage(client, sid, peer_sid, authorization, admin):
    from sqlalchemy import select
    from memory.database_models import ChatLog, async_session
    from security.har import HAR_CAPTURE_TYPE

    archive = json.loads(HAR_FIXTURE.read_bytes())
    [entry, _] = archive['log']['entries']
    entry['request']['url'] = entry['request']['url'].replace('records.example.test', 'api-fixture.example.test', 1)
    archive['log']['entries'] = [entry]
    path = f'/api/mission/{sid}/traffic'
    started = perf_counter()
    uploads = await asyncio.gather(*(client.post(path + '/import-har?include_bodies=true', headers=authorization, json=archive)
                                     for _ in range(2)))
    upload_ms = (perf_counter() - started) * 1000
    for upload in uploads:
        upload.raise_for_status()
    receipts = [upload.json() for upload in uploads]
    assert sorted((entry['imported'], entry['duplicates']) for entry in receipts) == [(0, 1), (1, 0)]
    [key] = receipts[0]['capture_ids']
    assert receipts[1]['capture_ids'] == [key]
    started = perf_counter()
    inspection = await client.get(path + f'/captures/{key}', headers=authorization)
    inspection_ms = (perf_counter() - started) * 1000
    inspection.raise_for_status()
    payload = inspection.json()
    assert inspection.headers['Cache-Control'] == 'no-store'
    assert payload['capture']['destination'] == 'https://api-fixture.example.test'
    assert payload['response']['preview']['state'] == 'available'
    assert 'fixture-har-private-' not in inspection.text
    assert 'Quarterly inventory sample' in inspection.text
    admin_headers = {'Authorization': 'Bearer ' + admin}
    foreign = await client.get(path + f'/captures/{key}', headers=admin_headers)
    other_engagement = await client.get(f'/api/mission/{peer_sid}/traffic/captures/{key}', headers=authorization)
    outside_owner = await client.post(path + '/import-har', headers=admin_headers, json=archive)
    assert (foreign.status_code, other_engagement.status_code, outside_owner.status_code) == (403, 404, 403)
    restored = await client.get(f'/api/session/{sid}/restore', headers=authorization)
    restored.raise_for_status()
    assert all(record.get('id') != key for record in restored.json()['logs'])
    activities = await client.get('/api/admin/activity', headers=admin_headers)
    activities.raise_for_status()
    assert all(record.get('msg_type') != HAR_CAPTURE_TYPE for record in activities.json()['activities'])
    async with async_session() as db:
        rows = (await db.execute(select(ChatLog).where(ChatLog.session_id == sid,
            ChatLog.msg_type == HAR_CAPTURE_TYPE))).scalars().all()
        assert len(rows) == 1 and rows[0].id == key
        saved_data = rows[0].data
        assert isinstance(saved_data, dict) and set(saved_data) == {'source', 'summary', 'sealed_inspection'}
        saved = rows[0].content + json.dumps(saved_data)
        assert 'fixture-har-private-' not in saved and 'Quarterly inventory sample' not in saved
    listed = await client.get(path, headers=authorization)
    listed.raise_for_status()
    assert 'Quarterly inventory sample' not in listed.text
    assert {record['source'] for record in listed.json()['captures']} == {
        'burp_community_selected_history', 'authenticated_worker_receipt', 'sanitized_har_import'}
    return key, hashlib.sha256(payload['response']['preview']['text'].encode()).hexdigest(), {
        'concurrent_import_deduplicated': True, 'encrypted_inspection': True, 'cross_engagement': 404,
        'foreign_administrator': 403, 'model_chat_and_admin_activity_exclusion': True,
        'two_concurrent_imports_ms': round(upload_ms, 3), 'capture_detail_ms': round(inspection_ms, 3)}


async def exercise(url, with_browser, output=Path('.local-lab/mission-control'), assets: Path | None = None):
    import asyncpg
    from sqlalchemy.engine import make_url

    dsn = make_url(url).set(drivername='postgresql').render_as_string(hide_password=False)
    for _ in range(60):
        try:
            conn = await asyncpg.connect(dsn, timeout=1)
        except (OSError, TimeoutError, asyncpg.PostgresError):
            await asyncio.sleep(0.25)
        else:
            await conn.close()
            break
    else:
        raise RuntimeError('The disposable PostgreSQL instance did not become ready')

    import tests  # set test-only runtime credentials before loading settings
    from config.settings import settings
    settings.DATABASE_URL = url
    settings.KALI_AGENT_URL = ''
    settings.LLM_ROUTING = 'local'

    import httpx
    from alembic import command as alembic
    from alembic.config import Config
    from api.auth import create_token
    from api.main import app
    from integration.mission_metrics import measure_database_reads
    from memory.campaign_observability import append_operation
    from memory.database_models import AutonomousCampaign, ChatLog, DecisionLog, PentestSession, User, UserRole, WebAction, async_session, engine
    from memory.team_tasks import digest
    from security.credentials import auth_revision, hash_password

    await asyncio.to_thread(alembic.upgrade, Config('alembic.ini'), 'head')
    owner_id, other_id, sid = (str(uuid4()) for _ in range(3))
    foreign_sid, peer_sid = str(uuid4()), str(uuid4())
    archived_id, latest_id, foreign_campaign = (f'10000000-0000-4000-8000-00000000000{n}' for n in range(1, 4))
    timestamp = datetime.now(timezone.utc).isoformat()
    proposal_id = str(uuid4())
    authorization_at = datetime.now(timezone.utc).replace(tzinfo=None)
    password = 'fixture-' + secrets.token_urlsafe(18)
    async with async_session() as db:
        owner = User(id=owner_id, username='mission-fixture', password_hash=hash_password(password))
        other = User(id=other_id, username='mission-fixture-admin', password_hash=hash_password(password), role=UserRole.ADMIN)
        db.add_all([owner, other])
        await db.flush()
        admin = create_token(other_id, other.username, 'admin', 'intermediate', auth_revision(other))
        db.add(PentestSession(id=sid, user_id=owner_id, name='Retained review fixture', target='records.example.test',
            scope={'targets': ['records.example.test']}, metadata_={'model_usage': {'calls': 15, 'reserved_tokens': 196074}}))
        db.add(PentestSession(id=foreign_sid, user_id=other_id, name='Separate review fixture', target='records.example.test'))
        db.add(PentestSession(id=peer_sid, user_id=owner_id, name='Second owned fixture', target='records.example.test',
                              updated_at=authorization_at - timedelta(days=1)))
        await db.flush()
        traffic_ids = [str(uuid4()) for _ in range(3)]
        for record_id, capture_sid in zip(traffic_ids, [sid, sid, foreign_sid]):
            db.add(ChatLog(id=record_id, session_id=capture_sid, role='tool_output', msg_type='burp_evidence',
                created_at=authorization_at, content='fixture-private-body',
                data={'source': 'burp_community_selected_history', 'protected_original': 'fixture-private-original',
                    'summary': {'method': 'GET', 'url': 'http://records.example.test/fixture-private-path',
                        'request_headers': {'authorization': 'fixture-private-token'},
                        'response_status': 200, 'response_body_bytes': 42,
                        'response_headers': [{'name': 'content-type', 'value': 'application/json'}]}}))
        evidence_id = str(uuid4())
        db.add(ChatLog(id=evidence_id, session_id=sid, role='system', content='Synthetic protected replay evidence'))
        await db.flush()
        for requester, replay_state in ((owner_id, 'cancel_requested'), (owner_id, 'unknown'),
                                        (owner_id, 'completed'), (other_id, 'cancel_requested')):
            db.add(WebAction(session_id=sid, requester_id=requester, evidence_id=evidence_id, state=replay_state,
                request_digest='a' * 64, scope_digest='b' * 64, protected_spec='fixture-private-replay-spec',
                result={'private': 'fixture-private-replay-result'}, expires_at=authorization_at + timedelta(hours=1)))
        for cid, campaign_sid, campaign_owner, state in ((archived_id, sid, owner_id, 'completed'),
                (latest_id, sid, owner_id, 'cancelled'), (foreign_campaign, foreign_sid, other_id, 'completed')):
            ring = append_operation(None, event='campaign_' + state, campaign_id=cid, to_state=state,
                message='fixture-private-campaign-message', now=authorization_at.replace(tzinfo=timezone.utc))
            db.add(AutonomousCampaign(id=cid, session_id=campaign_sid, owner_id=campaign_owner, state=state,
                goal='http_check', target='records.example.test', skill_level='intermediate', max_steps=1,
                auto_risk_threshold='manual', scope_digest='0' * 64, schedule={'timezone': 'UTC', 'weekdays': [0],
                'daily_runtime_seconds': 60}, budget={'max_tokens': 200000, 'max_cost_microusd': 0},
                usage={}, retry={}, operations=ring, created_at=authorization_at, updated_at=authorization_at))
        for seq in range(1, 11):
            task = {'id': f'task-{seq}', 'owner_role': 'web_intel', 'state': 'completed',
                    'revision': 1, 'private_payload': 'fixture-private-field'}
            event_id = f'event-{seq}'
            if seq == 10:
                event_id = str(uuid5(NAMESPACE_URL, f'aria-team:{sid}:fixture-task-run:result'))
                task.update(state='blocked', objective='Retained inventory review', revision=3, run_id='fixture-task-run', dependencies=['task-9'],
                            evidence_inputs=['retained-inventory'], result={'evidence_references': ['retained-inventory'],
                                'rejections': [{'detail': 'The inventory control disagrees with this observation'}],
                                'interpreted_request': 'fixture-private-result'})
            db.add(DecisionLog(session_id=sid, user_id=owner_id, decision_type='team_event',
                metadata_={'id': event_id, 'sequence': seq, 'timestamp': timestamp, 'collection': 'tasks',
                    'entity_id': f'task-{seq}', 'data': task}))
        db.add(DecisionLog(session_id=sid, user_id=owner_id, decision_type='worker_job',
            metadata_={'job_id': 'db-fixture-job', 'state': 'failed', 'exit_code': 1,
                'output_hash': 'a' * 64, 'protected_response': 'fixture-private-receipt'}))
        db.add(DecisionLog(id=proposal_id, session_id=sid, user_id=owner_id, decision_type='execution_authorization',
            created_at=authorization_at, human_decision='rejected', action_taken='fixture-private-command',
            metadata_={'status': 'rejected', 'command': 'fixture-private-metadata'}))
        db.add(DecisionLog(session_id=sid, user_id=other_id, decision_type='execution_rejected',
            created_at=authorization_at + timedelta(milliseconds=200), human_decision='reject',
            action_taken='fixture-private-command', metadata_={'action_id': proposal_id, 'scope_hash': 'fixture-private-metadata'}))
        for attempt_owner in (owner_id, other_id):
            attempt_id = str(uuid4())
            db.add(DecisionLog(id=attempt_id, session_id=sid, user_id=attempt_owner, decision_type='model_attempt',
                metadata_={'id': attempt_id, 'session_id': sid, 'timestamp': timestamp, 'provider': 'local',
                    'model': 'fixture-reviewed', 'state': 'failed', 'error_code': 'provider_timeout',
                    'timings': {'pool_attempt_ms': 4321, 'private_debug': 'fixture-private-diagnostic'},
                    'private_response': 'fixture-private-diagnostic'}))
        await db.commit()

    checks = {}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1') as client:
            readiness = await client.get('/api/ready')
            assert readiness.json()['database'] is True
            checks['migration_and_readiness'] = readiness.status_code
            login = await client.post('/api/login', json={'username': 'mission-fixture', 'password': password})
            login.raise_for_status()
            authorization = {'Authorization': 'Bearer ' + login.json()['token']}
            path = f'/api/mission/{sid}/events'
            latest = await client.get(path + '?limit=3', headers=authorization)
            latest.raise_for_status()
            assert latest.json()['team']['has_older'] is True
            assert [event['sequence'] for event in latest.json()['team']['events']] == [8, 9, 10]
            assert 'fixture-private-field' not in latest.text
            older = await client.get(path + '?team_before=8&limit=3', headers=authorization)
            assert [event['sequence'] for event in older.json()['team']['events']] == [5, 6, 7]
            newer = await client.get(path + '?team_after=8&limit=1', headers=authorization)
            assert newer.json()['team']['cursor'] == 9
            assert newer.json()['team']['has_more'] is True
            assert latest.json()['campaign']['campaign_id'] == latest_id
            checks['durable_event_paging'] = {'latest': [8, 9, 10], 'older': [5, 6, 7], 'newer': [9]}
            trace_path = f'/api/team/{sid}/tasks/task-10/trace'
            trace = await client.get(trace_path, headers=authorization)
            trace.raise_for_status()
            revision, = trace.json()['revisions']
            assert (revision['sequence'], revision['run_id'], revision['dependency_ids']) == (10, 'fixture-task-run', ['task-9'])
            assert revision['assigned_evidence_ids'] == revision['result_evidence_ids'] == ['retained-inventory']
            assert revision['rejections'] == ['The inventory control disagrees with this observation']
            assert 'fixture-private-' not in trace.text
            foreign_trace = await client.get(trace_path, headers={'Authorization': 'Bearer ' + admin})
            assert foreign_trace.status_code == 404
            checks['durable_task_trace'] = {'matched_task_revisions': 1, 'foreign_admin_denied': foreign_trace.status_code}
            traffic_path = f'/api/mission/{sid}/traffic'
            traffic_responses = []
            cursor = None
            for expected in sorted(traffic_ids[:2], reverse=True):
                params = {'limit': 1, **({'before': cursor} if cursor else {})}
                started = perf_counter()
                response = await client.get(traffic_path, headers=authorization, params=params)
                traffic_responses.append(round(1000 * (perf_counter() - started), 3))
                response.raise_for_status()
                assert response.headers['cache-control'] == 'no-store'
                body = response.json()
                capture, = body['captures']
                assert (capture['id'], capture['destination'], capture['response_content_type']) == (
                    expected, 'http://records.example.test', 'application/json')
                assert 'fixture-private-' not in response.text
                cursor = body['next_before']
            assert cursor is None
            foreign_capture = await client.get(traffic_path, headers=authorization, params={'before': traffic_ids[2]})
            foreign_traffic = await client.get(traffic_path, headers={'Authorization': 'Bearer ' + admin})
            assert (foreign_capture.status_code, foreign_traffic.status_code) == (404, 403)
            checks['durable_traffic_metadata'] = {'timestamp_tie_order': True, 'foreign_cursor': 404,
                                                  'foreign_admin': 403, 'request_ms': traffic_responses}
            campaigns = f'/api/mission/{sid}/campaigns'
            first = await client.get(campaigns + '?limit=1', headers=authorization)
            assert [row['id'] for row in first.json()['campaigns']] == [latest_id]
            assert first.json()['next_before'] == latest_id
            second = await client.get(campaigns + f'?limit=1&before={latest_id}', headers=authorization)
            assert [row['id'] for row in second.json()['campaigns']] == [archived_id]
            assert second.json()['next_before'] is None
            old_events = await client.get(campaigns + f'/{archived_id}/events', headers=authorization)
            assert [(row['kind'], row['campaign_id']) for row in old_events.json()['events']] == [('campaign_completed', archived_id)]
            assert 'fixture-private-campaign-message' not in old_events.text
            cross_campaign = await client.get(campaigns + f'/{foreign_campaign}/events', headers=authorization)
            cross_cursor = await client.get(campaigns + f'?before={foreign_campaign}', headers=authorization)
            assert cross_campaign.status_code == cross_cursor.status_code == 404
            checks['durable_campaign_archive'] = {'stable_paging_for_timestamp_ties': True, 'older_ring': old_events.status_code,
                                                  'cross_session_ring_and_cursor_denied': cross_campaign.status_code}
            denied = await client.get(path, headers={'Authorization': 'Bearer ' + admin})
            assert denied.status_code == 403
            checks['foreign_admin_denied'] = denied.status_code
            read = await client.get(f'/api/mission/{sid}/operations', headers=authorization)
            assert read.json()['receipts'][0]['id'] == 'db-fixture-job'
            assert 'fixture-private-receipt' not in read.text
            checks['durable_receipt_allowlist'] = read.status_code
            assert read.json()['web_replays'] == {'records': 3, 'pending_cancellations': 1, 'unknown_outcomes': 1}
            checks['durable_web_replay_summary'] = read.json()['web_replays']
            records = read.json()['authorizations']['records']
            assert [(record['event'], record['action_id'], record['decision']) for record in records] == [
                ('rejection_recorded', proposal_id, 'reject'), ('proposal_registered', proposal_id, None)]
            assert 'fixture-private-' not in read.text and other_id not in read.text
            denied_journal = await client.get(f'/api/mission/{sid}/operations', headers={'Authorization': 'Bearer ' + admin})
            assert denied_journal.status_code == 403
            checks['durable_authorization_history'] = {'events': [record['event'] for record in records],
                                                       'foreign_admin_denied': denied_journal.status_code}
            accounting = f'/api/mission/{sid}/accounting'
            budget = await client.get(accounting, headers=authorization)
            budget.raise_for_status()
            body = budget.json()
            result = body['admission']
            assert (result['state'], result['remaining']['tokens'], result['minimum_tokens']) == ('blocked', 3926, 8192)
            assert len(body['attempts']) == 1 and body['attempts'][0]['error_code'] == 'provider_timeout'
            assert 'fixture-private-diagnostic' not in budget.text
            denied = await client.get(accounting, headers={'Authorization': f'Bearer {admin}'})
            assert denied.status_code == 404
            checks['server_admission_explanation'] = {'remaining': 3926, 'floor': 8192}
            checks['durable_accounting_projection'] = {'sanitized_attempts': len(body['attempts']),
                'foreign_admin_denied': denied.status_code}
        async with async_session() as db:
            retained_id = str(uuid4())
            db.add(ChatLog(id=retained_id, session_id=sid, role='tool_output', msg_type='application_capture',
                content='Synthetic retained application capture', data={'source': 'authenticated_worker_receipt',
                    'summary': {'origin': 'https://application.example.test', 'method': 'GET'},
                    'protected_original': 'fixture-private-protected-capture'}))
            await db.commit()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1') as client:
            har_id, preview_digest, checks['durable_har_inspection'] = await verify_har_storage(
                client, sid, peer_sid, authorization, admin)
        concurrent_id = str(uuid4())
        async with async_session() as db:
            db.add(DecisionLog(session_id=sid, user_id=owner_id, decision_type='team_event',
                metadata_={'id': str(uuid4()), 'sequence': 11, 'timestamp': timestamp, 'collection': 'verification_findings',
                    'entity_id': concurrent_id, 'data': {'id': concurrent_id, 'title': 'Concurrent synthetic review',
                        'state': 'observation', 'revision': 1, 'evidence_snapshot': {},
                        'scope_digest': digest({'targets': ['records.example.test']})}}))
            db.add(DecisionLog(session_id=peer_sid, user_id=owner_id, decision_type='team_event',
                metadata_={'id': 'gap-fixture', 'sequence': 3, 'timestamp': timestamp, 'collection': 'knowledge',
                           'entity_id': 'unreadable-record', 'data': {}}))
            await db.commit()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://127.0.0.1') as client:
            review_path = f'/api/team/{sid}/findings/{concurrent_id}/review'
            revisions = [{'request_id': str(uuid4()), 'state': 'rejected', 'expected_revision': 1,
                          'reason': f'Synthetic review attempt {index}'} for index in range(2)]
            outcomes = await asyncio.gather(*(client.post(review_path, headers=authorization, json=item) for item in revisions))
            assert sorted(item.status_code for item in outcomes) == [200, 409]
            accepted = next(index for index, item in enumerate(outcomes) if item.status_code == 200)
            repeated = await client.post(review_path, headers=authorization, json=revisions[accepted])
            assert repeated.status_code == 200 and repeated.json()['duplicate'] is True
            assert repeated.json()['data']['revision'] == 2
            unauthorized_review = await client.post(review_path, headers={'Authorization': 'Bearer ' + admin}, json=revisions[0])
            assert unauthorized_review.status_code == 404
            history = review_path.replace('/review', '/history')
            latest_history = await client.get(history + '?limit=1', headers=authorization)
            assert latest_history.status_code == 200 and latest_history.json()['revisions'][0]['revision'] == 2
            cursor = latest_history.json()['next_before_sequence']
            older_history = await client.get(history, headers=authorization, params={'before_sequence': cursor})
            assert older_history.status_code == 200 and older_history.json()['revisions'][0]['revision'] == 1
            assert older_history.json()['next_before_sequence'] is None
            foreign_history = await client.get(history, headers={'Authorization': 'Bearer ' + admin})
            peer_history = await client.get(history.replace(sid, peer_sid), headers=authorization)
            assert foreign_history.status_code == peer_history.status_code == 404
            checks['durable_finding_history'] = {'ordered_revisions': [2, 1], 'foreign_owner': 404, 'other_engagement': 404}
            checkpoint_path = f'/api/mission/{sid}/exploration/checkpoint'
            checkpoint_pair = await asyncio.gather(*(client.get(checkpoint_path, headers=authorization,
                params={'sequence': sequence}) for sequence in (11, 12)))
            for response in checkpoint_pair:
                response.raise_for_status()
                assert response.headers['Cache-Control'] == 'no-store' and 'fixture-private-' not in response.text
            first_checkpoint, last_checkpoint = (response.json() for response in checkpoint_pair)
            observed, = first_checkpoint['records']['verification_findings']
            rejected, = last_checkpoint['records']['verification_findings']
            assert (observed['id'], observed['revision'], observed['state']) == (concurrent_id, 1, 'observation')
            assert (rejected['id'], rejected['revision'], rejected['state']) == (concurrent_id, 2, 'rejected')
            assert not first_checkpoint['event_gap'] and not first_checkpoint['truncated']
            assert sum(row['id'] == 'task-10' for row in first_checkpoint['records']['tasks']) == 1
            assert any(row['id'] == 'task-10' and row['dependencies'] == ['task-9'] for row in last_checkpoint['records']['tasks'])
            gap = await client.get(checkpoint_path.replace(sid, peer_sid) + '?sequence=3', headers=authorization)
            assert gap.status_code == 200 and gap.json()['event_gap'] and gap.json()['rejected_records'] == 1
            other_checkpoint = await client.get(checkpoint_path.replace(sid, peer_sid) + '?sequence=11', headers=authorization)
            foreign_checkpoint = await client.get(checkpoint_path + '?sequence=11', headers={'Authorization': 'Bearer ' + admin})
            assert (other_checkpoint.status_code, foreign_checkpoint.status_code) == (404, 403)
            checks['durable_exploration_checkpoint'] = {'saved_states': ['observation', 'rejected'], 'foreign_admin': 403,
                'other_engagement': 404, 'retention_gap_and_malformed_record': True}
            checks['retained_read_timings'] = await measure_database_reads(client, engine, authorization, {
                'event timeline': path, 'exploration checkpoint': checkpoint_path + '?sequence=11',
                'traffic index': traffic_path, 'traffic inspection': traffic_path + '/captures/' + har_id,
            })
        checks['concurrent_review_disposition'] = {'statuses': [200, 409], 'retries_deduplicated': True,
                                                   'cross_owner_denied': 404}
        probe = json.dumps({'url': url, 'sid': sid, 'password': password, 'har_id': har_id, 'fixture_fernet': settings.FERNET_KEY})
        snapshots = []
        for _ in range(2):
            result = await asyncio.to_thread(subprocess.run,
                [sys.executable, '-B', '-m', 'integration.mission_disposable', '--snapshot'],
                input=probe, text=True, capture_output=True, timeout=30, check=True)
            snapshots.append(json.loads(result.stdout.splitlines()[-1]))
        assert snapshots[0] == snapshots[1]
        assert snapshots[0]['captures'] == [har_id, retained_id, *sorted(traffic_ids[:2], reverse=True)]
        assert snapshots[0]['preview_sha256'] == preview_digest
        assert snapshots[0]['checkpoint'] == first_checkpoint
        assert ['task-10', 'blocked', 3] in snapshots[0]['tasks']
        checks['fresh_process_readback'] = {'processes': 2, 'identical_task_revisions': len(snapshots[0]['tasks']),
            'identical_capture_records': len(snapshots[0]['captures']), 'identical_reviewed_preview': True, 'identical_checkpoint': True}
        if with_browser:
            from memory.application_map import fresh, seal

            finding_id = str(uuid4())
            mapped = fresh()
            mapped['captures']['mapped-inventory'] = {'id': 'mapped-inventory', 'origin': 'http://records.example.test:80',
                'route': '/retained-inventory', 'method': 'GET', 'evidence_id': traffic_ids[0], 'created_at': timestamp,
                'expires_at': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(), 'expired': False}
            catalog_id = 'catalog-retained-capture'
            async with async_session() as db:
                db.add(DecisionLog(session_id=sid, user_id=owner_id, decision_type='team_event',
                    metadata_={'id': str(uuid4()), 'sequence': 13, 'timestamp': timestamp, 'collection': 'verification_findings',
                        'entity_id': finding_id, 'data': {'id': finding_id, 'title': 'Synthetic review candidate',
                            'state': 'observation', 'revision': 1, 'evidence_snapshot': {},
                            'scope_digest': digest({'targets': ['records.example.test']})}}))
                db.add(DecisionLog(session_id=sid, user_id=owner_id, decision_type='team_event',
                    metadata_={'id': str(uuid4()), 'sequence': 14, 'timestamp': timestamp, 'collection': 'evidence',
                        'entity_id': catalog_id, 'data': {'id': catalog_id, 'source_kind': 'chat', 'source_id': traffic_ids[0],
                            'source_timestamp': timestamp, 'trust': 'untrusted_observation'}}))
                db.add(DecisionLog(id=str(uuid5(NAMESPACE_URL, 'aria-application-map:' + sid)), session_id=sid, user_id=owner_id,
                                   decision_type='application_map_private', metadata_={'sealed': seal(mapped)}))
                await db.commit()
            checks['visible_database_browser'] = await database_browser(
                app, sid, password, proposal_id, archived_id, output, finding_id, assets)
    finally:
        await engine.dispose()
    return checks


def main(with_browser, output=Path('.local-lab/mission-control/postgres-result.json'), assets: Path | None = None):
    output.parent.mkdir(parents=True, exist_ok=True)
    name = 'aria-mission-db-' + uuid4().hex[:10]
    password = secrets.token_hex(20)
    environment = {**os.environ, 'POSTGRES_PASSWORD': password}
    started = perf_counter()
    command('run', '--detach', '--rm', '--pull=never', '--name', name, '-p', '127.0.0.1::5432',
        '-e', f'POSTGRES_USER={ROLE}', '-e', 'POSTGRES_PASSWORD', '-e', f'POSTGRES_DB={DB}', IMAGE, env=environment)
    try:
        binding = command('port', name, '5432/tcp').stdout.strip().splitlines()
        if len(binding) != 1 or not binding[0].startswith('127.0.0.1:'):
            raise RuntimeError('Unexpected disposable PostgreSQL binding')
        port = int(binding[0].split(':')[-1])
        if port < 1024 or port == 15432:
            raise RuntimeError('Unexpected disposable PostgreSQL port')
        checks = asyncio.run(exercise(f'postgresql+asyncpg://{ROLE}:{password}@127.0.0.1:{port}/{DB}', with_browser, output.parent, assets))
    finally:
        command('stop', '-t', '2', name)
    result = {'fixture': 'Fresh rootless Podman PostgreSQL 16.6', 'migration': '0005',
              'checks': checks, 'elapsedMs': round(1000 * (perf_counter() - started), 2)}
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(output)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--headed', action='store_true', help='Verify the same database through visible Chromium')
    parser.add_argument('--assets', type=Path, help='Serve a staged Mission Control bundle in the test browser')
    parser.add_argument('--output', type=Path, default=Path('.local-lab/mission-control/postgres-result.json'))
    args = parser.parse_args()
    if args.snapshot:
        print(json.dumps(asyncio.run(snapshot_readback(json.load(sys.stdin)))))
        raise SystemExit(0)
    try:
        main(args.headed, args.output, args.assets)
    except subprocess.CalledProcessError as error:
        print(error.stderr.strip()[:600], file=sys.stderr)
        raise SystemExit(1) from None
