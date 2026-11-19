"""Verify Mission Control read contracts against a fresh rootless PostgreSQL container.

Uses a cached image, a random loopback port, and a disposable container. Existing
databases and Redis are outside the fixture. Provider and worker APIs are never used.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4

PODMAN = '/usr/bin/podman'
IMAGE = 'docker.io/library/postgres:16.6'
DB = 'aria_mission_test'
ROLE = 'aria_fixture'


def command(*args, env=None, check=True):
    return subprocess.run([PODMAN, *args], check=check, capture_output=True, text=True, env=env)


async def database_browser(app, sid, password, proposal_id, archived_id):
    from playwright.async_api import async_playwright, expect
    from starlette.responses import JSONResponse
    from integration.mission_browser import loopback_server, sources

    async def readonly(scope, receive, send):
        if scope['type'] == 'http' and scope['method'] not in {'GET', 'HEAD'} and (
                scope['method'], scope['path']) != ('POST', '/api/login'):
            response = JSONResponse({'detail': 'Read-only browser fixture'}, status_code=405)
            return await response(scope, receive, send)
        if scope['type'] == 'websocket':
            return await send({'type': 'websocket.close', 'code': 1008})
        return await app(scope, receive, send)

    async with loopback_server(readonly) as base, async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False, chromium_sandbox=True,
            args=['--disable-background-networking'])
        try:
            context = await browser.new_context(viewport={'width': 1440, 'height': 960}, reduced_motion='reduce')
            await context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else route.abort())
            page = await context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            await page.goto(base + '/login?next=mission')
            await page.get_by_label('Username').fill('mission-fixture')
            await page.get_by_label('Password').fill(password)
            await page.get_by_role('button', name='Sign In').click()
            await expect(page.get_by_label('Current session')).to_have_value(sid)
            await expect(page.get_by_text('Admission blocked', exact=True)).to_be_visible()
            await page.get_by_role('navigation').get_by_role('link', name='Analytics', exact=True).click()
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
            screenshot = Path('.local-lab/mission-control/postgres-authorization.png')
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
            await context.close()
            return {'browser': browser.version, 'headless': False, 'checks': ['Login against migrated PostgreSQL',
                'Durable budget denial and model attempt redaction', 'Durable authorization detail and redaction',
                'Pending web replay state survives reload without contacting the connector',
                'Older campaign snapshot and replay'],
                'screenshot': screenshot.name, 'archiveScreenshot': archive.name, 'sourceHashes': sources('after')}
        finally:
            await browser.close()


async def exercise(url, with_browser):
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
    from memory.campaign_observability import append_operation
    from memory.database_models import AutonomousCampaign, ChatLog, DecisionLog, PentestSession, User, UserRole, WebAction, async_session, engine
    from security.credentials import auth_revision, hash_password

    await asyncio.to_thread(alembic.upgrade, Config('alembic.ini'), 'head')
    owner_id, other_id, sid = (str(uuid4()) for _ in range(3))
    foreign_sid = str(uuid4())
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
        await db.flush()
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
            db.add(DecisionLog(session_id=sid, user_id=owner_id, decision_type='team_event',
                metadata_={'id': f'event-{seq}', 'sequence': seq, 'timestamp': timestamp, 'collection': 'tasks',
                    'entity_id': f'task-{seq}', 'data': {'id': f'task-{seq}', 'owner_role': 'web_intel', 'state': 'completed',
                        'private_payload': 'fixture-private-field'}}))
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
        if with_browser:
            checks['visible_database_browser'] = await database_browser(app, sid, password, proposal_id, archived_id)
    finally:
        await engine.dispose()
    return checks


def main(with_browser):
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
        checks = asyncio.run(exercise(f'postgresql+asyncpg://{ROLE}:{password}@127.0.0.1:{port}/{DB}', with_browser))
    finally:
        command('stop', '-t', '2', name)
    result = {'fixture': 'Fresh rootless Podman PostgreSQL 16.6', 'migration': '0005',
              'checks': checks, 'elapsedMs': round(1000 * (perf_counter() - started), 2)}
    path = Path('.local-lab/mission-control/postgres-result.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(path)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--headed', action='store_true', help='Verify the same database through visible Chromium')
    try:
        main(parser.parse_args().headed)
    except subprocess.CalledProcessError as error:
        print(error.stderr.strip()[:600], file=sys.stderr)
        raise SystemExit(1) from None
