"""Opt-in isolated Phase 4 readiness acceptance; synthetic target and fresh SQL only."""
import asyncio
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.local-lab/phase4-readiness'


async def acceptance(lab):
    import httpx
    from starlette.responses import JSONResponse
    from api.main import app
    from api.auth import hash_password
    from config.settings import settings
    from memory.database_models import User, async_session, engine
    from memory.execution_authorization import execution_authorization
    from memory.worker_jobs import worker_jobs
    from memory.team_tasks import team_store
    from agents.result_contract import AgentResult
    from worker.store import JobStore
    from worker.runtime import DockerRuntime
    from worker.service import WorkerService
    from worker.app import create_app

    worker_store = JobStore(lab.url)
    await worker_store.open()
    service = WorkerService(worker_store, DockerRuntime(lab.image, lab.network, lab.executable),
                            [lab.addresses[0] + '/32'], [8080])
    worker_app = create_app(service, settings.KALI_AGENT_TOKEN)
    gate = {'deny_tools': False}
    async def capability_gate(scope, receive, send):
        if scope['type'] == 'http' and scope['path'] == '/capabilities' and gate['deny_tools']:
            response = JSONResponse({'protocol': 'aria-jobs-v1', 'idempotency': True,
                                     'cancellation': True, 'network_scope': True, 'tools': []})
            await response(scope, receive, send)
        else:
            await worker_app(scope, receive, send)
    worker_jobs.client.transport = httpx.ASGITransport(app=capability_gate)
    owner, other = str(uuid.uuid4()), str(uuid.uuid4())
    password = secrets.token_hex(20)
    async with async_session() as db:
        db.add_all([User(id=owner, username='phase4-owner', password_hash=hash_password(password)),
                    User(id=other, username='phase4-other', password_hash=hash_password(password))])
        await db.commit()
    checks = {}
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://synthetic') as client:
            async def call(method, path, expected=200, **kwargs):
                response = await client.request(method, path, **kwargs)
                assert response.status_code == expected, (method, path, response.status_code, response.text[:400])
                return response.json()
            login = await call('POST', '/api/login', json={'username': 'phase4-owner', 'password': password})
            client.headers['Authorization'] = 'Bearer ' + login['token']
            sid = (await call('POST', '/api/session/new', json={'target': lab.addresses[0],
                'scope': {'targets': [lab.addresses[0]], 'ports': [8080]}}))['session_id']
            base = '/api/team/' + sid
            command = 'curl -I http://' + lab.addresses[0] + ':8080/'
            async def approved():
                proposal = await execution_authorization.propose(owner, sid, command, require_approval=True)
                await execution_authorization.decide(owner, sid, proposal.id, 'approve')
                return proposal
            denied = await approved()
            gate['deny_tools'] = True
            await call('POST', '/api/kali/execute', expected=409, json={
                'session_id': sid, 'command': command, 'action_id': denied.id})
            assert not await worker_store.for_session(sid)
            checks['unadvertised_tool_denied_before_worker_submission'] = 'passed'
            gate['deny_tools'] = False
            proposal = await approved()
            receipt = await call('POST', '/api/kali/execute', json={
                'session_id': sid, 'command': command, 'action_id': proposal.id})
            assert receipt['exit_code'] == 0, receipt
            evidence = (await call('POST', base + '/evidence', json={'request_id': str(uuid.uuid4()),
                'source_kind': 'worker', 'source_id': receipt['job_id']}))['data']
            eid = evidence['id']
            checks['approved_isolated_worker_receipt'] = 'passed'
            spec = {'owner_role': 'web_intel', 'objective': 'Review the saved synthetic HTTP response',
                    'expected_output': 'Evidence-linked observation', 'completion_criteria': ['Review the observation'],
                    'evidence_inputs': [eid]}
            task = (await call('POST', base + '/tasks', json={'request_id': str(uuid.uuid4()), 'task': spec}))
            tid = task['entity_id']
            run_id = str(uuid.uuid4())
            await team_store.claim(sid, owner, tid, run_id)
            result = AgentResult(interpreted_request='Review synthetic response', evidence_references=[eid],
                                 uncertainty=['A response does not establish a finding'])
            collected = await team_store.collect(sid, owner, tid, run_id, result)
            completed = await call('POST', base + '/tasks/' + tid + '/transition', json={
                'request_id': str(uuid.uuid4()), 'expected_revision': collected['data']['revision'],
                'state': 'completed', 'reason': 'Legacy analysis reviewed'})
            phase_path = '/api/session/' + sid + '/phase'
            await call('PATCH', phase_path, expected=409, json={'phase': 'reconnaissance'})
            checks['legacy_task_without_questions_cannot_advance'] = 'passed'
            coverage = {'key': 'scope-review', 'question': 'Has the scoped synthetic response been reviewed?',
                        'feature': 'synthetic HTTP', 'gap_reason': '', 'evidence_references': [eid]}
            await call('POST', base + '/coverage', json={'request_id': str(uuid.uuid4()), **coverage,
                'status': 'blocked', 'gap_reason': 'Evidence is missing', 'evidence_references': []})
            migrate = {'request_id': str(uuid.uuid4()), 'expected_revision': completed['data']['revision'],
                       'phase': 'scope', 'security_questions': ['scope-review'], 'reason': 'Review legacy task evidence'}
            await call('POST', base + '/tasks/' + tid + '/migrate', expected=409, json=migrate)
            await call('POST', base + '/coverage', json={'request_id': str(uuid.uuid4()), **coverage, 'status': 'tested'})
            unreviewed = await call('POST', base + '/tasks', json={'request_id': str(uuid.uuid4()),
                'task': {**spec, 'phase': 'scope', 'security_questions': ['scope-review']}})
            status = await call('GET', '/api/v8/status/' + sid)
            assert status['progress']['readiness']['state'] == 'not_ready', status['progress']
            await call('PATCH', phase_path, expected=409, json={'phase': 'reconnaissance'})
            await call('POST', base + '/tasks/' + unreviewed['entity_id'] + '/transition', json={
                'request_id': str(uuid.uuid4()), 'expected_revision': unreviewed['data']['revision'],
                'state': 'cancelled', 'reason': 'Synthetic unreviewed control complete'})
            checks['human_review_required_even_with_tested_evidence'] = 'passed'
            await call('POST', base + '/tasks/' + tid + '/migrate', expected=409,
                       json={**migrate, 'expected_revision': migrate['expected_revision'] - 1})
            migrated = await call('POST', base + '/tasks/' + tid + '/migrate', json=migrate)
            assert migrated['data']['completion_review'][0]['evidence_references'] == [eid]
            assert (await call('POST', base + '/tasks/' + tid + '/migrate', json=migrate))['duplicate']
            checks['legacy_migration_revision_idempotency_and_review'] = 'passed'
            other_login = await call('POST', '/api/login', json={'username': 'phase4-other', 'password': password})
            client.headers['Authorization'] = 'Bearer ' + other_login['token']
            await call('GET', base, expected=404)
            await call('POST', base + '/tasks/' + tid + '/migrate', expected=404, json={**migrate, 'request_id': str(uuid.uuid4())})
            await call('PATCH', phase_path, expected=403, json={'phase': 'reconnaissance'})
            checks['foreign_owner_denied'] = 'passed'
            client.headers['Authorization'] = 'Bearer ' + login['token']
            await call('POST', base + '/coverage', json={'request_id': str(uuid.uuid4()), **coverage,
                'question': 'Changed question', 'status': 'tested'})
            await call('PATCH', phase_path, expected=409, json={'phase': 'reconnaissance'})
            await call('POST', base + '/coverage', json={'request_id': str(uuid.uuid4()), **coverage,
                'status': 'unresolved', 'gap_reason': 'Evidence needs review', 'evidence_references': []})
            await call('PATCH', phase_path, expected=409, json={'phase': 'reconnaissance'})
            checks['changed_or_missing_evidence_blocks_advancement'] = 'passed'
            await call('POST', base + '/coverage', json={'request_id': str(uuid.uuid4()), **coverage, 'status': 'tested'})
            await call('PATCH', phase_path, json={'phase': 'reconnaissance'})
            session = await call('GET', '/api/session/' + sid)
            assert session['phase'] == 'reconnaissance', session
            checks['reviewed_evidence_allows_one_phase_advance'] = 'passed'
            return {'status': 'passed', 'checks': checks, 'worker_image': lab.image,
                    'database': 'disposable', 'target': 'disposable internal network', 'live_model_calls': 0}
    finally:
        await worker_store.close()
        await engine.dispose()


def main():
    if os.environ.get('ARIA_PHASE4_READINESS') != '1':
        raise SystemExit('Set ARIA_PHASE4_READINESS=1 for a disposable isolated lab')
    from integration.test_worker import WorkerLab
    from cryptography.fernet import Fernet
    from sqlalchemy.engine import make_url
    OUTPUT.mkdir(parents=True, exist_ok=True)
    WorkerLab.setUpClass()
    try:
        WorkerLab.cli('exec', WorkerLab.containers[0], 'createdb', '-U', 'postgres', 'aria_phase4_test')
        url = make_url(WorkerLab.url).set(database='aria_phase4_test').render_as_string(hide_password=False)
        os.environ.update(DATABASE_URL=url, DEBUG='false', SECRET_KEY=secrets.token_hex(32),
            FERNET_KEY=Fernet.generate_key().decode(), KALI_AGENT_TOKEN=secrets.token_hex(32),
            KALI_AGENT_URL='http://phase4-worker', KALI_WORKER_PROTOCOL='jobs-v1',
            BURP_COMMUNITY_ENABLED='false', ARIA_EMBEDDING_MODEL_PATH='', REDIS_URL='redis://127.0.0.1:1/15')
        with (OUTPUT / 'migrations.log').open('w') as log:
            subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'], cwd=ROOT, check=True, stdout=log, stderr=log)
            subprocess.run([sys.executable, '-m', 'alembic', 'check'], cwd=ROOT, check=True, stdout=log, stderr=log)
        report = asyncio.run(acceptance(WorkerLab))
        (OUTPUT / 'result.json').write_text(json.dumps(report, indent=2))
        print(json.dumps(report))
    finally:
        WorkerLab.cleanup()


if __name__ == '__main__':
    main()
