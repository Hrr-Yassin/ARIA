"""Self-contained Phase 0 lab: synthetic databases/accounts and private containers.

ARIA_PHASE0=1 WORKER_TEST_RUNTIME=podman .venv/bin/python -B -m integration.phase0_baseline
No owner URL, provider key, database, Redis instance, or existing worker is used.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from unittest.mock import AsyncMock, patch
import uuid
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / '.local-lab/phase0'


def run(*args, env, output=None):
    with (OUTPUT / 'services.log').open('ab') as log:
        subprocess.run(args, cwd=ROOT, env=env, stdout=output or log,
                       stderr=log, check=True, timeout=180)


async def trace(lab, report):
    import httpx
    from sqlalchemy import select
    from api.auth import hash_password
    from api.main import app
    from config.settings import settings
    from memory.autonomous_runs import RunStore
    from memory.database_models import User, DecisionLog, engine, async_session
    from memory.execution_authorization import ExecutionAuthorization
    from memory.session_manager import session_manager
    from memory.worker_jobs import WorkerJobs, worker_jobs
    from worker.app import create_app
    from worker.runtime import DockerRuntime
    from worker.service import WorkerService
    from worker.store import JobStore

    store = JobStore(lab.url)
    await store.open()
    runtime = DockerRuntime(lab.image, lab.network, lab.executable)
    service = WorkerService(store, runtime, [lab.addresses[0] + '/32'], [8080])
    desktop = create_app(service, settings.KALI_AGENT_TOKEN)
    worker_jobs.client.transport = httpx.ASGITransport(app=desktop)
    uid, other_id = str(uuid.uuid4()), str(uuid.uuid4())
    password = secrets.token_hex(24)
    async with async_session() as db:
        db.add_all([User(id=uid, username='phase0-owner', password_hash=hash_password(password)),
                    User(id=other_id, username='phase0-other', password_hash=hash_password(password))])
        await db.commit()

    async def request(client, method, path, status=200, **kwargs):
        response = await client.request(method, path, **kwargs)
        if response.status_code != status:
            raise AssertionError(f'{method} {path}: expected {status}, got {response.status_code}')
        return response

    try:
        # Every model entry is forbidden; this test demonstrates execution plumbing.
        with patch('llm.pool_manager.pool_manager.query_for_task', AsyncMock(side_effect=AssertionError('No models in Phase 0'))), patch('llm.pool_manager.pool_manager.query', AsyncMock(side_effect=AssertionError('No models in Phase 0'))):
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://phase0') as client:
                    login = (await request(client, 'POST', '/api/login', json={'username':'phase0-owner', 'password':password})).json()
                    owner_token = login['token']
                    client.headers['Authorization'] = 'Bearer ' + owner_token
                    target = lab.addresses[0]
                    created = (await request(client, 'POST', '/api/session/new', json={
                        'target':target, 'name':'Phase 0 synthetic HTTP observation',
                        'scope':{'targets':[target], 'ports':[8080]}})).json()
                    sid = created['session_id']
                    command = f'curl -I --max-time 10 http://{target}:8080/'
                    # Force explicit approval for this otherwise low-risk observation.
                    proposal = await ExecutionAuthorization().propose(uid, sid, command, 'curl', require_approval=True)
                    await request(client, 'POST', '/api/kali/execute', status=403,
                                  json={'session_id':sid, 'command':command, 'action_id':proposal.id})
                    await request(client, 'POST', f'/api/execution/{proposal.id}/decision',
                                  json={'session_id':sid, 'decision':'approve'})
                    receipt = (await request(client, 'POST', '/api/kali/execute', json={
                        'session_id':sid, 'command':command, 'action_id':proposal.id})).json()
                    assert receipt['exit_code'] == 0 and '200 OK' in receipt['stdout']
                    await worker_jobs.verify_receipt(uid, sid, receipt['job_id'], receipt['stdout'], receipt['stderr'], receipt['exit_code'])
                    with patch('api.routers.pentest.orchestrator_agent.analyze_output', AsyncMock(return_value={
                        'findings':[], 'findings_count':0, 'summary':'Synthetic HTTP observation; no vulnerability claimed'})):
                        analyzed = (await request(client, 'POST', '/api/tool-results', json={
                            'session_id':sid, 'target':target, 'command':command, 'job_id':receipt['job_id'],
                            'stdout':receipt['stdout'], 'stderr':receipt['stderr'], 'exit_code':receipt['exit_code']})).json()
                        assert analyzed['analysis']['evidence_source'] == 'worker_receipt'
                    logs = await session_manager.get_chat_logs(sid)
                    evidence = next(row for row in logs if row['type'] == 'tool_output')
                    assert evidence['data']['job_id'] == proposal.id
                    generated = (await request(client, 'POST', '/api/report/generate', json={
                        'session_id':sid, 'format':'markdown'})).json()
                    assert generated['findings_count'] == 0  # HTTP availability is not a vulnerability.
                    assert proposal.id in generated['content']
                    assert hashlib.sha256(receipt['stdout'].encode()).hexdigest() in generated['content']
                    download = await request(client, 'GET', '/api/report/download/' + generated['filename'])
                    assert proposal.id in download.text
                    other = (await request(client, 'POST', '/api/login', json={'username':'phase0-other', 'password':password})).json()
                    client.headers['Authorization'] = 'Bearer ' + other['token']
                    await request(client, 'GET', f'/api/session/{sid}/restore', status=403)
                    await request(client, 'GET', '/api/report/download/' + generated['filename'], status=403)
                    client.headers['Authorization'] = 'Bearer ' + owner_token
                    run = RunStore()
                    rid = str(uuid.uuid4())
                    for state in ['planning', 'awaiting_approval', 'executing']:
                        await run.save({'run_id':rid, 'session_id':sid, 'run_state':state, 'active':True})

            # Recreate the worker controller and API lifespan on durable SQL records.
            before = (await store.get(proposal.id)).copy()
            await store.close()
            store = JobStore(lab.url)
            await store.open()
            restarted = WorkerService(store, runtime, [target + '/32'], [8080])
            await restarted.recover()
            worker_jobs.client.transport = httpx.ASGITransport(app=create_app(restarted, settings.KALI_AGENT_TOKEN))
            with patch.object(restarted, 'submit', wraps=restarted.submit) as submitted:
                async with app.router.lifespan_context(app):
                    snapshot = await RunStore().latest(sid)
                    assert not snapshot['active'] and snapshot['reason_code'] == 'restart_reconciliation'
                    assert [entry['state'] for entry in snapshot['transitions']] == ['planning','awaiting_approval','executing']
                    assert (await store.get(proposal.id)) == before
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://phase0', headers={'Authorization':'Bearer '+owner_token}) as client:
                        restored = (await request(client, 'GET', f'/api/session/{sid}/restore')).json()
                        assert any(row['data'].get('job_id') == proposal.id for row in restored['logs'])
                        await request(client, 'POST', '/api/kali/execute', status=403,
                                      json={'session_id':sid, 'command':command, 'action_id':proposal.id})
                        await request(client, 'GET', '/api/report/download/' + generated['filename'])
                    assert submitted.call_count == 0
                    assert (await WorkerJobs().status(uid, sid, proposal.id))['state'] == 'succeeded'
            async with async_session() as db:
                rows = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == sid))).scalars().all()
                kinds = {row.decision_type for row in rows}
                assert {'execution_authorization', 'execution_approved', 'execution_consumed', 'worker_job', 'report_artifact'} <= kinds
            report['trace'] = {'status':'passed', 'session_id':sid, 'action_id':proposal.id,
                'job_id':receipt['job_id'], 'evidence_id':evidence['id'],
                'report_filename':generated['filename'], 'report_sha256':hashlib.sha256(download.content).hexdigest(),
                'stdout_sha256':hashlib.sha256(receipt['stdout'].encode()).hexdigest(),
                'approval_required':True, 'unapproved_dispatch_denied':True,
                'other_user_denied':True, 'restart_no_replay':True, 'saved_history_preserved':True,
                'findings_count':0, 'live_model_calls':0,
                'analysis':'Mocked interpretation; real receipt verification and result ingestion',
                'transport':'ASGI API and worker endpoints; real SQL, Redis and Podman job container'}
    finally:
        await service.recover()
        await store.close()
        await engine.dispose()


def main():
    if os.environ.get('ARIA_PHASE0') != '1':
        raise SystemExit('Set ARIA_PHASE0=1 for the isolated synthetic Phase 0 lab')
    os.umask(0o077)
    OUTPUT.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Reuse the private-network fixture, not its test cases or any deployed service.
    from integration.test_worker import WorkerLab
    runtime = os.environ.get('WORKER_TEST_RUNTIME', 'podman')
    if runtime not in {'podman', 'docker'}:
        raise SystemExit('Expected podman or docker')
    image = subprocess.check_output([runtime, 'image', 'inspect', 'aria-worker:test', '--format', '{{.Id}}'], text=True).strip()
    if not image.startswith('sha256:'):
        image = 'sha256:' + image
    os.environ['WORKER_TEST_RUNTIME'] = runtime
    os.environ['WORKER_TEST_IMAGE'] = image
    sources = [path for directory in ('api', 'agents', 'config', 'memory', 'orchestrator', 'security', 'llm', 'worker', 'migrations', 'integration', 'tests', 'web')
               for path in (ROOT/directory).rglob('*') if path.is_file() and path.suffix in {'.py', '.js', '.cjs', '.html', '.css', '.sql', '.json'}]
    manifest = {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(sources)}
    (OUTPUT/'source-manifest.json').write_text(json.dumps(manifest, indent=2))
    report = {'source_revision':subprocess.check_output(['git','rev-parse','HEAD'], text=True).strip(),
              'source_manifest_sha256':hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
              'started_at_utc':datetime.now(timezone.utc).isoformat(),
              'working_tree_changes':True, 'worker_image':image, 'runtime':runtime,
              'python':sys.version.split()[0], 'owner_data_accessed':False}
    try:
        WorkerLab.setUpClass()
        from sqlalchemy.engine import make_url
        pg = WorkerLab.containers[0]
        redis_name = WorkerLab.prefix + '-redis'
        WorkerLab.containers.append(redis_name)
        WorkerLab.cli('run', '-d', '--pull=never', '--name', redis_name, '--network', WorkerLab.network,
                      '-p', '127.0.0.1::6379', 'docker.io/library/redis:7.4.1')
        redis_port = int(WorkerLab.cli('port', redis_name, '6379/tcp').splitlines()[0].rsplit(':',1)[1])
        app_url = make_url(WorkerLab.url).set(database='aria_phase0_test')
        env = {**os.environ, 'DEBUG':'false', 'DATABASE_URL':app_url.render_as_string(hide_password=False),
               'REDIS_URL':f'redis://127.0.0.1:{redis_port}/15', 'REPORT_OUTPUT_DIR':str(OUTPUT/'reports'),
               'SECRET_KEY':secrets.token_hex(32), 'FERNET_KEY':'', 'FERNET_PREVIOUS_KEYS':'[]',
               'KALI_AGENT_TOKEN':secrets.token_hex(32), 'KALI_AGENT_URL':'http://phase0-worker',
               'KALI_WORKER_PROTOCOL':'jobs-v1', 'BURP_COMMUNITY_ENABLED':'false',
               'BURP_CONNECTOR_USER_ID':'', 'BURP_CONNECTOR_TOKEN':'', 'ARIA_EMBEDDING_MODEL_PATH':'',
               'ARIA_INTEGRATION':'1'}
        from cryptography.fernet import Fernet
        env['FERNET_KEY'] = Fernet.generate_key().decode()
        for database in ['aria_phase0_test','aria_restore_test','aria_rollback_test']:
            WorkerLab.cli('exec', pg, 'createdb', '-U', 'postgres', database)
        # Existing service regressions cover empty upgrades, legacy adoption, and SQL/cache recovery.
        run(sys.executable, '-B', '-m', 'unittest', 'integration.test_services', '-v', env=env)
        report['service_regressions'] = 'passed'
        # A genuine pg_dump/pg_restore exercise using synthetic 0001 data only.
        restored_env = {**env, 'DATABASE_URL':app_url.set(database='aria_restore_test').render_as_string(hide_password=False)}
        run(sys.executable, '-B', '-m', 'alembic', 'upgrade', '0001', env=restored_env)
        WorkerLab.cli('exec', pg, 'psql', '-U', 'postgres', '-d', 'aria_restore_test', '-v', 'ON_ERROR_STOP=1',
            '-c', "INSERT INTO users(id,username,password_hash,role,skill_level,is_active,created_at) VALUES ('00000000-0000-4000-8000-000000000001','phase0-backup','synthetic-retained-hash','PENTESTER','INTERMEDIATE',true,now())")
        backup = OUTPUT/'synthetic-0001.dump'
        with backup.open('wb') as destination:
            run(runtime, 'exec', pg, 'pg_dump', '-U', 'postgres', '-d', 'aria_restore_test', '-Fc', env=env, output=destination)
        def restore(database):
            with backup.open('rb') as source:
                subprocess.run([runtime,'exec','-i',pg,'pg_restore','--exit-on-error','--no-owner','-U','postgres','-d',database], stdin=source, check=True, timeout=60)
        restore('aria_rollback_test')
        upgrade_env = {**env, 'DATABASE_URL':app_url.set(database='aria_rollback_test').render_as_string(hide_password=False)}
        run(sys.executable, '-B', '-m', 'alembic', 'upgrade', 'head', env=upgrade_env)
        run(sys.executable, '-B', '-m', 'alembic', 'check', env=upgrade_env)
        retained = WorkerLab.cli('exec', pg, 'psql', '-U', 'postgres', '-d', 'aria_rollback_test', '-Atc',
            "SELECT password_hash FROM users WHERE username='phase0-backup'")
        assert retained == 'synthetic-retained-hash'
        # Rollback by restoring the backup into a fresh DB, never by dropping owner tables.
        WorkerLab.cli('exec', pg, 'createdb', '-U', 'postgres', 'aria_verify_restore_test')
        restore('aria_verify_restore_test')
        rollback = WorkerLab.cli('exec', pg, 'psql', '-U', 'postgres', '-d', 'aria_verify_restore_test', '-Atc',
            "SELECT version_num FROM alembic_version; SELECT password_hash FROM users WHERE username='phase0-backup'")
        assert rollback.splitlines() == ['0001', 'synthetic-retained-hash']
        report['backup_restore'] = {'status':'passed', 'from_revision':'0001', 'to_revision':'0003',
                                   'retained_data_verified':True, 'rollback_restore_verified':True,
                                   'backup_sha256':hashlib.sha256(backup.read_bytes()).hexdigest()}
        os.environ.update(env)  # Set before importing application settings or models.
        asyncio.run(trace(WorkerLab, report))
        report['status'] = 'passed'
    except BaseException as exc:
        report['status'], report['failure_type'] = 'failed', type(exc).__name__
        raise
    finally:
        WorkerLab.doClassCleanups()
        (OUTPUT/'result.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
