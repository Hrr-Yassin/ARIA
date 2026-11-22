"""P4 authorization-profile acceptance on a fresh rootless PostgreSQL container.

Phase ``configure`` (process 1): migrate, seed an owner and engagement, configure a
Private Lab profile, approve a command-bound proposal, record a denial, then
change the profile. Phase ``restart`` (process 2): verify persistence, approval
invalidation, denial persistence across restart, audit records, bug-bounty
provenance requirement and the active-execution guard. The worker is a tripwire:
any dispatch fails the run. No target, worker or provider is contacted.
Run: ``python -m integration.profiles_postgres``.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

PODMAN = '/usr/bin/podman'
IMAGE = 'docker.io/library/postgres:16.6'
DB = 'aria_profiles_test'
ROLE = 'aria_fixture'
OUT = Path('.local-lab/p4-postgres')
STATEMENT = 'The owner operates this isolated lab and authorizes testing of the listed assets.'


def podman(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([PODMAN, *args], check=True, capture_output=True, text=True, env=env)


def configure_settings() -> None:
    from config.settings import settings
    settings.DATABASE_URL = os.environ['DATABASE_URL']
    settings.KALI_AGENT_URL = ''
    settings.LLM_ROUTING = 'local'


def lab_profile(**changes):
    from memory.engagement_profiles import PrivateLabProfile
    return PrivateLabProfile(**{'targets': ['192.168.77.20'], 'ports': [80], 'inventory': ['192.168.77.20'],
                                'permitted_capabilities': ['curl'], 'prohibited_capabilities': ['nmap'],
                                'approval': 'sensitive', 'ownership_statement': STATEMENT,
                                'isolation': {'network_isolated': True, 'description': 'Disposable test fixture'},
                                **changes})


def reason_of(error) -> str | None:
    return error.detail.get('reason') if isinstance(error.detail, dict) else None


async def tripwire(*args, **kwargs):
    raise AssertionError('Worker dispatch reached the tripwire')


async def configure_phase() -> dict:
    configure_settings()
    from alembic import command as alembic
    from alembic.config import Config
    from memory.database_models import PentestSession, User, async_session
    from memory.engagement_profiles import ProfileUpdate, profile_store
    from memory.execution_authorization import ExecutionAuthorization
    from fastapi import HTTPException
    await asyncio.to_thread(alembic.upgrade, Config('alembic.ini'), 'head')
    owner, sid = os.environ['ARIA_P4_OWNER'], os.environ['ARIA_P4_SID']
    async with async_session() as db:
        db.add(User(id=owner, username='p4-' + owner[:8], password_hash='unused'))
        await db.flush()
        db.add(PentestSession(id=sid, user_id=owner, target='192.168.77.20', status='active',
                              scope={'targets': ['192.168.77.20'], 'exclusions': []}))
        await db.commit()
    checks: dict = {}
    first = await profile_store.update(sid, owner, ProfileUpdate(expected_revision=0, reason='Initial lab authorization',
                                                                 profile=lab_profile()))
    checks['configured_revision'] = first['profile']['revision']
    service = ExecutionAuthorization(worker=tripwire)
    command = 'curl http://192.168.77.20/'
    proposal = await service.propose(owner, sid, command, 'curl')
    checks['proposal_status_under_profile'] = proposal.status
    approved = await service.decide(owner, sid, proposal.id, 'approve')
    checks['approved_status'] = approved.status
    try:
        await service.propose(owner, sid, 'nmap -p 80 192.168.77.20', 'nmap')
    except HTTPException as error:
        checks['prohibited_denied'] = (error.status_code, reason_of(error))
    try:
        await profile_store.update(sid, owner, ProfileUpdate(expected_revision=0, reason='stale', profile=lab_profile()))
    except HTTPException as error:
        checks['stale_revision'] = error.status_code
    second = await profile_store.update(sid, owner, ProfileUpdate(expected_revision=1, reason='Add port 443',
                                                                  profile=lab_profile(ports=[80, 443])))
    checks['changed_revision'] = second['profile']['revision']
    Path(os.environ['ARIA_P4_STATE']).write_text(json.dumps({'approved_action': proposal.id}))
    return checks


async def restart_phase() -> dict:
    configure_settings()
    from fastapi import HTTPException
    from sqlalchemy import select
    from memory.database_models import DecisionLog, PentestSession, async_session
    from memory.engagement_profiles import BugBountyProfile, ProfileUpdate, profile_store
    from memory.execution_authorization import ExecutionAuthorization
    owner, sid = os.environ['ARIA_P4_OWNER'], os.environ['ARIA_P4_SID']
    state = json.loads(Path(os.environ['ARIA_P4_STATE']).read_text())
    checks: dict = {}
    view = await profile_store.view(sid, owner)
    checks['persisted'] = {'kind': view['profile']['kind'], 'revision': view['profile']['revision'],
                           'ports': view['profile']['ports'], 'integrity': view['profile']['integrity']}
    checks['restrictions_match_backend'] = view['restrictions']['enforced']['prohibited_capabilities'] == ['nmap']
    service = ExecutionAuthorization(worker=tripwire)
    try:
        await service.execute(owner, sid, 'curl http://192.168.77.20/', 'curl', action_id=state['approved_action'])
        checks['stale_approval'] = 'DISPATCHED'
    except HTTPException as error:
        checks['stale_approval'] = (error.status_code, str(error.detail)[:60])
    for attempt in range(2):
        try:
            await service.execute(owner, sid, 'nmap -p 80 192.168.77.20', 'nmap')
            checks[f'prohibited_after_restart_{attempt}'] = 'DISPATCHED'
        except HTTPException as error:
            checks[f'prohibited_after_restart_{attempt}'] = (error.status_code, reason_of(error))
    try:
        await service.propose(owner, sid, 'curl http://192.168.77.99/', 'curl')
        checks['out_of_scope'] = 'PROPOSED'
    except HTTPException as error:
        checks['out_of_scope'] = error.status_code
    try:
        await profile_store.update(sid, owner, ProfileUpdate(expected_revision=2, reason='Switch to bounty',
            profile=BugBountyProfile(targets=['app.example.test'], permitted_capabilities=['curl'], exclusions_reviewed=True,
                                     program_snapshot_id='missing', testing_restrictions=STATEMENT)))
        checks['bug_bounty_without_program'] = 'ACCEPTED'
    except HTTPException as error:
        checks['bug_bounty_without_program'] = error.status_code
    async with async_session() as db:
        db.add(DecisionLog(id=str(uuid.uuid4()), session_id=sid, user_id=owner, decision_type='worker_job',
                           metadata_={'state': 'running'}))
        await db.commit()
    try:
        await profile_store.update(sid, owner, ProfileUpdate(expected_revision=2, reason='During execution',
                                                             profile=lab_profile(ports=[80])))
        checks['change_during_execution'] = 'ACCEPTED'
    except HTTPException as error:
        checks['change_during_execution'] = error.status_code
    async with async_session() as db:
        rows = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == sid))).scalars().all()
        session = (await db.execute(select(PentestSession).where(PentestSession.id == sid))).scalar_one()
    changes: list[dict] = [dict(r.metadata_ or {}) for r in rows if str(r.decision_type) == 'engagement_profile_change']
    denials: list[dict] = [dict(r.metadata_ or {}) for r in rows if str(r.decision_type) == 'policy_denied']
    checks['audit_profile_changes'] = [(c['revision'], c['previous_kind'], c['kind'], c['scope_digest_before'] != c['scope_digest_after'])
                                       for c in sorted(changes, key=lambda c: c['revision'])]
    checks['audit_denials'] = sorted({(d['stage'], d.get('reason')) for d in denials})
    checks['worker_epoch'] = dict(session.metadata_ or {}).get('worker_epoch')
    checks['view_denials_listed'] = len((await profile_store.view(sid, owner))['denied_operations'])
    return checks


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    name = 'aria-p4-db-' + uuid.uuid4().hex[:10]
    password = secrets.token_hex(20)
    started = time.perf_counter()
    podman('run', '--detach', '--rm', '--pull=never', '--name', name, '-p', '127.0.0.1::5432',
           '-e', f'POSTGRES_USER={ROLE}', '-e', 'POSTGRES_PASSWORD', '-e', f'POSTGRES_DB={DB}', IMAGE,
           env={**os.environ, 'POSTGRES_PASSWORD': password})
    result: dict = {'fixture': f'Fresh rootless Podman {IMAGE}', 'database': DB}
    try:
        binding = podman('port', name, '5432/tcp').stdout.strip().splitlines()
        port = int(binding[0].split(':')[-1])
        assert binding[0].startswith('127.0.0.1:') and port != 15432, 'Unexpected disposable binding'
        from cryptography.fernet import Fernet
        run_dir = OUT / uuid.uuid4().hex[:8]
        run_dir.mkdir()
        env = {**os.environ, 'DATABASE_URL': f'postgresql+asyncpg://{ROLE}:{password}@127.0.0.1:{port}/{DB}',
               'SECRET_KEY': secrets.token_hex(32), 'FERNET_KEY': Fernet.generate_key().decode(),
               'KALI_AGENT_TOKEN': secrets.token_hex(32), 'LLM_ROUTING': 'local', 'KALI_AGENT_URL': '',
               'ARIA_P4_OWNER': str(uuid.uuid4()), 'ARIA_P4_SID': str(uuid.uuid4()),
               'ARIA_P4_STATE': str(run_dir / 'state.json')}
        for _ in range(60):
            if subprocess.run([PODMAN, 'exec', name, 'pg_isready', '-U', ROLE, '-d', DB], capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        time.sleep(1.0)
        for phase in ('configure', 'restart'):
            run = subprocess.run([sys.executable, '-m', 'integration.profiles_postgres', '--phase', phase],
                                 env=env, capture_output=True, text=True)
            if run.returncode:
                raise RuntimeError(f'{phase} failed: ' + run.stdout[-800:] + run.stderr[-2500:])
            result[phase] = json.loads(run.stdout.strip().splitlines()[-1])
    finally:
        podman('stop', '-t', '2', name)
    result['elapsed_s'] = round(time.perf_counter() - started, 2)
    (OUT / 'result.json').write_text(json.dumps(result, indent=2, default=str) + '\n')
    print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['configure', 'restart'])
    args = parser.parse_args()
    if args.phase == 'configure':
        print(json.dumps(asyncio.run(configure_phase()), default=str))
    elif args.phase == 'restart':
        print(json.dumps(asyncio.run(restart_phase()), default=str))
    else:
        main()
