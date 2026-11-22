"""P1 restart acceptance on a fresh rootless PostgreSQL container.

Phases run in separate interpreters against one disposable database:

* ``crash``: seed synthetic worker receipts, catalog them through the canonical
  evidence path, create a collaboration plan and advance it. One specialist
  returns; the other is still inside its (scripted) model call when the parent
  kills the process with SIGKILL, leaving the task ``running`` in SQL.
* ``restart``: a fresh process runs the production restart reconciliation,
  re-delivers the completed run, advances the plan with a new coordinator,
  completes owner reviews explicitly, and verifies plan, task, reasoning and
  evidence-identity state.

Specialists are scripted and analysis-only. No provider, worker or target is used.
Run: ``python -m integration.collaboration_postgres``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

PODMAN = '/usr/bin/podman'
IMAGE = 'docker.io/library/postgres:16.6'
DB = 'aria_collab_test'
ROLE = 'aria_fixture'
OUT = Path('.local-lab/p1-postgres')
JOBS = {'http': 'HTTP 200 synthetic fixture', 'path': '/health 200', 'admin': '/admin 404'}


def podman(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([PODMAN, *args], check=True, capture_output=True, text=True, env=env)


# ── child-process helpers ────────────────────────────────────────────────────

def configure() -> None:
    from config.settings import settings
    settings.DATABASE_URL = os.environ['DATABASE_URL']
    settings.KALI_AGENT_URL = ''
    settings.LLM_ROUTING = 'local'


def log_call(role: str, phase: str) -> None:
    with open(os.environ['ARIA_P1_CALLS'], 'a') as handle:
        handle.write(json.dumps({'role': role, 'phase': phase, 'at': time.time()}) + '\n')


def specialists(phase: str, script: dict, slow: set[str]):
    from agents.result_contract import AgentResult
    from orchestrator.team_coordinator import TeamCoordinator
    released = asyncio.Event()

    class Scripted:
        def __init__(self, role: str):
            self.role = role

        async def process(self, sid, owner, data, skill):
            log_call(self.role, phase)
            if self.role in slow:
                await released.wait()           # web has returned
                await asyncio.sleep(1.0)        # its result is committed
                Path(os.environ['ARIA_P1_MARKER']).write_text('running')
                await asyncio.sleep(600)        # killed here by the parent
            body = script[self.role].pop(0)
            offered = {h['claim']: h['id'] for h in ((data.get('research_context') or {})
                       .get('investigation_reasoning') or {}).get('hypotheses', [])}
            for hyp in body['hypotheses']:
                target = hyp.pop('claim_of', None)
                if target in offered:
                    hyp['claim_id'] = offered[target]
            refs = sorted({r for h in body['hypotheses'] for r in h['evidence_references']})
            if self.role not in slow:
                released.set()
            return {'agent_result': AgentResult(interpreted_request='Analyse', evidence_references=refs,
                                                hypotheses=body['hypotheses'], uncertainty=['Unverified']).model_dump()}

    from unittest.mock import patch
    return patch.object(TeamCoordinator, 'specialists', lambda _self: {
        role: Scripted(role) for role in ('recon', 'scan', 'vuln', 'web_intel', 'correlation', 'report')})


def scripts(ev: dict[str, str]) -> dict:
    admin = 'The application may expose an /admin path.'
    return {
        'web_intel': [{'hypotheses': [
            {'description': admin, 'evidence_references': [ev['http']], 'alternative_explanations': ['No admin path']},
            {'description': 'The /health path may disclose internal status details.', 'evidence_references': [ev['path']],
             'alternative_explanations': ['Liveness probe']}]}],
        'vuln': [{'hypotheses': [
            {'description': 'An /admin path may be exposed by the application.', 'evidence_references': [ev['http']],
             'alternative_explanations': ['Static site']}]}],
        'correlation': [{'hypotheses': [
            {'description': 'The /admin follow-up returned 404.', 'evidence_references': [ev['admin']],
             'disposition': 'rejected', 'claim_of': admin}]}],
    }


async def crash_phase() -> None:
    configure()
    from alembic import command as alembic
    from alembic.config import Config
    from memory.database_models import DecisionLog, PentestSession, User, async_session
    from memory.investigation_state import InvestigationStateStore, canonical_worker_evidence
    from memory.worker_jobs import SQLJobStore
    from orchestrator.collaboration import CollaborationCoordinator, Delegation, DelegationPlan
    from orchestrator.team_coordinator import TeamCoordinator
    await asyncio.to_thread(alembic.upgrade, Config('alembic.ini'), 'head')
    owner, sid = os.environ['ARIA_P1_OWNER'], os.environ['ARIA_P1_SID']
    jobs = {key: str(uuid.uuid5(uuid.NAMESPACE_URL, f'p1-job:{sid}:{key}')) for key in JOBS}
    async with async_session() as db:
        db.add(User(id=owner, username='p1-fixture-' + owner[:8], password_hash='unused'))
        await db.flush()
        db.add(PentestSession(id=sid, user_id=owner, target='192.0.2.1', status='active',
                              scope={'targets': ['192.0.2.1']}))
        await db.flush()
        for key, job in jobs.items():
            db.add(DecisionLog(id=SQLJobStore.key(job), session_id=sid, user_id=owner, decision_type='worker_job',
                               metadata_={'job_id': job, 'session_id': sid, 'user_id': owner, 'state': 'succeeded',
                                          'exit_code': 0, 'output_hash': hashlib.sha256(JOBS[key].encode()).hexdigest(),
                                          'stderr_hash': hashlib.sha256(b'').hexdigest()}))
        await db.commit()
    canonical = await canonical_worker_evidence(sid, owner, list(jobs.values()))
    ev = {key: canonical[job] for key, job in jobs.items()}
    Path(os.environ['ARIA_P1_STATE']).write_text(json.dumps({'jobs': jobs, 'evidence': ev}))
    coordinator = CollaborationCoordinator(TeamCoordinator(), InvestigationStateStore())
    plan = await coordinator.create_plan(sid, owner, DelegationPlan(
        request_id=uuid.UUID(int=7), objective='Interpret retained synthetic receipts.', delegations=[
            Delegation(key='analysis-web', role='web_intel', objective='Interpret HTTP receipts.',
                       evidence_inputs=[ev['http'], ev['path']], completion_criteria=['Cite evidence']),
            Delegation(key='analysis-vuln', role='vuln', objective='Assess exposure.',
                       evidence_inputs=[ev['http']], completion_criteria=['Cite evidence']),
            Delegation(key='cross-review', role='correlation', objective='Challenge both analyses.',
                       prerequisites=['analysis-web', 'analysis-vuln'], evidence_inputs=list(ev.values()),
                       completion_criteria=['Each claim supported, rejected or inconclusive'])]))
    state = json.loads(Path(os.environ['ARIA_P1_STATE']).read_text())
    Path(os.environ['ARIA_P1_STATE']).write_text(json.dumps({**state, 'plan_id': plan['id'],
                                                             'task_ids': plan['task_ids']}))
    with specialists('crash', scripts(ev), slow={'vuln'}):
        await coordinator.advance(sid, owner, plan['id'])


async def restart_phase() -> dict:
    configure()
    from memory.database_models import DecisionLog, async_session
    from memory.investigation_state import InvestigationStateStore, worker_evidence_request
    from memory.team_tasks import EvidenceInput, Transition, team_store
    from orchestrator.collaboration import CollaborationCoordinator
    from orchestrator.team_coordinator import TeamCoordinator
    from sqlalchemy import select
    owner, sid = os.environ['ARIA_P1_OWNER'], os.environ['ARIA_P1_SID']
    fixture = json.loads(Path(os.environ['ARIA_P1_STATE']).read_text())
    ev, plan_id, task_ids = fixture['evidence'], fixture['plan_id'], fixture['task_ids']
    checks: dict = {}

    def states(view):
        return {t['id']: t['state'] for t in view['tasks']}
    before = states(await team_store.view(sid, owner))
    checks['after_kill'] = {k: before.get(v) for k, v in task_ids.items()}
    await team_store.recover()                                  # production restart reconciliation
    after = states(await team_store.view(sid, owner))
    checks['after_recover'] = {k: after.get(v) for k, v in task_ids.items()}
    # Re-delivery of the run that completed before the crash never calls a specialist.
    web_run = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan-run:{plan_id}:{task_ids["analysis-web"]}:1'))
    with specialists('restart', scripts(ev), slow=set()):
        retry = await TeamCoordinator().run(sid, owner, task_ids['analysis-web'], web_run, 'intermediate')
        checks['redelivery_duplicate'] = bool(retry.get('duplicate'))
        # The research catalog identity resolves to the same canonical evidence entries.
        again = await team_store.catalog(sid, owner, EvidenceInput(
            request_id=worker_evidence_request(sid, fixture['jobs']['http']), source_kind='worker',
            source_id=fixture['jobs']['http']))
        checks['catalog_identity_shared'] = again['duplicate'] and again['data']['id'] == ev['http']
        coordinator = CollaborationCoordinator(TeamCoordinator(), InvestigationStateStore())
        first = await coordinator.advance(sid, owner, plan_id)
        checks['replans'] = [r['event'] for r in first['plan']['replans']]
        checks['states_after_replan'] = first['states']
        view = await team_store.view(sid, owner)
        tasks = {t['id']: t for t in view['tasks']}
        for key in ('analysis-web', 'analysis-vuln~r1'):
            task = tasks[first['plan']['task_ids'][key]]
            await team_store.transition(sid, owner, task['id'], Transition(
                request_id=uuid.uuid4(), expected_revision=task['revision'], state='completed',
                reason='Explicit owner review in the restart acceptance'))
        second = await coordinator.advance(sid, owner, plan_id)
        checks['final_states'] = second['states']
        checks['supervision'] = {k: second['plan']['supervision'][k] for k in (
            'contradictions', 'duplicated_conclusions', 'unattributed_rejections', 'avoided_specialist_calls')}
        # A further fresh coordinator (second restart) performs no specialist work.
        calls_before = Path(os.environ['ARIA_P1_CALLS']).read_text().count('\n')
        third = await CollaborationCoordinator(TeamCoordinator(), InvestigationStateStore()).advance(sid, owner, plan_id)
        checks['second_restart_new_calls'] = Path(os.environ['ARIA_P1_CALLS']).read_text().count('\n') - calls_before
        checks['second_restart_status'] = third['plan']['status']
    view = await team_store.view(sid, owner)
    reasoning = next(iter(view['investigation_reasoning']))['state']
    supports = {ref for h in reasoning['hypotheses'].values() for ref in h['support'] + h['contradict']}
    catalog = {e['id'] for e in view['evidence']}
    checks['reasoning_cycles'] = reasoning['cycle']
    checks['reasoning_ids_are_ledger_ids'] = supports <= catalog
    checks['reasoning_contains_raw_job_ids'] = bool(supports & set(fixture['jobs'].values()))
    checks['admin_claim_status'] = next(h['status'] for h in reasoning['hypotheses'].values() if '/admin' in h['claim'])
    async with async_session() as db:
        rows = (await db.execute(select(DecisionLog.metadata_).where(
            DecisionLog.session_id == sid, DecisionLog.decision_type == 'team_event'))).scalars().all()
    checks['ledger_events'] = len(rows)
    checks['plan_revisions'] = sum(1 for r in rows if r and r.get('collection') == 'orchestration_plans')
    return checks


# ── parent ───────────────────────────────────────────────────────────────────

def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    name = 'aria-p1-db-' + uuid.uuid4().hex[:10]
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
               'ARIA_P1_OWNER': str(uuid.uuid4()), 'ARIA_P1_SID': str(uuid.uuid4()),
               'ARIA_P1_CALLS': str(run_dir / 'calls.jsonl'), 'ARIA_P1_MARKER': str(run_dir / 'marker'),
               'ARIA_P1_STATE': str(run_dir / 'state.json')}
        Path(env['ARIA_P1_CALLS']).write_text('')
        for _ in range(60):
            if subprocess.run([PODMAN, 'exec', name, 'pg_isready', '-U', ROLE, '-d', DB],
                              capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        time.sleep(1.0)
        child = subprocess.Popen([sys.executable, '-m', 'integration.collaboration_postgres', '--phase', 'crash'],
                                 env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        deadline = time.time() + 120
        while not Path(env['ARIA_P1_MARKER']).exists():
            if child.poll() is not None:
                raise RuntimeError('Crash phase exited early: ' + child.stdout.read().decode()[-1500:])  # type: ignore[union-attr]
            if time.time() > deadline:
                raise RuntimeError('Crash phase did not reach the in-flight specialist')
            time.sleep(0.2)
        child.send_signal(signal.SIGKILL)
        child.wait()
        result['crash_exit'] = child.returncode
        restart = subprocess.run([sys.executable, '-m', 'integration.collaboration_postgres', '--phase', 'restart'],
                                 env=env, capture_output=True, text=True)
        if restart.returncode:
            raise RuntimeError('Restart phase failed: ' + restart.stdout[-800:] + restart.stderr[-2500:])
        result['checks'] = json.loads(restart.stdout.strip().splitlines()[-1])
        calls = [json.loads(line) for line in Path(env['ARIA_P1_CALLS']).read_text().splitlines()]
        result['specialist_calls'] = [{'role': c['role'], 'phase': c['phase']} for c in calls]
    finally:
        podman('stop', '-t', '2', name)
    result['elapsed_s'] = round(time.perf_counter() - started, 2)
    path = OUT / 'result.json'
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['crash', 'restart'])
    args = parser.parse_args()
    if args.phase == 'crash':
        asyncio.run(crash_phase())
    elif args.phase == 'restart':
        print(json.dumps(asyncio.run(restart_phase()), default=str))
    else:
        main()
