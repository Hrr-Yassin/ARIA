"""Twelve harmless operations through real authorization, worker and team code.

PostgreSQL is real and disposable. Worker HTTP uses ASGITransport and the real
worker policy/service with an in-memory runtime: no container or tool starts.
Existing specialist entry points run with deterministic local-model transport
fixtures and real accounting. No hosted model or target network is contacted.
"""
from __future__ import annotations

import asyncio
import copy
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import socket
import statistics
import time
import uuid
from unittest.mock import patch

import httpx
from fastapi import HTTPException
from sqlalchemy import event, select, text
from sqlalchemy.engine import make_url

from config.settings import settings
from memory.database_models import User, PentestSession, async_session, engine
from memory.execution_authorization import execution_authorization
from memory.worker_jobs import worker_jobs
from memory.team_tasks import CreateTask, EvidenceInput, TaskSpec, Transition, team_store
from llm.engagement_budget import ModelLimits, model_accounting, task_context
from llm.local_client import LocalClient
from agents.base_agent import BaseAgent, _agent_context
from orchestrator.team_coordinator import team_coordinator
from worker.app import create_app
from worker.service import WorkerService

OBJECTIVE = 'Process twelve harmless engineering operations, retaining evidence, errors and unfinished work.'
ROLES = ['recon', 'scan', 'web_intel', 'vuln', 'correlation', 'report',
         'recon', 'scan', 'web_intel', 'vuln', 'correlation', 'report']
EXPECTED = ['completed', 'completed', 'completed', 'blocked', 'completed', 'cancelled',
            'completed', 'completed', 'completed', 'cancelled', 'completed', 'completed']


class FixtureStore:
    def __init__(self):
        self.rows = {}

    async def get(self, job_id):
        return copy.deepcopy(self.rows.get(job_id))

    async def save(self, job):
        self.rows[job['job_id']] = copy.deepcopy(job)

    async def active(self):
        return [copy.deepcopy(row) for row in self.rows.values()
                if row['state'] not in {'succeeded', 'failed', 'cancelled'}]


class FixtureRuntime:
    def __init__(self):
        self.rows, self.starts = {}, []
        self.cancellable = asyncio.Event()

    @staticmethod
    def number(job):
        return int(job['command'].rsplit('/', 1)[-1])

    async def create(self, job):
        self.rows[job['job_id']] = {'Status': 'created', 'Running': False, 'ExitCode': 0}

    async def start(self, job):
        n = self.number(job)
        self.starts.append(job['job_id'])
        self.rows[job['job_id']] = {'Status': 'running' if n == 6 else 'exited',
                                  'Running': n == 6, 'ExitCode': 1 if n == 11 else 0}
        if n == 6:
            self.cancellable.set()

    async def inspect(self, job):
        return self.rows.get(job['job_id'])

    async def stop(self, job):
        self.rows.pop(job['job_id'], None)
        return True

    async def output(self, job):
        if self.number(job) == 11:
            return '', 'Synthetic observation failure; no tool was executed.'
        return f'HTTP/1.1 200 OK\r\nX-Synthetic-Operation: {self.number(job)}\r\n', ''


def now():
    return datetime.now(timezone.utc).isoformat()


async def run_twelve_operations(output: Path | None = None) -> dict:
    url = make_url(settings.DATABASE_URL)
    if os.environ.get('ARIA_INTEGRATION') != '1' or not (url.database or '').endswith('_test'):
        raise RuntimeError('An explicitly provisioned disposable *_test database is required')
    if url.host not in {'127.0.0.1', 'localhost', '::1'}:
        raise RuntimeError('This fixture permits only a local disposable database')
    output = output or Path('.local-lab/operational-reliability') / ('workload-' + uuid.uuid4().hex[:12])
    started, cpu_start = time.monotonic_ns(), time.process_time()
    rss_start = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    owner, other_owner, sid = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    async with async_session() as db:
        db.add(User(id=owner, username='reliability-' + uuid.uuid4().hex[:16], password_hash='unused'))
        db.add(User(id=other_owner, username='outsider-' + uuid.uuid4().hex[:16], password_hash='unused'))
        await db.flush()
        db.add(PentestSession(id=sid, user_id=owner, target='192.0.2.1',
            scope={'targets': ['192.0.2.1'], 'ports': [80]},
            metadata_={'synthetic_reliability': True, 'fixture_objective': OBJECTIVE}))
        await db.commit()
    await model_accounting.configure(sid, owner, ModelLimits(
        max_calls=30, max_tokens=1000000, max_cost_microusd=0))
    runtime = FixtureRuntime()
    worker = create_app(WorkerService(FixtureStore(), runtime, ['192.0.2.0/24'], [80]),
                        token=secrets.token_urlsafe(32))
    operations, task_numbers, precreated = [], {}, {}
    counters = {'sql_statements': 0, 'serialized_sql_statement_bytes': 0,
                'fixture_model_calls': 0, 'fixture_model_payload_bytes': 0,
                'preapproval_denials': 0, 'duplicate_authorization_denials': 0,
                'dependency_denials': 0, 'owner_denials': 0, 'sql_statement_wall_sum_ms': 0.,
                'repeated_authoritative_context_bytes': 0, 'forbidden_network_attempts': 0}
    shared_contexts = set()
    def sql(conn, cursor, statement, parameters, context, executemany):
        context.aria_started_ns = time.monotonic_ns()
        counters['sql_statements'] += 1
        counters['serialized_sql_statement_bytes'] += len(statement.encode())
    def sql_finished(conn, cursor, statement, parameters, context, executemany):
        counters['sql_statement_wall_sum_ms'] += (time.monotonic_ns() - context.aria_started_ns) / 1e6
    event.listen(engine.sync_engine, 'before_cursor_execute', sql)
    event.listen(engine.sync_engine, 'after_cursor_execute', sql_finished)
    original_connect = socket.socket.connect
    def database_only(sock, address):
        if not isinstance(address, tuple) or address[0] not in {'127.0.0.1', '::1'} or address[1] != (url.port or 5432):
            counters['forbidden_network_attempts'] += 1
            raise AssertionError('Non-database network access is forbidden in the synthetic benchmark')
        return original_connect(sock, address)
    original_parse = BaseAgent.parse_json
    def parse(agent, content):
        begin = time.monotonic_ns()
        try:
            return original_parse(agent, content)
        finally:
            ctx = task_context.get() or {}
            number = task_numbers.get(ctx.get('id'))
            if number:
                operations[number - 1]['json_parse_validation_ms'].append((time.monotonic_ns() - begin) / 1e6)
    async def fixture_model(prompt, system=''):
        ctx = task_context.get() or {}
        number = task_numbers[ctx['id']]
        op = operations[number - 1]
        op['fixture_model_calls'] += 1
        counters['fixture_model_calls'] += 1
        size = len((prompt + system).encode())
        counters['fixture_model_payload_bytes'] += size
        trusted = _agent_context.get() or {}
        shared = json.dumps({key: trusted.get(key) for key in ('scope', 'worker_tools', 'rules')}, sort_keys=True).encode()
        shared_digest = hashlib.sha256(shared).hexdigest()
        if shared_digest in shared_contexts:
            counters['repeated_authoritative_context_bytes'] += len(shared)
        shared_contexts.add(shared_digest)
        op['serialized_model_input_bytes'] += size
        if op['objective'] not in prompt:
            raise AssertionError('Specialist lost its assigned objective')
        if number == 10:
            current = next(t for t in (await team_store.view(sid, owner))['tasks'] if t['id'] == op['task_id'])
            await team_store.transition(sid, owner, op['task_id'], Transition(
                request_id=uuid.uuid4(), expected_revision=current['revision'], state='cancelled',
                reason='Synthetic owner cancellation while analysis is in flight'))
        content = '{"commands":[' if number == 4 else json.dumps({
            'commands': [], 'findings': [], 'correlations': [], 'vulnerability_assessment': [],
            'suggested_response': 'Synthetic observation only; no vulnerability verified.'})
        op['serialized_model_output_bytes'] += len(content.encode())
        return {'success': True, 'content': content, 'tokens_used': 20, 'cost_microusd': 0}
    def measured_specialist(agent):
        original = agent.process
        async def process(session_id, user_id, data, skill):
            number = task_numbers[(task_context.get() or {})['id']]
            op = operations[number - 1]
            op['actual_agent_invocations'] += 1
            op['runtime_agent'] = agent.agent_name
            op['agent_input_bytes'] += len(json.dumps(data).encode())
            result = await original(session_id, user_id, data, skill)
            op['agent_output_bytes'] += len(json.dumps(result).encode())
            return result
        return process
    stack = ExitStack()
    try:
        stack.enter_context(patch.object(socket.socket, 'connect', database_only))
        stack.enter_context(patch.object(settings, 'KALI_AGENT_URL', 'http://synthetic-worker'))
        stack.enter_context(patch.object(settings, 'KALI_AGENT_TOKEN', worker.state.token))
        stack.enter_context(patch.object(settings, 'KALI_WORKER_PROTOCOL', 'jobs-v1'))
        stack.enter_context(patch.object(worker_jobs.client, 'transport', httpx.ASGITransport(app=worker)))
        stack.enter_context(patch.object(settings, 'LLM_ROUTING', 'local'))
        stack.enter_context(patch.object(settings, 'LOCAL_LLM_MODEL', 'synthetic-fixture'))
        if output:
            output.mkdir(parents=True, exist_ok=True)
            stack.enter_context(patch.object(settings, 'REPORT_OUTPUT_DIR', str(output / 'fixture-reports')))
        stack.enter_context(patch.object(LocalClient, 'query', side_effect=fixture_model))
        stack.enter_context(patch.object(BaseAgent, 'parse_json', parse))
        stack.enter_context(patch('memory.vector_store._embedder.available', return_value=False))
        for agent in team_coordinator.specialists().values():
            stack.enter_context(patch.object(agent, 'process', side_effect=measured_specialist(agent)))
        for denied_operation in (lambda: team_store.view(sid, other_owner),
                                 lambda: execution_authorization.propose(other_owner, sid, 'curl -I http://192.0.2.1/')):
            try:
                await denied_operation()
                raise AssertionError('Foreign owner was accepted')
            except HTTPException as denied:
                assert denied.status_code in {403, 404}
                counters['owner_denials'] += 1
        # Every operation uses the ordinary command-bound approval and worker policy.
        for number in range(1, 13):
            op_start = time.monotonic_ns()
            sql_start = counters['sql_statements']
            op = {'number': number, 'correlation_id': f'{sid}:operation:{number}',
                  'role': ROLES[number - 1], 'objective': f'Operation {number}: review a harmless saved fixture with explicit uncertainty.',
                  'started_at': now(), 'fixture_model_calls': 0, 'serialized_model_input_bytes': 0,
                  'serialized_model_output_bytes': 0, 'json_parse_validation_ms': [], 'events': []}
            op.update(actual_agent_invocations=0, runtime_agent=None, agent_input_bytes=0, agent_output_bytes=0)
            operations.append(op)
            command = f'curl -I http://192.0.2.1/fixture/{number}'
            phase = time.monotonic_ns()
            proposal = await execution_authorization.propose(owner, sid, command, 'curl',
                                                             require_approval=True, turn_id=op['correlation_id'])
            op['proposal_wall_ms'] = (time.monotonic_ns() - phase) / 1e6
            op['job_id'] = proposal.id
            creates = len(runtime.starts)
            try:
                await execution_authorization.execute(owner, sid, command, 'curl', action_id=proposal.id, timeout=5)
                raise AssertionError('Unapproved fixture command was admitted')
            except HTTPException as denied:
                assert denied.status_code == 403
                counters['preapproval_denials'] += 1
            assert len(runtime.starts) == creates
            phase = time.monotonic_ns()
            await execution_authorization.decide(owner, sid, proposal.id, 'approve')
            op['synthetic_owner_decision_wall_ms'] = (time.monotonic_ns() - phase) / 1e6
            phase = time.monotonic_ns()
            execute = lambda: execution_authorization.execute(owner, sid, command, 'curl', action_id=proposal.id, timeout=5)
            if number == 6:
                execution = asyncio.create_task(execute())
                await asyncio.wait_for(runtime.cancellable.wait(), timeout=5)
                cancellation = await worker_jobs.cancel_session(owner, sid)
                assert cancellation['pending'] == 0
                receipt = await execution
                await worker_jobs.resume_session(owner, sid)  # Explicit synthetic owner action.
            elif number == 8:
                delivered = await asyncio.gather(execute(), execute(), return_exceptions=True)
                receipt = next(item for item in delivered if isinstance(item, dict))
                denials = [item for item in delivered if isinstance(item, HTTPException)]
                assert len(denials) == 1 and denials[0].status_code in {403, 409}
                counters['duplicate_authorization_denials'] += 1
            else:
                receipt = await execute()
            op['worker_path_wall_ms'] = (time.monotonic_ns() - phase) / 1e6
            op['worker_state'] = receipt['status']
            op['worker_stdout_sha256'] = hashlib.sha256(receipt['stdout'].encode()).hexdigest()
            refs = []
            if number != 6:
                await worker_jobs.verify_receipt(owner, sid, proposal.id,
                    receipt['stdout'], receipt['stderr'], receipt['exit_code'])
                evidence = await team_store.catalog(sid, owner, EvidenceInput(
                    request_id=uuid.uuid4(), source_kind='worker', source_id=proposal.id))
                refs = [evidence['entity_id']]
            op['evidence_ids'] = refs
            if number in precreated:
                task, op_start = precreated[number]
                op['enqueued_at'] = task['timestamp']
                op['analysis_input_evidence_ids'] = task['data']['evidence_inputs']
            else:
                task = await team_store.create(sid, owner, CreateTask(request_id=uuid.uuid4(),
                    task=TaskSpec(owner_role=op['role'], objective=op['objective'], evidence_inputs=refs,
                                  expected_output='Evidence-linked observations; no confirmed vulnerability',
                                  completion_criteria=['Cite saved evidence or explicit uncertainty'])))
                op['analysis_input_evidence_ids'] = refs
            op['task_id'] = task['entity_id']
            task_numbers[op['task_id']] = number
            if number == 6:
                await team_store.transition(sid, owner, op['task_id'], Transition(request_id=uuid.uuid4(),
                    expected_revision=1, state='cancelled', reason='Synthetic owner cancelled this operation'))
            else:
                if number == 7:
                    # Operation 8 cooperates on 7's saved observation. Its own
                    # later worker response is retained separately in the catalog.
                    child = await team_store.create(sid, owner, CreateTask(request_id=uuid.uuid4(),
                        task=TaskSpec(owner_role=ROLES[7],
                            objective='Operation 8: review a harmless saved fixture with explicit uncertainty.',
                            dependencies=[op['task_id']], evidence_inputs=refs,
                            expected_output='Evidence-linked observations; no confirmed vulnerability',
                            completion_criteria=['Cite saved evidence or explicit uncertainty'])))
                    precreated[8] = (child, time.monotonic_ns())
                    try:
                        await team_store.claim(sid, owner, child['entity_id'], str(uuid.uuid4()))
                        raise AssertionError('Dependent task ran before prerequisite review')
                    except HTTPException as denied:
                        assert denied.status_code == 409
                        counters['dependency_denials'] += 1
                    await team_store.claim(sid, owner, op['task_id'], str(uuid.uuid4()))
                    await team_store.recover()  # Known interruption before specialist invocation.
                    blocked = next(t for t in (await team_store.view(sid, owner))['tasks'] if t['id'] == op['task_id'])
                    assert blocked['state'] == 'blocked'
                    await team_store.transition(sid, owner, op['task_id'], Transition(request_id=uuid.uuid4(),
                        expected_revision=blocked['revision'], state='queued', reason='Synthetic owner reconciled the unstarted analysis'))
                    op['recovered_before_model_dispatch'] = True
                request = str(uuid.uuid4())
                phase = time.monotonic_ns()
                try:
                    if number == 8:
                        responses = await asyncio.gather(*[team_coordinator.run(sid, owner, op['task_id'], request, 'expert') for _ in range(5)])
                        assert sum(bool(item['duplicate']) for item in responses) == 4
                    else:
                        await team_coordinator.run(sid, owner, op['task_id'], request, 'expert')
                except HTTPException as exc:
                    if number != 10 or exc.status_code != 409:
                        raise
                    op['safe_error'] = 'late_cancelled_result_rejected'
                op['coordinator_wall_ms'] = (time.monotonic_ns() - phase) / 1e6
                current = next(t for t in (await team_store.view(sid, owner))['tasks'] if t['id'] == op['task_id'])
                if current['state'] == 'awaiting_review':
                    await team_store.transition(sid, owner, op['task_id'], Transition(request_id=uuid.uuid4(),
                        expected_revision=current['revision'], state='completed', reason='Synthetic owner reviewed evidence and uncertainty'))
            op['lifecycle_wall_ms'] = (time.monotonic_ns() - op_start) / 1e6
            op['sql_statements_during_operation'] = counters['sql_statements'] - sql_start
            op['finished_at'] = now()
        ledger = await team_store.view(sid, owner)
        events = (await team_store.events(sid, owner))['events']
        for op, expected in zip(operations, EXPECTED):
            task = next(t for t in ledger['tasks'] if t['id'] == op['task_id'])
            op['state'], op['expected_state'] = task['state'], expected
            assert task['state'] == expected, (op['number'], task['state'], expected)
            assert task['owner_role'] == op['role'] and task['objective'] == op['objective']
            op['events'] = [{'state': e['data']['state'], 'sequence': e['sequence'],
                             'revision': e['data']['revision'], 'timestamp': e['timestamp']}
                            for e in events if e['collection'] == 'tasks' and e['entity_id'] == op['task_id']]
            assert op['events'] and op['events'][-1]['state'] == expected
            if task.get('result'):
                assert task['result']['interpreted_request'] == op['objective']
                assert set(task['result']['evidence_references']) <= set(task['evidence_inputs'])
                assert all(item.get('verified') is not True for item in task['result']['observations'] + task['result']['hypotheses'])
        jobs = await worker_jobs.store.list(sid)
        assert len(jobs) == 12 and len(runtime.starts) == len(set(runtime.starts)) == 12
        assert len(ledger['tasks']) == 12
        assert counters['dependency_denials'] == 1 and counters['owner_denials'] == 2
        assert sum(op['actual_agent_invocations'] for op in operations) == 11
        assert all(op['actual_agent_invocations'] <= 1 for op in operations)
        assert counters['forbidden_network_attempts'] == 0
        counters['actual_agent_invocations'] = sum(op['actual_agent_invocations'] for op in operations)
        counters['agent_request_result_messages'] = 2 * counters['actual_agent_invocations']
        counters['agent_input_bytes'] = sum(op['agent_input_bytes'] for op in operations)
        counters['agent_output_bytes'] = sum(op['agent_output_bytes'] for op in operations)
        assert [op['worker_state'] for op in operations] == ['succeeded'] * 5 + ['cancelled'] + ['succeeded'] * 4 + ['failed', 'succeeded']
        async with async_session() as db:
            session = await db.get(PentestSession, sid)
            assert session.metadata_['fixture_objective'] == OBJECTIVE
        accounting = await model_accounting.status(sid, owner)
        latencies = [op['lifecycle_wall_ms'] for op in operations]
        return {'schema': 'aria.reliability.twelve.v1', 'synthetic': True, 'benchmark_passed': True,
            'objective': OBJECTIVE, 'session_id': sid, 'expected_operations': 12, 'recorded_operations': 12,
            'workload_state': 'blocked', 'workload_reason': 'Injected malformed model response remains blocked and visible; cancellations retained.',
            'operations': operations, 'counters': counters, 'actual_external_provider_calls': 0,
            'actual_tools_executed': 0, 'simulated_runtime_starts': len(runtime.starts),
            'duplicate_dispatches': 0, 'lost_operations': 0, 'unauthorized_dispatches': 0,
            'fixture_model_accounting': accounting,
            'lifecycle_statistics_ms': {'n': 12, 'mean': statistics.mean(latencies),
                'median': statistics.median(latencies), 'maximum': max(latencies), 'p95': None,
                'p95_note': 'Twelve mixed fault-injection operations are insufficient for an operational p95.'},
            'wall_seconds': (time.monotonic_ns() - started) / 1e9,
            'cpu_seconds': time.process_time() - cpu_start,
            'peak_rss_kb': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'peak_rss_growth_kb': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - rss_start,
            'limitations': ['In-process ASGI worker and in-memory runtime; no container/tool/network execution.',
                'Model transport and owner decisions are deterministic synthetic fixtures, not paid inference or graphical acceptance.',
                'SQL statement bytes exclude bound parameters and protocol framing; operation 8 analyzes prior operation 7 evidence.',
                'Provider latency, actual tool latency, human waiting, browser rendering and actual reported provider cost are unavailable.',
                'This benchmark is not an endurance run or bounded live discovery acceptance.']}
    except BaseException as exc:
        output.mkdir(parents=True, exist_ok=True)
        partial = {'schema': 'aria.reliability.twelve.v1', 'synthetic': True,
                   'benchmark_passed': False, 'session_id': sid, 'objective': OBJECTIVE,
                   'expected_operations': 12, 'operations': operations, 'counters': counters,
                   'error_type': type(exc).__name__,
                   'limitation': 'Inspect durable SQL events for any outcome not recorded before failure; no automatic replay.'}
        (output / 'partial-workload.json').write_text(json.dumps(partial, indent=2) + '\n')
        raise
    finally:
        stack.close()
        event.remove(engine.sync_engine, 'before_cursor_execute', sql)
        event.remove(engine.sync_engine, 'after_cursor_execute', sql_finished)
