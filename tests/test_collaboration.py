"""P1 multi-specialist collaboration: delegation, concurrency, ordering, supervision and replanning."""
import asyncio
import copy
import uuid
from typing import Any
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pydantic import ValidationError

from agents.result_contract import AgentResult
from memory.investigation_state import InvestigationStateStore
from memory.team_tasks import TeamStore, Transition, digest, materialize, team_store
from orchestrator.collaboration import (CollaborationCoordinator, Delegation, DelegationPlan,
                                        delegations_from_reasoning)
from orchestrator.team_coordinator import TeamCoordinator
from tests.support import OfflineCase

EVIDENCE = {
    'ev-http': 'httpx: http://192.0.2.1:8080/ 200 title Synthetic fixture',
    'ev-path': 'ffuf: /health 200 length 10',
    'ev-port': 'nmap: tcp/8080 open',
    'ev-admin': 'ffuf follow-up: /admin 404, /test 404',
}


def result(*hypotheses, refs):
    return {'agent_result': AgentResult(interpreted_request='Analyse', evidence_references=list(refs),
                                        hypotheses=list(hypotheses), uncertainty=['Unverified']).model_dump()}


def hyp(description, refs, **extra):
    return {'description': description, 'evidence_references': list(refs), **extra}


class ScriptedSpecialist:
    """Analysis-only stand-in for an LLM specialist; records calls and overlap."""

    def __init__(self, harness, role):
        self.harness, self.role = harness, role

    async def process(self, sid, owner, data, skill):
        self.harness.calls.append(self.role)
        self.harness.contexts[self.role] = data.get('research_context', {})
        self.harness.active += 1
        self.harness.max_active = max(self.harness.max_active, self.harness.active)
        try:
            if self.role in self.harness.barrier_roles:
                self.harness.entered.add(self.role)
                if self.harness.entered >= self.harness.barrier_roles:
                    self.harness.overlap.set()
                await asyncio.wait_for(self.harness.overlap.wait(), timeout=2)
            behaviour = self.harness.script[self.role]
            if isinstance(behaviour, Exception):
                raise behaviour
            return behaviour.pop(0) if isinstance(behaviour, list) else behaviour
        finally:
            self.harness.active -= 1


class CollaborationHarness(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.events, self.pending = [], []
        self.session = SimpleNamespace(id='engagement', scope={'targets': ['192.0.2.1']}, metadata_={})

        async def commit():
            self.events.extend(copy.deepcopy(row.metadata_) for row in self.pending)
            self.pending.clear()
        db = SimpleNamespace(add=self.pending.append, commit=AsyncMock(side_effect=commit))
        cm = AsyncMock()
        cm.__aenter__.return_value = db
        self.stack = ExitStack()
        self.stack.enter_context(patch('memory.team_tasks.async_session', return_value=cm))
        self.stack.enter_context(patch('memory.team_tasks.owned_engagement', AsyncMock(return_value=self.session)))
        self.stack.enter_context(patch.object(TeamStore, '_events', AsyncMock(
            side_effect=lambda *args: copy.deepcopy(self.events))))
        for index, (ref, summary) in enumerate(EVIDENCE.items(), 1):
            self.events.append({'collection': 'evidence', 'entity_id': ref, 'sequence': index, 'id': str(uuid.uuid4()),
                                'data': {'id': ref, 'source_kind': 'worker', 'source_id': f'job-{ref}',
                                         'summary': summary, 'owner_id': 'owner', 'session_id': 'engagement',
                                         'hashes': {'content_sha256': digest({'s': summary})}}})
        self.calls, self.contexts, self.entered = [], {}, set()
        self.active = self.max_active = 0
        self.overlap = asyncio.Event()
        self.barrier_roles: set = set()
        self.script: dict = {}
        self.stack.enter_context(patch.object(TeamCoordinator, 'specialists', lambda _self: {
            role: ScriptedSpecialist(self, role) for role in ('recon', 'scan', 'vuln', 'web_intel', 'correlation', 'report')}))

    async def asyncTearDown(self):
        self.stack.close()
        await super().asyncTearDown()

    def coordinator(self):
        # A fresh instance models a process restart: all state comes from the ledger.
        return CollaborationCoordinator(TeamCoordinator(), InvestigationStateStore())

    def plan_body(self, **changes):
        delegations = [
            Delegation(key='analysis-web', role='web_intel', objective='Interpret the HTTP responses.',
                       evidence_inputs=['ev-http', 'ev-path'], completion_criteria=['Cite evidence']),
            Delegation(key='analysis-vuln', role='vuln', objective='Assess service exposure.',
                       evidence_inputs=['ev-http', 'ev-port'], completion_criteria=['Cite evidence']),
            Delegation(key='cross-review', role='correlation', objective='Challenge both analyses.',
                       prerequisites=['analysis-web', 'analysis-vuln'],
                       evidence_inputs=['ev-http', 'ev-path', 'ev-port', 'ev-admin'],
                       completion_criteria=['Each claim supported, rejected or inconclusive']),
        ]
        return DelegationPlan(**{'request_id': uuid.UUID(int=1), 'objective': 'Interpret retained lab evidence.',
                                 'delegations': delegations, **changes})

    async def complete(self, plan, *keys):
        view = await team_store.view('engagement', 'owner')
        tasks = {t['id']: t for t in view['tasks']}
        for key in keys:
            task = tasks[plan['task_ids'][key]]
            await team_store.transition('engagement', 'owner', task['id'], Transition(
                request_id=uuid.uuid4(), expected_revision=task['revision'], state='completed',
                reason='Owner reviewed the specialist result'))

    def standard_script(self):
        self.script = {
            'web_intel': result(
                hyp('The /health path may disclose internal service status details.', ['ev-path'],
                    alternative_explanations=['Generic liveness probe']),
                hyp('The application may expose an /admin path.', ['ev-http'],
                    alternative_explanations=['No admin path']),
                hyp('The server is confirmed vulnerable to remote code execution.', ['ev-http']),
                refs=['ev-http', 'ev-path']),
            'vuln': result(
                hyp('An /admin path may be exposed by the application.', ['ev-http', 'ev-port'],
                    alternative_explanations=['Static site']),
                refs=['ev-http', 'ev-port']),
            'correlation': [result(
                hyp('The application may expose an /admin path.', ['ev-admin'], disposition='rejected'),
                hyp('The /health path may disclose internal service status details.', ['ev-path'],
                    disposition='inconclusive', alternative_explanations=['Fixed OK string']),
                refs=['ev-admin', 'ev-path']), result(
                hyp('The admin path claim remains unsupported after the 404 follow-up.', ['ev-admin'],
                    disposition='inconclusive', alternative_explanations=['Path exists elsewhere']),
                refs=['ev-admin', 'ev-http'])],
        }


class CollaborationTests(CollaborationHarness):
    async def test_plan_validation_rejects_cycles_duplicates_and_unknown_prerequisites(self):
        base: dict[str, Any] = dict(role='vuln', objective='Assess', evidence_inputs=['ev-http'], completion_criteria=['x'])
        for delegations in (
                [Delegation(key='a', prerequisites=['b'], **base), Delegation(key='b', prerequisites=['a'], **{**base, 'objective': 'Other'})],
                [Delegation(key='a', **base), Delegation(key='b', **base)],
                [Delegation(key='a', prerequisites=['missing'], **base)]):
            with self.subTest(delegations=[d.key for d in delegations]), self.assertRaises(ValidationError):
                DelegationPlan(request_id=uuid.uuid4(), objective='x', delegations=delegations)

    async def test_concurrent_analyses_dependency_order_supervision_and_replanning(self):
        self.standard_script()
        self.barrier_roles = {'web_intel', 'vuln'}
        coordinator = self.coordinator()
        plan = await coordinator.create_plan('engagement', 'owner', self.plan_body())
        first = await coordinator.advance('engagement', 'owner', plan['id'])
        # Two independent analyses were inside their specialists at the same time.
        self.assertTrue(self.overlap.is_set())
        self.assertEqual(self.max_active, 2)
        self.assertCountEqual(self.calls, ['web_intel', 'vuln'])
        # The dependent review waits for owner completion of both prerequisites.
        self.assertEqual(first['states']['cross-review'], 'queued')
        await self.complete(first['plan'], 'analysis-web')
        await coordinator.advance('engagement', 'owner', plan['id'])
        self.assertNotIn('correlation', self.calls)
        await self.complete(first['plan'], 'analysis-vuln')
        second = await coordinator.advance('engagement', 'owner', plan['id'])
        self.assertEqual(self.calls[2], 'correlation')
        supervision = second['plan']['supervision']
        # Unsupported conclusion rejected by the P0 supervisor.
        self.assertTrue(any('unsupported_conclusion' in u['challenges'] for u in supervision['unsupported_claims']))
        # The same admin-path claim from two specialists is one conclusion, not two.
        self.assertTrue(any(set(d['delegations']) == {'analysis-web', 'analysis-vuln'}
                            for d in supervision['duplicated_conclusions']))
        # The reviewer's contradiction is attributed and triggers a targeted challenge.
        contradiction = next(c for c in supervision['contradictions'] if 'challenged_by' in c)
        self.assertEqual(contradiction['challenged_by'], 'cross-review')
        self.assertIn('analysis-web', contradiction['originated_by'])
        challenge = [r for r in second['plan']['replans'] if r['event'] == 'contradiction_challenge']
        self.assertEqual(len(challenge), 1)
        # Shared evidence provenance: every task cites cataloged ledger evidence.
        view = await team_store.view('engagement', 'owner')
        catalog = {e['id'] for e in view['evidence']}
        for task in view['tasks']:
            if task.get('result'):
                self.assertLessEqual(set(task['result']['evidence_references']), catalog)
        # Reasoning reached the reviewer as task-scoped context.
        self.assertIn('investigation_reasoning', self.contexts['correlation'])

    async def test_retry_and_restart_never_duplicate_specialist_calls(self):
        self.standard_script()
        coordinator = self.coordinator()
        plan = await coordinator.create_plan('engagement', 'owner', self.plan_body())
        again = await coordinator.create_plan('engagement', 'owner', self.plan_body())
        self.assertEqual(again['id'], plan['id'])
        first = await coordinator.advance('engagement', 'owner', plan['id'])
        calls = list(self.calls)
        # Delivery retry of an already-collected run returns the claim without a model call.
        run = first['plan']['runs']['analysis-web'][0]
        retried = await TeamCoordinator().run('engagement', 'owner', first['plan']['task_ids']['analysis-web'],
                                              run['run_id'], 'intermediate')
        self.assertTrue(retried['duplicate'])
        # Restart: a new coordinator rebuilds plan, tasks and reasoning from the ledger.
        restarted = await self.coordinator().advance('engagement', 'owner', plan['id'])
        self.assertEqual(self.calls, calls)
        self.assertEqual(restarted['plan']['interpretations'].keys(), first['plan']['interpretations'].keys())
        state = materialize(self.events)
        self.assertIn(plan['id'], state['orchestration_plans'])
        self.assertGreaterEqual(state['investigation_reasoning']['current']['state']['cycle'], 2)

    async def test_failed_specialist_is_replaced_and_dependents_rewired(self):
        self.standard_script()
        self.script['vuln'] = RuntimeError('provider unavailable')
        coordinator = self.coordinator()
        plan = await coordinator.create_plan('engagement', 'owner', self.plan_body())
        self.script_after_failure = result(hyp('Port 8080 may host the same application.', ['ev-port'],
                                               alternative_explanations=['Proxy']), refs=['ev-port'])
        outcome = await coordinator.advance('engagement', 'owner', plan['id'], max_rounds=1)
        self.assertEqual(outcome['states']['analysis-vuln'], 'failed')
        self.script['vuln'] = self.script_after_failure
        outcome = await coordinator.advance('engagement', 'owner', plan['id'])
        replan = next(r for r in outcome['plan']['replans'] if r['event'] == 'specialist_failed')
        self.assertEqual(replan['replacement'], 'analysis-vuln~r1')
        self.assertEqual(replan['rewired'], [{'from': 'cross-review', 'to': 'cross-review~r1'}])
        self.assertEqual(outcome['states']['cross-review'], 'cancelled')
        self.assertEqual(outcome['states']['analysis-vuln~r1'], 'awaiting_review')
        self.assertEqual(self.calls.count('vuln'), 2)
        delegations = {d['key']: d for d in outcome['plan']['delegations']}
        self.assertEqual(delegations['cross-review~r1']['prerequisites'], ['analysis-web', 'analysis-vuln~r1'])

    async def test_duplicate_work_reuses_existing_task(self):
        self.standard_script()
        coordinator = self.coordinator()
        await coordinator.create_plan('engagement', 'owner', self.plan_body())
        second = await coordinator.create_plan('engagement', 'owner', self.plan_body(request_id=uuid.UUID(int=2)))
        # Identical analyses and an identical review over the same reused prerequisites.
        self.assertEqual(sorted(second['reused_work']), ['analysis-vuln', 'analysis-web', 'cross-review'])
        changed = self.plan_body(request_id=uuid.UUID(int=3))
        changed.delegations[0] = changed.delegations[0].model_copy(update={'objective': 'Different HTTP question.'})
        third = await coordinator.create_plan('engagement', 'owner', changed)
        # The review now depends on a different analysis, so it is new work.
        self.assertEqual(sorted(third['reused_work']), ['analysis-vuln'])

    async def test_delegations_from_reasoning_focus_and_depend(self):
        from orchestrator.reasoning import CycleInput, ProposedHypothesis, run_cycle
        state, _ = run_cycle(None, CycleInput(
            evidence=[{'job_id': 'ev-http', 'output': [{'kind': 'http', 'locator': 'u', 'summary': '200'}]}],
            interpretations=[], available_follow_ups={}, hypotheses=[ProposedHypothesis(
                description='The page may be a default install', evidence_job_ids=['ev-http'],
                alternative_explanations=['Custom app'])]))
        delegations = delegations_from_reasoning(state, {'web_intel': ['ev-http'], 'vuln': ['ev-port']}, 'Assess.')
        self.assertEqual([d.key for d in delegations], ['analysis-web_intel', 'analysis-vuln', 'cross-review'])
        self.assertEqual(len(delegations[0].focus_hypotheses), 1)
        self.assertEqual(delegations[2].prerequisites, ['analysis-web_intel', 'analysis-vuln'])

    async def test_unknown_evidence_is_rejected(self):
        body = self.plan_body(delegations=[Delegation(key='a', role='vuln', objective='x',
                                                      evidence_inputs=['ev-missing'], completion_criteria=['x'])])
        with self.assertRaises(HTTPException) as denied:
            await self.coordinator().create_plan('engagement', 'owner', body)
        self.assertEqual(denied.exception.status_code, 422)


class CollaborationEvaluation(OfflineCase):
    async def test_collaborative_arm_catches_shared_first_pass_errors(self):
        from evaluation.collaboration_eval import evaluate
        result = (await evaluate())['arms']
        self.assertEqual(result['single_raw']['quality']['false_claims_accepted'], '2/2')
        self.assertEqual(result['collaborative']['quality']['false_claims_accepted'], '0/2')
        self.assertEqual(result['collaborative']['quality']['true_claims_retained'], '2/2')
        self.assertGreater(result['collaborative']['cost']['max_pairwise_overlap_seconds'], 0.2)
        self.assertEqual(result['collaborative']['cost']['specialist_calls'], 4)
