"""Evidence-driven multi-specialist collaboration over the team ledger (P1).

A plan is a persisted set of structured delegations: objective, prerequisites,
evidence references, completion criteria and resource limits per specialist.
``advance`` repeatedly:

1. interprets newly collected specialist results through the P0 reasoning
   kernel, so the shared reasoning state merges duplicate claims across
   specialists, links competing explanations and rejects unsupported ones;
2. runs a supervisory review for contradictions, duplicated work and
   unsupported claims;
3. replans when a specialist fails or new evidence contests a hypothesis;
4. dispatches every ready task concurrently (bounded), through the existing
   ``TeamCoordinator.run`` path, whose idempotent claim guarantees a retried or
   recovered dispatch never calls a specialist twice for the same run.

Dependent tasks run only after their prerequisites are ``completed`` by owner
review, preserving the existing ledger gate. Nothing here dispatches tools;
specialists remain analysis-only and every conclusion stays unverified.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import HTTPException
from pydantic import Field, model_validator

from memory.team_tasks import (CreateTask, Criterion, Reference, Role, Strict, TaskBudget, TaskSpec,
                               Transition, digest, team_store)
from orchestrator.reasoning import CycleInput, ProposedHypothesis, Retraction, claim_key

COLLECTION = 'orchestration_plans'
Key = Annotated[str, Field(pattern=r'^[a-z0-9][a-z0-9._~-]{0,63}$')]
TERMINAL_FAILURE = {'failed', 'blocked'}
# Denials that an identical replacement cannot overcome: they need an owner decision.
DETERMINISTIC_DENIALS = {'task_model_budget_exhausted', 'model_budget_exhausted', 'model_budget_denied',
                         'model_provider_sharing_denied', 'profile_denied', 'capability_blocked',
                         'all_exhausted', 'no_keys'}
MAX_REPLANS = 1
MAX_DELEGATIONS = 24


class Delegation(Strict):
    key: Key
    role: Role
    objective: str = Field(min_length=1, max_length=2000)
    prerequisites: list[Key] = Field(default_factory=list, max_length=12)
    evidence_inputs: list[Reference] = Field(min_length=1, max_length=50)
    completion_criteria: list[Criterion] = Field(min_length=1, max_length=10)
    expected_output: str = Field(default='Evidence-linked unverified hypotheses with alternatives', max_length=500)
    # Sized for real specialist prompts: each call reserves prompt bytes plus an 8192-token output allowance.
    budget: TaskBudget = Field(default_factory=lambda: TaskBudget(max_attempts=1, max_model_calls=2, max_tokens=60000))
    focus_hypotheses: list[str] = Field(default_factory=list, max_length=10)


class DelegationPlan(Strict):
    request_id: uuid.UUID
    objective: str = Field(min_length=1, max_length=2000)
    delegations: list[Delegation] = Field(min_length=1, max_length=12)
    max_concurrency: int = Field(default=2, ge=1, le=4)

    @model_validator(mode='after')
    def acyclic(self):
        topological_order(self.delegations)
        return self


def work_key(role: str, objective: str, evidence: list[str]) -> str:
    """Identity of a unit of analysis; equal keys are duplicated work."""
    return digest({'role': role, 'objective': claim_key(objective), 'evidence': sorted(set(evidence))})[:24]


def topological_order(delegations: list[Delegation]) -> list[str]:
    keys = [d.key for d in delegations]
    if len(set(keys)) != len(keys):
        raise ValueError('Delegation keys must be unique')
    by_key = {d.key: d for d in delegations}
    works = [work_key(d.role, d.objective, d.evidence_inputs) for d in delegations]
    if len(set(works)) != len(works):
        raise ValueError('Plan contains duplicated work (same role, objective and evidence)')
    for d in delegations:
        if set(d.prerequisites) - set(by_key) or d.key in d.prerequisites:
            raise ValueError(f'Delegation {d.key} has an unknown prerequisite')
    order: list[str] = []
    marks: dict[str, int] = {}

    def visit(key: str) -> None:
        if marks.get(key) == 2:
            return
        if marks.get(key) == 1:
            raise ValueError('Delegation prerequisites form a cycle')
        marks[key] = 1
        for dep in by_key[key].prerequisites:
            visit(dep)
        marks[key] = 2
        order.append(key)
    for key in keys:
        visit(key)
    return order


def delegations_from_reasoning(reasoning: dict[str, Any] | None, groups: dict[str, list[str]],
                               objective: str) -> list[Delegation]:
    """Independent analysis per evidence group, then one dependent cross-review.

    Focus hypotheses come from the P0 reasoning state, so each specialist sees
    the live claims that rest on its evidence and the reviewer sees the
    contested or competing ones.
    """
    live = [h for h in (reasoning or {}).get('hypotheses', {}).values() if h['status'] in {'active', 'contested'}]
    delegations: list[Delegation] = []
    all_evidence: list[str] = []
    for role, refs in groups.items():
        focus = [h['id'] for h in live if set(refs) & set(h['support'])][:10]
        all_evidence += refs
        delegations.append(Delegation(
            key=f'analysis-{role}', role=role,  # type: ignore[arg-type]
            objective=f'{objective} Analyse only the assigned evidence as the {role} specialist.',
            evidence_inputs=refs, focus_hypotheses=focus,
            completion_criteria=['Every hypothesis cites assigned evidence',
                                 'Alternative explanations and missing controls are stated']))
    contested = [h['id'] for h in live if h['status'] == 'contested' or h['competes_with']][:10]
    delegations.append(Delegation(
        key='cross-review', role='correlation', prerequisites=[d.key for d in delegations],
        objective=(f'{objective} Challenge the specialists\' conclusions against the same evidence; mark '
                   'unsupported or contradicted claims rejected.'),
        evidence_inputs=list(dict.fromkeys(all_evidence))[:50], focus_hypotheses=contested,
        completion_criteria=['Each prior claim is supported, rejected or inconclusive with evidence']))
    return delegations


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CollaborationCoordinator:
    def __init__(self, coordinator=None, reasoning_store=None) -> None:
        from memory.investigation_state import investigation_state
        from orchestrator.team_coordinator import team_coordinator
        self.coordinator = coordinator or team_coordinator
        self.reasoning = reasoning_store or investigation_state
        self.clock = time.monotonic

    # ── plan persistence ──────────────────────────────────────────────────

    async def _save(self, sid: str, owner: str, plan: dict[str, Any], expected_revision: int) -> dict[str, Any]:
        content = {k: v for k, v in plan.items() if k != 'revision'}
        request_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan:{plan["id"]}:{digest(content)}'))

        async def build(db, session, state):
            current = state[COLLECTION].get(plan['id'])
            if (current or {}).get('revision', 0) != expected_revision:
                raise HTTPException(409, 'Collaboration plan changed; reload before advancing')
            return COLLECTION, plan['id'], {**plan, 'revision': expected_revision + 1, 'updated_at': _now()}
        event = await team_store.mutate(sid, owner, request_id, {'plan': plan['id'], 'digest': digest(content)}, build)
        return event['data']

    async def _create_task(self, sid: str, owner: str, plan_id: str, delegation: Delegation,
                           task_ids: dict[str, str], existing: dict[str, dict[str, Any]]) -> tuple[str, bool]:
        """Create (or reuse an equivalent live task for) one delegation; idempotent."""
        work = work_key(delegation.role, delegation.objective, delegation.evidence_inputs)
        dependencies = [task_ids[k] for k in delegation.prerequisites]
        for task in existing.values():
            # Reuse only work another plan has already started or finished: a queued task of
            # another plan would never be dispatched by this one.
            if (task.get('collaboration_work') == work and task['dependencies'] == dependencies
                    and task['state'] in {'running', 'awaiting_review', 'completed', 'analyzed'}
                    and task.get('collaboration_plan') != plan_id):
                return task['id'], True
        request_id = uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan-task:{plan_id}:{delegation.key}')
        spec = TaskSpec(owner_role=delegation.role, objective=delegation.objective,
                        dependencies=dependencies,
                        evidence_inputs=delegation.evidence_inputs, budget=delegation.budget,
                        expected_output=delegation.expected_output,
                        completion_criteria=delegation.completion_criteria)
        # Plan metadata rides the existing internal-metadata channel of the ledger.
        event = await team_store._create(sid, owner, CreateTask(request_id=request_id, task=spec), {
            'collaboration_plan': plan_id, 'collaboration_key': delegation.key, 'collaboration_work': work,
            'focus_hypotheses': delegation.focus_hypotheses})
        return event['entity_id'], False

    async def create_plan(self, sid: str, owner: str, body: DelegationPlan) -> dict[str, Any]:
        plan_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan:{sid}:{body.request_id}'))
        view = await team_store.view(sid, owner)
        existing_plan = next((p for p in view.get(COLLECTION, []) if p['id'] == plan_id), None)
        if existing_plan:
            if existing_plan['request_digest'] != digest(body.model_dump(mode='json')):
                raise HTTPException(409, 'Plan request ID already bound to a different plan')
            return existing_plan
        evidence = {e['id'] for e in view['evidence']}
        if any(set(d.evidence_inputs) - evidence for d in body.delegations):
            raise HTTPException(422, 'Delegation evidence must be cataloged in this engagement')
        tasks = {t['id']: t for t in view['tasks']}
        task_ids: dict[str, str] = {}
        reused: list[str] = []
        by_key = {d.key: d for d in body.delegations}
        for key in topological_order(body.delegations):
            task_ids[key], was_reused = await self._create_task(sid, owner, plan_id, by_key[key], task_ids, tasks)
            if was_reused:
                reused.append(key)
        plan = {'id': plan_id, 'objective': body.objective, 'request_digest': digest(body.model_dump(mode='json')),
                'max_concurrency': body.max_concurrency, 'status': 'active', 'created_at': _now(),
                'delegations': [d.model_dump(mode='json') for d in body.delegations], 'task_ids': task_ids,
                'reused_work': reused, 'interpretations': {}, 'runs': {}, 'replans': [], 'supervision': {},
                'verification': 'unverified collaboration plan; no execution authority'}
        return await self._save(sid, owner, plan, 0)

    # ── interpretation through the P0 kernel ──────────────────────────────

    @staticmethod
    def _cycle_input(task: dict[str, Any], evidence_index: dict[str, dict[str, Any]],
                     reasoning_state: dict[str, Any] | None) -> tuple[CycleInput, list[dict[str, Any]]]:
        """Translate a collected result into one reasoning cycle.

        Reviewer dispositions bind to prior claims only through a stable
        ``claim_id`` that names a live hypothesis resting on this task's
        evidence. A rejection without such an identity is reported as
        unattributed instead of being guessed from wording.
        """
        result = task.get('result') or {}
        task_refs = set(task['evidence_inputs'])
        evidence = [{'job_id': ref, 'output': [{
            'kind': str(evidence_index[ref].get('source_kind', 'evidence')),
            'locator': str(evidence_index[ref].get('source_id', ref)),
            'summary': str(evidence_index[ref].get('summary') or evidence_index[ref].get('digest')
                           or (evidence_index[ref].get('hashes') or {}).get('content_sha256', ''))[:300]}]}
            for ref in task['evidence_inputs'] if ref in evidence_index]
        proposals: list[ProposedHypothesis] = []
        retractions: list[Retraction] = []
        unattributed: list[dict[str, Any]] = []
        eligible = {hid for hid, h in ((reasoning_state or {}).get('hypotheses') or {}).items()
                    if h['status'] in {'active', 'contested'} and task_refs & set(h['support'] + h['contradict'])}
        for hyp in result.get('hypotheses', [])[:6]:
            text = str(hyp.get('description', ''))[:300]
            refs = [r for r in hyp.get('evidence_references', []) if isinstance(r, str)]
            claim_id = hyp.get('claim_id') if hyp.get('claim_id') in eligible else None
            if not text:
                continue
            if hyp.get('disposition') == 'rejected':
                if claim_id and refs:
                    retractions.append(Retraction(prior_hypothesis_id=claim_id,
                                                  reason=f'{task["owner_role"]} specialist rejected: {text[:180]}',
                                                  evidence_job_ids=refs))
                else:
                    unattributed.append({'claim': text, 'claim_id': hyp.get('claim_id'),
                                         'reason': 'unknown_claim_id' if hyp.get('claim_id') else 'missing_claim_id'})
                continue
            uncertainty = hyp.get('uncertainty')
            alternatives = [str(a)[:200] for a in hyp.get('alternative_explanations', []) if a][:3]
            if not alternatives and isinstance(uncertainty, str) and uncertainty:
                alternatives = [uncertainty[:200]]
            proposals.append(ProposedHypothesis(
                description=text, evidence_job_ids=refs, alternative_explanations=alternatives,
                confidence=0.35 if hyp.get('disposition') == 'supported' else 0.25,
                missing_information=[str(p)[:200] for p in hyp.get('prerequisites', []) if p][:2],
                prior_hypothesis_id=claim_id or 'none'))
        return CycleInput(evidence=evidence, interpretations=[], hypotheses=proposals,
                          available_follow_ups={}, retractions=retractions,
                          run_id=str(task.get('run_id', ''))), unattributed

    async def _interpret(self, sid: str, owner: str, plan: dict[str, Any], view: dict[str, Any]) -> list[str]:
        evidence_index = {e['id']: e for e in view['evidence']}
        tasks = {t['id']: t for t in view['tasks']}
        interpreted = []
        for key, task_id in plan['task_ids'].items():
            task = tasks.get(task_id)
            if not task or task['state'] not in {'awaiting_review', 'completed'} or not task.get('result'):
                continue
            seen = plan['interpretations'].get(key)
            if seen and seen.get('run_id') == task.get('run_id'):
                continue
            prior = await self.reasoning.current(sid, owner)
            cycle, unattributed = self._cycle_input(task, evidence_index, prior.get('state'))
            _, report = await self.reasoning.advance(
                sid, owner, f'task:{task_id}:{task.get("run_id")}', cycle)
            plan['interpretations'][key] = {
                'task_id': task_id, 'run_id': task.get('run_id'), 'role': task['owner_role'],
                'hypotheses': report['hypothesize']['proposal_ids'],
                'rejected': report['hypothesize']['rejected'], 'retracted': report['hypothesize']['retracted'],
                'merged': report['hypothesize']['merged'], 'contested': report['contradictions']['contested'],
                'decision_revised': bool(report['decision']['revised']),
                'unattributed_rejections': unattributed}
            interpreted.append(key)
        return interpreted

    # ── supervision ───────────────────────────────────────────────────────

    @staticmethod
    def supervise(plan: dict[str, Any], reasoning_state: dict[str, Any] | None) -> dict[str, Any]:
        hyps = (reasoning_state or {}).get('hypotheses', {})
        origin: dict[str, set[str]] = {}
        for key, item in plan['interpretations'].items():
            for hid in item['hypotheses']:
                if hid:
                    origin.setdefault(hid, set()).add(key)
        unsupported = [{'delegation': key, 'claim': r['claim'], 'challenges': r['challenges']}
                       for key, item in plan['interpretations'].items() for r in item['rejected']]
        duplicated = [{'hypothesis': hid, 'delegations': sorted(keys), 'claim': hyps.get(hid, {}).get('claim', '')}
                      for hid, keys in origin.items() if len(keys) > 1]
        contradictions = []
        for key, item in plan['interpretations'].items():
            for hid in item['retracted']:
                contradictions.append({'hypothesis': hid, 'challenged_by': key,
                                       'originated_by': sorted(origin.get(hid, set()) - {key}),
                                       'status': hyps.get(hid, {}).get('status')})
        seen_pairs = set()
        for hid, hyp in hyps.items():
            for other in hyp.get('competes_with', []):
                pair = tuple(sorted((hid, other)))
                if pair in seen_pairs or not origin.get(hid) or not origin.get(other):
                    continue
                if origin[hid] != origin[other]:
                    seen_pairs.add(pair)
                    contradictions.append({'competing': list(pair),
                                           'delegations': sorted(origin[hid] | origin[other])})
        unattributed = [{'delegation': key, **u} for key, item in plan['interpretations'].items()
                        for u in item.get('unattributed_rejections', [])]
        return {'unsupported_claims': unsupported, 'duplicated_conclusions': duplicated,
                'unattributed_rejections': unattributed,
                'avoided_specialist_calls': len(plan.get('avoided_calls', [])),
                'duplicated_work_reused': list(plan.get('reused_work', [])),
                'contradictions': contradictions,
                'accepted_hypotheses': sorted(h for h in origin if hyps.get(h, {}).get('status') in {'active', 'contested'}),
                'verification': 'supervisory review of unverified analysis'}

    # ── adaptive replanning ───────────────────────────────────────────────

    async def _replan(self, sid: str, owner: str, plan: dict[str, Any], view: dict[str, Any],
                      reasoning_state: dict[str, Any] | None) -> list[dict[str, Any]]:
        tasks = {t['id']: t for t in view['tasks']}
        delegations = {d['key']: Delegation.model_validate(d) for d in plan['delegations']}
        changes: list[dict[str, Any]] = []
        replanned = {r['replaces'] for r in plan['replans'] if r.get('replaces')}
        # 1. A failed specialist is replaced once, unless the failure is a deterministic
        #    policy or budget denial (an identical replacement would fail the same way).
        #    All failures of this round are replaced first; each queued dependent is then
        #    re-pointed exactly once to every replacement it needs.
        replacements: dict[str, str] = {}
        for key, task_id in list(plan['task_ids'].items()):
            task = tasks.get(task_id)
            if not task or task['state'] not in TERMINAL_FAILURE or key in replanned:
                continue
            denial = sorted({r.get('code') for r in ((task.get('result') or {}).get('rejections') or [])}
                            & DETERMINISTIC_DENIALS)
            generation = key.count('~r') + 1
            if denial or generation > MAX_REPLANS:
                plan['status'] = 'blocked'
                event = 'blocked_by_denial' if denial else 'replan_exhausted'
                changes.append({'event': event, 'delegation': key, 'reason': task.get('reason'), 'denials': denial,
                                'replaces': key})
                plan['replans'].append(changes[-1])
                replanned.add(key)
                continue
            original = delegations[key]
            replacement = original.model_copy(update={'key': f'{key.split("~r")[0]}~r{generation}'})
            plan['task_ids'][replacement.key], _ = await self._create_task(
                sid, owner, plan['id'], replacement, plan['task_ids'], tasks)
            delegations[replacement.key] = replacement
            plan['delegations'].append(replacement.model_dump(mode='json'))
            replacements[key] = replacement.key
            changes.append({'event': 'specialist_failed', 'replaces': key, 'replacement': replacement.key,
                            'reason': task.get('reason'), 'rewired': []})
            plan['replans'].append(changes[-1])
            replanned.add(key)
        for dep_key, dep in list(delegations.items()):
            failed = [p for p in dep.prerequisites if p in replacements]
            dep_task = tasks.get(plan['task_ids'].get(dep_key, ''))
            if not failed or not dep_task or dep_task['state'] != 'queued':
                continue
            await team_store.transition(sid, owner, dep_task['id'], Transition(
                request_id=uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan-cancel:{plan["id"]}:{dep_key}'),
                expected_revision=dep_task['revision'], state='cancelled',
                reason=f'Replanned: prerequisites {", ".join(failed)} failed and were replaced'))
            generation = max(replacements[p].count('~r') for p in failed)
            new_dep = dep.model_copy(update={
                'key': f'{dep_key.split("~r")[0]}~r{generation}',
                'prerequisites': [replacements.get(p, p) for p in dep.prerequisites]})
            plan['task_ids'][new_dep.key], _ = await self._create_task(
                sid, owner, plan['id'], new_dep, plan['task_ids'], tasks)
            delegations[new_dep.key] = new_dep
            plan['delegations'].append(new_dep.model_dump(mode='json'))
            replanned.add(dep_key)
            for change in changes:
                if change.get('replaces') in failed and change['event'] == 'specialist_failed':
                    change['rewired'].append({'from': dep_key, 'to': new_dep.key})
        # 2. Contested hypotheses get one targeted challenge; work focused only on
        #    rejected hypotheses is cancelled before it wastes a model call.
        hyps = (reasoning_state or {}).get('hypotheses', {})
        challenged = {r.get('hypothesis') for r in plan['replans']
                      if r.get('event') in {'contradiction_challenge', 'challenge_skipped'}}
        evidence = {e['id'] for e in view['evidence']}
        for hid, hyp in hyps.items():
            if hyp['status'] != 'contested' or hid in challenged:
                continue
            if not any(hid in item['hypotheses'] for item in plan['interpretations'].values()):
                continue
            observations = (reasoning_state or {}).get('observations', {})
            superseding = [observations[o['superseded_by']]['evidence_ref'] for o in observations.values()
                           if o.get('superseded') and o['evidence_ref'] in hyp['support']
                           and o.get('superseded_by') in observations]
            # Changed facts (for example a new tool observation) join the challenge evidence.
            refs = [r for r in dict.fromkeys(hyp['support'] + hyp['contradict'] + superseding) if r in evidence][:50]
            if not refs:
                continue
            reviewed_by = [key for key, item in plan['interpretations'].items()
                           if hid in item['retracted'] and item['role'] == 'correlation'
                           and set(refs) <= set(tasks.get(item['task_id'], {}).get('evidence_inputs', []))]
            if reviewed_by:
                # A reviewer already judged this claim over a superset of its evidence;
                # a second review of the same records would add cost, not information.
                changes.append({'event': 'challenge_skipped', 'hypothesis': hid, 'reviewed_by': reviewed_by,
                                'reason': 'reviewer already examined all supporting and contradicting evidence'})
                plan['replans'].append(changes[-1])
                plan.setdefault('avoided_calls', []).append(changes[-1])
                continue
            challenge = Delegation(key=f'challenge-{hid[2:12]}', role='correlation',
                                   objective=f'Re-examine the contested claim against new evidence: {hyp["claim"][:300]}',
                                   evidence_inputs=refs, focus_hypotheses=[hid],
                                   completion_criteria=['State whether the claim is supported, rejected or inconclusive'])
            plan['task_ids'][challenge.key], _ = await self._create_task(
                sid, owner, plan['id'], challenge, plan['task_ids'], tasks)
            plan['delegations'].append(challenge.model_dump(mode='json'))
            changes.append({'event': 'contradiction_challenge', 'hypothesis': hid, 'delegation': challenge.key})
            plan['replans'].append(changes[-1])
        for key, delegation in delegations.items():
            task = tasks.get(plan['task_ids'].get(key, ''))
            if (not task or task['state'] != 'queued' or not delegation.focus_hypotheses
                    or not all(hyps.get(h, {}).get('status') == 'rejected' for h in delegation.focus_hypotheses)):
                continue
            await team_store.transition(sid, owner, task['id'], Transition(
                request_id=uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan-obsolete:{plan["id"]}:{key}'),
                expected_revision=task['revision'], state='cancelled',
                reason='Replanned: every focus hypothesis was rejected by later evidence'))
            changes.append({'event': 'obsolete_cancelled', 'delegation': key})
            plan['replans'].append(changes[-1])
            plan.setdefault('avoided_calls', []).append(changes[-1])
        # 3. A ready review with no live claim on its evidence has nothing to challenge.
        for key, delegation in delegations.items():
            task = tasks.get(plan['task_ids'].get(key, ''))
            if (not task or task['state'] != 'queued' or delegation.role != 'correlation'
                    or not delegation.prerequisites
                    or not all(tasks.get(plan['task_ids'].get(p, ''), {}).get('state') == 'completed'
                               for p in delegation.prerequisites)):
                continue
            refs = set(delegation.evidence_inputs)
            if any(h['status'] in {'active', 'contested'} and refs & set(h['support'] + h['contradict'])
                   for h in hyps.values()):
                continue
            await team_store.transition(sid, owner, task['id'], Transition(
                request_id=uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan-noclaims:{plan["id"]}:{key}'),
                expected_revision=task['revision'], state='cancelled',
                reason='Skipped: prerequisite analyses left no live claim on this evidence to review'))
            changes.append({'event': 'review_skipped', 'delegation': key, 'reason': 'no live claims to review'})
            plan['replans'].append(changes[-1])
            plan.setdefault('avoided_calls', []).append(changes[-1])
        return changes

    # ── scheduling ────────────────────────────────────────────────────────

    def _ready(self, plan: dict[str, Any], tasks: dict[str, dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
        delegations = {d['key']: d for d in plan['delegations']}
        ready = []
        for key, task_id in plan['task_ids'].items():
            task = tasks.get(task_id)
            if not task or task['state'] != 'queued' or task.get('collaboration_plan') != plan['id']:
                continue
            prereqs = [tasks.get(plan['task_ids'].get(p, ''), {}) for p in delegations[key]['prerequisites']]
            if all(p.get('state') == 'completed' for p in prereqs):
                ready.append((key, task))
        return ready

    async def advance(self, sid: str, owner: str, plan_id: str, *, skill: str = 'intermediate',
                      max_rounds: int = 6) -> dict[str, Any]:
        rounds = []
        for _ in range(max_rounds):
            view = await team_store.view(sid, owner)
            plan = next((p for p in view.get(COLLECTION, []) if p['id'] == plan_id), None)
            if plan is None:
                raise HTTPException(404, 'Collaboration plan not found')
            revision = plan['revision']
            plan = {k: v for k, v in plan.items() if k not in {'revision', 'updated_at'}}
            interpreted = await self._interpret(sid, owner, plan, view)
            reasoning_state = (await self.reasoning.current(sid, owner)).get('state')
            if interpreted:
                view = await team_store.view(sid, owner)
            changes = await self._replan(sid, owner, plan, view, reasoning_state)
            if changes:
                view = await team_store.view(sid, owner)
            plan['supervision'] = self.supervise(plan, reasoning_state)
            tasks = {t['id']: t for t in view['tasks']}
            ready = self._ready(plan, tasks)[:plan['max_concurrency']]
            started = self.clock()

            async def dispatch(key: str, task: dict[str, Any]) -> tuple[str, dict[str, Any]]:
                run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-plan-run:{plan_id}:{task["id"]}:{task["attempts"] + 1}'))
                begin = self.clock() - started
                outcome: dict[str, Any] = {'run_id': run_id, 'started_s': round(begin, 4)}
                try:
                    event = await self.coordinator.run(sid, owner, task['id'], run_id, skill)
                    outcome['duplicate'] = bool(event.get('duplicate'))
                    outcome['state'] = (event.get('data') or {}).get('state')
                except HTTPException as error:
                    outcome['error'] = str(error.detail)[:300]
                outcome['finished_s'] = round(self.clock() - started, 4)
                return key, outcome
            results = await asyncio.gather(*(dispatch(k, t) for k, t in ready))
            for key, outcome in results:
                plan['runs'].setdefault(key, []).append(outcome)
            tasks_after = {t['id']: t['state'] for t in (await team_store.view(sid, owner))['tasks']} if results else \
                {t['id']: t['state'] for t in view['tasks']}
            states = {key: tasks_after.get(tid) for key, tid in plan['task_ids'].items()}
            live_states = [s for s in states.values() if s != 'cancelled']
            if plan['status'] != 'blocked':
                plan['status'] = ('complete' if live_states and all(s == 'completed' for s in live_states) else
                                  'awaiting_review' if any(s == 'awaiting_review' for s in live_states) and not results else
                                  'active')
            rounds.append({'interpreted': interpreted, 'replans': changes, 'dispatched': [k for k, _ in results]})
            saved = await self._save(sid, owner, plan, revision)
            if not results and not interpreted and not changes:
                return {'plan': saved, 'states': states, 'rounds': rounds}
        view = await team_store.view(sid, owner)
        saved = next(p for p in view[COLLECTION] if p['id'] == plan_id)
        return {'plan': saved, 'states': {k: next((t['state'] for t in view['tasks'] if t['id'] == v), None)
                                          for k, v in saved['task_ids'].items()}, 'rounds': rounds}


collaboration = CollaborationCoordinator()
