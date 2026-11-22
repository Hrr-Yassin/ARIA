"""P1 collaboration evaluation: collaborative workflow versus single-specialist baselines.

All arms run the real ``CollaborationCoordinator``, ``TeamCoordinator``, team
ledger and P0 reasoning store over an in-memory ledger. Specialists are
scripted (analysis-only, fixed latency) so every arm starts from the same
first-pass errors: an unhedged overclaim and a path claim that later evidence
contradicts. The comparison therefore isolates what orchestration adds —
error detection, deduplication, concurrency and cost — not model intelligence.

Arms:
* ``single_raw``: one specialist over all evidence; results accepted as reported.
* ``single_supervised``: the same single specialist, interpreted by the P0 supervisor.
* ``collaborative``: two concurrent specialists, owner review, dependent
  cross-review, supervision and adaptive replanning.

Run: ``python -m evaluation.collaboration_eval``. No network or provider access.
"""
from __future__ import annotations

import asyncio
import copy
import json
import time
import uuid
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from agents.result_contract import AgentResult

OUT = Path('reports/collaboration-eval')
LATENCY_S = 0.25
EVIDENCE = {
    'ev-http': ('tests/fixtures/security_tools/httpx.json', 'httpx: http://192.0.2.1:8080/ 200 title Synthetic fixture'),
    'ev-path': ('tests/fixtures/security_tools/ffuf.json', 'ffuf: /health 200 length 10'),
    'ev-port': ('tests/fixtures/security_tools/nmap.json', 'nmap: tcp/8080 open'),
    'ev-admin': ('labelled synthetic bounded follow-up outcome', 'ffuf follow-up: /admin 404, /test 404'),
}
# Ground truth for the scenario (author labels).
TRUE_CLAIMS = ['The /health path may disclose internal service status details.',
               'Port 8080 may host the same web application as the HTTP root.']
FALSE_CLAIMS = ['The server is confirmed vulnerable to remote code execution.',   # unsupported conclusion
                'The application may expose an /admin path.']                     # contradicted by ev-admin


def _result(hypotheses: list[dict[str, Any]], refs: list[str]) -> dict[str, Any]:
    return {'agent_result': AgentResult(interpreted_request='Analyse', evidence_references=refs,
                                        hypotheses=hypotheses, uncertainty=['Unverified']).model_dump()}


def _h(text: str, refs: list[str], **extra) -> dict[str, Any]:
    return {'description': text, 'evidence_references': refs, **extra}


WEB = _result([_h(TRUE_CLAIMS[0], ['ev-path'], alternative_explanations=['Generic liveness probe']),
               _h(FALSE_CLAIMS[1], ['ev-http'], alternative_explanations=['No admin path']),
               _h(FALSE_CLAIMS[0], ['ev-http'])], ['ev-http', 'ev-path'])
VULN = _result([_h('An /admin path may be exposed by the application.', ['ev-http', 'ev-port'],
                   alternative_explanations=['Static site']),
                _h(TRUE_CLAIMS[1], ['ev-port', 'ev-http'], alternative_explanations=['Separate proxy'])],
               ['ev-http', 'ev-port'])
REVIEW = _result([_h('The /admin path returned 404 in the bounded follow-up.', ['ev-admin'],
                     disposition='rejected', claim_of=FALSE_CLAIMS[1]),
                  _h(TRUE_CLAIMS[0], ['ev-path'], disposition='inconclusive', claim_of=TRUE_CLAIMS[0],
                     alternative_explanations=['Fixed OK string'])], ['ev-admin', 'ev-path'])
CHALLENGE = _result([_h('The admin path claim remains unsupported after the 404 follow-up.', ['ev-admin'],
                        disposition='inconclusive', alternative_explanations=['Path exists elsewhere'])],
                    ['ev-admin', 'ev-http'])
# The single specialist sees all evidence and makes the same first-pass errors.
SINGLE = _result([*WEB['agent_result']['hypotheses'], *VULN['agent_result']['hypotheses']],
                 ['ev-http', 'ev-path', 'ev-port', 'ev-admin'])


class Ledger:
    """In-memory team ledger with the production store code paths."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.pending: list[Any] = []
        self.calls: list[dict[str, Any]] = []
        self.stack = ExitStack()

    def __enter__(self) -> 'Ledger':
        from memory.team_tasks import TeamStore, digest
        from orchestrator.team_coordinator import TeamCoordinator
        session = SimpleNamespace(id='engagement', scope={'targets': ['192.0.2.1']}, metadata_={})

        async def commit():
            self.events.extend(copy.deepcopy(row.metadata_) for row in self.pending)
            self.pending.clear()
        db = SimpleNamespace(add=self.pending.append, commit=AsyncMock(side_effect=commit))
        cm = AsyncMock()
        cm.__aenter__.return_value = db
        self.stack.enter_context(patch('memory.team_tasks.async_session', return_value=cm))
        self.stack.enter_context(patch('memory.team_tasks.owned_engagement', AsyncMock(return_value=session)))
        self.stack.enter_context(patch.object(TeamStore, '_events', AsyncMock(
            side_effect=lambda *args: copy.deepcopy(self.events))))
        self.stack.enter_context(patch('memory.research.research_store.view', AsyncMock(
            return_value={'queue': [], 'application_model': {}, 'limitations': []})))
        for index, (ref, (provenance, summary)) in enumerate(EVIDENCE.items(), 1):
            self.events.append({'collection': 'evidence', 'entity_id': ref, 'sequence': index, 'id': str(uuid.uuid4()),
                                'data': {'id': ref, 'source_kind': 'worker', 'source_id': f'job-{ref}',
                                         'provenance': provenance, 'summary': summary, 'owner_id': 'owner',
                                         'session_id': 'engagement', 'hashes': {'content_sha256': digest({'s': summary})}}})
        ledger = self

        class Specialist:
            def __init__(self, role: str, script: dict[str, list[dict[str, Any]]]):
                self.role, self.script = role, script

            async def process(self, sid, owner, data, skill):
                begin = time.perf_counter()
                await asyncio.sleep(LATENCY_S)
                ledger.calls.append({'role': self.role, 'started': begin, 'finished': time.perf_counter(),
                                     'prompt_chars': len(json.dumps(data, default=str))})
                response = copy.deepcopy(self.script[self.role].pop(0))
                # Echo offered stable claim IDs, as the reviewer instruction asks a model to.
                offered = {h['claim']: h['id'] for h in ((data.get('research_context') or {})
                           .get('investigation_reasoning') or {}).get('hypotheses', [])}
                for hyp in response['agent_result']['hypotheses']:
                    target = hyp.pop('claim_of', None)
                    if target in offered:
                        hyp['claim_id'] = offered[target]
                return response
        self.Specialist = Specialist
        self.TeamCoordinator = TeamCoordinator
        return self

    def specialists(self, script: dict[str, list[dict[str, Any]]]):
        return patch.object(self.TeamCoordinator, 'specialists', lambda _self: {
            role: self.Specialist(role, script) for role in ('recon', 'scan', 'vuln', 'web_intel', 'correlation', 'report')})

    def __exit__(self, *exc) -> None:
        self.stack.close()


async def _complete(plan: dict[str, Any], keys: list[str]) -> None:
    from memory.team_tasks import Transition, team_store
    view = await team_store.view('engagement', 'owner')
    tasks = {t['id']: t for t in view['tasks']}
    for key in keys:
        task = tasks[plan['task_ids'][key]]
        if task['state'] == 'awaiting_review':
            await team_store.transition('engagement', 'owner', task['id'], Transition(
                request_id=uuid.uuid4(), expected_revision=task['revision'], state='completed',
                reason='Simulated owner review in a controlled evaluation'))


def _score(accepted: list[str], contradictions: int, duplicates: int) -> dict[str, Any]:
    from orchestrator.reasoning import _similar

    def present(claim: str) -> bool:
        return any(_similar(claim, a) >= 0.8 for a in accepted)
    tp = sum(present(c) for c in TRUE_CLAIMS)
    fp = sum(present(c) for c in FALSE_CLAIMS)
    return {'true_claims_retained': f'{tp}/{len(TRUE_CLAIMS)}', 'false_claims_accepted': f'{fp}/{len(FALSE_CLAIMS)}',
            'precision': round(tp / max(tp + fp, 1), 4), 'contradictions_detected': contradictions,
            'duplicate_conclusions_in_output': duplicates, 'accepted_conclusions': len(accepted)}


def _cost(calls: list[dict[str, Any]], wall: float) -> dict[str, Any]:
    overlap = 0.0
    for i, a in enumerate(calls):
        for b in calls[i + 1:]:
            overlap = max(overlap, min(a['finished'], b['finished']) - max(a['started'], b['started']))
    busy, end = 0.0, float('-inf')
    for start, finish in sorted((c['started'], c['finished']) for c in calls):
        if start > end:
            busy, end = busy + finish - start, finish
        elif finish > end:
            busy, end = busy + finish - end, finish
    return {'specialist_busy_seconds': round(busy, 3),
            'orchestration_overhead_seconds': round(max(wall - busy, 0.0), 3),
            'specialist_calls': len(calls), 'specialist_prompt_chars': sum(c['prompt_chars'] for c in calls),
            'estimated_prompt_tokens': sum(c['prompt_chars'] for c in calls) // 4,
            'wall_seconds': round(wall, 3), 'serial_specialist_seconds': round(len(calls) * LATENCY_S, 3),
            'max_pairwise_overlap_seconds': round(max(overlap, 0.0), 3)}


async def _single(supervised: bool) -> dict[str, Any]:
    from memory.investigation_state import InvestigationStateStore
    from orchestrator.collaboration import CollaborationCoordinator, Delegation, DelegationPlan
    from memory.team_tasks import team_store
    with Ledger() as ledger, ledger.specialists({'vuln': [copy.deepcopy(SINGLE)]}):
        coordinator = CollaborationCoordinator(ledger.TeamCoordinator(), InvestigationStateStore())
        started = time.perf_counter()
        plan = await coordinator.create_plan('engagement', 'owner', DelegationPlan(
            request_id=uuid.UUID(int=10), objective='Interpret retained lab evidence.', delegations=[Delegation(
                key='single', role='vuln', objective='Interpret all retained evidence.',
                evidence_inputs=list(EVIDENCE), completion_criteria=['Cite evidence'])]))
        outcome = await coordinator.advance('engagement', 'owner', plan['id'])
        wall = time.perf_counter() - started
        if supervised:
            sup = outcome['plan']['supervision']
            state = (await coordinator.reasoning.current('engagement', 'owner'))['state']
            accepted = [state['hypotheses'][h]['claim'] for h in sup['accepted_hypotheses']]
            contradictions = len(sup['contradictions'])
        else:
            view = await team_store.view('engagement', 'owner')
            task = next(t for t in view['tasks'] if t['id'] == plan['task_ids']['single'])
            accepted = [h['description'] for h in task['result']['hypotheses']]
            contradictions = 0
        from orchestrator.reasoning import _similar
        duplicates = sum(1 for i, a in enumerate(accepted) for b in accepted[i + 1:] if _similar(a, b) >= 0.8)
        return {'quality': _score(accepted, contradictions, duplicates), 'cost': _cost(ledger.calls, wall),
                'accepted': accepted}


async def _collaborative() -> dict[str, Any]:
    from memory.investigation_state import InvestigationStateStore
    from orchestrator.collaboration import CollaborationCoordinator, Delegation, DelegationPlan
    from orchestrator.reasoning import _similar
    script = {'web_intel': [copy.deepcopy(WEB)], 'vuln': [copy.deepcopy(VULN)],
              'correlation': [copy.deepcopy(REVIEW), copy.deepcopy(CHALLENGE)]}
    with Ledger() as ledger, ledger.specialists(script):
        coordinator = CollaborationCoordinator(ledger.TeamCoordinator(), InvestigationStateStore())
        started = time.perf_counter()
        plan = await coordinator.create_plan('engagement', 'owner', DelegationPlan(
            request_id=uuid.UUID(int=11), objective='Interpret retained lab evidence.', delegations=[
                Delegation(key='analysis-web', role='web_intel', objective='Interpret the HTTP responses.',
                           evidence_inputs=['ev-http', 'ev-path'], completion_criteria=['Cite evidence']),
                Delegation(key='analysis-vuln', role='vuln', objective='Assess service exposure.',
                           evidence_inputs=['ev-http', 'ev-port'], completion_criteria=['Cite evidence']),
                Delegation(key='cross-review', role='correlation', objective='Challenge both analyses.',
                           prerequisites=['analysis-web', 'analysis-vuln'], evidence_inputs=list(EVIDENCE),
                           completion_criteria=['Each claim supported, rejected or inconclusive'])]))
        rounds = 0
        outcome = await coordinator.advance('engagement', 'owner', plan['id'])
        while outcome['plan']['status'] not in {'complete', 'blocked'} and rounds < 6:
            rounds += 1
            await _complete(outcome['plan'], [k for k, s in outcome['states'].items() if s == 'awaiting_review'])
            outcome = await coordinator.advance('engagement', 'owner', plan['id'])
        wall = time.perf_counter() - started
        sup = outcome['plan']['supervision']
        state = (await coordinator.reasoning.current('engagement', 'owner'))['state']
        accepted = [state['hypotheses'][h]['claim'] for h in sup['accepted_hypotheses']
                    if state['hypotheses'][h]['status'] == 'active']
        duplicates = sum(1 for i, a in enumerate(accepted) for b in accepted[i + 1:] if _similar(a, b) >= 0.8)
        return {'quality': {**_score(accepted, len(sup['contradictions']), duplicates),
                            'duplicate_specialist_conclusions_merged': len(sup['duplicated_conclusions']),
                            'unsupported_claims_rejected': len(sup['unsupported_claims']),
                            'replans': [r['event'] for r in outcome['plan']['replans']],
                            'avoided_specialist_calls': sup['avoided_specialist_calls']},
                'cost': _cost(ledger.calls, wall), 'accepted': accepted,
                'owner_review_rounds': rounds, 'final_status': outcome['plan']['status'],
                'note': 'Contested claims are excluded from accepted conclusions; they remain under challenge.'}


async def evaluate() -> dict[str, Any]:
    return {'schema_version': 'aria.collaboration-eval.result.v1', 'specialist_latency_s': LATENCY_S,
            'arms': {'single_raw': await _single(False), 'single_supervised': await _single(True),
                     'collaborative': await _collaborative()},
            'limitations': [
                'Specialists are scripted with fixed latency; this measures orchestration mechanics, not model reasoning.',
                'All arms share the same first-pass errors by construction; the scenario is author-labelled.',
                'Owner review is simulated by completing awaiting_review tasks; in production it is a human gate.',
                'No provider usage: specialist calls and prompt sizes are counted, not billed.']}


def main() -> None:
    result = asyncio.run(evaluate())
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps({arm: {'quality': r['quality'], 'cost': r['cost']} for arm, r in result['arms'].items()}, indent=2))


if __name__ == '__main__':
    main()
