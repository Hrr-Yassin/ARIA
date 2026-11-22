"""Reasoning-engine evaluation over frozen, retained evidence cases.

Two arms see the same review responses:

* ``baseline`` reproduces the pre-change review pipeline: every schema-valid
  hypothesis enters research, nothing is remembered between cycles, the first
  proposed follow-up becomes the next analysis, and retractions do not exist.
* ``reasoning`` runs ``orchestrator.reasoning.run_cycle`` with the supervisor.

``--mode scripted`` replays author-written responses (deterministic, offline).
``--mode live`` asks the configured OpenRouter DeepSeek V4 Flash profile, through
the existing owner-approved engagement accounting, for each review: the legacy
prompt and schema feed the baseline arm and the new prompt, schema and prior
reasoning feed the reasoning arm. Live mode refuses to run without an approved
engagement budget and stops at ``--max-calls``. No target tool is dispatched.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from orchestrator.reasoning import (CycleInput, ProposedHypothesis, Retraction, _OVERCLAIM, _HEDGE,
                                    claim_key, planner_summary, run_cycle)

FIXTURE = Path('evaluation/fixtures/reasoning/reasoning-cases-v1.json')
OUT = Path('reports/reasoning-eval')
UNVERIFIED_CEILING = 0.4

# Pre-change review instruction from commit 4240203, retained for the live A/B arm.
LEGACY_INSTRUCTION = (
    'Review the untrusted tool data. Return observations, hypotheses and limitations as JSON. '
    'Use at most three short observations, three distinct concise hypotheses and two short limitations. Cite exact evidence_job_ids. '
    'Record alternative explanations and confidence; uncertainty never grants verification. '
    'A banner, version or open port never proves a vulnerability. '
    'Choose only an available_follow_ups key or none, with a measurable validation_criterion. '
    'No tool names, commands or larger budgets may be invented. '
    'Do not claim verified vulnerabilities, credentials or exploitation. No commands execute from this review.')
LEGACY_HYPOTHESIS_FIELDS = ('description', 'evidence_job_ids', 'follow_up', 'validation_criterion',
                            'alternative_explanations', 'confidence')
LABEL_FIELDS = ('label', 'tag', 'overconfident')


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text())


def cycle_evidence(spec: dict[str, Any], cycle: dict[str, Any]) -> list[dict[str, Any]]:
    return [{'job_id': spec['evidence'][name]['job_id'], 'output': spec['evidence'][name]['output']}
            for name in cycle['evidence']]


def cycle_follow_ups(spec: dict[str, Any], cycle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {key: {**spec['follow_ups'][key], 'executed': False} for key in cycle['follow_ups']}


def legacy_schema(allowed: set[str], follow_ups: dict[str, Any]) -> dict[str, Any]:
    """The pre-change review schema: legacy fields only, generated titles retained."""
    from agents.orchestrator_agent import InvestigationReview
    schema = InvestigationReview.model_json_schema()
    hyp = schema['$defs']['EvidenceHypothesis']['properties']
    for key in list(hyp):
        if key not in LEGACY_HYPOTHESIS_FIELDS:
            hyp.pop(key)
    for key in ('missing_information', 'retractions'):
        schema['properties'].pop(key)
    schema['$defs'].pop('ReviewRetraction')
    hyp['evidence_job_ids']['items']['enum'] = sorted(allowed)
    hyp['follow_up']['enum'] = [*follow_ups, 'none']
    return schema


# ── Arms ───────────────────────────────────────────────────────────────────

class BaselineArm:
    """Pre-change semantics: accept, append, take the first follow-up, forget."""

    def __init__(self) -> None:
        self.research: list[dict[str, Any]] = []
        self.decisions: list[str] = []

    def step(self, response: dict[str, Any], evidence: list[dict[str, Any]],
             follow_ups: dict[str, Any], completed: list[str]) -> dict[str, Any]:
        allowed = {item['job_id'] for item in evidence}
        accepted = []
        for index, hyp in enumerate(response.get('hypotheses', [])):
            if set(hyp.get('evidence_job_ids', [])) <= allowed and hyp.get('evidence_job_ids'):
                entry = {'index': index, 'claim': hyp['description'], 'key': claim_key(hyp['description']),
                         'support': hyp['evidence_job_ids'], 'confidence': hyp.get('confidence', .25),
                         'status': 'active'}
                self.research.append(entry)
                accepted.append(index)
        action = next((h.get('follow_up') for h in response.get('hypotheses', [])
                       if h.get('follow_up', 'none') != 'none' and h.get('follow_up') in follow_ups), 'none')
        self.decisions.append(action)
        return {'accepted': accepted, 'action': action, 'redundant': action in completed,
                'live': [{'key': r['key'], 'status': r['status']} for r in self.research]}


class ReasoningArm:
    def __init__(self) -> None:
        self.state: dict[str, Any] | None = None
        self.tags: dict[str, str] = {}
        self.decisions: list[str] = []
        self.kernel_ms = 0.0

    def prior(self) -> dict[str, Any]:
        return planner_summary(self.state)

    def step(self, response: dict[str, Any], evidence: list[dict[str, Any]], follow_ups: dict[str, Any],
             completed: list[str], tags: list[str | None] | None = None) -> dict[str, Any]:
        hyps = response.get('hypotheses', [])
        retractions = []
        for item in response.get('retractions', []):
            target = item.get('prior_hypothesis_id') or self.tags.get(item.get('tag', ''), '')
            retractions.append(Retraction(prior_hypothesis_id=target, reason=item.get('reason', ''),
                                          evidence_job_ids=item.get('evidence_job_ids', [])))
        started = time.perf_counter()
        self.state, report = run_cycle(self.state, CycleInput(
            evidence=evidence, interpretations=response.get('observations', []),
            hypotheses=[ProposedHypothesis.from_dict({k: v for k, v in h.items() if k not in LABEL_FIELDS})
                        for h in hyps],
            available_follow_ups=follow_ups, completed_follow_ups=completed, retractions=retractions,
            missing_information=response.get('missing_information', [])))
        self.kernel_ms += (time.perf_counter() - started) * 1000
        ids = report['hypothesize']['proposal_ids']
        for index, tag in enumerate(tags or []):
            if tag and ids[index]:
                self.tags[tag] = ids[index]
        accepted = [i for i, hid in enumerate(ids) if hid in report['accepted_for_research']]
        action = report['decision']['action']
        self.decisions.append(action)
        return {'accepted': accepted, 'action': action, 'redundant': action in completed,
                'revised': bool(report['decision']['revised']), 'report': report,
                'live': [{'key': h['key'], 'status': h['status'], 'id': h['id']}
                         for h in self.state['hypotheses'].values()]}


# ── Scoring ────────────────────────────────────────────────────────────────

def _actions_match(arm: str, actual: str, expected: str) -> bool:
    if arm == 'baseline' and actual == 'none':
        # Generous: the baseline cannot express "collect information" or "stop".
        return expected in {'no_further_analysis', 'collect_missing_information'}
    return actual == expected


def new_tally() -> dict[str, Any]:
    return {'tp': 0, 'fp': 0, 'tp_accepted': 0, 'fp_rejected': 0, 'accepted': 0,
            'accepted_with_facts': 0, 'contradiction_expected': 0, 'contradiction_handled': 0,
            'decisions': 0, 'decisions_correct': 0, 'stable_expected': 0, 'stable_kept': 0,
            'revision_expected': 0, 'revision_made': 0, 'redundant_decisions': 0,
            'duplicate_entries': 0, 'competing_expected': 0, 'competing_linked': 0,
            'overconfident_accepted_excess': [], 'overclaims_reaching_research': 0}


def score_cycle(tally: dict[str, Any], arm: str, cycle: dict[str, Any], response: dict[str, Any],
                result: dict[str, Any], evidence: list[dict[str, Any]], previous_action: str | None,
                labels: list[str | None]) -> None:
    facts = {item['job_id'] for item in evidence if item['output']}
    hyps = response.get('hypotheses', [])
    accepted = set(result['accepted'])
    for index, hyp in enumerate(hyps):
        if index in accepted:
            tally['accepted'] += 1
            tally['accepted_with_facts'] += int(set(hyp['evidence_job_ids']) <= facts)
            if _OVERCLAIM.search(hyp['description']) and not _HEDGE.search(hyp['description']):
                tally['overclaims_reaching_research'] += 1
        label = labels[index] if index < len(labels) else None
        if label:
            positive = label == 'supported'
            tally['tp' if positive else 'fp'] += 1
            if positive and index in accepted:
                tally['tp_accepted'] += 1
            if not positive and index not in accepted:
                tally['fp_rejected'] += 1
    tally['decisions'] += 1
    tally['decisions_correct'] += int(_actions_match(arm, result['action'], cycle['expect_action']))
    tally['redundant_decisions'] += int(result['redundant'])
    if cycle.get('expect_stable'):
        tally['stable_expected'] += 1
        tally['stable_kept'] += int(result['action'] == previous_action)
    if cycle.get('expect_revised'):
        tally['revision_expected'] += 1
        tally['revision_made'] += int(bool(result.get('revised')))


def summarize(tally: dict[str, Any]) -> dict[str, Any]:
    def ratio(num: str, den: str) -> float | None:
        return round(tally[num] / tally[den], 4) if tally[den] else None
    excess = tally['overconfident_accepted_excess']
    return {
        'hypothesis_precision': round(tally['tp_accepted'] / max(tally['tp_accepted'] + (tally['fp'] - tally['fp_rejected']), 1), 4) if tally['tp'] + tally['fp'] else None,
        'false_positive_rejection': ratio('fp_rejected', 'fp'),
        'supported_retention': ratio('tp_accepted', 'tp'),
        'evidence_attribution': ratio('accepted_with_facts', 'accepted'),
        'contradiction_handling': ratio('contradiction_handled', 'contradiction_expected'),
        'competing_hypotheses_linked': ratio('competing_linked', 'competing_expected'),
        'decision_accuracy': ratio('decisions_correct', 'decisions'),
        'decision_consistency': ratio('stable_kept', 'stable_expected'),
        'replanning_on_evidence_change': ratio('revision_made', 'revision_expected'),
        'redundant_decisions': tally['redundant_decisions'],
        'duplicate_hypothesis_entries': tally['duplicate_entries'],
        'overclaims_reaching_research': tally['overclaims_reaching_research'],
        'mean_unverified_confidence_excess': round(sum(excess) / len(excess), 4) if excess else 0.0,
        'counts': {k: v for k, v in tally.items() if k != 'overconfident_accepted_excess'},
    }


# ── Runner ─────────────────────────────────────────────────────────────────

def strip_labels(response: dict[str, Any], legacy: bool) -> dict[str, Any]:
    out = {k: v for k, v in response.items() if k not in ('retractions',) or not legacy}
    out['hypotheses'] = [{k: v for k, v in h.items() if k not in LABEL_FIELDS and (
        not legacy or k in LEGACY_HYPOTHESIS_FIELDS)} for h in response.get('hypotheses', [])]
    if legacy:
        out.pop('missing_information', None)
    return out


def prompt_chars(objective: str, evidence: list[dict[str, Any]], follow_ups: dict[str, Any],
                 prior: dict[str, Any] | None, instruction: str, schema: dict[str, Any]) -> int:
    context: dict[str, Any] = {'objective': objective, 'evidence': evidence, 'available_follow_ups': follow_ups}
    if prior:
        context['prior_reasoning'] = prior
    return len(json.dumps(context)) + len(instruction) + len(json.dumps(schema))


async def evaluate(mode: str, responder=None, cases: list[str] | None = None) -> dict[str, Any]:
    from agents.autonomous_engine import REVIEW_INSTRUCTION, review_schema
    spec = load()
    if cases:
        unknown = set(cases) - {c['id'] for c in spec['cases']}
        assert not unknown, f'Unknown cases: {sorted(unknown)}'
        spec = {**spec, 'cases': [c for c in spec['cases'] if c['id'] in cases]}
    tallies = {'baseline': new_tally(), 'reasoning': new_tally()}
    cases_out = []
    cost = {'baseline': {'prompt_chars': 0, 'usage': []}, 'reasoning': {'prompt_chars': 0, 'usage': []}}
    for case in spec['cases']:
        baseline, reasoning = BaselineArm(), ReasoningArm()
        previous = {'baseline': None, 'reasoning': None}
        case_out: dict[str, Any] = {'id': case['id'], 'cycles': []}
        for number, cycle in enumerate(case['cycles']):
            evidence = cycle_evidence(spec, cycle)
            follow_ups = cycle_follow_ups(spec, cycle)
            allowed = {item['job_id'] for item in evidence}
            prior = reasoning.prior()
            prior_ids = [h['id'] for h in prior.get('live_hypotheses', [])]
            new_schema = review_schema(allowed, follow_ups, prior_ids)
            old_schema = legacy_schema(allowed, follow_ups)
            cost['baseline']['prompt_chars'] += prompt_chars(case['objective'], evidence, follow_ups, None,
                                                             LEGACY_INSTRUCTION, old_schema)
            cost['reasoning']['prompt_chars'] += prompt_chars(case['objective'], evidence, follow_ups, prior,
                                                              REVIEW_INSTRUCTION, new_schema)
            labelled = mode == 'scripted'
            if labelled:
                legacy_response = strip_labels(cycle['scripted'], legacy=True)
                new_response = cycle['scripted']
                tags: list[str | None] = [h.get('tag') for h in new_response.get('hypotheses', [])]
            else:
                assert responder is not None
                legacy_response, legacy_usage = await responder(case['objective'], evidence, follow_ups,
                                                                None, LEGACY_INSTRUCTION, old_schema)
                new_response, new_usage = await responder(case['objective'], evidence, follow_ups,
                                                          prior, REVIEW_INSTRUCTION, new_schema)
                cost['baseline']['usage'].append(legacy_usage)
                cost['reasoning']['usage'].append(new_usage)
                tags = [None for _ in new_response.get('hypotheses', [])]
                if number == 0:
                    # Tag first-cycle path hypotheses so contradiction scoring can follow them.
                    for index, hyp in enumerate(new_response.get('hypotheses', [])):
                        if hyp.get('follow_up') == 'bounded_http_paths':
                            tags[index] = 'admin' if case['id'] == 'contradiction-retraction' else 'test'
            if mode == 'scripted':
                retractions = [{**r, 'prior_hypothesis_id': reasoning.tags.get(r.get('tag', ''), r.get('prior_hypothesis_id', ''))}
                               for r in new_response.get('retractions', [])]
                new_response = {**new_response, 'retractions': retractions}
            b = baseline.step(legacy_response, evidence, follow_ups, cycle['completed'])
            r = reasoning.step(new_response, evidence, follow_ups, cycle['completed'], tags)
            for arm, result, response in (('baseline', b, legacy_response), ('reasoning', r, new_response)):
                labels = ([h.get('label') for h in cycle['scripted'].get('hypotheses', [])]
                          if labelled else [])
                score_cycle(tallies[arm], arm, cycle, response, result, evidence, previous[arm], labels)
                previous[arm] = result['action']
            # Contradiction, duplication, competition and confidence are judged on resulting state.
            for tag in cycle.get('expect_contradicted', []):
                for arm in tallies:
                    tallies[arm]['contradiction_expected'] += 1
                hid = reasoning.tags.get(tag)
                status = reasoning.state['hypotheses'][hid]['status'] if hid and reasoning.state else None
                tallies['reasoning']['contradiction_handled'] += int(status in {'contested', 'rejected'})
            for left, right in cycle.get('expect_competing', []) if labelled else []:
                for arm in tallies:
                    tallies[arm]['competing_expected'] += 1
                ids = r['report']['hypothesize']['proposal_ids']
                if ids[left] and ids[right] and reasoning.state:
                    tallies['reasoning']['competing_linked'] += int(
                        ids[right] in reasoning.state['hypotheses'][ids[left]]['competes_with'])
            for index, hyp in enumerate(new_response.get('hypotheses', [])):
                if index in r['accepted'] and reasoning.state:
                    hid = r['report']['hypothesize']['proposal_ids'][index]
                    conf = reasoning.state['hypotheses'][hid]['confidence']
                    tallies['reasoning']['overconfident_accepted_excess'].append(max(0.0, conf - UNVERIFIED_CEILING))
            for index, hyp in enumerate(legacy_response.get('hypotheses', [])):
                if index in b['accepted']:
                    tallies['baseline']['overconfident_accepted_excess'].append(
                        max(0.0, float(hyp.get('confidence', .25)) - UNVERIFIED_CEILING))
            case_out['cycles'].append({
                'cycle': number + 1, 'expected_action': cycle['expect_action'],
                'baseline': {'action': b['action'], 'accepted': b['accepted']},
                'reasoning': {'action': r['action'], 'accepted': r['accepted'],
                              'rejected': r['report']['hypothesize']['rejected'],
                              'challenges': r['report']['supervisor_challenges'],
                              'decision': r['report']['decision']},
                'responses_sha256': {'baseline': digest(legacy_response), 'reasoning': digest(new_response)},
                **({'responses': {'baseline': legacy_response, 'reasoning': new_response}} if mode == 'live' else {})})
        # Redundancy: entries that duplicate a live entry with the same normalized claim.
        b_keys = [entry['key'] for entry in baseline.research]
        tallies['baseline']['duplicate_entries'] += len(b_keys) - len(set(b_keys))
        live_keys = [h['key'] for h in reasoning.state['hypotheses'].values()] if reasoning.state else []
        tallies['reasoning']['duplicate_entries'] += len(live_keys) - len(set(live_keys))
        case_out['kernel_ms'] = round(reasoning.kernel_ms, 3)
        cases_out.append(case_out)
    for arm in cost:
        cost[arm]['estimated_prompt_tokens'] = cost[arm]['prompt_chars'] // 4
        usage = [u for u in cost[arm]['usage'] if u]
        if usage:
            cost[arm]['provider'] = {key: sum(int(u.get(key) or 0) for u in usage)
                                     for key in ('prompt_tokens', 'completion_tokens', 'total_tokens')}
            cost[arm]['provider']['cost_usd'] = str(sum(float(u.get('cost') or 0) for u in usage))
            cost[arm]['provider']['calls'] = len(usage)
    return {'schema_version': 'aria.reasoning-eval.result.v1', 'mode': mode,
            'fixture_sha256': digest(load()), 'selected_cases': [c['id'] for c in spec['cases']], 'cases': len(spec['cases']),
            'cycles': sum(len(c['cycles']) for c in spec['cases']),
            'metrics': {arm: summarize(t) for arm, t in tallies.items()},
            'cost': cost, 'per_case': cases_out,
            'limitations': [
                'Author-written development cases over retained synthetic receipts and one retained lab observation; not an independent or blinded holdout.',
                'Scripted mode measures deterministic pipeline behaviour on fixed responses, not model intelligence.',
                'Live mode measures one model on this case set with automatic, attributable checks only; no human grading.',
                'Overclaim detection uses the same lexical rule as the supervisor; it is a conservative floor, not semantic understanding.',
            ]}


# ── Live responder ─────────────────────────────────────────────────────────

def live_responder(user_id: str, max_calls: int, accounting, session_id: str, max_cost_microusd: int,
                   baseline_cost_microusd: int):
    """Query the approved OpenRouter profile through normal engagement accounting.

    Before every call the settled spend recorded by the engagement ledger is
    re-read; the run stops before a call that could exceed the actual-spend ceiling.
    """
    from agents.orchestrator_agent import InvestigationReview
    from llm.base_llm import response_schema
    from llm.pool_manager import pool_manager
    calls = {'n': 0, 'max_call_cost': 0}

    async def respond(objective, evidence, follow_ups, prior, instruction, schema):
        if calls['n'] >= max_calls:
            raise RuntimeError('Live evaluation call ceiling reached')
        status = await accounting.status(session_id, user_id)
        spent = int(status['usage'].get('reported_cost_microusd') or 0) - baseline_cost_microusd
        if status['usage'].get('stopped') or spent + max(calls['max_call_cost'], 1000) > max_cost_microusd:
            raise RuntimeError(f'Actual-spend ceiling would be exceeded or accounting stopped (spent {spent} micro-USD)')
        calls['n'] += 1
        context: dict[str, Any] = {'objective': objective, 'evidence': evidence, 'available_follow_ups': follow_ups}
        if prior:
            context['prior_reasoning'] = prior
        token = response_schema.set(schema)  # pyright: ignore[reportArgumentType]
        started = time.perf_counter()
        try:
            result = await pool_manager.query_for_task(user_id, 'output_analysis', json.dumps(context), instruction)
        finally:
            response_schema.reset(token)
        usage = {'latency_ms': round((time.perf_counter() - started) * 1000, 1),
                 'success': bool(result.get('success')), 'error': result.get('error'),
                 'model': result.get('model'), 'logical_request_id': result.get('logical_request_id')}
        receipt = result.get('provider_usage') or {}
        for key in ('prompt_tokens', 'completion_tokens', 'total_tokens', 'cost', 'provider', 'id'):
            if key in receipt:
                usage[key] = receipt[key]
        if receipt.get('model'):
            usage['model'] = receipt['model']
        try:
            calls['max_call_cost'] = max(calls['max_call_cost'], int(float(receipt.get('cost') or 0) * 1e6) + 1)
        except (TypeError, ValueError):
            pass
        try:
            parsed = InvestigationReview.model_validate_json(result.get('content', '')).model_dump()
            usage['schema_valid'] = True
        except Exception:
            parsed = {'observations': [], 'hypotheses': [], 'limitations': []}
            usage['schema_valid'] = False
        return parsed, usage
    return respond


async def run_live(session_id: str, max_calls: int, max_cost_microusd: int,
                   cases: list[str] | None = None) -> dict[str, Any]:
    from api.auth import authenticate_socket_token
    from config.settings import settings
    from llm.engagement_budget import bound_model_context, engagement_context, model_accounting
    from llm.pool_manager import openrouter_only, pool_manager
    from memory.database_models import engine
    token = json.loads(Path('.local-lab/intelligence/auth.json').read_text())['token']
    identity = await authenticate_socket_token(token)
    before = await model_accounting.status(session_id, identity.user_id)
    limits, usage = before['limits'], before['usage']
    assert before['approved_at'], 'Owner approval is required for live evaluation'
    assert not usage.get('stopped'), 'Accounting stopped; no inference allowed'
    assert settings.OPENROUTER_MODEL == 'deepseek/deepseek-v4-flash', 'Configured profile is not DeepSeek V4 Flash'
    assert any(t.get('model') == settings.OPENROUTER_MODEL for t in limits.get('tariffs', [])), 'No approved tariff'
    # Scripted dry run gives exact prompt sizes for the same selected cycles.
    dry = await evaluate('scripted', cases=cases)
    planned_calls = 2 * dry['cycles']
    planned_tokens = dry['cost']['baseline']['prompt_chars'] + dry['cost']['reasoning']['prompt_chars'] \
        + planned_calls * (8192 + 1024)
    headroom = {'calls': limits['max_calls'] - int(usage.get('calls') or 0),
                'tokens': limits['max_tokens'] - int(usage.get('reserved_tokens') or 0),
                'cost_microusd': limits['max_cost_microusd'] - int(usage.get('reserved_cost_microusd') or 0)}
    assert planned_calls <= min(max_calls, headroom['calls']), (planned_calls, headroom)
    assert planned_tokens <= headroom['tokens'], f'Planned reservation {planned_tokens} exceeds token headroom {headroom}'
    assert headroom['cost_microusd'] >= max_cost_microusd, f'Approved cost headroom below ceiling: {headroom}'
    attempt_ids = {a['id'] for a in before.get('attempts', [])}
    only = openrouter_only.set(True)
    context = engagement_context.set(bound_model_context(session_id, identity.user_id, 'reasoning-eval'))  # pyright: ignore[reportArgumentType]
    started = time.perf_counter()
    result: dict[str, Any] = {}
    error = None
    try:
        await pool_manager.refresh_user_keys(identity.user_id)
        preflight = await pool_manager.planner_preflight(identity.user_id, session_id)
        assert preflight['ready'] and preflight['provider'] == 'openrouter', preflight
        try:
            result = await evaluate('live', live_responder(
                identity.user_id, max_calls, model_accounting, session_id, max_cost_microusd,
                int(usage.get('reported_cost_microusd') or 0)), cases=cases)
        except Exception as exc:  # retain accounting for partial runs
            error = f'{type(exc).__name__}: {str(exc)[:300]}'
    finally:
        after = await model_accounting.status(session_id, identity.user_id)
        engagement_context.reset(context)
        openrouter_only.reset(only)
        await engine.dispose()
    attempts = [a for a in after.get('attempts', []) if a.get('id') not in attempt_ids]
    spent = int(after['usage'].get('reported_cost_microusd') or 0) - int(usage.get('reported_cost_microusd') or 0)
    result['accounting'] = {
        'session_id': session_id, 'planned_calls': planned_calls, 'planned_reserved_tokens': planned_tokens,
        'headroom_before': headroom, 'usage_before': usage, 'usage_after': after['usage'],
        'settled_cost_microusd': spent, 'ceiling_microusd': max_cost_microusd,
        'within_ceiling': spent <= max_cost_microusd, 'wall_seconds': round(time.perf_counter() - started, 2),
        'attempts': [{k: a.get(k) for k in ('id', 'state', 'provider', 'model', 'reserved_tokens',
                                            'reported_tokens', 'reserved_cost_microusd', 'reported_cost_microusd',
                                            'provider_usage')} for a in attempts],
        'error': error}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['scripted', 'live'], default='scripted')
    parser.add_argument('--session-id', default='')
    parser.add_argument('--max-calls', type=int, default=30)
    parser.add_argument('--max-cost-microusd', type=int, default=50000)
    parser.add_argument('--cases', default='', help='Comma-separated case IDs (default: all)')
    args = parser.parse_args()
    cases = [c for c in args.cases.split(',') if c] or None
    if args.mode == 'live':
        if not args.session_id:
            parser.error('--session-id of an owner-approved engagement is required for live mode')
        result = asyncio.run(run_live(args.session_id, args.max_calls, args.max_cost_microusd, cases))
    else:
        result = asyncio.run(evaluate('scripted', cases=cases))
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f'{args.mode}-result.json'
    path.write_text(json.dumps(result, indent=2))
    print(json.dumps({'written': str(path), 'metrics': result.get('metrics'), 'cost': {
        arm: {k: v for k, v in c.items() if k != 'usage'} for arm, c in result.get('cost', {}).items()},
        'accounting': {k: v for k, v in result.get('accounting', {}).items() if k != 'attempts'}}, indent=2, default=str))


if __name__ == '__main__':
    main()
