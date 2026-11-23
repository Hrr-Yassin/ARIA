"""Score the frozen saved-review pilot from local receipts, without provider I/O."""
import argparse
from collections import Counter
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import json
from pathlib import Path

FIXTURE = Path(__file__).parent / 'fixtures' / 'competence' / 'saved-review-pilot-v1.json'
FROZEN_SHA256 = '2e81e6d5f4311f5d061ebf5e890e530f222e3679ca122733e84a88a82e1df495'
MODEL = 'deepseek/deepseek-v4-flash'
LABELS = ('supported', 'rejected', 'inconclusive')


def read_object(path: Path) -> dict:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f'Invalid record: {path.name}')
    return value


def score_stage(task: dict | None, attempts: list[dict], physical: set[tuple[str, str]],
                evidence_ids: list[str], objective: str) -> dict:
    if not task:
        return {'state': 'missing', 'label': None}
    run_key = (task['id'], task.get('run_id'))
    linked = [row for row in attempts if (row.get('task_id'), row.get('task_run_id')) == run_key]
    if len(linked) > 1:
        return {'state': 'ambiguous_attempts', 'label': None}
    attempt = linked[0] if linked else {}
    if run_key not in physical:
        return {'state': 'no_provider_dispatch', 'label': None}
    receipt = attempt.get('provider_usage') or {}
    tokens, cost = attempt.get('reported_tokens'), attempt.get('reported_cost_microusd')
    try:
        billed = Decimal(receipt['cost']) * 1_000_000
        cost_matches = billed.is_finite() and billed >= 0 and billed.to_integral_value(rounding=ROUND_CEILING) == cost
    except (KeyError, TypeError, InvalidOperation, ValueError):
        cost_matches = False
    if (attempt.get('provider') != 'openrouter' or attempt.get('model') != MODEL
            or receipt.get('model') != MODEL or not receipt.get('id')
            or type(tokens) is not int or type(cost) is not int
            or not 0 <= tokens <= attempt.get('reserved_tokens', -1)
            or not 0 <= cost <= attempt.get('reserved_cost_microusd', -1)
            or tokens != receipt.get('total_tokens') or not cost_matches):
        return {'state': 'unreconciled_attempt', 'label': None}

    metering = {'attempt_id': attempt['id'], 'tokens': tokens, 'cost_microusd': cost,
                'latency_ms': (attempt.get('timings') or {}).get('provider_attempt_ms')}
    if attempt.get('state') != 'succeeded':
        return {'state': 'provider_failed', 'label': None, **metering}
    result = task.get('result') or {}
    hypotheses = result.get('hypotheses') or []
    if (task.get('state') != 'analyzed' or task.get('objective') != objective
            or task.get('evidence_inputs') != evidence_ids or len(hypotheses) != 1):
        return {'state': 'invalid_result', 'label': None, **metering}
    claim = hypotheses[0]
    label = claim.get('disposition')
    if label not in LABELS or claim.get('verified') is not False or not evidence_ids or (
            set(claim.get('evidence_references', [])) != set(evidence_ids)):
        return {'state': 'invalid_citation_or_disposition', 'label': None, **metering}
    return {'state': 'scored', 'label': label, 'has_explicit_uncertainty': bool(claim.get('uncertainty')),
            **metering}


def matched_handoff(parent: dict, child: dict, initial: dict, follow_up: dict,
                    journal: dict, refs: list[str], objective: str) -> bool:
    """Check the two captured inputs against the retained task/run pair."""
    for task, stage in ((parent, initial), (child, follow_up)):
        recorded = journal.get((task['id'], task['run_id']))
        if (not recorded or recorded.get('objective') != objective or recorded.get('evidence_ids') != refs
                or (recorded.get('result') or {}).get('attempt_id') != stage['attempt_id']):
            return False
    initial_prompt = journal[parent['id'], parent['run_id']]
    challenge_prompt = journal[child['id'], child['run_id']]
    hypothesis = parent['result']['hypotheses'][0]
    return initial_prompt.get('prior_claims') == [] and challenge_prompt.get('prior_claims') == [{
        'task_id': parent['id'], 'run_id': parent['run_id'], 'description': hypothesis['description'][:500],
        'evidence_references': hypothesis['evidence_references'], 'disposition': initial['label'],
    }]


def score(directory: Path) -> dict:
    if hashlib.sha256(FIXTURE.read_bytes()).hexdigest() != FROZEN_SHA256:
        raise ValueError('Frozen fixture changed')
    if read_object(directory / 'scope.json').get('frozen_sha256') != FROZEN_SHA256:
        raise ValueError('Run does not identify the frozen fixture')
    accounting = read_object(directory / 'accounting.json')
    attempts = accounting['status']['attempts']
    path = directory / 'physical.jsonl'
    sends = [row for line in path.read_text().splitlines() if (row := json.loads(line))['event'] == 'send'] if path.exists() else []
    physical = {(row['task_id'], row['run_id']) for row in sends}
    if len(sends) != accounting['physical_calls'] or len(physical) != len(sends) or len(sends) > 6:
        raise ValueError('Physical attempt count does not reconcile')

    journal = {}
    path = directory / 'stages.jsonl'
    if path.exists():
        for line in path.read_text().splitlines():
            entry = json.loads(line)
            key = (entry['task']['id'], entry['task']['run_id'])
            if key in journal:
                raise ValueError('Duplicate stage input')
            journal[key] = entry

    cases = []
    matrices = {stage: {label: Counter() for label in LABELS} for stage in ('initial', 'follow_up')}
    outcomes = Counter()
    for case in read_object(FIXTURE)['cases']:
        path = directory / (case['id'] + '.json')
        retained = read_object(path) if path.exists() else {}
        tasks = retained.get('tasks', [])
        parent_id = retained.get('parent_id')
        parent = next((task for task in tasks if task['id'] == parent_id and task.get('internal_review') == 'analyze'), None)
        children = [task for task in tasks if task.get('internal_review') == 'challenge' and
                    task.get('dependencies') == [parent_id] and parent and task['session_id'] == parent['session_id']]
        refs = parent.get('evidence_inputs', []) if parent else []
        stages = {
            'initial': score_stage(parent, attempts, physical, refs, case['objective']),
            'follow_up': {'state': 'ambiguous_follow_up', 'label': None} if len(children) > 1 else
                score_stage(children[0] if children else None, attempts, physical, refs, case['objective']),
        }
        expected = case['expected']
        for stage, answer in stages.items():
            matrices[stage][expected][answer['label'] or answer['state']] += 1
        before, after = stages['initial']['label'], stages['follow_up']['label']
        change = ('unpaired' if before is None or after is None else
                  'handoff_unverified' if not matched_handoff(
                      parent, children[0], stages['initial'], stages['follow_up'], journal, refs, case['objective']) else
                  'same_label' if before == after else
                  'label_corrected' if after == expected else
                  'label_regressed' if before == expected else 'different_incorrect_label')
        outcomes[change] += 1
        cases.append({'case': case['id'], 'expected': expected, **stages, 'paired_disposition_change': change})
    return {'physical_attempts': len(physical), 'cases': cases, 'confusion_matrices': matrices,
            'paired_disposition_changes': outcomes,
            'interpretation': 'Label shifts require human review of factual support and usefulness.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run_directory', type=Path)
    print(json.dumps(score(parser.parse_args().run_directory), indent=2))
