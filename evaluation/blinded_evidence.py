"""Export a blinded saved-evidence packet and score returned assessments locally."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from itertools import combinations
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from evaluation.competence import digest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'evaluation/fixtures/competence/blinded-evidence-v1.json'
CORPUS_SHA256 = '5e3044c3f779e77798d04f78f36e9d7318d26bc63cddfce132df9d589415d769'
Disposition = Literal['supported', 'rejected', 'inconclusive']
EvidenceID = Annotated[str, Field(pattern=r'^E[1-9][0-9]?$')]
EvidencePair = Annotated[list[EvidenceID], Field(min_length=2, max_length=2)]


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Decision(Contract):
    case_id: str = Field(pattern=r'^C[0-9]{2}$')
    disposition: Disposition
    evidence_sufficient: bool
    confidence: int = Field(ge=0, le=100)
    citations: list[EvidenceID] = Field(min_length=1, max_length=20)
    conflicts: list[EvidencePair] = Field(default_factory=list, max_length=20)
    rationale: str = Field(min_length=1, max_length=2000)


class Review(Contract):
    schema_version: Literal['aria.blinded-evidence.review.v1']
    packet_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    reviewer_id: str = Field(pattern=r'^[A-Za-z0-9_-]{1,80}$')
    kind: Literal['independent_human', 'scorer_fixture']
    round: Literal[1, 2]
    blind_attestation: bool
    decisions: list[Decision] = Field(min_length=1, max_length=100)


def load_corpus() -> dict:
    raw = CORPUS.read_bytes()
    if sha256(raw).hexdigest() != CORPUS_SHA256:
        raise ValueError('Frozen evidence corpus changed')
    return json.loads(raw)


def export_packet(corpus: dict) -> dict:
    body = {
        'schema_version': 'aria.blinded-evidence.packet.v1',
        'instructions': [
            'Assess each claim using only the observations in its case.',
            'Use supported for a claim established by the observations and rejected for a claim they rule out.',
            'Use inconclusive when the available evidence does not settle the claim.',
            'Evidence sufficiency describes whether the observations settle the claim in either direction.',
            'Give a confidence from 0 to 100 in your disposition, cite relevant observations, and name any conflicting pairs in scope.',
            'Complete each round privately using this packet. Avoid reference keys, other reviews, prior answers, and ARIA interpretations.',
        ],
        'cases': [{'id': case['id'], 'claim': case['claim'],
                   'observations': [{'id': row['id'], 'text': row['text']} for row in case['observations']]}
                  for case in corpus['cases']],
    }
    return {**body, 'packet_sha256': digest(body)}


def source_checks(corpus: dict) -> dict[str, str]:
    checks = {}
    for key, source in corpus['sources'].items():
        path = ROOT / source['path']
        checks[key] = ('missing' if not path.is_file() else
                       'matched' if sha256(path.read_bytes()).hexdigest() == source['sha256'] else 'changed')
    return checks


def rate(numerator: int, denominator: int) -> dict:
    return {'numerator': numerator, 'denominator': denominator,
            'rate': round(numerator / denominator, 6) if denominator else None}


def validated_decisions(review: Review, cases: dict, packet_sha256: str) -> dict[str, Decision]:
    if review.packet_sha256 != packet_sha256 or (review.kind == 'independent_human' and not review.blind_attestation):
        raise ValueError('Review lacks the packet binding or blind attestation')
    output = {}
    for decision in review.decisions:
        case = cases.get(decision.case_id)
        if case is None or decision.case_id in output:
            raise ValueError('Unknown or repeated reviewed case')
        known = {observation['id'] for observation in case['observations']}
        cited = set(decision.citations)
        conflicts = {tuple(sorted(pair)) for pair in decision.conflicts}
        if len(cited) != len(decision.citations) or not cited <= known or not decision.rationale.strip():
            raise ValueError('Review has invalid citations or an empty rationale')
        if (len(conflicts) != len(decision.conflicts)
                or any(left == right or not {left, right} <= cited for left, right in conflicts)):
            raise ValueError('Conflict pairs must use distinct cited observations')
        output[decision.case_id] = decision
    return output


def calibration(samples: list[tuple[int, bool]]) -> dict:
    bins = []
    for lower, upper in ((0, 24), (25, 49), (50, 74), (75, 100)):
        band = [(confidence, accurate) for confidence, accurate in samples if lower <= confidence <= upper]
        bins.append({'minimum': lower, 'maximum': upper, 'accuracy': rate(sum(ok for _, ok in band), len(band)),
                     'mean_confidence': round(sum(confidence for confidence, _ in band) / (100 * len(band)), 6) if band else None})
    return {'brier_correctness': round(sum((confidence / 100 - ok) ** 2 for confidence, ok in samples) / len(samples), 6)
            if samples else None, 'bins': bins}


def compare_with_design(decisions: dict[str, Decision], cases: dict) -> dict:
    expected = {case_id: cases[case_id]['reference'] for case_id in decisions}
    negatives = [key for key, reference in expected.items() if reference['disposition'] == 'rejected']
    unsupported = [key for key, reference in expected.items() if reference['disposition'] == 'inconclusive']
    contradictions = [key for key, reference in expected.items() if reference['conflicts']]
    correct = {key: answer.disposition == expected[key]['disposition'] for key, answer in decisions.items()}
    sufficiency = sum(answer.evidence_sufficient == (expected[key]['disposition'] != 'inconclusive')
                      for key, answer in decisions.items())
    return {
        'coverage': rate(len(decisions), len(cases)),
        'missing_cases': sorted(cases.keys() - decisions.keys()),
        'disposition_accuracy': rate(sum(correct.values()), len(decisions)),
        'false_positive_rate': rate(sum(decisions[key].disposition == 'supported' for key in negatives), len(negatives)),
        'unsupported_confirmation_rate': rate(sum(decisions[key].disposition == 'supported' for key in unsupported), len(unsupported)),
        'evidence_sufficiency_accuracy': rate(sufficiency, len(decisions)),
        'required_citation_coverage': rate(sum(set(expected[key]['citations']) <= set(answer.citations)
                                              for key, answer in decisions.items()), len(decisions)),
        'contradiction_handling': rate(sum(correct[key] and
                                           {tuple(sorted(pair)) for pair in expected[key]['conflicts']} ==
                                           {tuple(sorted(pair)) for pair in decisions[key].conflicts}
                                           for key in contradictions), len(contradictions)),
        'confidence_calibration': calibration([(answer.confidence, correct[key]) for key, answer in decisions.items()]),
    }


def agreement(left: dict[str, Decision], right: dict[str, Decision]) -> dict:
    keys = left.keys() & right.keys()
    size = len(keys)
    value = rate(sum(left[key].disposition == right[key].disposition for key in keys), size)
    left_labels = Counter(left[key].disposition for key in keys)
    right_labels = Counter(right[key].disposition for key in keys)
    chance = sum(count * right_labels[label] for label, count in left_labels.items())
    matches = value['numerator']
    kappa = round((matches * size - chance) / (size * size - chance), 6) if chance < size * size else None
    return {'agreement': value, 'cohens_kappa': kappa}


def score(corpus: dict, reviews: list[Review]) -> dict:
    packet_sha256 = export_packet(corpus)['packet_sha256']
    cases = {case['id']: case for case in corpus['cases']}
    groups: dict[str, dict[tuple[str, int], dict[str, Decision]]] = {'independent_human': {}, 'scorer_fixture': {}}
    for review in reviews:
        key = (review.reviewer_id, review.round)
        group = groups[review.kind]
        if key in group:
            raise ValueError('Duplicate reviewer and round')
        group[key] = validated_decisions(review, cases, packet_sha256)

    def summarize(group: dict[tuple[str, int], dict[str, Decision]]) -> dict:
        reviewers = sorted({reviewer for reviewer, _ in group})
        first = [reviewer for reviewer in reviewers if (reviewer, 1) in group]
        consensus = {}
        if len(first) >= 2:
            for case_id in cases:
                votes = [group[reviewer, 1][case_id].disposition for reviewer in first if case_id in group[reviewer, 1]]
                if len(votes) == len(first) and len(set(votes)) == 1:
                    consensus[case_id] = votes[0]
        return {
            'reviewers': len(reviewers),
            'rounds': [{'reviewer': reviewer, 'round': number, **compare_with_design(decisions, cases)}
                       for (reviewer, number), decisions in sorted(group.items())],
            'inter_reviewer': [{'reviewers': [left, right], **agreement(group[left, 1], group[right, 1])}
                               for left, right in combinations(first, 2)],
            'repeatability': [{'reviewer': reviewer, **agreement(group[reviewer, 1], group[reviewer, 2])}
                              for reviewer in first if (reviewer, 2) in group],
            'unanimous_first_round': consensus,
        }

    return {
        'schema_version': 'aria.blinded-evidence.score.v1', 'packet_sha256': packet_sha256,
        'cases': len(cases), 'design_categories': dict(Counter(case['reference']['category'] for case in cases.values())),
        'source_integrity': source_checks(corpus),
        'independent_assessments': summarize(groups['independent_human']),
        'scorer_fixtures': summarize(groups['scorer_fixture']),
        'reference_basis': 'Engineering-authored fixture key. Independent first-round agreement is reported separately.',
        'provider_requests': 0, 'provider_cost_microusd': 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    export = commands.add_parser('export')
    export.add_argument('--output', type=Path, required=True)
    scoring = commands.add_parser('score')
    scoring.add_argument('--output', type=Path, required=True)
    scoring.add_argument('reviews', type=Path, nargs='*')
    options = parser.parse_args()
    corpus = load_corpus()
    if options.operation == 'export':
        result = export_packet(corpus)
    else:
        result = score(corpus, [Review.model_validate_json(path.read_bytes()) for path in options.reviews])
    options.output.parent.mkdir(parents=True, exist_ok=True)
    with options.output.open('x', encoding='utf-8') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(options.output)


if __name__ == '__main__':
    main()
