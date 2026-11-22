"""Deterministic investigation reasoning kernel.

The kernel runs one reasoning cycle over retained, receipt-bound evidence:

    OBSERVE -> ANALYZE -> HYPOTHESIZE -> (SUPERVISE) -> PRIORITIZE -> PLAN -> REVIEW -> REPLAN

It performs no IO, model calls, tool calls or execution. Its output is a
JSON-serializable state that the caller persists. Every conclusion stays a
hypothesis: the kernel can reject, contest or deprioritize a claim, but it can
never confirm a vulnerability. Confirmation keeps its existing path through the
independent verifier and human signoff in ``memory.research``.

Facts are only receipt-derived observations. Model interpretations, assumptions
and confidence values are recorded separately and are challenged by a
deterministic supervisor before anything reaches the persistent research queue.
"""
from __future__ import annotations

import copy
import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal

REASONING_VERSION = 1
MAX_HYPOTHESES = 200
MAX_DECISIONS = 100
MAX_REJECTED_MEMORY = 200
MAX_UNVERIFIED_CONFIDENCE = 0.7
DECISION_HYSTERESIS = 0.15
NO_FOLLOW_UP = 'none'

HypothesisStatus = Literal['active', 'contested', 'rejected', 'superseded']
DecisionStatus = Literal['active', 'completed', 'superseded']

# A claim that asserts a settled security outcome. Hypothesis language ("may",
# "candidate", "possible") is allowed; these assertions need verification that
# a review cycle over passive receipts cannot supply.
_OVERCLAIM = re.compile(
    r"\b(?:is|are|was|were|has been|have been)\s+(?:confirmed|verified|proven|exploitable|"
    r"exploited|compromised|vulnerable)\b|\bconfirmed\s+(?:vulnerab|exploit|rce|sqli|xss|"
    r"injection|bypass)|\bproves?\b|\bsuccessfully\s+exploit|\bcredentials?\s+(?:are|were)\s+"
    r"(?:valid|obtained|recovered)|\bremote code execution (?:is|was) (?:possible|achieved)",
    re.IGNORECASE)
_HEDGE = re.compile(r"\b(?:may|might|could|possibl[ey]|candidate|suggests?|unverified|untested|unconfirmed|"
                    r"potential(?:ly)?|appears?|seems?|probabl[ey]|likely|plausibl[ey]|perhaps|whether|"
                    r"hypothes[ie]s|if)\b", re.IGNORECASE)
_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset('a an the of to on in at for and or is are be may might could possibly '
                  'potentially candidate suggests that this with by from as it its which'.split())


def _stem(word: str) -> str:
    for suffix in ('ing', 'ed', 'es', 's'):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            word = word[:-len(suffix)]
            break
    return word[:-1] if word.endswith('e') and len(word) > 3 else word


def _terms(text: str) -> set[str]:
    return {_stem(w) for w in _WORD.findall(text.lower()) if w not in _STOP and len(w) > 1}


def claim_key(text: str) -> str:
    """Order- and inflection-insensitive key used for redundancy and rejection memory."""
    return hashlib.sha256(' '.join(sorted(_terms(text))).encode()).hexdigest()[:16]


def _similar(left: str, right: str) -> float:
    a, b = _terms(left), _terms(right)
    return len(a & b) / len(a | b) if a and b else 0.0


def _entropy(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def empty_state() -> dict[str, Any]:
    return {'version': REASONING_VERSION, 'cycle': 0, 'observations': {}, 'interpretations': [],
            'hypotheses': {}, 'decisions': {}, 'dependencies': {}, 'verification_results': {},
            'rejected_claims': {}, 'completed_analyses': [], 'cycles': []}


@dataclass
class ProposedHypothesis:
    """Model proposal normalized from the structured review output."""
    description: str
    evidence_job_ids: list[str]
    follow_up: str = NO_FOLLOW_UP
    validation_criterion: str = ''
    alternative_explanations: list[str] = field(default_factory=list)
    confidence: float = 0.25
    contradicting_evidence_job_ids: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
    competes_with: list[int] = field(default_factory=list)
    prior_hypothesis_id: str = NO_FOLLOW_UP

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> 'ProposedHypothesis':
        known = {k: value[k] for k in cls.__dataclass_fields__ if k in value}
        return cls(**known)


@dataclass
class Retraction:
    prior_hypothesis_id: str
    reason: str
    evidence_job_ids: list[str] = field(default_factory=list)


@dataclass
class CycleInput:
    """Everything a single reasoning cycle may use. All of it is retained data."""
    evidence: list[dict[str, Any]]
    interpretations: list[str]
    hypotheses: list[ProposedHypothesis]
    available_follow_ups: dict[str, dict[str, Any]]
    completed_follow_ups: list[str] = field(default_factory=list)
    retractions: list[Retraction] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
    run_id: str = ''
    # Classified typed-tool outcomes bound to canonical evidence (P2); recorded, never verification.
    tool_outcomes: list[dict[str, Any]] = field(default_factory=list)


def _hid(key: str, first_cycle: int) -> str:
    return 'h-' + hashlib.sha256(f'{key}:{first_cycle}'.encode()).hexdigest()[:12]


def _did(cycle: int, action: str) -> str:
    return 'd-' + hashlib.sha256(f'{cycle}:{action}'.encode()).hexdigest()[:12]


def _support_refs(state: dict[str, Any], hypothesis: dict[str, Any]) -> list[str]:
    observed = {o['evidence_ref'] for o in state['observations'].values() if not o.get('superseded')}
    return [ref for ref in hypothesis['support'] if ref in observed]


# ── OBSERVE ────────────────────────────────────────────────────────────────

def observe(state: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Record receipt-derived facts; detect facts that changed since a prior cycle."""
    changed: list[str] = []
    added = 0
    new_ids: list[str] = []
    by_locator = {(o['kind'], o['locator']): oid for oid, o in state['observations'].items()
                  if not o.get('superseded') and o['locator']}
    for item in evidence:
        ref = str(item.get('job_id', ''))
        output = item.get('output')
        facts = output if isinstance(output, list) else [
            {'kind': 'raw', 'locator': '', 'summary': str(output or '')[:300]}]
        for fact in facts:
            if not isinstance(fact, dict):
                continue
            kind = str(fact.get('kind', 'raw'))[:40]
            locator = str(fact.get('locator', ''))[:300]
            summary = str(fact.get('summary', ''))[:300]
            oid = 'o-' + hashlib.sha256(f'{ref}:{kind}:{locator}:{summary}'.encode()).hexdigest()[:12]
            if oid in state['observations']:
                continue
            previous = by_locator.get((kind, locator)) if locator else None
            if previous and state['observations'][previous]['evidence_ref'] != ref \
                    and state['observations'][previous]['summary'] != summary:
                state['observations'][previous]['superseded'] = True
                state['observations'][previous]['superseded_by'] = oid
                changed.append(state['observations'][previous]['evidence_ref'])
            state['observations'][oid] = {'id': oid, 'evidence_ref': ref, 'kind': kind,
                                          'locator': locator, 'summary': summary,
                                          'cycle': state['cycle'], 'fact': True}
            if locator:
                by_locator[(kind, locator)] = oid
            added += 1
            new_ids.append(oid)
    return {'observations_added': added, 'changed_evidence': sorted(set(changed)), 'new_observations': new_ids}


# ── ANALYZE ────────────────────────────────────────────────────────────────

def analyze(state: dict[str, Any], interpretations: list[str], changed_evidence: list[str]) -> dict[str, Any]:
    """Separate facts from assumptions and invalidate conclusions built on changed facts."""
    for text in interpretations[:5]:
        state['interpretations'].append({'text': str(text)[:300], 'cycle': state['cycle'],
                                         'kind': 'assumption',
                                         'note': 'Model interpretation; not a receipt fact.'})
    state['interpretations'] = state['interpretations'][-30:]
    revalidate: list[str] = []
    changed = set(changed_evidence)
    for hid, hyp in state['hypotheses'].items():
        if hyp['status'] in {'active', 'contested'} and changed & set(hyp['support']):
            hyp['requires_revalidation'] = True
            hyp['history'].append({'cycle': state['cycle'], 'event': 'evidence_changed',
                                   'evidence': sorted(changed & set(hyp['support']))})
            revalidate.append(hid)
    return {'facts': sum(1 for o in state['observations'].values() if not o.get('superseded')),
            'assumptions': len(interpretations[:5]), 'requires_revalidation': revalidate}


_ABSENT_FACT = re.compile(r'\b(?:404|410|not found)\b', re.I)
_UNREACHABLE_FACT = re.compile(r'\b(?:closed|filtered|refused|unreachable|no route)\b', re.I)
_ACCESS_DENIED_FACT = re.compile(r'\b(?:401|403|forbidden|unauthori[sz]ed|authentication required|access denied)\b', re.I)
# Claims about who can access an endpoint, as opposed to whether it exists.
_UNAUTH_ACCESS_CLAIM = re.compile(r'\b(?:public(?:ly)?|unauthenticated|without (?:any )?(?:auth\w*|credentials|login)|'
                                  r'anonymous(?:ly)?|no (?:login|authentication|credentials)|freely|accessible|'
                                  r'readable|browsable)\b', re.I)
_AUTH_REQUIRED_CLAIM = re.compile(r'\b(?:requires? (?:auth\w*|login|credentials)|behind (?:\w+ )?(?:auth\w*|login)|'
                                  r'access[- ]controlled|protected|restricted)\b', re.I)
_EXISTENCE_CLAIM = re.compile(r'\b(?:exists?|installed|present|deployed|hosts?|runs?|enabled)\b', re.I)


def fact_signal(summary: str) -> str | None:
    """Typed meaning of a receipt fact for contradiction analysis."""
    if _ACCESS_DENIED_FACT.search(summary):
        return 'access_denied'     # the endpoint exists; unauthenticated access is refused
    if _ABSENT_FACT.search(summary):
        return 'absent'
    if _UNREACHABLE_FACT.search(summary):
        return 'unreachable'
    return None
_NEGATIVE_CLAIM = re.compile(r'\b(?:404|410|closed|filtered|refused|not found|absent|unavailable|no longer|returned)\b', re.I)


def _fact_targets(locator: str) -> tuple[set[str], set[str]]:
    """Paths and TCP ports a receipt fact is about."""
    from urllib.parse import urlsplit
    paths: set[str] = set()
    ports: set[str] = set()
    port_match = re.search(r'(?::|^)(\d{1,5})(?:/tcp)?$', locator) or re.search(r'\b(\d{1,5})/tcp\b', locator)
    if '://' in locator:
        parts = urlsplit(locator)
        if parts.path and parts.path != '/':
            paths.add(parts.path.rstrip('/').lower())
        if parts.port:
            ports.add(str(parts.port))
    elif port_match:
        ports.add(port_match.group(1))
    return paths, ports


def detect_fact_contradictions(state: dict[str, Any], new_observation_ids: list[str]) -> list[dict[str, Any]]:
    """Relate new receipt facts to live claims that name the same path or port.

    * ``absent`` (404/410) contradicts claims about the path.
    * ``access_denied`` (401/403) contradicts only claims of unauthenticated or
      public access; it corroborates claims that the endpoint exists or is protected.
    * ``unreachable`` (closed/filtered/refused) contradicts claims about the port.

    Claims that already assert the negative, or rest on the same evidence, are
    left alone. Nothing here rejects; contradiction resolution decides status.
    """
    found: list[dict[str, Any]] = []
    for oid in new_observation_ids:
        fact = state['observations'].get(oid)
        signal = fact_signal(fact['summary']) if fact else None
        if not fact or not signal:
            continue
        paths, ports = _fact_targets(fact['locator'])
        if not paths and not ports:
            continue
        ref = fact['evidence_ref']
        for hid, hyp in state['hypotheses'].items():
            if hyp['status'] not in {'active', 'contested'} or ref in hyp['support']:
                continue
            claim = hyp['claim'].lower()
            named_path = any(re.search(re.escape(path) + r'(?![a-z0-9_-])', claim) for path in paths)
            named_port = any(re.search(rf'(?:\bport\s*|:){port}\b|\b{port}/tcp\b', claim) for port in ports)
            if signal == 'access_denied':
                if not named_path:
                    continue
                if _UNAUTH_ACCESS_CLAIM.search(claim) and not _AUTH_REQUIRED_CLAIM.search(claim):
                    relation = 'contradicts'
                elif _AUTH_REQUIRED_CLAIM.search(claim) or _EXISTENCE_CLAIM.search(claim):
                    relation = 'supports'
                else:
                    continue           # ambiguous wording ("reachable", "exposed"): no automatic relation
            else:
                if _NEGATIVE_CLAIM.search(claim) or not ((signal == 'absent' and named_path) or
                                                         (signal == 'unreachable' and named_port)):
                    continue
                relation = 'contradicts'
            field = 'contradict' if relation == 'contradicts' else 'support'
            if ref in hyp[field]:
                continue
            hyp[field] = sorted({*hyp[field], ref})[:30]
            hyp['history'].append({'cycle': state['cycle'], 'event': f'fact_{relation}', 'signal': signal,
                                   'evidence': [ref], 'fact': fact['summary'][:160]})
            found.append({'hypothesis': hid, 'evidence': ref, 'relation': relation, 'signal': signal,
                          'fact': fact['summary'][:160]})
    return found


# ── HYPOTHESIZE + SUPERVISE ────────────────────────────────────────────────

def supervise(proposal: ProposedHypothesis, allowed: set[str], observed_refs: set[str],
              state: dict[str, Any]) -> tuple[bool, list[str], float]:
    """Deterministic challenge of one proposal. Returns (accepted, challenges, confidence)."""
    challenges: list[str] = []
    support = [ref for ref in proposal.evidence_job_ids if ref in allowed]
    contradict = [ref for ref in proposal.contradicting_evidence_job_ids if ref in allowed]
    if not proposal.evidence_job_ids:
        challenges.append('no_supporting_evidence')
    if len(support) != len(proposal.evidence_job_ids) or len(contradict) != len(
            proposal.contradicting_evidence_job_ids):
        challenges.append('unknown_evidence_cited')
    if support and not set(support) & observed_refs:
        challenges.append('evidence_has_no_retained_fact')
    if set(support) & set(contradict):
        challenges.append('same_evidence_supports_and_contradicts')
    description = proposal.description
    if _OVERCLAIM.search(description) and not _HEDGE.search(description):
        challenges.append('unsupported_conclusion')
    elif not _HEDGE.search(description):
        # A conclusion stated as settled fact is an assertion, not a hypothesis: facts come
        # only from receipts, so unhedged security claims never enter research.
        challenges.append('unhedged_assertion')
    key = claim_key(description)
    rejected = state['rejected_claims'].get(key)
    if rejected and not set(support) - set(rejected.get('evidence', [])):
        challenges.append('previously_rejected_without_new_evidence')
    if not proposal.alternative_explanations and not proposal.competes_with:
        challenges.append('single_explanation')
    fatal = {'no_supporting_evidence', 'unknown_evidence_cited', 'evidence_has_no_retained_fact',
             'same_evidence_supports_and_contradicts', 'unsupported_conclusion', 'unhedged_assertion',
             'previously_rejected_without_new_evidence'}
    # Confidence must be earned by independent retained evidence; it is capped
    # below verification because a review over passive receipts cannot verify.
    cap = 0.25 + 0.15 * min(len(set(support)), 3) - 0.2 * len(set(contradict))
    if 'single_explanation' in challenges:
        cap -= 0.1
    cap = max(0.05, min(cap, MAX_UNVERIFIED_CONFIDENCE))
    confidence = float(proposal.confidence)
    if confidence > cap:
        challenges.append('confidence_capped')
        confidence = cap
    return not (fatal & set(challenges)), challenges, round(confidence, 4)


def _match_existing(state: dict[str, Any], proposal: ProposedHypothesis) -> str | None:
    if proposal.prior_hypothesis_id in state['hypotheses']:
        return proposal.prior_hypothesis_id
    key = claim_key(proposal.description)
    for hid, hyp in state['hypotheses'].items():
        if hyp['status'] in {'active', 'contested'} and (
                hyp['key'] == key or _similar(hyp['claim'], proposal.description) >= 0.8):
            return hid
    return None


def hypothesize(state: dict[str, Any], cycle_input: CycleInput) -> dict[str, Any]:
    allowed = {str(item.get('job_id')) for item in cycle_input.evidence} | {
        o['evidence_ref'] for o in state['observations'].values()}
    observed = {o['evidence_ref'] for o in state['observations'].values() if not o.get('superseded')}
    outcome: dict[str, Any] = {'accepted': [], 'merged': [], 'rejected': [], 'retracted': [],
                               'challenges': {}}
    proposal_ids: list[str | None] = []
    for index, proposal in enumerate(cycle_input.hypotheses):
        accepted, challenges, confidence = supervise(proposal, allowed, observed, state)
        for code in challenges:
            outcome['challenges'][code] = outcome['challenges'].get(code, 0) + 1
        key = claim_key(proposal.description)
        if not accepted:
            entry = state['rejected_claims'].get(key, {'claim': proposal.description[:300],
                                                       'evidence': [], 'reasons': [], 'cycles': []})
            entry['evidence'] = sorted(set(entry['evidence']) | set(proposal.evidence_job_ids))[:20]
            entry['reasons'] = sorted(set(entry['reasons']) | set(challenges))
            entry['cycles'] = [*entry['cycles'], state['cycle']][-10:]
            state['rejected_claims'][key] = entry
            outcome['rejected'].append({'index': index, 'claim': proposal.description[:300],
                                        'challenges': challenges})
            proposal_ids.append(None)
            continue
        existing = _match_existing(state, proposal)
        support = sorted(set(proposal.evidence_job_ids) & allowed)
        contradict = sorted(set(proposal.contradicting_evidence_job_ids) & allowed)
        if existing:
            hyp = state['hypotheses'][existing]
            new_support = sorted(set(support) - set(hyp['support']))
            if hyp['status'] == 'contested' and not new_support:
                # Restating a contested claim is not evidence for it.
                outcome['challenges']['contested_without_new_evidence'] = outcome['challenges'].get(
                    'contested_without_new_evidence', 0) + 1
                outcome['rejected'].append({'index': index, 'claim': proposal.description[:300],
                                            'challenges': [*challenges, 'contested_without_new_evidence'],
                                            'prior_hypothesis_id': existing})
                proposal_ids.append(None)
                continue
            hyp['support'] = sorted(set(hyp['support']) | set(support))[:30]
            hyp['contradict'] = sorted(set(hyp['contradict']) | set(contradict))[:30]
            hyp['assumptions'] = list(dict.fromkeys([*hyp['assumptions'], *proposal.assumptions]))[:6]
            hyp['missing_information'] = list(dict.fromkeys(
                [*hyp['missing_information'], *proposal.missing_information]))[:6]
            hyp['alternative_explanations'] = list(dict.fromkeys(
                [*hyp['alternative_explanations'], *proposal.alternative_explanations]))[:6]
            if proposal.follow_up != NO_FOLLOW_UP:
                hyp['follow_up'] = proposal.follow_up
                hyp['validation_criterion'] = proposal.validation_criterion[:240]
            hyp['confidence'] = confidence
            hyp['challenges'] = challenges
            hyp['last_cycle'] = state['cycle']
            if new_support:
                hyp['requires_revalidation'] = False
            hyp['history'].append({'cycle': state['cycle'], 'event': 'revised',
                                   'new_support': new_support, 'new_contradict': contradict,
                                   'confidence': confidence})
            outcome['merged'].append(existing)
            proposal_ids.append(existing)
            continue
        if len(state['hypotheses']) >= MAX_HYPOTHESES:
            outcome['rejected'].append({'index': index, 'claim': proposal.description[:300],
                                        'challenges': ['hypothesis_limit']})
            proposal_ids.append(None)
            continue
        hid = _hid(key, state['cycle'])
        state['hypotheses'][hid] = {
            'id': hid, 'key': key, 'claim': proposal.description[:300], 'status': 'active',
            'support': support, 'contradict': contradict,
            'assumptions': proposal.assumptions[:6], 'missing_information': proposal.missing_information[:6],
            'alternative_explanations': proposal.alternative_explanations[:6],
            'competes_with': [], 'follow_up': proposal.follow_up,
            'validation_criterion': proposal.validation_criterion[:240],
            'confidence': confidence, 'model_confidence': float(proposal.confidence),
            'challenges': challenges, 'requires_revalidation': False,
            'first_cycle': state['cycle'], 'last_cycle': state['cycle'], 'verified': False,
            'history': [{'cycle': state['cycle'], 'event': 'proposed', 'confidence': confidence}]}
        outcome['accepted'].append(hid)
        proposal_ids.append(hid)
    # Competing hypotheses: explicit model links, or distinct claims resting on
    # the same retained evidence (they cannot both be the best explanation).
    for index, proposal in enumerate(cycle_input.hypotheses):
        hid = proposal_ids[index]
        if not hid:
            continue
        for other in proposal.competes_with:
            if 0 <= other < len(proposal_ids) and proposal_ids[other] and proposal_ids[other] != hid:
                _link(state, hid, str(proposal_ids[other]))
    live = [h for h in state['hypotheses'].values() if h['status'] in {'active', 'contested'}]
    for i, left in enumerate(live):
        for right in live[i + 1:]:
            if set(left['support']) & set(right['support']) and left['key'] != right['key']:
                _link(state, left['id'], right['id'])
    for retraction in cycle_input.retractions:
        hyp = state['hypotheses'].get(retraction.prior_hypothesis_id)
        refs = [ref for ref in retraction.evidence_job_ids if ref in allowed]
        if not hyp or hyp['status'] not in {'active', 'contested'}:
            continue
        if not refs:
            outcome['challenges']['retraction_without_evidence'] = outcome['challenges'].get(
                'retraction_without_evidence', 0) + 1
            continue
        hyp['contradict'] = sorted(set(hyp['contradict']) | set(refs))
        hyp['history'].append({'cycle': state['cycle'], 'event': 'retraction_requested',
                               'reason': retraction.reason[:240], 'evidence': refs})
        outcome['retracted'].append(hyp['id'])
    outcome['proposal_ids'] = proposal_ids
    return outcome


def _link(state: dict[str, Any], left: str, right: str) -> None:
    a, b = state['hypotheses'][left], state['hypotheses'][right]
    if right not in a['competes_with']:
        a['competes_with'] = [*a['competes_with'], right][:10]
    if left not in b['competes_with']:
        b['competes_with'] = [*b['competes_with'], left][:10]


# ── REVIEW of contradictions ───────────────────────────────────────────────

def resolve_contradictions(state: dict[str, Any]) -> dict[str, Any]:
    """Contest or reject hypotheses whose retained support no longer outweighs contradictions."""
    contested: list[str] = []
    rejected: list[str] = []
    for hid, hyp in state['hypotheses'].items():
        if hyp['status'] not in {'active', 'contested'}:
            continue
        current = set(_support_refs(state, hyp)) - set(hyp['contradict'])
        # Support whose facts were superseded or are no longer retained is stale, not
        # refuted: the claim needs revalidation, never automatic rejection.
        stale = set(hyp['support']) - set(_support_refs(state, hyp)) - set(hyp['contradict'])
        if stale and not current and not hyp.get('requires_revalidation'):
            hyp['requires_revalidation'] = True
            hyp['history'].append({'cycle': state['cycle'], 'event': 'support_stale', 'evidence': sorted(stale)})
        if hyp['contradict'] and not current and not stale:
            hyp['status'] = 'rejected'
            hyp['history'].append({'cycle': state['cycle'], 'event': 'rejected',
                                   'reason': 'Contradicting evidence with no current or stale independent support'})
            state['rejected_claims'][hyp['key']] = {
                'claim': hyp['claim'], 'evidence': hyp['support'],
                'reasons': ['contradicted'], 'cycles': [state['cycle']]}
            rejected.append(hid)
        elif hyp['contradict'] or hyp.get('requires_revalidation'):
            if hyp['status'] != 'contested':
                hyp['status'] = 'contested'
                hyp['history'].append({'cycle': state['cycle'], 'event': 'contested'})
            contested.append(hid)
        elif hyp['status'] == 'contested':
            hyp['status'] = 'active'
            hyp['history'].append({'cycle': state['cycle'], 'event': 'reinstated'})
        if hyp['status'] == 'contested':
            hyp['confidence'] = round(min(hyp['confidence'], 0.4), 4)
    while len(state['rejected_claims']) > MAX_REJECTED_MEMORY:
        state['rejected_claims'].pop(next(iter(state['rejected_claims'])))
    return {'contested': contested, 'rejected': rejected}


# ── PRIORITIZE ─────────────────────────────────────────────────────────────

def missing_information(state: dict[str, Any], global_items: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Open dependencies: what each live hypothesis still needs before it can be tested."""
    items: dict[str, dict[str, Any]] = {}
    for text in global_items:
        key = claim_key(text)
        items[key] = {'id': 'm-' + key, 'requires': str(text)[:240], 'hypotheses': [], 'source': 'model'}
    for hid, hyp in state['hypotheses'].items():
        if hyp['status'] not in {'active', 'contested'}:
            continue
        needs = list(hyp['missing_information'])
        if len(set(_support_refs(state, hyp))) < 2:
            needs.append('Independent corroborating evidence for: ' + hyp['claim'][:160])
        if not hyp['contradict'] and not hyp.get('negative_control_observed'):
            needs.append('Negative control distinguishing this claim from its alternatives')
        if hyp.get('requires_revalidation'):
            needs.append('Revalidation against changed evidence')
        for text in needs:
            key = claim_key(text)
            entry = items.setdefault(key, {'id': 'm-' + key, 'requires': text[:240],
                                           'hypotheses': [], 'source': 'kernel'})
            entry['hypotheses'] = sorted(set(entry['hypotheses']) | {hid})
    return list(items.values())


def prioritize(state: dict[str, Any], available: dict[str, dict[str, Any]],
               completed: list[str]) -> list[dict[str, Any]]:
    """Rank next analyses by expected information value over the live hypotheses."""
    live = {hid: h for hid, h in state['hypotheses'].items() if h['status'] in {'active', 'contested'}}
    done = set(state['completed_analyses']) | set(completed)
    ranked: list[dict[str, Any]] = []
    for key, follow_up in available.items():
        attached = [h for h in live.values() if h['follow_up'] == key]
        if key in done:
            ranked.append({'action': key, 'score': 0.0, 'redundant': True, 'hypotheses': [],
                           'rationale': 'Analysis already completed in this investigation.'})
            continue
        if not attached:
            ranked.append({'action': key, 'score': 0.0, 'redundant': False, 'hypotheses': [],
                           'rationale': 'No live hypothesis depends on this analysis.'})
            continue
        gain = sum(_entropy(h['confidence']) for h in attached)
        discriminates = sum(1 for h in attached if h['competes_with'])
        contested = sum(1 for h in attached if h['status'] == 'contested')
        cost = 0.1 if follow_up.get('requires_approval', True) else 0.0
        score = round(gain + 0.5 * discriminates + 0.3 * contested - cost, 4)
        ranked.append({'action': key, 'score': score, 'redundant': False,
                       'hypotheses': sorted(h['id'] for h in attached),
                       'evidence': sorted({r for h in attached for r in h['support']}),
                       'rationale': (f'Expected information {gain:.2f} bits over {len(attached)} '
                                     f'hypothesis(es); {discriminates} discriminate competing '
                                     f'explanations; {contested} contested.')})
    if live:
        # Open claims: no analysis is available for them, or their analysis completed
        # without contradicting them (an ambiguous or partial answer leaves them open).
        # A claim the completed analysis contradicted is not reopened here.
        open_ids = sorted(hid for hid, h in live.items()
                          if h['follow_up'] == NO_FOLLOW_UP or (h['follow_up'] in done and h['status'] == 'active'))
        uncertain = sum(_entropy(live[hid]['confidence']) for hid in open_ids)
        if uncertain:
            ranked.append({'action': 'collect_missing_information', 'score': round(0.5 * uncertain, 4),
                           'redundant': False, 'hypotheses': open_ids,
                           'evidence': sorted({r for hid in open_ids for r in live[hid]['support']}),
                           'rationale': 'Open hypotheses need information no available analysis supplies.'})
    ranked.sort(key=lambda item: (-item['score'], item['action']))
    return ranked


# ── PLAN / REPLAN ──────────────────────────────────────────────────────────

def plan(state: dict[str, Any], ranked: list[dict[str, Any]], completed: list[str]) -> dict[str, Any]:
    """Keep a consistent decision unless evidence or materially better options require revision."""
    cycle = state['cycle']
    active = [d for d in state['decisions'].values() if d['status'] == 'active']
    revised: list[dict[str, Any]] = []
    for decision in active:
        if decision['action'] in completed:
            decision['status'] = 'completed'
            decision['closed_cycle'] = cycle
            if decision['action'] not in state['completed_analyses']:
                state['completed_analyses'].append(decision['action'])
            continue
        dead = [hid for hid in decision['depends_on_hypotheses']
                if state['hypotheses'].get(hid, {}).get('status') not in {'active', 'contested'}]
        changed = [hid for hid in decision['depends_on_hypotheses']
                   if state['hypotheses'].get(hid, {}).get('requires_revalidation')]
        if decision['depends_on_hypotheses'] and (len(dead) == len(decision['depends_on_hypotheses']) or changed):
            decision['status'] = 'superseded'
            decision['closed_cycle'] = cycle
            decision['revision_reason'] = ('dependent hypotheses rejected or superseded' if not changed
                                           else 'supporting evidence changed')
            revised.append({'decision': decision['id'], 'reason': decision['revision_reason']})
    for item in completed:
        if item not in state['completed_analyses']:
            state['completed_analyses'].append(item)
    candidates = [r for r in ranked if not r['redundant'] and r['score'] > 0]
    best = candidates[0] if candidates else None
    current = next((d for d in state['decisions'].values() if d['status'] == 'active'), None)
    if current:
        current_rank = next((r for r in ranked if r['action'] == current['action']), None)
        current_score = current_rank['score'] if current_rank else 0.0
        if best is None or best['action'] == current['action'] or (
                best['score'] - current_score < DECISION_HYSTERESIS and current_score > 0):
            current['reaffirmed_cycles'] = [*current.get('reaffirmed_cycles', []), cycle][-20:]
            if current_rank:
                current['depends_on_hypotheses'] = current_rank['hypotheses']
                current['score'] = current_score
            return {'decision': current['id'], 'action': current['action'], 'changed': False,
                    'revised': revised}
        current['status'] = 'superseded'
        current['closed_cycle'] = cycle
        current['revision_reason'] = (f"higher information value: {best['action']} "
                                      f"{best['score']:.2f} vs {current_score:.2f}")
        revised.append({'decision': current['id'], 'reason': current['revision_reason']})
    action = best['action'] if best else 'no_further_analysis'
    did = _did(cycle, action)
    state['decisions'][did] = {
        'id': did, 'cycle': cycle, 'action': action, 'status': 'active',
        'score': best['score'] if best else 0.0,
        'rationale': best['rationale'] if best else 'No live hypothesis has an informative next analysis.',
        'depends_on_hypotheses': best['hypotheses'] if best else [],
        'depends_on_evidence': best.get('evidence', []) if best else [],
        'requires_approval': action not in {'collect_missing_information', 'no_further_analysis'},
        'executed': False, 'supersedes': [r['decision'] for r in revised]}
    while len(state['decisions']) > MAX_DECISIONS:
        oldest = next(d for d in state['decisions'] if state['decisions'][d]['status'] != 'active')
        state['decisions'].pop(oldest)
    return {'decision': did, 'action': action, 'changed': True, 'revised': revised}


# ── Full cycle ─────────────────────────────────────────────────────────────

def run_cycle(previous: dict[str, Any] | None, cycle_input: CycleInput) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one OBSERVE→…→REPLAN cycle on a copy of ``previous``.

    Returns ``(state, report)``. ``report['accepted_for_research']`` lists the
    supervisor-accepted hypotheses that may enter the persistent research queue.
    """
    state = copy.deepcopy(previous) if previous else empty_state()
    if state.get('version') != REASONING_VERSION:
        state = empty_state()
    state['cycle'] += 1
    observed = observe(state, cycle_input.evidence)
    for outcome in cycle_input.tool_outcomes[:8]:
        key = str(outcome.get('evidence_id') or outcome.get('job_id') or '')
        if key:
            state['verification_results'][key] = {**{k: v for k, v in outcome.items()
                                                     if isinstance(v, (str, int, float, bool)) or v is None},
                                                  'cycle': state['cycle']}
    while len(state['verification_results']) > 100:
        state['verification_results'].pop(next(iter(state['verification_results'])))
    analysis = analyze(state, cycle_input.interpretations, observed['changed_evidence'])
    hypothesized = hypothesize(state, cycle_input)
    # Every fact observed this cycle is checked, including against claims proposed this cycle.
    fact_contradictions = detect_fact_contradictions(state, observed['new_observations'])
    contradictions = resolve_contradictions(state)
    contradictions['from_facts'] = fact_contradictions
    needs = missing_information(state, cycle_input.missing_information)
    state['dependencies'] = {item['id']: {**item, 'status': 'open'} for item in needs}
    ranked = prioritize(state, cycle_input.available_follow_ups, cycle_input.completed_follow_ups)
    decision = plan(state, ranked, cycle_input.completed_follow_ups)
    report = {
        'cycle': state['cycle'], 'run_id': cycle_input.run_id,
        'observe': observed, 'analyze': analysis,
        'hypothesize': {k: hypothesized[k] for k in ('accepted', 'merged', 'rejected', 'retracted',
                                                     'proposal_ids')},
        'supervisor_challenges': hypothesized['challenges'],
        'contradictions': contradictions, 'missing_information': needs[:10],
        'priorities': ranked[:6], 'decision': decision,
        'accepted_for_research': [hid for hid in [*hypothesized['accepted'], *hypothesized['merged']]
                                  if state['hypotheses'][hid]['status'] in {'active', 'contested'}],
        'verification': 'unverified; no conclusion in this report is a confirmed finding',
    }
    state['cycles'] = [*state['cycles'], {k: report[k] for k in ('cycle', 'run_id', 'decision')}][-30:]
    return state, report


def planner_summary(state: dict[str, Any] | None, *, limit: int = 4,
                    focus: Iterable[str] = ()) -> dict[str, Any]:
    """Compact, bounded view for planner and review prompts.

    ``focus`` names the evidence under review: hypotheses and rejected claims that
    touch it come first, so the bound drops unrelated history, never this evidence.
    """
    if not state or not state.get('hypotheses') and not state.get('decisions'):
        return {}
    refs = set(focus)
    candidates = [h for h in state['hypotheses'].values() if h['status'] in {'active', 'contested'}]
    live = sorted(candidates, key=lambda h: (not refs & set(h['support'] + h['contradict']),
                                             -_entropy(h['confidence']), h['id']))[:limit]
    active = next((d for d in state['decisions'].values() if d['status'] == 'active'), None)
    rejected_all = list(state['rejected_claims'].values())
    rejected = sorted(rejected_all, key=lambda r: not refs & set(r.get('evidence', [])))[:limit] if refs \
        else rejected_all[-limit:]
    return {
        'cycle': state['cycle'],
        'live_hypotheses': [{k: h[k] for k in ('id', 'claim', 'status', 'support', 'contradict',
                                                'competes_with', 'confidence', 'follow_up')}
                            for h in live],
        'rejected_claims': [{'claim': r['claim'][:160], 'reasons': r['reasons']} for r in rejected],
        'open_dependencies': [d['requires'] for d in list(state.get('dependencies', {}).values())[:limit]],
        'active_decision': ({k: active[k] for k in ('id', 'action', 'rationale', 'depends_on_hypotheses')}
                            if active else None),
        'completed_analyses': list(state['completed_analyses'])[-limit:],
        'tool_outcomes': [{k: r.get(k) for k in ('capability', 'category', 'observation_count', 'evidence_id')}
                          for r in list(state.get('verification_results', {}).values())[-limit:]],
        'omitted_live_hypotheses': max(0, len(candidates) - len(live)),
        'verification': 'unverified reasoning state; grants no execution authority',
    }


def task_reasoning_context(state: dict[str, Any] | None, evidence_refs: Iterable[str],
                           *, limit: int = 4) -> dict[str, Any]:
    """Reasoning relevant to one specialist task: only claims resting on its evidence."""
    refs = set(evidence_refs)
    if not state or not refs:
        return {}
    related = [h for h in state.get('hypotheses', {}).values()
               if h['status'] in {'active', 'contested'} and refs & set(h['support'] + h['contradict'])]
    related.sort(key=lambda h: (-_entropy(h['confidence']), h['id']))
    rejected = [r for r in state.get('rejected_claims', {}).values() if refs & set(r.get('evidence', []))]
    if not related and not rejected:
        return {}
    ids = {h['id'] for h in related[:limit]}
    return {
        'hypotheses': [{k: h[k] for k in ('id', 'claim', 'status', 'support', 'contradict', 'competes_with',
                                           'confidence', 'missing_information')} for h in related[:limit]],
        'rejected_claims': [{'claim': r['claim'][:160], 'reasons': r['reasons']} for r in rejected[-limit:]],
        'open_dependencies': [d['requires'] for d in state.get('dependencies', {}).values()
                              if ids & set(d.get('hypotheses', []))][:limit],
        'instruction': ('Test or challenge these unverified hypotheses with the assigned evidence. When a '
                        'conclusion concerns one of them, set claim_id to its id and disposition to supported, '
                        'rejected or inconclusive, citing the evidence. Do not restate rejected claims without '
                        'new evidence.'),
    }


def review_needed(state: dict[str, Any] | None, evidence: list[dict[str, Any]]) -> tuple[bool, str]:
    """Supervisor decision: is a model review of this evidence informative?

    A review is skipped only when every receipt fact is already in the reasoning
    state. Re-reading identical facts cannot resolve a contested hypothesis; that
    needs new evidence (for example an approved follow-up), not another model call.
    """
    if not state or state.get('version') != REASONING_VERSION or not state.get('observations'):
        return True, 'no_prior_reasoning'
    new = 0
    for item in evidence:
        ref = str(item.get('job_id', ''))
        output = item.get('output')
        facts = output if isinstance(output, list) else [
            {'kind': 'raw', 'locator': '', 'summary': str(output or '')[:300]}]
        for fact in facts:
            if not isinstance(fact, dict):
                continue
            kind = str(fact.get('kind', 'raw'))[:40]
            locator = str(fact.get('locator', ''))[:300]
            summary = str(fact.get('summary', ''))[:300]
            oid = 'o-' + hashlib.sha256(f'{ref}:{kind}:{locator}:{summary}'.encode()).hexdigest()[:12]
            new += oid not in state['observations']
    if new:
        return True, f'{new} new receipt fact(s)'
    return False, 'no_new_receipt_facts'
