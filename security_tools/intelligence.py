"""Tool readiness, outcome classification, objective-driven selection and reasoning integration (P2).

This module sits outside the reviewed adapter contract (``contract_digest``):
changing it never invalidates approvals or the worker registry hash. It grants
no execution authority. Recommendations are proposals that still require the
existing command-bound owner approval; nothing here dispatches a tool.
"""
from __future__ import annotations

import math
import re
from typing import Any, Iterable

from security_tools.adapters import ADAPTERS, AdapterError, decode, encode, sha256

# Retained runtime validation (docs/tool-adapters.md, Kali rootless Podman,
# isolated 192.168.77.20/32 lab). A capability is "validated" only when the worker
# advertises it with this exact declared version and image identity.
VALIDATION_BASELINE: dict[str, dict[str, Any]] = {
    'nmap.tcp.connect.v1': {'version': '7.93', 'image_id': 'sha256:b8982e2e539f7503ee91e3cb038600322eae1c924bc9722305f04bea3a72f7e7',
                            'runtime_validated': True, 'receipt_job': '6f67dfc2-436c-4b9a-a5b6-593d3ae0a0a5'},
    'httpx.http.probe.v1': {'version': '1.7.1', 'image_id': 'sha256:938b67c9ac2ff95a72af3d09fd0acfa93962f0acfd923738d0bcf871936d6693',
                            'runtime_validated': True, 'receipt_job': '90e6cb9c-6984-4966-9346-2dabf74ba4f6'},
    'nuclei.http.observe.v1': {'version': '3.4.10', 'image_id': 'sha256:118601592a0d69199c1bbb4c9f058f68f6fc7612f98aa6f3f56fcca2e1b1f366',
                               'runtime_validated': True, 'receipt_job': 'e97894e8-2945-4602-adf4-bc727d9f6e3c'},
    'ffuf.http.paths.v1': {'version': '2.1.0', 'image_id': 'sha256:eaca8423a30b0adb87eba31d71ac95c0ade7c15d01a22123dc1b92fd154fa3b4',
                           'runtime_validated': True, 'receipt_job': 'e00652ea-43d9-4dc9-b2d7-d1084714b851'},
    'semgrep.source.scan.v1': {'version': '1.99.0', 'image_id': 'sha256:134a95690847b7a53eb06f2b712517aa889f25bc5f4a63e2c5f5755042db07ee',
                               'runtime_validated': True, 'receipt_job': 'ffcda00a-399e-4f2b-852d-466daaa06459'},
    'subfinder.domain.passive.v1': {'version': '2.9.0', 'image_id': 'sha256:16bd43a00838d1898a874840a8f3673a65504490c2893a4c83c4d7b59b88381f',
                                    'runtime_validated': True, 'receipt_job': 'bd3b9f21-26c5-4851-9cc7-229e7999f2a7',
                                    'limitation': 'offline fixture source only'},
    'katana.http.crawl.v1': {'version': '1.1.2', 'runtime_validated': False,
                             'limitation': 'exit 137 at the 256 MiB memory limit; crawl did not complete'},
    'playwright.browser.observe.v1': {'version': '1.56.0', 'runtime_validated': False,
                                      'limitation': 'Chromium sandbox failed under the container security policy'},
    'zap.http.passive.v1': {'version': '2.16.1', 'runtime_validated': False,
                            'limitation': 'exhausted the 128 MiB /tmp envelope during the version probe'},
    'sqlmap.http.boolean.v1': {'version': '1.9.11', 'runtime_validated': False,
                               'limitation': 'worker could not start the isolated job'},
}
_VERSION = re.compile(r'^[0-9]+(?:\.[0-9]+)+[a-zA-Z0-9.+_-]*$')


# ── Capability discovery and version compatibility ─────────────────────────

def readiness(advertisement: dict[str, Any] | None, *, local_digest: str,
              blocked: Iterable[str] = (), worker_status: str = 'online') -> dict[str, Any]:
    """Explain per capability whether it is ready, and why not.

    ``advertisement`` is the worker's authenticated ``/capabilities`` payload.
    Missing version pins are reported as unconfirmed rather than assumed.
    """
    advertised = (advertisement or {}).get('typed_adapters') or {}
    pins = (advertisement or {}).get('typed_profile_pins') or {}
    worker_digest = (advertisement or {}).get('typed_registry_sha256')
    if worker_status != 'online' or advertisement is None:
        contract = 'worker_unavailable'
    elif worker_digest is None:
        contract = 'not_reported'
    elif worker_digest == local_digest:
        contract = 'matched'
    else:
        contract = 'mismatch'
    blocked_set = set(blocked)
    entries = []
    for adapter in ADAPTERS.values():
        capability = adapter.capability
        baseline = VALIDATION_BASELINE.get(capability, {})
        pin = pins.get(capability) if isinstance(pins, dict) else None
        version = pin.get('declared_version') if isinstance(pin, dict) else None
        version = version if isinstance(version, str) and _VERSION.match(version) else None
        image = pin.get('image_id') if isinstance(pin, dict) else None
        image = image if isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image) else None
        available = type(advertised.get(capability)) is int and advertised.get(capability) == 1
        reasons: list[str] = []
        if not available:
            reasons.append('worker_capability_unavailable')
        if not baseline.get('runtime_validated'):
            reasons.append('not_runtime_validated')
        if contract == 'mismatch':
            reasons.append('worker_contract_mismatch')
        elif contract in {'not_reported', 'worker_unavailable'}:
            reasons.append('worker_contract_unconfirmed')
        if available and version is None:
            reasons.append('version_unpinned')
        elif version and baseline.get('version') and version != baseline['version']:
            reasons.append('version_drift')
        if available and image is None:
            reasons.append('image_unpinned')
        elif image and baseline.get('image_id') and image != baseline['image_id']:
            reasons.append('image_drift')
        if capability in blocked_set:
            reasons.append('blocked_by_owner')
        if not available:
            status = 'unavailable'
        elif 'blocked_by_owner' in reasons:
            status = 'blocked'
        elif not baseline.get('runtime_validated'):
            status = 'unvalidated'
        elif {'worker_contract_mismatch', 'version_drift', 'image_drift'} & set(reasons):
            status = 'incompatible'
        elif {'version_unpinned', 'image_unpinned', 'worker_contract_unconfirmed'} & set(reasons):
            status = 'unconfirmed'
        else:
            status = 'ready'
        entries.append({'capability': capability, 'tool': adapter.name, 'status': status,
                        'ready': status == 'ready', 'selectable': status in {'ready', 'unconfirmed'},
                        'reasons': reasons, 'declared_version': version, 'validated_version': baseline.get('version'),
                        'image_id': image, 'validation_receipt_job': baseline.get('receipt_job'),
                        'limitation': baseline.get('limitation'), 'risk': adapter.risk, 'role': adapter.role})
    return {'worker_status': worker_status, 'contract': contract, 'local_registry_sha256': local_digest,
            'capabilities': entries,
            'summary': {status: sum(e['status'] == status for e in entries)
                        for status in ('ready', 'unconfirmed', 'incompatible', 'unvalidated', 'blocked', 'unavailable')},
            'authorization': 'Readiness grants no execution permission; each run needs owner approval.'}


# ── Outcome classification ────────────────────────────────────────────────

OUTCOMES: dict[str, tuple[bool, str]] = {
    'observed': (False, 'Interpret the unverified observations.'),
    'no_observations': (False, 'The tool completed without observations; record the negative result.'),
    'tool_failure': (True, 'Inspect the receipt stderr digest; retry only with a new approval.'),
    'timeout': (True, 'Narrow the operation or request a larger approved timeout.'),
    'resource_exhausted': (False, 'The worker resource envelope is too small; do not retry unchanged.'),
    'cancelled': (False, 'Cancelled before completion; no evidence was produced.'),
    'malformed_output': (False, 'Output failed parsing or scope checks; treat the receipt as origin-only.'),
    'truncated': (False, 'Output exceeded the bounded contract; narrow the operation.'),
    'unknown': (False, 'Outcome is unknown; inspect the job before any retry.'),
}


def classify_outcome(state: str, output: dict[str, Any], exit_code: int | None = None) -> dict[str, Any]:
    """Map a typed result to an operator-facing category, retryability and next action."""
    error = output.get('error', 'unknown')
    count = len(output.get('observations') or [])
    if state == 'cancelled' or error == 'cancelled':
        category = 'cancelled'
    elif output.get('truncated'):
        category = 'truncated'
    elif error == 'none':
        category = 'observed' if count else 'no_observations'
    elif error == 'timeout':
        category = 'timeout'
    elif error == 'resource_exhausted':
        category = 'resource_exhausted'
    elif error == 'invalid_output':
        category = 'malformed_output'
    elif error == 'tool_failed':
        category = 'tool_failure'
    else:
        category = 'unknown'
    retryable, action = OUTCOMES[category]
    return {'category': category, 'retryable': retryable, 'operator_action': action,
            'observation_count': count, 'adapter_error': error, 'state': state,
            'exit_code': exit_code if type(exit_code) is int else None,
            'evidence_usable': category in {'observed', 'no_observations'}}


# ── Objective-driven selection ─────────────────────────────────────────────

_NEEDS = (
    ('ffuf.http.paths.v1', re.compile(r'\b(path|paths|endpoint|directory|admin|/[a-z0-9_-]+)\b', re.I),
     'distinguishes path hypotheses with a bounded status comparison'),
    ('nuclei.http.observe.v1', re.compile(r'\b(technology|fingerprint|template|product|framework|header)\b', re.I),
     'captures one pinned informational observation of the response'),
    ('httpx.http.probe.v1', re.compile(r'\b(http|web|page|response|title|status|maintenance|redirect)\b', re.I),
     'observes the current HTTP response, status and title'),
    ('nmap.tcp.connect.v1', re.compile(r'\b(port|service|tcp|listen|open|closed|host)\b', re.I),
     'observes whether the approved TCP ports accept connections'),
)


def _entropy(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def _operation(capability: str, target: str, scope: dict[str, Any]) -> dict[str, Any] | None:
    """Smallest in-scope operation for a capability, or None when scope cannot express it."""
    ports = [p for p in scope.get('ports', []) if type(p) is int][:8]
    scheme_port = next((p for p in ports if p in {80, 443, 8080, 8443}), None)
    url = None
    if target:
        url = target if target.startswith(('http://', 'https://')) else (
            f'https://{target}' if scheme_port in {443, 8443} else f'http://{target}'
            + (f':{scheme_port}' if scheme_port not in {None, 80, 443} else ''))
    name = capability.split('.', 1)[0]
    if name == 'nmap':
        host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
        return {'tool': 'nmap', 'parameters': {'host': host, 'ports': ports}} if host and ports else None
    if name in {'httpx', 'nuclei'} and url:
        return {'tool': name, 'parameters': {'url': url}}
    if name == 'ffuf' and url:
        return {'tool': 'ffuf', 'parameters': {'url': url, 'words': ['admin', 'test']}}
    return None


def select_tools(reasoning_state: dict[str, Any] | None, readiness_report: dict[str, Any], *,
                 target: str, scope: dict[str, Any], executed_requests: Iterable[str] = (),
                 objective: str = '', limit: int = 3) -> list[dict[str, Any]]:
    """Rank in-scope, ready tools by the information they add to live hypotheses.

    Inputs are the P0 reasoning state (live hypotheses and open dependencies),
    the readiness report, the engagement scope and already-executed canonical
    requests (encoded commands or their SHA-256 request digests); prior tool
    outcomes in the reasoning state count as executed. Output entries are proposals that require owner approval.
    """
    state = reasoning_state or {}
    live = [h for h in state.get('hypotheses', {}).values() if h['status'] in {'active', 'contested'}]
    needs = [d['requires'] for d in state.get('dependencies', {}).values()]
    selectable = {e['capability']: e for e in readiness_report.get('capabilities', []) if e['selectable']}
    executed = set(executed_requests) | {r['request_sha256'] for r in state.get('verification_results', {}).values()
                                         if isinstance(r.get('request_sha256'), str)}
    ranked: dict[str, dict[str, Any]] = {}
    for capability, pattern, purpose in _NEEDS:
        entry = selectable.get(capability)
        if not entry:
            continue
        addressed = [h for h in live if pattern.search(h['claim'])]
        gaps = [n for n in needs if pattern.search(n)]
        objective_hit = bool(objective and pattern.search(objective))
        if not addressed and not gaps and not objective_hit:
            continue
        operation = _operation(capability, target, scope)
        if operation is None:
            continue
        try:
            command = encode(operation)
            adapter, parameters = decode(command)
            adapter.validate_scope(parameters, scope)
        except (AdapterError, ValueError, TypeError):
            continue
        if command in executed or sha256(command) in executed:
            continue
        value = (sum(_entropy(h['confidence']) for h in addressed)
                 + 0.5 * sum(1 for h in addressed if h['status'] == 'contested')
                 + 0.25 * len(gaps) + (0.3 if objective_hit else 0.0))
        if entry['status'] != 'ready':
            value *= 0.5      # unconfirmed versions are usable only with an explicit caveat
        ranked[capability] = {
            'capability': capability, 'operation': operation, 'request': command,
            'information_value': round(value, 4), 'readiness': entry['status'],
            'readiness_reasons': entry['reasons'], 'purpose': purpose,
            'addresses_hypotheses': sorted(h['id'] for h in addressed)[:6],
            'addresses_dependencies': gaps[:4], 'requires_approval': True, 'executed': False,
            'risk': entry['risk']}
    return sorted(ranked.values(), key=lambda r: (-r['information_value'], r['capability']))[:limit]


# ── Integration with P0 reasoning and P1 orchestration ─────────────────────

def tool_cycle_input(evidence_id: str, result: dict[str, Any], run_id: str = ''):
    """Observation-only reasoning cycle for one typed tool result."""
    from orchestrator.reasoning import CycleInput
    output = result.get('output') or {}
    provenance = result.get('provenance') or {}
    outcome = classify_outcome(result.get('state', 'unknown'), output, result.get('exit_code'))
    facts = [{'kind': o.get('kind', 'observation'), 'locator': o.get('locator', ''),
              'summary': str(o.get('summary', ''))[:300]} for o in (output.get('observations') or [])[:32]]
    return CycleInput(
        evidence=[{'job_id': evidence_id, 'output': facts}] if outcome['evidence_usable'] else [],
        interpretations=[], hypotheses=[], available_follow_ups={}, run_id=run_id,
        tool_outcomes=[{'evidence_id': evidence_id, 'job_id': provenance.get('job_id'),
                        'capability': result.get('capability'), **outcome,
                        'request_sha256': provenance.get('request_sha256'),
                        'output_sha256': provenance.get('output_sha256'),
                        'declared_tool_version': provenance.get('declared_tool_version'),
                        'image_id': provenance.get('image_id')}])


async def ingest_tool_result(sid: str, owner: str, result: dict[str, Any]) -> dict[str, Any]:
    """Catalog a typed result under its canonical ledger ID and feed it to reasoning.

    Changed facts mark dependent hypotheses for revalidation; the P1 coordinator
    then replans on its next advance. Unusable outcomes are recorded, not observed.
    """
    from memory.investigation_state import canonical_worker_evidence, investigation_state
    provenance = result.get('provenance') or {}
    job_id = provenance.get('job_id')
    if not isinstance(job_id, str) or not job_id:
        outcome = classify_outcome(result.get('state', 'unknown'), result.get('output') or {})
        return {'status': 'not_ingested', 'reason': 'no verified receipt', 'outcome': outcome}
    canonical = await canonical_worker_evidence(sid, owner, [job_id])
    evidence_id = canonical[job_id]
    _, report = await investigation_state.advance(
        sid, owner, f'tool:{job_id}', tool_cycle_input(evidence_id, result, run_id=job_id))
    return {'status': 'ingested', 'evidence_id': evidence_id,
            'outcome': classify_outcome(result.get('state', 'unknown'), result.get('output') or {}),
            'changed_evidence': report['observe']['changed_evidence'],
            'requires_revalidation': report['analyze']['requires_revalidation'],
            'decision': report['decision']}
