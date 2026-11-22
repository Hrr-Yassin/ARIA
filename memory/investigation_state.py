"""Persistent investigation reasoning state on the owner-bound team ledger.

One revisioned entity per engagement holds observations, assumptions,
hypotheses with supporting and contradicting evidence, decisions, open
dependencies and verification results produced by ``orchestrator.reasoning``.
Each cycle is an immutable ledger event with an idempotent request identity,
so a retried review replays the same cycle instead of reasoning twice.

The state grants no scope, execution or verification authority.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import HTTPException

from memory.team_tasks import digest, team_store
from orchestrator.reasoning import CycleInput, run_cycle

COLLECTION = 'investigation_reasoning'
ENTITY = 'current'


def worker_evidence_request(sid: str, job_id: str) -> uuid.UUID:
    """The single catalog identity of a worker receipt, shared by every reasoning path."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f'research-evidence:{sid}:{job_id}')


async def canonical_worker_evidence(sid: str, owner: str, job_ids: list[str]) -> dict[str, str]:
    """Map worker job IDs to their ledger evidence IDs, cataloging receipts idempotently.

    The ledger evidence ID is the canonical identifier used by reasoning,
    specialists and research; worker job IDs remain the model-facing citation.
    """
    from memory.team_tasks import EvidenceInput
    mapping: dict[str, str] = {}
    for job_id in dict.fromkeys(job_ids):
        event = await team_store.catalog(sid, owner, EvidenceInput(
            request_id=worker_evidence_request(sid, job_id), source_kind='worker', source_id=job_id))
        mapping[job_id] = event['data']['id']
    return mapping


def evidence_aliases(view: dict[str, Any]) -> dict[str, str]:
    """Ledger evidence ID -> worker job ID for cataloged worker receipts."""
    return {e['id']: e['source_id'] for e in view.get('evidence', [])
            if e.get('source_kind') == 'worker' and isinstance(e.get('source_id'), str)}


class InvestigationStateStore:
    async def current(self, sid: str, owner: str) -> dict[str, Any]:
        ledger = await team_store.view(sid, owner)
        return next(iter(ledger.get(COLLECTION, [])), {})

    async def snapshot(self, sid: str, owner: str) -> tuple[dict[str, Any], dict[str, str]]:
        """Reasoning record plus ledger-to-worker evidence aliases from one ledger read."""
        ledger = await team_store.view(sid, owner)
        return next(iter(ledger.get(COLLECTION, [])), {}), evidence_aliases(ledger)

    async def advance(self, sid: str, owner: str, cycle_key: str,
                      cycle_input: CycleInput) -> tuple[dict[str, Any], dict[str, Any]]:
        """Run and persist one reasoning cycle against the latest durable state.

        ``cycle_key`` must identify the logical review (for example its run and
        evidence identities). Replaying the same key returns the stored cycle.
        """
        request_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-reasoning:{sid}:{cycle_key}'))
        operation = {'reasoning_cycle': cycle_key}
        captured: dict[str, Any] = {}

        async def build(db, session, state):
            previous = state[COLLECTION].get(ENTITY) or None
            reasoning, report = run_cycle(previous and previous.get('state'), cycle_input)
            revision = (previous or {}).get('revision', 0) + 1
            if previous and previous.get('scope_digest') not in (None, digest(session.scope or {})):
                # Scope changed: every prior conclusion needs revalidation.
                for hyp in reasoning['hypotheses'].values():
                    if hyp['status'] in {'active', 'contested'}:
                        hyp['requires_revalidation'] = True
            captured['report'] = report
            return COLLECTION, ENTITY, {
                'id': ENTITY, 'revision': revision, 'cycle_key': cycle_key,
                'scope_digest': digest(session.scope or {}), 'state': reasoning, 'last_report': report,
                'verification': 'unverified reasoning state; no execution authority'}

        event = await team_store.mutate(sid, owner, request_id, operation, build)
        data = event.get('data') or {}
        if event.get('duplicate'):
            if data.get('cycle_key') != cycle_key:
                raise HTTPException(409, 'Reasoning cycle identity conflict')
            return data.get('state', {}), data.get('last_report', {})
        return data.get('state', {}), captured.get('report', data.get('last_report', {}))


investigation_state = InvestigationStateStore()
