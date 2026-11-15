"""Owner-bound review response journal; never an execution or retry authority.

A claim commits before inference. An encrypted response commits before research
projection. Reconciliation can replay that exact response through idempotent
research events. A claim without a response has an unknown outcome and cannot
silently issue another physical provider request.
"""
from __future__ import annotations

import hashlib
import uuid

from memory.database_models import DecisionLog, async_session
from memory.program_policy import owned_engagement
from security.encryption import evidence_cipher

MAX_RESPONSE_CHARS = 16000


class ReviewJournalError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ReviewJournal:
    def __init__(self, session_factory=None):
        self.session_factory = session_factory or async_session

    @staticmethod
    def identity(sid: str, owner: str, run_id: str, jobs: list[str]) -> dict:
        if (any(not isinstance(value, str) or not value or len(value) > 100
                for value in (sid, owner, run_id))
                or not isinstance(jobs, list) or len(jobs) > 100
                or any(not isinstance(job, str) or not job or len(job) > 100 for job in jobs)
                or len(set(jobs)) != len(jobs)):
            raise ReviewJournalError('review_journal_invalid', 'Review journal identity is invalid.')
        return {'session_id': sid, 'owner_id': owner, 'run_id': run_id,
                'evidence_job_ids': sorted(jobs)}

    @staticmethod
    def _validate(row, binding: dict) -> dict:
        data = row.metadata_ or {}
        if (row.session_id != binding['session_id']
                or row.user_id != binding['owner_id']
                or row.decision_type != 'investigation_review_state'
                or any(data.get(key) != value for key, value in binding.items())
                or data.get('state') not in {'requested', 'response', 'failed'}):
            raise ReviewJournalError('review_journal_invalid', 'Review journal binding is invalid.')
        return dict(data)

    async def acquire(self, sid: str, owner: str, run_id: str, jobs: list[str]) -> dict:
        binding = self.identity(sid, owner, run_id, jobs)
        # One response per run: a changed receipt set requires inspection, never
        # reuse or overwrite of an earlier review under the same run identity.
        key = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-investigation-review:{sid}:{run_id}'))
        async with self.session_factory() as db:
            await owned_engagement(db, sid, owner)  # Serializes competing claims.
            row = await db.get(DecisionLog, key)
            if row is not None:
                return {**self._validate(row, binding), 'id': key, 'created': False}
            data = {**binding, 'state': 'requested', 'token': uuid.uuid4().hex}
            db.add(DecisionLog(id=key, session_id=sid, user_id=owner,
                              decision_type='investigation_review_state', metadata_=data))
            await db.commit()
            return {**data, 'id': key, 'created': True}

    async def _record(self, claim: dict, values: dict) -> None:
        sid, owner = claim['session_id'], claim['owner_id']
        binding = self.identity(sid, owner, claim['run_id'], claim['evidence_job_ids'])
        async with self.session_factory() as db:
            await owned_engagement(db, sid, owner)
            row = await db.get(DecisionLog, claim['id'])
            if row is None:
                raise ReviewJournalError('review_journal_invalid', 'Review journal claim is missing.')
            data = self._validate(row, binding)
            if (data.get('token') != claim.get('token') or data['state'] != 'requested'):
                raise ReviewJournalError('review_journal_conflict', 'Review journal claim has changed.')
            row.metadata_ = {**data, **values}
            await db.commit()

    async def capture(self, claim: dict, raw: str) -> None:
        if not isinstance(raw, str) or len(raw) > MAX_RESPONSE_CHARS:
            raise ReviewJournalError('review_response_oversized',
                                     'Review response exceeds the bounded journal contract.')
        sealed = evidence_cipher().encrypt(raw.encode()).decode()
        await self._record(claim, {'state': 'response', 'sealed_response': sealed,
                                  'response_sha256': hashlib.sha256(raw.encode()).hexdigest()})

    async def fail(self, claim: dict, code: str) -> None:
        from llm.planner_errors import MESSAGES
        # Only server-defined codes are provided here; no provider/model text.
        allowed = {'review_provider_timeout', 'review_transport_failed',
                   'review_output_truncated', 'review_provider_unavailable',
                   'review_provider_response_invalid', 'review_response_oversized',
                   'invalid_review_output', 'model_call_budget'} | MESSAGES.keys()
        if not isinstance(code, str) or code not in allowed:
            raise ReviewJournalError('review_journal_invalid', 'Review failure code is invalid.')
        await self._record(claim, {'state': 'failed', 'reason_code': code})

    @staticmethod
    def response(claim: dict) -> str:
        try:
            raw = evidence_cipher().decrypt(claim['sealed_response'].encode()).decode()
            if (len(raw) > MAX_RESPONSE_CHARS
                    or hashlib.sha256(raw.encode()).hexdigest() != claim['response_sha256']):
                raise ValueError('Invalid response digest')
            return raw
        except Exception:
            raise ReviewJournalError('review_journal_invalid',
                                     'Saved review response could not be verified.') from None


review_journal = ReviewJournal()
