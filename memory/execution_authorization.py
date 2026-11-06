"""Durable, command-bound authorization shared by every execution caller.

DecisionLog is the existing SQL ledger: no parallel in-memory approval authority.
A consumed dispatch is not retried automatically, even after a worker timeout.
"""
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, replace

import httpx
from fastapi import HTTPException
from sqlalchemy import select

from config.settings import settings
from memory.database_models import DecisionLog, PentestSession, User, async_session
from orchestrator.execution_policy import PolicyError, validate_command
from memory.worker_jobs import worker_jobs
from security.credentials import auth_revision


@dataclass(frozen=True)
class Proposal:
    id: str
    session_id: str
    requester_id: str
    command: str
    tool: str
    risk: str
    scope_hash: str
    expires_at: float
    status: str
    approver_id: str = ''
    revision: int = 0
    decision: str = ""
    turn_id: str = ""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class SQLAuthorizationStore:
    async def add(self, proposal):
        async with async_session() as db:
            db.add(DecisionLog(id=proposal.id, session_id=proposal.session_id,
                               user_id=proposal.requester_id, decision_type='execution_authorization',
                               action_taken=proposal.command, risk_color=proposal.risk,
                               human_decision=proposal.status, metadata_=asdict(proposal)))
            await db.commit()

    async def get(self, action_id):
        async with async_session() as db:
            row = (await db.execute(select(DecisionLog).where(
                DecisionLog.id == action_id, DecisionLog.decision_type == 'execution_authorization'))).scalar_one_or_none()
            return Proposal(**row.metadata_) if row else None

    async def transition(self, previous, updated):
        async with async_session() as db:
            row = (await db.execute(select(DecisionLog).where(
                DecisionLog.id == previous.id, DecisionLog.decision_type == 'execution_authorization')
                .with_for_update())).scalar_one_or_none()
            if not row or row.metadata_ != asdict(previous):
                return False
            row.metadata_ = asdict(updated)
            row.human_decision = updated.status
            row.action_taken = updated.command
            row.risk_color = updated.risk
            # Append the actor and exact command to the audit trail before dispatch.
            db.add(DecisionLog(session_id=updated.session_id,
                               user_id=updated.approver_id or updated.requester_id,
                               decision_type='execution_' + updated.status,
                               action_taken=updated.command, risk_color=updated.risk,
                               human_involved=bool(updated.approver_id), human_decision=updated.decision or updated.status,
                               metadata_={'action_id': updated.id, 'revision': updated.revision,
                                          'scope_hash': updated.scope_hash, 'command_hash': digest(updated.command)}))
            await db.commit()
            return True


async def authoritative_context(user_id, session_id, *, allow_inactive_session=False):
    if not user_id or not session_id:
        raise HTTPException(403, 'An authenticated engagement is required')
    async with async_session() as db:
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        session = (await db.execute(select(PentestSession).where(PentestSession.id == session_id))).scalar_one_or_none()
        if not user or not user.is_active or not session or not session.user_id:
            raise HTTPException(403, 'Engagement access denied')
        if user.role.value != 'admin' and session.user_id != user.id:
            raise HTTPException(403, 'Engagement access denied')
        if not allow_inactive_session and session.status.value != 'active':
            raise HTTPException(403, 'Engagement is not active')
        scope = dict(session.scope or {})
        if session.attack_mode == 'bug_bounty':
            scope['mode'] = 'bug_bounty'
        metadata = getattr(session, 'metadata_', None)
        metadata = metadata if isinstance(metadata, dict) else {}
        return {'owner_id': session.user_id, 'scope': scope, 'auth_revision': auth_revision(user),
                'worker_epoch': int(metadata.get('worker_epoch', 0)),
                'worker_blocked': bool(metadata.get('worker_blocked', False))}


class ExecutionAuthorization:
    def __init__(self, store=None, context_loader=None, worker=None):
        self.store = store or SQLAuthorizationStore()
        self.context_loader = context_loader or authoritative_context
        self.worker = worker or self._worker

    async def _context(self, user_id, session_id, *, allow_blocked=False):
        try:
            context = await self.context_loader(user_id, session_id)
            if context.get("worker_blocked") and not allow_blocked:
                raise HTTPException(409, "Engagement execution is fenced")
            return context
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(503, 'Authorization storage unavailable') from None

    def _validate(self, command, context, tool=''):
        try:
            return validate_command(command, context['scope'], tool)
        except (PolicyError, ValueError, TypeError, KeyError):
            raise HTTPException(403, 'Command is not permitted by engagement policy') from None

    async def _stored(self, operation, *args):
        try:
            return await operation(*args)
        except Exception:
            raise HTTPException(503, 'Authorization storage unavailable') from None

    async def propose(self, user_id, session_id, command, tool='', require_approval=False, turn_id=''):
        context = await self._context(user_id, session_id)
        validated = self._validate(command, context, tool)
        proposal = Proposal(str(uuid.uuid4()), session_id, user_id, validated.command,
                            validated.tool, validated.risk, digest(context), time.time() + 600,
                            'pending' if validated.risk == 'red' or require_approval else 'authorized', turn_id=turn_id)
        await self._stored(self.store.add, proposal)
        return proposal

    async def _load(self, action_id, user_id, session_id, requester=False):
        context = await self._context(user_id, session_id)
        proposal = await self._stored(self.store.get, action_id)
        if (not proposal or proposal.session_id != session_id or proposal.expires_at <= time.time()
                or proposal.scope_hash != digest(context) or (requester and proposal.requester_id != user_id)):
            raise HTTPException(403, 'Authorization is absent, expired or no longer valid')
        return proposal, context

    async def decide(self, user_id, session_id, action_id, decision, modified_command=''):
        proposal, context = await self._load(action_id, user_id, session_id)
        if decision not in {'approve', 'modify', 'reject'} or proposal.status != 'pending':
            raise HTTPException(409, 'Authorization is not pending')
        if decision == 'modify' and not modified_command.strip():
            raise HTTPException(422, 'A modified command is required')
        validated = self._validate(modified_command if decision == 'modify' else proposal.command, context)
        updated = replace(proposal, command=validated.command, tool=validated.tool, risk=validated.risk,
                          status='rejected' if decision == 'reject' else 'approved',
                          approver_id=user_id, revision=proposal.revision + 1, decision=decision)
        if not await self._stored(self.store.transition, proposal, updated):
            raise HTTPException(409, 'Authorization changed concurrently')
        return updated

    async def execute(self, user_id, session_id, command, tool='', action_id='', timeout=120, executor=None, expected_revision=None, expected_worker_epoch=None):
        if not action_id:
            # Legacy callers may request passive/scanning commands, but red-risk
            # requests cannot create their own approval. Every dispatch is durable.
            proposal = await self.propose(user_id, session_id, command, tool)
            action_id = proposal.id
        proposal, context = await self._load(action_id, user_id, session_id, requester=True)
        if expected_revision is not None and context.get("auth_revision", 0) != expected_revision:
            raise HTTPException(403, "Run credentials were revoked")
        if expected_worker_epoch is not None and context.get("worker_epoch", 0) != expected_worker_epoch:
            raise HTTPException(403, "Run was invalidated by cancellation")
        validated = self._validate(command, context, tool)
        if proposal.command != validated.command or proposal.tool != validated.tool:
            raise HTTPException(403, 'Authorization does not match this command')
        if proposal.status not in {'approved', 'authorized'} or (validated.risk == 'red' and proposal.status != 'approved'):
            raise HTTPException(403, 'Explicit command-bound approval is required')
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            raise HTTPException(422, 'Invalid timeout') from None
        if not 1 <= timeout <= settings.AUTONOMOUS_STEP_TIMEOUT_SECONDS:
            raise HTTPException(422, 'Timeout exceeds policy limit')
        if validated.tool == 'aria-http' and timeout > 10:
            raise HTTPException(422, 'Authenticated HTTP is bounded to ten seconds')
        claimed = replace(proposal, status='consumed', revision=proposal.revision + 1)
        if not await self._stored(self.store.transition, proposal, claimed):
            raise HTTPException(409, 'Authorization already consumed')
        # Claim commits before contacting the worker; a timeout cannot replay it.
        if context['scope'].get('program_policy') and executor is not None:
            raise HTTPException(403, 'Program traffic requires the budgeted isolated worker')
        if context['scope'].get('program_policy') and settings.KALI_WORKER_PROTOCOL != 'jobs-v1':
            raise HTTPException(403, 'Program traffic requires jobs-v1')
        if validated.tool == 'aria-http' and (executor is not None or settings.KALI_WORKER_PROTOCOL != 'jobs-v1'):
            raise HTTPException(403, 'Authenticated HTTP requires the reviewed jobs worker')
        if executor is not None:
            output = await executor({'tool': validated.tool, 'command': validated.command, 'risk_color': validated.risk})
            return {'stdout': str(output), 'stderr': '', 'exit_code': 0, 'turn_id': proposal.turn_id}
        if self.worker == self._worker:
            result = await self._worker(validated.command, session_id, timeout, job_id=proposal.id, user_id=user_id)
        else:
            result = await self.worker(validated.command, session_id, timeout)
        return {**result, "turn_id": proposal.turn_id}

    async def _worker(self, command, session_id, timeout, *, job_id=None, user_id=None):
        if not job_id or not user_id:
            raise HTTPException(403, "Authorized job identity is required")
        async def check():
            proposal, context = await self._load(job_id, user_id, session_id, requester=True)
            validated = self._validate(command, context)
            if proposal.status != 'consumed' or proposal.command != validated.command:
                raise HTTPException(403, 'Dispatch authorization changed')
            if validated.tool == 'aria-http':
                from memory.application_map import application_map
                from worker.http_profile import parse
                args = parse(command)
                current, _ = await application_map.replay_material(session_id, user_id, args[1], args[2])
                if current != validated.command:
                    raise HTTPException(403, 'HTTP identity/request binding changed')
            return context
        return await worker_jobs.execute(job_id, user_id, session_id, command, timeout, authorization_check=check)


execution_authorization = ExecutionAuthorization()
