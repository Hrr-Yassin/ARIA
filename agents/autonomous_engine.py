"""
PentestAI v10 — Autonomous Execution Engine
===========================================

The central new component of v10. Implements the full cycle:

    plan → auto_execute(green/orange) → structured_parse → kb_update → re_plan → …

CRITICAL ACADEMIC-BRIEF ALIGNMENT:
    The project brief states: "L'exploitation assistée par l'IA mais validée
    par l'humain" and "Toute action critique doit être explicitement validée
    par l'humain".

    This engine HARD-BLOCKS on any risk_color == "red" step. The loop emits a
    [WAITING_APPROVAL] event and awaits a human decision via
    `provide_approval_decision()`. Nothing bypasses this gate.

    The AUTO_RISK_THRESHOLD setting further restricts auto-execution:
        - "green_only"   → only green auto-runs
        - "green_orange" → green + orange auto-run (default; brief-aligned)

Every autonomous step writes a DecisionLog row for complete traceability —
the jury can replay exactly which decisions were AI-made vs human-validated.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict, List, Optional, Any

import httpx
import structlog

from config.settings import settings
from memory.execution_authorization import execution_authorization
from memory.worker_jobs import worker_jobs
from memory.autonomous_runs import (
    CheckpointAccessError,
    CheckpointConflict,
    CheckpointError,
    CheckpointIntegrityError,
    CheckpointStateError,
    MAX_MODEL_CALLS,
    RESTORABLE_BLOCKED_REASONS,
    TERMINAL,
    command_digest,
    run_store,
    validate_checkpoint,
)
from orchestrator.risk_scorer import classify_risk
from config.tools_registry import TOOL_AGENT_MAP
from memory.attack_knowledge_base import attack_kb
from memory.knowledge_store import knowledge_store, scope_identity_digest
from memory.parsers import dispatch_parser

log = structlog.get_logger("autonomous_engine")


def _objective_text(value) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.replace("\x00", " ").split())


def _normalize_objective(value) -> str:
    """Preserve the user's objective as one bounded, control-free string."""
    return _objective_text(value)[:settings.AUTONOMOUS_OBJECTIVE_MAX_CHARS]


def _campaign_supervisor_token(value) -> str:
    """Accept only an internal, bounded supervisor lease token."""
    if not isinstance(value, str) or not value or len(value) > 128:
        return ""
    return value


def required_observations(goal: str) -> tuple[str, ...]:
    """Measurable observations needed to complete a supported goal."""
    if goal == "discovery":
        return ("port_discovery", "http_response")
    if goal == "http_check":
        return ("http_response",)
    return ()


def command_was_executed(state: "SessionRunState", command: str) -> bool:
    """Replay guard: exact match, plus a digest that survives snapshot redaction."""
    return (command in state.executed_commands
            or command_digest(command) in state.executed_command_hashes)


def completion_criteria_text(goal: str) -> str:
    required = required_observations(goal)
    if required:
        return ("Completion requires durable current-run worker receipts for: "
                + ", ".join(required)
                + ". Each observation must be backed by a successful worker job with "
                  "non-empty output; planner claims or model statements do not satisfy completion.")
    return ("Completion requires verified execution evidence for the requested objective; "
            "planner claims or model statements do not satisfy completion.")


def observation_completion(state: "SessionRunState") -> dict:
    """Deterministic completion status based on durable worker receipts, not claims."""
    required = required_observations(state.goal)
    recorded = state.observation_job_ids if isinstance(state.observation_job_ids, dict) else {}
    satisfied = [observation for observation in required
                 if any(isinstance(job_id, str) and job_id
                        for job_id in recorded.get(observation, []))]
    missing = [observation for observation in required if observation not in satisfied]
    return {
        "required": list(required),
        "satisfied": satisfied,
        "missing": missing,
        "completed_observations": list(state.completed_observations),
        "evidence_job_ids": list(state.evidence_job_ids),
        "basis": "durable_worker_receipts",
        "complete": bool(required) and not missing,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Data shapes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ApprovalRequest:
    """A pending red-risk step waiting for human decision."""
    action_id: str
    session_id: str
    step_number: int
    command: str
    tool: str
    risk_color: str
    purpose: str
    created_at: float = field(default_factory=time.time)
    decision: Optional[str] = None      # None | "approve" | "reject" | "modify"
    modified_command: str = ""


@dataclass
class AutoActivityEvent:
    """Event streamed over WebSocket for each autonomous step."""
    type: str = "auto_activity"
    step: int = 0
    action: str = ""
    tool: str = ""
    risk_color: str = "green"
    status: str = "running"             # running | done | failed | waiting_approval
    output_preview: str = ""
    kb_updates: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "step": self.step,
            "action": self.action,
            "tool": self.tool,
            "risk_color": self.risk_color,
            "status": self.status,
            "output_preview": self.output_preview,
            "kb_updates": self.kb_updates,
            "timestamp": self.timestamp,
            **self.extra,
        }


@dataclass
class SessionRunState:
    """Per-session autonomous run state."""
    session_id: str
    user_id: str
    goal: str
    target: str
    skill_level: str
    objective: str = ""
    objective_truncated: bool = False
    started_at: float = field(default_factory=time.time)
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    auth_revision: int = 0
    worker_epoch: int = 0
    subscribers: set = field(default_factory=set, repr=False)
    max_steps: int = 12
    steps_taken: int = 0
    run_state: str = "planning"
    reason_code: str = ""
    reason: str = ""
    failure_detail: str = ""
    capabilities: dict = field(default_factory=dict)
    successful_steps: int = 0
    evidence_job_ids: list = field(default_factory=list)
    completed_observations: list = field(default_factory=list)
    observation_job_ids: dict = field(default_factory=dict)
    executed_commands: list = field(default_factory=list)
    executed_command_hashes: list = field(default_factory=list)
    model_calls: int = 0
    risk_threshold: str = settings.AUTO_RISK_THRESHOLD
    active: bool = True
    current_phase: str = "recon"
    pending_approval: Optional[ApprovalRequest] = None
    stop_requested: bool = False
    pause_requested: bool = False
    event_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    activity_log: List[dict] = field(default_factory=list)
    owner_id: str = ""  # Session owner; may differ from an admin actor in user_id.
    scope_digest: str = ""
    last_action_id: str = ""
    last_action_command: str = ""
    # SPEC-13: only a durable campaign runs the specialist review phase.
    campaign_id: str = ""
    # Transient proof that a live campaign supervisor owns this run.  It is
    # never serialized into checkpoints or public status.
    campaign_supervisor_token: str = field(default="", repr=False)
    specialist_phase_done: bool = False
    specialist_investigation_ids: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  AutonomousEngine
# ─────────────────────────────────────────────────────────────────────────────
class AutonomousEngine:
    """
    Drives the autonomous cycle for a single session.

    Usage:
        engine = AutonomousEngine()
        # Start
        asyncio.create_task(engine.autonomous_cycle(session_id, user_id, ...))
        # Stream activity
        async for event in engine.stream_events(session_id):
            await websocket.send_json(event)
        # Stop
        engine.request_stop(session_id)
    """

    MAX_STEPS = settings.AUTONOMOUS_MAX_STEPS
    MAX_MODEL_CALLS = MAX_MODEL_CALLS
    STEP_TIMEOUT = settings.AUTONOMOUS_STEP_TIMEOUT_SECONDS
    STEP_DELAY = settings.AUTONOMOUS_STEP_DELAY_SECONDS

    def __init__(self):
        self._runs: Dict[str, SessionRunState] = {}
        self._tasks = {}
        self._start_locks = {}
        # Queue of pending approvals per session
        self._approvals: Dict[str, Dict[str, ApprovalRequest]] = {}
        # Injectable only for offline tests; production reads campaign_store.
        self.campaign_loader = None

    # ────────────────────────────────────────────────────────────────────
    #  Public API — lifecycle
    # ────────────────────────────────────────────────────────────────────

    async def start(self, session_id: str, user_id: str, **kwargs):
        async with self._start_locks.setdefault(session_id, asyncio.Lock()):
            task = self._tasks.get(session_id)
            if task is not None and not task.done():
                return {"status": "already_running"}
            return await self._start(session_id, user_id, **kwargs)

    async def _start(self, session_id: str, user_id: str,
                    goal: str = "discovery",
                    target: str = "",
                    skill_level: str = "intermediate", max_steps: Optional[int] = None,
                    auto_risk_threshold: Optional[str] = None,
                    objective: str = "", campaign_id: str = "",
                    campaign_supervisor_token: str = "") -> dict:
        """Create a run state and kick off the loop in a background task."""
        context = await execution_authorization._context(user_id, session_id)
        execution_authorization._validate("searchsploit scope-check", context)
        if session_id in self._runs and self._runs[session_id].active:
            return {"status": "already_running",
                    "steps_taken": self._runs[session_id].steps_taken}

        original_objective = _normalize_objective(objective)
        objective_truncated = (len(_objective_text(objective))
                               > settings.AUTONOMOUS_OBJECTIVE_MAX_CHARS)
        if not original_objective:
            # Deterministic restatement when the caller did not supply free text.
            original_objective = (f"Complete a {goal.replace('_', ' ')} assessment of "
                                  f"{target or 'the authorized target'} within the authorized scope.")
        state = SessionRunState(
            session_id=session_id, user_id=user_id,
            owner_id=context.get("owner_id") or user_id,
            goal=goal, target=target, skill_level=skill_level,
            objective=original_objective, objective_truncated=objective_truncated,
            max_steps=min(max_steps or self.MAX_STEPS, self.MAX_STEPS),
            auth_revision=context.get("auth_revision", 0),
            worker_epoch=context.get("worker_epoch", 0),
            scope_digest=(context.get("scope_digest")
                          or scope_identity_digest(context.get("scope") or {},
                                                   context.get("target", ""))),
            campaign_id=_objective_text(campaign_id)[:100],
            campaign_supervisor_token=_campaign_supervisor_token(
                campaign_supervisor_token),
        )
        state.risk_threshold = "green_only" if "green_only" in {settings.AUTO_RISK_THRESHOLD,auto_risk_threshold} else "green_orange" if settings.AUTO_RISK_THRESHOLD=="green_orange" and auto_risk_threshold in {None,"green_orange"} else "manual"
        if goal not in {"discovery", "http_check"}:
            state.run_state, state.reason_code = "blocked", "unsupported_goal"
            state.reason = "This worker supports discovery and HTTP checks. Verified access capabilities are unavailable; the requested goal was preserved."
            state.active = False
        else:
            try:
                async with asyncio.timeout(3):
                    state.capabilities = await worker_jobs.client.capabilities()
                tools = state.capabilities.get('tools') if isinstance(state.capabilities, dict) else None
                if not isinstance(tools, list) or any(not isinstance(tool, str) for tool in tools):
                    raise ValueError('Worker did not advertise a valid tool list')
                required = {'curl', 'nmap'} if goal == 'discovery' else {'curl'}
                missing = required.difference(tools)
                if missing:
                    state.run_state, state.reason_code = 'blocked', 'capability_unavailable'
                    state.reason, state.active = 'Worker lacks required capabilities: ' + ', '.join(sorted(missing)), False
            except Exception:
                state.run_state, state.reason_code = "blocked", "worker_unavailable"
                state.reason, state.active = "Worker capability discovery failed", False
        if state.active:
            from llm.pool_manager import pool_manager
            preflight = await pool_manager.planner_preflight(user_id, session_id)
            if not preflight['ready']:
                state.run_state, state.reason_code = 'blocked', preflight['code']
                state.reason, state.active = preflight['message'], False
        if state.active:
            try:
                await knowledge_store.restore(session_id, state.owner_id)
            except Exception as exc:  # noqa: BLE001 - storage failure is fail-closed.
                state.run_state, state.reason_code = "blocked", "knowledge_restore_failed"
                state.reason = "Durable knowledge restoration failed; autonomous run was not started."
                state.active = False
                log.warning("knowledge restoration failed", session=session_id,
                            error=type(exc).__name__)
        self._runs[session_id] = state
        try:
            await self._persist(state)
        except BaseException:
            self._runs.pop(session_id, None)
            raise
        if not state.active:
            return self.get_status(session_id)
        self._approvals[session_id] = {}

        # Subscribe to KB replan events for adaptive behaviour
        attack_kb.register_replan_callback(session_id, lambda event: self._on_replan_event(
            event, session_id=state.session_id, run_id=state.run_id))

        # Write audit record
        await self._write_decision_log(
            state, decision_type="autonomous_start",
            reasoning=f"Autonomous cycle started toward goal: {goal}",
            action_taken="engine.start()", risk_color="info",
        )

        # Kick off the loop
        self._tasks[session_id] = asyncio.create_task(self._run_loop(state))

        log.info("autonomous cycle started",
                 session=session_id, goal=goal, target=target)
        return {
            "status": "started", "session_id": session_id,
            "goal": goal, "target": target, "max_steps": state.max_steps,
            "original_objective": state.objective,
        }

    async def request_graceful_stop(self, session_id: str,
                                    user_id: str = "") -> dict:
        """Stop the loop without fencing worker jobs.

        Campaign pauses use this path so the durable checkpoint remains
        restorable.  Cancellation still uses ``request_stop`` exclusively.
        """
        await execution_authorization._context(user_id, session_id,
                                               allow_blocked=True)
        state = self._runs.get(session_id)
        if not state:
            return {"status": "not_running", "session_id": session_id}
        if state.run_state in TERMINAL:
            return {"status": "stopped", "session_id": session_id}
        state.pause_requested = True
        state.stop_requested = True
        await self._persist(state)
        return {"status": "pause_pending", "session_id": session_id,
                "run_state": state.run_state}

    async def request_stop(self, session_id: str, user_id: str = "") -> dict:
        await execution_authorization._context(user_id, session_id, allow_blocked=True)
        state = self._runs.get(session_id)
        if state:
            state.stop_requested = True
            if state.run_state not in TERMINAL:
                state.run_state = "cancelling"
            await self._persist(state)
        cancellation = await worker_jobs.cancel_session(user_id, session_id)
        task = self._tasks.get(session_id)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return {"status": "cancellation_pending" if cancellation['pending'] else "stopped", **cancellation}

    async def detach_session(self, session_id):
        """Internal cleanup after the caller has authorized the engagement."""
        state = self._runs.get(session_id)
        if state:
            state.stop_requested = True
        task = self._tasks.get(session_id)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def revoke_principal(self, user_id):
        for sid, state in list(self._runs.items()):
            if state.user_id == user_id:
                await self.detach_session(sid)

    async def shutdown(self):
        for state in self._runs.values():
            state.stop_requested = True
        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def get_status(self, session_id: str) -> dict:
        state = self._runs.get(session_id)
        if not state:
            return {"active": False}
        return {
            "schema_version": 1,
            "session_id": state.session_id,
            "run_id": state.run_id,
            "turn_id": state.run_id,
            "user_id": state.user_id,
            "owner_id": state.owner_id,
            "scope_digest": state.scope_digest,
            "auth_revision": state.auth_revision,
            "worker_epoch": state.worker_epoch,
            "skill_level": state.skill_level,
            "run_state": state.run_state,
            "reason_code": state.reason_code,
            "reason": state.reason,
            "failure_detail": state.failure_detail,
            "successful_steps": state.successful_steps,
            "evidence_job_ids": list(state.evidence_job_ids),
            "completed_observations": list(state.completed_observations),
            "observation_job_ids": {key: list(value) for key, value in
                                     state.observation_job_ids.items()},
            "original_objective": state.objective,
            "objective_truncated": state.objective_truncated,
            "completion_criteria": completion_criteria_text(state.goal),
            "completion": observation_completion(state),
            "required_observations": list(required_observations(state.goal)),
            "required_capabilities": ["nmap", "curl"] if state.goal == "discovery" else ["curl"] if state.goal == "http_check" else ["verified_access"],
            "capabilities": {
                "tools": list(state.capabilities.get("tools") or []),
                **{name: state.capabilities[name]
                   for name in ("authenticated_http_version",
                                "specialist_http_version")
                   if type(state.capabilities.get(name)) is int},
            },
            "model_calls": state.model_calls,  # Legacy field: logical attempts only.
            "planning_attempts": state.model_calls,
            "model_calls_basis": "logical_planning_attempts; physical calls are in model accounting",
            "auto_risk_threshold": state.risk_threshold,
            "active": state.active and state.run_state not in TERMINAL,
            "steps_taken": state.steps_taken,
            "max_steps": state.max_steps,
            "remaining_steps": max(0, state.max_steps - state.steps_taken),
            "remaining_model_calls": max(0, self.MAX_MODEL_CALLS - state.model_calls),
            "executed_commands": list(state.executed_commands),
            "executed_command_hashes": list(state.executed_command_hashes),
            "last_action_id": state.last_action_id,
            "last_action_command": state.last_action_command,
            "current_phase": state.current_phase,
            "campaign_id": state.campaign_id,
            "specialist_phase_done": state.specialist_phase_done,
            "specialist_investigation_ids": list(state.specialist_investigation_ids),
            "specialist_investigation_count": len(state.specialist_investigation_ids),
            "goal": state.goal,
            "target": state.target,
            "started_at": state.started_at,
            "elapsed_seconds": int(time.time() - state.started_at),
            "waiting_approval": state.pending_approval is not None,
            "pending_action_id": state.pending_approval.action_id
                                  if state.pending_approval else None,
            "stop_requested": state.stop_requested,
            "pause_requested": state.pause_requested,
            "activity_tail": state.activity_log[-10:],
        }

    async def restored_status(self, session_id):
        if session_id in self._runs:
            return self.get_status(session_id)
        return await run_store.latest(session_id)

    async def _persist(self, state):
        await run_store.save(self.get_status(state.session_id))

    # ────────────────────────────────────────────────────────────────────
    #  Durable checkpoint restoration
    # ────────────────────────────────────────────────────────────────────

    @staticmethod
    def _restore_rejection(exc: CheckpointError) -> dict:
        return {
            "status": "rejected",
            "reason_code": getattr(exc, "code", "checkpoint_error"),
            "reason": str(exc),
            "active": False,
        }

    async def restore(self, session_id: str, user_id: str,
                      run_id: Optional[str] = None, resume: bool = True,
                      campaign_id: str = "",
                      campaign_supervisor_token: str = "") -> dict:
        """Validate and rehydrate a durable checkpoint.

        Validation is read-only with respect to execution: it reads durable
        receipts and knowledge rows, never submits jobs, and never calls a
        model.  When ``resume`` is true a resumable checkpoint is rehydrated
        and the normal autonomous loop continues from its counters.
        """
        async with self._start_locks.setdefault(session_id, asyncio.Lock()):
            current = self._runs.get(session_id)
            task = self._tasks.get(session_id)
            if current is not None and (current.active or (task is not None and not task.done())):
                return {"status": "already_running", "run_id": current.run_id,
                        "steps_taken": current.steps_taken}

            context = await execution_authorization._context(user_id, session_id)
            try:
                claimed = await run_store.claim_restore(session_id, run_id)
            except CheckpointConflict as exc:
                if exc.code in {"restore_in_progress", "run_active"}:
                    return {"status": "already_running", "reason_code": exc.code,
                            "active": True}
                return self._restore_rejection(exc)
            except CheckpointError as exc:
                return self._restore_rejection(exc)

            try:
                state = await self._rehydrate_checkpoint(
                    session_id, claimed, context, user_id,
                    campaign_id=_objective_text(campaign_id)[:100])
            except CheckpointError as exc:
                await run_store.release_restore(session_id, claimed["run_id"],
                                                claimed["token"])
                return self._restore_rejection(exc)
            except Exception:
                await run_store.release_restore(session_id, claimed["run_id"],
                                                claimed["token"])
                raise

            # Proof of supervisor ownership is transient: it is accepted only
            # from the caller, never restored from a checkpoint or status.
            state.campaign_supervisor_token = _campaign_supervisor_token(
                campaign_supervisor_token)
            previous = self._runs.get(session_id)
            if resume:
                state.active = state.run_state != "completed"
            else:
                state.active = False
                if state.run_state != "completed":
                    state.run_state = "restored"
            self._runs[session_id] = state
            try:
                status = self.get_status(session_id)
                await run_store.commit_restore(session_id, claimed["run_id"],
                                               claimed["token"], status)
            except Exception:
                if previous is None:
                    self._runs.pop(session_id, None)
                else:
                    self._runs[session_id] = previous
                await run_store.release_restore(session_id, claimed["run_id"],
                                                claimed["token"])
                raise

            self._approvals[session_id] = {}
            if state.active:
                attack_kb.register_replan_callback(session_id, lambda event: self._on_replan_event(
                    event, session_id=state.session_id, run_id=state.run_id))
            await self._write_decision_log(
                state, decision_type="autonomous_restore",
                reasoning=("Restored a durable checkpoint without replaying commands "
                           "or reusing previous authorizations."),
                action_taken="engine.restore()", risk_color="info",
                actor_id=user_id,
            )
            if state.active:
                self._tasks[session_id] = asyncio.create_task(self._run_loop(state))
            result = self.get_status(session_id)
            log.info("autonomous checkpoint restored", session=session_id,
                     run=state.run_id, resumed=bool(state.active))
            return {
                "status": "restored",
                "session_id": session_id,
                "run_id": state.run_id,
                "run_state": result["run_state"],
                "campaign_id": result["campaign_id"],
                "active": result["active"],
                "resumed": bool(state.active),
                "steps_taken": result["steps_taken"],
                "max_steps": result["max_steps"],
                "model_calls": result["model_calls"],
                "remaining_steps": result["remaining_steps"],
                "remaining_model_calls": result["remaining_model_calls"],
                "completed_observations": result["completed_observations"],
                "evidence_job_ids": result["evidence_job_ids"],
            }

    async def _rehydrate_checkpoint(self, session_id: str, claimed: dict,
                                    context: dict, user_id: str,
                                    campaign_id: str = "") -> SessionRunState:
        """Validate every checkpoint binding before creating in-memory state."""
        snapshot = claimed.get("snapshot") if isinstance(claimed, dict) else None
        raw = snapshot.get("checkpoint") if isinstance(snapshot, dict) else None
        if not isinstance(raw, dict):
            raise CheckpointIntegrityError("No durable checkpoint is present")

        owner_id = context.get("owner_id") or user_id
        checkpoint = validate_checkpoint(
            raw,
            expected_run_id=claimed.get("run_id", ""),
            expected_session_id=session_id,
            expected_owner_id=owner_id,
            max_steps_limit=self.MAX_STEPS,
            max_model_calls=self.MAX_MODEL_CALLS,
        )
        if checkpoint["session_id"] != claimed.get("session_id"):
            raise CheckpointIntegrityError("Checkpoint row identity is inconsistent")

        expected_scope = context.get("scope_digest") or scope_identity_digest(
            context.get("scope") or {}, context.get("target", ""))
        if (not expected_scope or not isinstance(checkpoint["scope_digest"], str)
                or not hmac.compare_digest(checkpoint["scope_digest"], expected_scope)):
            raise CheckpointAccessError(
                "Engagement scope changed since this checkpoint was written")
        if not hmac.compare_digest(checkpoint["owner_id"], owner_id):
            raise CheckpointAccessError("Checkpoint is bound to another owner")
        if checkpoint["auth_revision"] != int(context.get("auth_revision", 0)):
            raise CheckpointAccessError(
                "Run credentials were revoked after this checkpoint")
        if checkpoint["worker_epoch"] != int(context.get("worker_epoch", 0)):
            raise CheckpointAccessError(
                "Run was invalidated by cancellation after this checkpoint")

        checkpoint_campaign = checkpoint.get("campaign_id", "")
        if not isinstance(checkpoint_campaign, str) or len(checkpoint_campaign) > 100:
            raise CheckpointIntegrityError("Checkpoint campaign identity is invalid")
        if (campaign_id and checkpoint_campaign
                and not hmac.compare_digest(checkpoint_campaign, campaign_id)):
            raise CheckpointAccessError(
                "Checkpoint belongs to another campaign")
        campaign_id = checkpoint_campaign or campaign_id

        specialist_done = checkpoint.get("specialist_phase_done", False)
        specialist_ids = checkpoint.get("specialist_investigation_ids", [])
        if type(specialist_done) is not bool:
            raise CheckpointIntegrityError(
                "Checkpoint specialist phase flag is invalid")
        if (not isinstance(specialist_ids, list) or len(specialist_ids) > 20
                or len(set(specialist_ids)) != len(specialist_ids)
                or any(not isinstance(item, str) or not item or len(item) > 100
                       for item in specialist_ids)):
            raise CheckpointIntegrityError(
                "Checkpoint specialist investigation identity is invalid")

        goal = checkpoint["goal"]
        if goal not in {"discovery", "http_check"}:
            raise CheckpointStateError("Checkpoint goal is not supported")
        if tuple(checkpoint["required_observations"]) != required_observations(goal):
            raise CheckpointIntegrityError(
                "Checkpoint completion requirements are inconsistent")
        if checkpoint["completion_criteria"] != completion_criteria_text(goal):
            raise CheckpointIntegrityError(
                "Checkpoint completion criteria changed")
        if any(observation not in checkpoint["required_observations"]
               for observation in checkpoint["completed_observations"]):
            raise CheckpointIntegrityError(
                "Checkpoint records an unrelated observation")

        checkpoint_state = checkpoint["run_state"]
        if checkpoint_state == "cancelling":
            raise CheckpointStateError(
                "Run cancellation was in progress when the checkpoint was written")
        if checkpoint_state in {"blocked", "failed"}:
            if checkpoint["reason_code"] not in RESTORABLE_BLOCKED_REASONS:
                raise CheckpointStateError(
                    "Checkpoint ended in a non-recoverable state")

        try:
            active_jobs, last_job = await run_store.restore_jobs(
                session_id, checkpoint["last_action_id"])
        except Exception:
            raise CheckpointStateError(
                "Durable worker receipt state is unavailable") from None
        if active_jobs:
            raise CheckpointStateError(
                "Engagement has unresolved worker jobs; operator review is required")
        if checkpoint_state == "executing" and not checkpoint["last_action_id"]:
            raise CheckpointIntegrityError(
                "Executing checkpoint has no action identity")
        if checkpoint_state == "executing" and checkpoint["last_action_id"] not in (
                checkpoint["evidence_job_ids"]):
            if last_job is not None:
                # A durable job exists but its result was never committed to
                # the checkpoint.  Do not guess whether remote work completed.
                raise CheckpointStateError(
                    "Execution state is uncertain; operator review is required")

        try:
            restored = await knowledge_store.restore(
                session_id, checkpoint["owner_id"])
        except Exception:
            raise CheckpointStateError(
                "Durable knowledge restoration failed") from None
        if not isinstance(restored, dict):
            raise CheckpointStateError("Durable knowledge restoration failed")
        known_jobs = set(restored.get("job_ids") or [])
        job_observations = restored.get("job_observations") or {}
        job_runs = restored.get("job_runs") or {}
        evidence = set(checkpoint["evidence_job_ids"])
        if not evidence.issubset(known_jobs):
            raise CheckpointIntegrityError(
                "Checkpoint evidence has no durable observation receipt")
        for observation, job_ids in checkpoint["observation_job_ids"].items():
            for job_id in job_ids:
                if job_observations.get(job_id) != observation:
                    raise CheckpointIntegrityError(
                        "Observation receipt does not match the checkpoint")
                if job_runs.get(job_id) != checkpoint["run_id"]:
                    raise CheckpointIntegrityError(
                        "Observation receipt belongs to another run")

        required_tools = {"curl", "nmap"} if goal == "discovery" else {"curl"}
        if checkpoint_state != "completed" and not required_tools.issubset(
                set(checkpoint["capabilities"]["tools"])):
            raise CheckpointStateError(
                "Recorded worker capabilities are insufficient for this goal")
        if checkpoint_state != "completed":
            if checkpoint["steps_taken"] >= checkpoint["max_steps"]:
                raise CheckpointStateError("Checkpoint step budget is exhausted")
            if checkpoint["model_calls"] >= self.MAX_MODEL_CALLS:
                raise CheckpointStateError("Checkpoint model-call budget is exhausted")

        capabilities = {"tools": list(checkpoint["capabilities"]["tools"])}
        if 'typed_adapters' in checkpoint['capabilities']:
            capabilities['typed_adapters'] = dict(checkpoint['capabilities']['typed_adapters'])
        for name in ("authenticated_http_version", "specialist_http_version"):
            if name in checkpoint["capabilities"]:
                capabilities[name] = checkpoint["capabilities"][name]
        state = SessionRunState(
            session_id=session_id, user_id=user_id,
            owner_id=checkpoint["owner_id"], goal=goal,
            target=checkpoint["target"], skill_level=checkpoint["skill_level"],
            objective=checkpoint["objective"],
            objective_truncated=checkpoint["objective_truncated"],
            started_at=checkpoint["started_at"], run_id=checkpoint["run_id"],
            auth_revision=checkpoint["auth_revision"],
            worker_epoch=checkpoint["worker_epoch"],
            max_steps=checkpoint["max_steps"],
            steps_taken=checkpoint["steps_taken"],
            run_state=checkpoint["run_state"],
            reason_code=checkpoint["reason_code"],
            reason=checkpoint["reason"],
            failure_detail=checkpoint["failure_detail"],
            capabilities=capabilities,
            successful_steps=checkpoint["successful_steps"],
            evidence_job_ids=list(checkpoint["evidence_job_ids"]),
            completed_observations=list(checkpoint["completed_observations"]),
            observation_job_ids={key: list(value) for key, value in
                                 checkpoint["observation_job_ids"].items()},
            executed_commands=list(checkpoint["executed_commands"]),
            executed_command_hashes=list(checkpoint["executed_command_hashes"]),
            model_calls=checkpoint["model_calls"],
            risk_threshold=checkpoint["risk_threshold"],
            current_phase=checkpoint["current_phase"],
            scope_digest=checkpoint["scope_digest"],
            last_action_id=checkpoint["last_action_id"],
            last_action_command=checkpoint["last_action_command"],
            campaign_id=campaign_id,
            specialist_phase_done=specialist_done,
            specialist_investigation_ids=list(specialist_ids),
        )
        # Approval IDs are intentionally not restored: a checkpoint may never
        # revive an expired execution authorization.
        state.pending_approval = None
        state.stop_requested = False
        if checkpoint_state == "completed":
            state.active = False
            state.run_state = "completed"
        else:
            state.active = True
            state.run_state = "planning"
            state.reason_code = ""
            state.reason = ""
        return state

    # ────────────────────────────────────────────────────────────────────
    #  Public API — WebSocket streaming
    # ────────────────────────────────────────────────────────────────────

    async def stream_events(self, session_id: str) -> AsyncGenerator[dict, None]:
        """
        Async generator of events to stream over WebSocket. Emits a snapshot
        of recent activity, then streams live events until the run ends.
        """
        state = self._runs.get(session_id)
        if not state:
            yield {"type": "error", "message": "autonomous run not found"}
            return

        queue = asyncio.Queue(maxsize=256)
        state.subscribers.add(queue)
        tail = list(state.activity_log[-10:])
        try:
            for event in tail:
                yield event
            while state.active or not queue.empty():
                try:
                    yield await asyncio.wait_for(queue.get(), timeout=1)
                except asyncio.TimeoutError:
                    continue
        finally:
            state.subscribers.discard(queue)

    # ────────────────────────────────────────────────────────────────────
    #  Public API — human approval handling
    # ────────────────────────────────────────────────────────────────────

    def get_pending_approvals(self, session_id: str) -> List[dict]:
        """List pending red-risk approvals for a session."""
        queue = self._approvals.get(session_id, {})
        return [
            {"action_id": a.action_id, "command": a.command,
             "tool": a.tool, "risk_color": a.risk_color,
             "purpose": a.purpose, "step_number": a.step_number,
             "created_at": a.created_at,
             "waiting_seconds": int(time.time() - a.created_at)}
            for a in queue.values() if a.decision is None
        ]

    async def provide_approval_decision(self, session_id: str, action_id: str,
                                         decision: str,
                                         modified_command: str = "", user_id: str = "") -> dict:
        """
        Called by the API when the human responds to an approval request.

        `decision`: one of "approve" | "reject" | "modify"
        """
        if decision not in ("approve", "reject", "modify"):
            return {"status": "error", "message": "invalid decision"}

        queue = self._approvals.get(session_id, {})
        req = queue.get(action_id)
        if not req:
            return {"status": "error", "message": "approval request not found"}
        if req.decision is not None:
            return {"status": "error", "message": "already decided"}

        approved = await execution_authorization.decide(user_id, session_id, action_id, decision, modified_command)
        req.decision = decision
        if decision == "modify":
            req.modified_command = approved.command
            req.tool = approved.tool
            req.risk_color = approved.risk

        # Write decision-log entry for traceability
        state = self._runs.get(session_id)
        if state:
            await self._write_decision_log(
                state, decision_type="approval_decision",
                reasoning=f"Human decided: {decision}",
                action_taken=approved.command,
                risk_color=req.risk_color,
                human_involved=True, human_decision=decision, actor_id=user_id,
            )

        log.info("approval decided", session=session_id,
                 action=action_id, decision=decision)
        return {"status": "recorded", "decision": decision}

    # ────────────────────────────────────────────────────────────────────
    #  Main loop
    # ────────────────────────────────────────────────────────────────────

    async def _run_loop(self, state: SessionRunState):
        """The actual autonomous loop. Runs as a background task."""
        # Background tasks may be started by the campaign supervisor rather
        # than an HTTP request; model accounting requires the owner binding.
        from llm.engagement_budget import engagement_context
        engagement_token = engagement_context.set(
            {"session_id": state.session_id, "owner": state.user_id})
        try:
            while state.active and state.steps_taken < state.max_steps:
                if state.stop_requested:
                    break

                context = await execution_authorization._context(state.user_id, state.session_id)
                if context.get("auth_revision", 0) != state.auth_revision or context.get("worker_epoch", 0) != state.worker_epoch:
                    break
                # 1) Check if goal achieved
                achieved, reason = await self._check_goal_achieved(state)
                if achieved and state.successful_steps:
                    if not await self._run_specialist_phase_guarded(state):
                        break
                    state.run_state = "completed"
                    await self._emit(state, AutoActivityEvent(
                        type="goal_achieved", step=state.steps_taken,
                        action=reason, status="done",
                    ))
                    attack_kb.mark_goal_achieved(state.session_id, state.goal, reason)
                    break

                # 2) Ask the orchestrator/planner for the next step
                state.run_state = "planning"
                await self._persist(state)
                next_step = await self._plan_next_step(state)
                if not next_step:
                    state.run_state = "blocked"
                    state.reason_code = state.reason_code or "no_executable_proposal"
                    state.reason = state.reason or "Planner produced no executable action; goal completion is unproven."
                    await self._emit(state, AutoActivityEvent(
                        type="auto_complete", step=state.steps_taken,
                        action=state.reason,
                        status="blocked",
                    ))
                    break

                if state.stop_requested:
                    break
                state.steps_taken += 1
                state.current_phase = next_step.get("phase", state.current_phase)

                command = next_step.get("command", "")
                tool = next_step.get("tool", "").lower()
                purpose = next_step.get("purpose", "")
                threshold = state.risk_threshold
                proposal = await execution_authorization.propose(
                    state.user_id, state.session_id, command, tool,
                    turn_id=state.run_id,
                    require_approval=(next_step.get("risk_color") == "red" or threshold not in {"green_only", "green_orange"}
                                      or (threshold == "green_only" and classify_risk(tool, command) != "green")),
                )
                command, tool, risk = proposal.command, proposal.tool, proposal.risk
                action_id = proposal.id
                auto_ok = proposal.status == "authorized"

                if not auto_ok:
                    # HARD STOP — requires human approval (academic brief req't)
                    req = ApprovalRequest(
                        action_id=action_id,
                        session_id=state.session_id,
                        step_number=state.steps_taken,
                        command=command, tool=tool,
                        risk_color=risk, purpose=purpose,
                    )
                    self._approvals[state.session_id][action_id] = req
                    state.pending_approval = req
                    state.run_state = "awaiting_approval"

                    await self._emit(state, AutoActivityEvent(
                        type="waiting_approval",
                        step=state.steps_taken,
                        action=f"Step {state.steps_taken}: {command}",
                        tool=tool, risk_color=risk,
                        status="waiting_approval",
                        extra={"action_id": action_id,
                               "command": command,
                               "purpose": purpose,
                               "reason": ("Risk level requires explicit "
                                          "human validation per project scope.")},
                    ))
                    await self._write_decision_log(
                        state, decision_type="await_approval",
                        reasoning=f"Step {state.steps_taken} at {risk} risk requires approval",
                        action_taken=f"blocked: {command}",
                        risk_color=risk,
                        human_involved=True, human_decision="pending",
                    )

                    # Wait for decision (or stop)
                    decision = await self._wait_for_approval(state, req)
                    state.pending_approval = None

                    if decision == "reject" or state.stop_requested:
                        if state.pause_requested:
                            state.run_state = "blocked"
                            state.reason_code = "run_interrupted"
                            state.reason = ("Paused by the campaign supervisor; "
                                            "the checkpoint remains resumable.")
                            break
                        await self._emit(state, AutoActivityEvent(
                            type="auto_activity",
                            step=state.steps_taken,
                            action=f"Step {state.steps_taken} REJECTED by human",
                            tool=tool, risk_color=risk, status="failed",
                        ))
                        state.reason_code = "human_rejected"
                        state.reason = "Human rejected the proposed action"
                        # Feed the rejection back into planning context
                        attack_kb.log_event(
                            state.session_id, "human_rejected_step",
                            "autonomous_engine",
                            f"Human rejected: {command[:120]}",
                        )
                        state.run_state = "blocked"
                        break
                    if decision == "modify":
                        command = req.modified_command or command
                        tool, risk = req.tool, req.risk_color
                    # decision == "approve" → fall through to execute

                if state.stop_requested:
                    break
                # Record the possibly-dispatched action before touching the
                # worker.  If the API crashes now, restoration can prove whether
                # a durable job ever existed instead of blindly replaying.
                state.run_state = "executing"
                state.last_action_id = action_id
                state.last_action_command = command
                await self._persist(state)
                # 4) Execute the step
                await self._emit(state, AutoActivityEvent(
                    step=state.steps_taken,
                    action=f"Running {command[:140]}",
                    tool=tool, risk_color=risk, status="running",
                    extra={"purpose": purpose, "action_id": action_id},
                ))

                stdout, stderr, success = await self._execute_command(
                    state, tool, command, action_id=action_id,
                )

                job_id = state.evidence_job_ids[-1] if success and state.evidence_job_ids else ""
                if success:
                    state.successful_steps += 1
                    if command not in state.executed_commands:
                        state.executed_commands.append(command)
                    digest = command_digest(command)
                    if digest not in state.executed_command_hashes:
                        state.executed_command_hashes.append(digest)
                    observation = "port_discovery" if tool == "nmap" else "http_response" if tool in {"curl", "httpx"} else ""
                    if observation:
                        if observation not in state.completed_observations:
                            state.completed_observations.append(observation)
                        if job_id and job_id not in state.observation_job_ids.setdefault(observation, []):
                            state.observation_job_ids[observation].append(job_id)
                else:
                    state.run_state = "failed"
                    state.reason_code = state.reason_code or "execution_failed"
                    state.reason = state.reason or "Worker execution did not succeed"
                # 5) Parse output deterministically → KB
                parse_result = dispatch_parser(
                    state.session_id, tool, command,
                    stdout if success else "", state.target,
                )

                if success:
                    try:
                        if not job_id:
                            raise RuntimeError("successful execution has no durable job receipt")
                        await knowledge_store.record_observation(
                            session_id=state.session_id,
                            owner_id=state.owner_id or state.user_id,
                            run_id=state.run_id,
                            job_id=job_id,
                            tool=tool,
                            observation=observation or tool,
                            target=state.target,
                            stdout=stdout,
                            stderr=stderr,
                            exit_code=0,
                            hosts_updated=getattr(parse_result, "hosts_updated", []),
                            ports_added=getattr(parse_result, "ports_added", []),
                            vulns_added=getattr(parse_result, "vulns_added", []),
                        )
                    except Exception as exc:  # noqa: BLE001 - accepted facts must be durable.
                        state.run_state = "blocked"
                        state.reason_code = "knowledge_persist_failed"
                        state.reason = ("Accepted observation could not be durably recorded; "
                                        "the autonomous run stopped.")
                        log.warning("knowledge observation persistence failed",
                                    session=state.session_id, error=type(exc).__name__)
                        await self._emit(state, AutoActivityEvent(
                            type="auto_complete", step=state.steps_taken,
                            action=state.reason, status="blocked",
                            extra={"reason_code": state.reason_code},
                        ))
                        break

                output_preview = (stdout or stderr or "")[:300].replace("\n", " ")
                await self._emit(state, AutoActivityEvent(
                    step=state.steps_taken,
                    action=f"{'✓' if success else '✗'} {tool} "
                           f"{'done' if success else 'failed'}",
                    tool=tool, risk_color=risk,
                    status="done" if success else "failed",
                    output_preview=output_preview,
                    kb_updates=parse_result.events[:10],
                    extra={"action_id": action_id,
                           "ports_added": len(parse_result.ports_added),
                           "vulns_added": len(parse_result.vulns_added),
                           "creds_added": len(parse_result.creds_added),
                           "shells_added": len(parse_result.shells_added)},
                ))

                # 6) Decision log
                await self._write_decision_log(
                    state,
                    decision_type="auto_execute" if auto_ok else "approved_execute",
                    reasoning=purpose or f"Autonomous step {state.steps_taken}",
                    action_taken=command,
                    risk_color=risk,
                    observation=output_preview,
                    human_involved=not auto_ok,
                    human_decision=decision if not auto_ok else "none",
                )

                if not success:
                    break
                completion = observation_completion(state)
                if completion["complete"]:
                    if state.capabilities.get('typed_adapters', {}).get('httpx.http.probe.v1') == 1:
                        await self._review_investigation(state)
                    if not await self._run_specialist_phase_guarded(state):
                        break
                    state.run_state = "completed"
                    await self._emit(state, AutoActivityEvent(type="goal_achieved", status="done",
                        action="Required observations completed with durable worker receipts: "
                               + ", ".join(completion["satisfied"])))
                    break
                # Rate-limit between steps
                await asyncio.sleep(self.STEP_DELAY)

            # Loop ended
            if state.steps_taken >= state.max_steps and state.run_state != "completed":
                state.run_state = "blocked"
                state.reason_code = state.reason_code or "step_budget_exhausted"
                state.reason = state.reason or "Step budget exhausted without goal evidence"
                await self._emit(state, AutoActivityEvent(
                    type="auto_complete",
                    step=state.steps_taken,
                    action=state.reason,
                    status="blocked",
                ))
        except asyncio.CancelledError:
            state.run_state = "blocked"
            state.reason_code, state.reason = "cancelled", "Run cancelled; inspect worker jobs for final cancellation status"
            raise
        except Exception as exc:  # noqa: BLE001
            state.run_state = "failed"
            state.reason_code, state.reason = "run_error", "Run failed; inspect protected server diagnostics"
            log.exception("autonomous loop crashed",
                          session=state.session_id, error=str(exc))
            await self._emit(state, AutoActivityEvent(
                type="auto_error", step=state.steps_taken,
                action=f"Loop error: {str(exc)[:200]}", status="failed",
            ))
        finally:
            state.active = False
            if state.run_state not in TERMINAL:
                state.run_state = "blocked"
                state.reason_code = state.reason_code or "run_interrupted"
            try:
                await self._emit(state, AutoActivityEvent(type="auto_complete", status=state.run_state,
                    action=state.reason or "Run ended", extra={"reason_code": state.reason_code}))
            finally:
                if self._runs.get(state.session_id) is state:
                    attack_kb.unregister_replan_callback(state.session_id)
                if self._tasks.get(state.session_id) is asyncio.current_task():
                    self._tasks.pop(state.session_id, None)
            await self._write_decision_log(
                state, decision_type="autonomous_stop",
                reasoning=f"Cycle ended after {state.steps_taken} steps",
                action_taken="engine._run_loop exit",
                risk_color="info",
            )
            log.info("autonomous cycle ended",
                     session=state.session_id, steps=state.steps_taken)
            engagement_context.reset(engagement_token)

    # ────────────────────────────────────────────────────────────────────
    #  Planning / goal checking
    # ────────────────────────────────────────────────────────────────────

    async def _plan_next_step(self, state: SessionRunState) -> Optional[dict]:
        """
        Ask the orchestrator agent for the next single best action.
        Imports are deferred to avoid import cycles.
        """
        from agents.orchestrator_agent import orchestrator_agent  # noqa: PLC0415

        open_ports = []
        host = attack_kb.get_host(state.session_id, state.target)
        if host:
            open_ports = [
                {"port": p, "service": d.get("service", ""),
                 "version": d.get("version", "")}
                for p, d in host.ports.items() if d.get("state") == "open"
            ]

        recent_events = attack_kb.get_timeline(state.session_id, limit=10)
        history_str = [
            {"role": "system", "content": f"[{e['event']}] {e['detail']}"}
            for e in recent_events
        ]

        feedback = []
        for attempt in range(3):
            if state.stop_requested:
                return None
            if state.model_calls >= self.MAX_MODEL_CALLS:
                state.reason_code, state.reason = "model_call_budget", "Model call budget exhausted"
                return None
            state.model_calls += 1
            await self._persist(state)
            proposal = await self._validated_plan(state, orchestrator_agent, history_str, open_ports, feedback)
            if proposal:
                return proposal
            if state.reason_code and state.reason_code not in {'provider_timeout', 'provider_request_failed', 'local_model_request_failed'}:
                return None
            if proposal is None and state.reason_code and attempt < 2:
                feedback.append(state.reason)
                state.reason_code, state.reason = '', ''
        state.reason_code = state.reason_code or "invalid_planner_output"
        state.reason = state.reason or "Planner could not produce a supported proposal after two corrective attempts: " + "; ".join(feedback[-3:])
        return None

    async def _validated_plan(self, state, orchestrator_agent, history_str, open_ports, feedback):
        objective = state.objective or (
            f"Complete a {state.goal.replace('_', ' ')} assessment of "
            f"{state.target or 'the authorized target'} within the authorized scope.")
        instruction = (f"AUTO {state.goal} step {state.steps_taken+1}: "
                       "choose a missing observation.")
        try:
            specialist_context = await self._specialist_context(state)
        except Exception as exc:  # noqa: BLE001 - durable context is fail-closed.
            from orchestrator.specialist_integration import (
                SpecialistIntegrationError,
            )
            state.reason_code = (exc.code if isinstance(
                exc, SpecialistIntegrationError) else
                "specialist_context_unavailable")
            state.reason = ("Specialist results could not be read from the "
                            "durable ledger; planning stopped.")
            return None
        try:
            resp = await orchestrator_agent.process(
                session_id=state.session_id, user_id=state.user_id,
                input_data={
                    "autonomous_mode": True,
                    "original_objective": objective,
                    "autonomous_instruction": instruction,
                    "execution_evidence": [{"job_id":job_id,"source":"worker_receipt"} for job_id in state.evidence_job_ids],
                    "user_input": instruction,
                    "goal": state.goal,
                    "step": state.steps_taken + 1,
                    "target": state.target,
                    "worker_capabilities": state.capabilities,
                    "engagement_scope": (await execution_authorization._context(state.user_id, state.session_id))["scope"],
                    "validation_feedback": list(feedback),
                    "completion_criteria": completion_criteria_text(state.goal),
                    "completed_observations": list(state.completed_observations),
                    "completion_status": observation_completion(state),
                    "specialist_context": specialist_context,
                    "executed_commands": list(state.executed_commands),
                    "chat_history": history_str,
                    "tools_run": [e["event"] for e in attack_kb.get_timeline(state.session_id, limit=10)
                                  if "_parsed" in e["event"]],
                    "open_ports": open_ports,
                },
                skill_level=state.skill_level,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("planner failed in auto-loop",
                        session=state.session_id, error=str(exc))
            feedback.append("Provider failed or timed out")
            return None

        if not isinstance(resp, dict):
            feedback.append("Expected an object containing commands")
            return None
        for rejection in resp.get('rejections', []):
            code = rejection.get('code', '') if isinstance(rejection, dict) else ''
            if code == 'unsupported_or_out_of_scope_action':
                detail = rejection.get('detail', '') if isinstance(rejection, dict) else ''
                feedback.append((str(detail) or 'Proposal failed server scope or duplicate-evidence validation')[:250])
                continue
            if code and code not in {'malformed_planner_output', 'malformed_model_output'}:
                from llm.planner_errors import public_error
                state.reason_code, state.reason = code, public_error(code)
                return None
        commands = resp.get("commands") or []
        if not isinstance(commands, list) or not commands:
            for rejection in resp.get("rejections", []):
                if isinstance(rejection, dict):
                    feedback.append(str(rejection.get("detail", rejection.get("code", "Proposal rejected")))[:250])
            feedback.append("Expected a nonempty commands list")
            return None
        context = await execution_authorization._context(state.user_id, state.session_id)
        from worker.policy import validate_worker_command
        required = set(required_observations(state.goal))
        missing_observations = required.difference(state.completed_observations)
        observation_by_tool = {"nmap": "port_discovery", "curl": "http_response", "httpx": "http_response"}
        for command in commands:
            try:
                if not isinstance(command, dict):
                    raise ValueError('Command must be an object')
                validator = validate_worker_command
                if str(command.get('command', '')).startswith('aria-tool '):
                    from orchestrator.execution_policy import validate_command
                    validator = validate_command
                checked = validator(command.get('command', ''), context['scope'])
                if command_was_executed(state, checked.command):
                    raise ValueError('Command already executed in this run; propose a missing observation')
                from security_tools.adapters import ADAPTERS
                advertised = state.capabilities.get('typed_adapters', {})
                version = advertised.get(ADAPTERS[checked.tool].capability) if checked.tool in ADAPTERS else None
                typed_available = type(version) is int and version == 1
                if checked.tool not in state.capabilities.get('tools', []) and not typed_available:
                    raise ValueError('Tool is not advertised by the worker')
                observation = observation_by_tool.get(checked.tool)
                if observation not in missing_observations:
                    raise ValueError(f'{checked.tool} cannot satisfy a missing observation; outstanding: '
                                     + ', '.join(sorted(missing_observations)))
                return {**command, 'command': checked.command, 'tool': checked.tool, 'risk_color': checked.risk}
            except (ValueError, TypeError) as exc:
                feedback.append(str(exc)[:250])
                continue
        return None

    # ────────────────────────────────────────────────────────────────────
    #  SPEC-13: evidence-driven specialist review phase
    # ────────────────────────────────────────────────────────────────────

    @staticmethod
    def _verified_observations(state: SessionRunState) -> list[dict]:
        """Only durable worker receipts are confirmed evidence for planning."""
        observations = []
        for observation in list(state.completed_observations)[:20]:
            jobs = state.observation_job_ids.get(observation, [])
            if not isinstance(jobs, list):
                continue
            for job_id in jobs[:20]:
                if not isinstance(job_id, str) or not job_id:
                    continue
                observations.append({
                    "observation": observation, "job_id": job_id,
                    "source": "durable_worker_receipt", "verified": True,
                })
                if len(observations) >= 20:
                    return observations
        return observations

    async def _verify_campaign_supervisor(self, state: SessionRunState) -> None:
        """Fail closed unless a live supervisor lease owns this campaign run.

        A campaign-bound checkpoint can be restored manually after its campaign
        became terminal.  Without this check the engine would execute specialist
        tasks with no supervisor and no campaign reservation ledger.
        """
        from memory.campaign_store import MODEL_STATES, campaign_store
        from orchestrator.specialist_integration import SpecialistIntegrationError

        def deny() -> SpecialistIntegrationError:
            return SpecialistIntegrationError(
                "A live campaign supervisor lease is required for specialist work",
                code="campaign_supervisor_required")

        token = state.campaign_supervisor_token
        if not state.campaign_id or not isinstance(token, str) or not token:
            raise deny()
        try:
            if self.campaign_loader is not None:
                row = await self.campaign_loader(state.campaign_id)
            else:
                row = await campaign_store.get(state.campaign_id)
        except Exception:  # noqa: BLE001 - an unreadable lease is not proof.
            raise deny() from None
        if not isinstance(row, dict):
            raise deny()
        owner_id = state.owner_id or state.user_id
        if (row.get("session_id") != state.session_id
                or row.get("owner_id") != owner_id
                or row.get("state") not in MODEL_STATES):
            raise deny()
        holder = row.get("lease_holder")
        if (not isinstance(holder, str) or not holder.isascii()
                or not hmac.compare_digest(holder, token)):
            raise deny()
        expires = row.get("lease_expires_at")
        if not isinstance(expires, datetime):
            raise deny()
        if expires.tzinfo is not None:
            expires = expires.astimezone(timezone.utc).replace(tzinfo=None)
        if expires <= datetime.now(timezone.utc).replace(tzinfo=None):
            raise deny()

    async def _run_specialist_phase_guarded(self, state: SessionRunState) -> bool:
        """Run the bounded review phase before declaring the campaign complete.

        A storage failure blocks the run instead of silently completing it.
        Model/task budget exhaustion is terminal for this checkpoint.  A
        specialist that returns a failed hypothesis does not block campaign
        completion: its task stays in the durable ledger for human review and
        the planner sees it as a failed investigation.
        """
        if not state.campaign_id or state.specialist_phase_done:
            return True
        from orchestrator.specialist_integration import (
            SpecialistBudgetExhausted, SpecialistIntegrationError,
            specialist_integration,
        )
        try:
            summary = await self._run_specialist_phase(state, specialist_integration)
        except asyncio.CancelledError:
            raise
        except SpecialistBudgetExhausted as exc:
            state.run_state, state.reason_code = "blocked", exc.code
            state.reason = "Specialist review stopped because its model budget was exhausted."
            await self._emit(state, AutoActivityEvent(
                type="auto_complete", step=state.steps_taken,
                action=state.reason, status="blocked",
                extra={"reason_code": state.reason_code}))
            return False
        except SpecialistIntegrationError as exc:
            state.run_state, state.reason_code = "blocked", exc.code
            state.reason = ("Specialist review could not be durably integrated; "
                            "the run stopped without treating any hypothesis as verified.")
            await self._emit(state, AutoActivityEvent(
                type="auto_complete", step=state.steps_taken,
                action=state.reason, status="blocked",
                extra={"reason_code": state.reason_code}))
            return False
        except Exception:  # noqa: BLE001 - specialist storage is fail-closed.
            state.run_state, state.reason_code = "blocked", "specialist_integration_failed"
            state.reason = ("Specialist review failed unexpectedly; the run "
                            "stopped without changing campaign evidence.")
            await self._emit(state, AutoActivityEvent(
                type="auto_complete", step=state.steps_taken,
                action=state.reason, status="blocked",
                extra={"reason_code": state.reason_code}))
            return False
        state.specialist_phase_done = True
        await self._persist(state)
        await self._emit(state, AutoActivityEvent(
            type="specialist_investigations", step=state.steps_taken,
            action="Specialist review tasks are durable; findings remain unverified",
            status="done",
            extra={
                "investigations": len(summary.get("task_ids", [])),
                "executed": len(summary.get("executed", [])),
                "skipped": len(summary.get("skipped", [])),
                "errors": len(summary.get("errors", [])),
                "limitations": len(summary.get("limitations", [])),
            }))
        return True

    async def _run_specialist_phase(self, state: SessionRunState,
                                    service) -> dict:
        if state.stop_requested:
            return {"task_ids": list(state.specialist_investigation_ids),
                    "executed": [], "skipped": [], "errors": [],
                    "limitations": []}
        # This runs before candidate selection, evidence cataloging and any
        # model call, so a manual restore cannot create or execute campaign-
        # bound specialist tasks outside the supervisor's budget envelope.
        await self._verify_campaign_supervisor(state)
        context = await execution_authorization._context(
            state.user_id, state.session_id)
        from orchestrator.specialist_integration import (
            SpecialistIntegrationError,
        )
        if (context.get("auth_revision", 0) != state.auth_revision
                or context.get("worker_epoch", 0) != state.worker_epoch):
            raise SpecialistIntegrationError(
                "Engagement authorization changed before specialist review",
                code="authorization_changed")
        current_digest = context.get("scope_digest") or scope_identity_digest(
            context.get("scope") or {}, context.get("target", ""))
        if (state.scope_digest
                and not hmac.compare_digest(current_digest, state.scope_digest)):
            raise SpecialistIntegrationError(
                "Engagement scope changed before specialist review",
                code="scope_changed")
        owner_id = state.owner_id or state.user_id
        selection = await service.candidates(
            session_id=state.session_id, owner_id=owner_id,
            campaign_id=state.campaign_id, scope_digest=state.scope_digest,
            scope=context.get("scope") or {},
            advertised=state.capabilities or {},
            observation_job_ids=state.observation_job_ids)
        ensured = await service.ensure(
            session_id=state.session_id, owner_id=owner_id,
            campaign_id=state.campaign_id, scope_digest=state.scope_digest,
            candidates=selection["candidates"])
        task_ids = sorted(set(state.specialist_investigation_ids)
                          | set(ensured["task_ids"]))
        if len(task_ids) > 20:
            raise SpecialistIntegrationError(
                "Specialist investigation limit is inconsistent")
        state.specialist_investigation_ids = task_ids
        # Persist identities before any model call: a crash now leaves a
        # deterministic, deduplicated ledger that a restore can inspect.
        await self._persist(state)
        result = await service.run_pending(
            session_id=state.session_id, owner_id=owner_id,
            task_ids=task_ids, skill_level=state.skill_level,
            max_tasks=settings.SPECIALIST_MAX_TASKS_PER_RUN,
            campaign_id=state.campaign_id,
            campaign_supervisor_token=state.campaign_supervisor_token,
            scope_digest=state.scope_digest,
            auth_revision=state.auth_revision,
            worker_epoch=state.worker_epoch)
        limitations = [*selection.get("limitations", []),
                       *ensured.get("limitations", [])]
        return {**result, "limitations": limitations}

    async def _specialist_context(self, state: SessionRunState) -> dict:
        if not state.specialist_investigation_ids:
            return {}
        from orchestrator.specialist_integration import specialist_integration
        return await specialist_integration.planner_context(
            session_id=state.session_id,
            owner_id=state.owner_id or state.user_id,
            task_ids=list(state.specialist_investigation_ids),
            verified_observations=self._verified_observations(state))

    async def _check_goal_achieved(self, state: SessionRunState) -> tuple[bool, str]:
        """
        Check if the goal is achieved based on KB state. Returns (achieved, reason).
        """
        completion = observation_completion(state)
        if completion["complete"]:
            return True, ("Required observations completed with durable worker receipts: "
                          + ", ".join(completion["satisfied"]))
        if completion["required"]:
            # Supported assessment goals complete only from measured receipts.
            return False, ""

        summary = attack_kb.get_full_summary(state.session_id)
        shells = summary.get("shells", [])
        creds = summary.get("credentials", [])

        goal = state.goal.lower()
        if goal == "initial_access":
            if shells:
                return True, f"Shell obtained on {shells[0].get('host', state.target)}"
        elif goal == "dump_creds":
            if creds:
                return True, f"Credential extracted: {creds[0].get('user', '?')}"
        elif goal == "privilege_escalation":
            rooted = any(s.get("privilege") in ("root", "SYSTEM", "admin")
                         for s in shells)
            if rooted:
                return True, "Privileged shell obtained"
        elif goal == "full_compromise":
            rooted = any(s.get("privilege") in ("root", "SYSTEM", "admin")
                         for s in shells)
            if rooted and creds:
                return True, "Full compromise: root shell + credentials"
        return False, ""

    async def _on_replan_event(self, event: dict, *, session_id: str = "", run_id: str = ""):
        state = self._runs.get(session_id)
        if not state or not state.active or state.run_id != run_id:
            return
        await self._emit(state, {
            "type": "plan_updated",
            "trigger": event.get("trigger"),
            "host": event.get("host"),
            "detail": event.get("detail"),
            "urgency": event.get("urgency", "normal"),
            "timestamp": datetime.utcnow().isoformat(),
        })

    # ────────────────────────────────────────────────────────────────────
    #  Command execution (via Kali agent)
    # ────────────────────────────────────────────────────────────────────

    async def _execute_command(self, state: SessionRunState, tool: str, command: str,
                               action_id: str = "") -> tuple[str, str, bool]:
        if state.stop_requested:
            return "", "Run stopped before dispatch", False
        timeout = self.STEP_TIMEOUT
        if command.startswith('aria-tool '):
            from security_tools.adapters import decode
            adapter, _ = decode(command)
            timeout = min(timeout, adapter.timeout)
        result = await execution_authorization.execute(
            state.user_id, state.session_id, command, tool=tool, action_id=action_id,
            timeout=timeout, expected_revision=state.auth_revision, expected_worker_epoch=state.worker_epoch,
        )
        success = result.get("exit_code", -1) == 0 and bool(result.get("job_id")) and bool(result.get("stdout", "").strip())
        if success and command.startswith('aria-tool '):
            from security_tools.adapters import decode
            adapter, parameters = decode(command)
            context = await execution_authorization._context(state.user_id, state.session_id)
            normalized = adapter.normalize(result['stdout'], parameters, context['scope'], 0, 'succeeded')
            success = normalized.error == 'none'
        if success:
            state.evidence_job_ids.append(result["job_id"])
        else:
            status = str(result.get("status") or "").lower()
            stderr = str(result.get("stderr") or "").strip()
            if status in {"timeout", "timed_out"}:
                state.reason_code = "worker_timeout"
                state.reason = "Worker execution timed out; the autonomous run stopped."
            elif status in {"cancelled", "cancellation_pending", "interrupted"}:
                state.reason_code = "worker_cancelled"
                state.reason = "Worker execution was cancelled or interrupted; the autonomous run stopped."
            elif result.get("exit_code", -1) not in (0, None):
                state.reason_code = "worker_exit_nonzero"
                state.reason = "Worker command exited with a nonzero status; the autonomous run stopped."
            else:
                state.reason_code = "worker_failed"
                state.reason = "Worker did not return a successful execution receipt; the autonomous run stopped."
            if stderr:
                from security.redaction import deployment_secrets, redact
                state.failure_detail = str(redact(stderr, deployment_secrets()))[:1000]
        return result.get("stdout", ""), result.get("stderr", ""), success

    async def _review_investigation(self, state: SessionRunState) -> None:
        """Review only current-run, reverified receipts; conclusions remain hypotheses."""
        from agents.orchestrator_agent import orchestrator_agent, InvestigationReview
        from llm.base_llm import response_schema
        evidence = []
        follow_ups = {}
        for job_id in state.evidence_job_ids[-5:]:
            job = await worker_jobs.store.get(job_id)
            if not job or job.get('session_id') != state.session_id:
                raise ValueError('Review receipt ownership mismatch')
            snapshot = await worker_jobs.client.status(job)
            await worker_jobs.verify_receipt(state.user_id, state.session_id, job_id,
                snapshot['stdout'], snapshot['stderr'], snapshot['exit_code'])
            summary = snapshot['stdout'][:1000]
            if job.get('adapter_request_sha256'):
                from security_tools.adapters import decode, sha256
                command = next((item for item in state.executed_commands
                                if sha256(item) == job['adapter_request_sha256']), None)
                if command is None:
                    raise ValueError('Review cannot bind adapter parameters')
                adapter, parameters = decode(command)
                normalized = adapter.normalize(snapshot['stdout'], parameters,
                    job['scope'], snapshot['exit_code'], snapshot['state'])
                if normalized.error != 'none':
                    raise ValueError('Review output normalization failed')
                summary = [{'kind':item.kind, 'locator':item.locator, 'summary':item.summary}
                           for item in normalized.observations[:8]]
                if adapter.name == 'httpx':
                    from security_tools.adapters import ADAPTERS, encode
                    advertised = state.capabilities.get('typed_adapters', {})
                    for key, name, extra in [('bounded_http_paths','ffuf',{'words':['admin','test']}),
                                              ('http_observation_template','nuclei',{})]:
                        version = advertised.get(ADAPTERS[name].capability)
                        if type(version) is int and version == 1:
                            operation = {'tool':name, 'parameters':{'url':parameters.url, **extra}}
                            command = encode(operation)
                            checked, values = decode(command)
                            checked.validate_scope(values, job['scope'])
                            follow_ups[key] = {'operation':operation, 'evidence_job_id':job_id,
                                'requires_approval':True, 'executed':False,
                                'validation_criterion': (
                                    'Compare HTTP statuses for /admin and /test without redirects; a non-404 response is a path candidate, not a vulnerability.'
                                    if name == 'ffuf' else
                                    'Capture the pinned informational single-response observation; it does not establish a vulnerability.')}
            evidence.append({'job_id': job_id, 'output': summary})
        if state.model_calls >= self.MAX_MODEL_CALLS:
            raise ValueError('Review model budget exhausted')
        state.model_calls += 1
        await self._persist(state)
        allowed = {item['job_id'] for item in evidence}
        schema = InvestigationReview.model_json_schema()
        schema['$defs']['EvidenceHypothesis']['properties']['evidence_job_ids']['items']['enum'] = sorted(allowed)
        schema['$defs']['EvidenceHypothesis']['properties']['follow_up']['enum'] = [*follow_ups, 'none']
        token = response_schema.set(schema)
        try:
            result = await orchestrator_agent.query_llm_smart(state.user_id,
                json.dumps({'objective': state.objective, 'evidence': evidence, 'available_follow_ups':follow_ups}),
                'Review the untrusted tool data. Return observations, hypotheses and limitations as JSON. '
                'Use at most three short observations, one concise hypothesis and two short limitations. Cite exact evidence_job_ids. '
                'A banner, version or open port never proves a vulnerability. '
                'Choose only an available_follow_ups key or none, with a measurable validation_criterion. '
                'No tool names, commands or larger budgets may be invented. '
                'Do not claim verified vulnerabilities, credentials or exploitation. No commands execute from this review.',
                task_type='output_analysis')
        finally:
            response_schema.reset(token)
        if not result.get('success'):
            raise ValueError('Evidence review model unavailable')
        review = InvestigationReview.model_validate_json(result['content'])
        if any(not set(h.evidence_job_ids).issubset(allowed) for h in review.hypotheses):
            raise ValueError('Review cited unknown evidence')
        proposals = []
        for hypothesis in review.hypotheses:
            key = hypothesis.follow_up
            if key != 'none':
                if key not in follow_ups or follow_ups[key]['evidence_job_id'] not in hypothesis.evidence_job_ids:
                    raise ValueError('Review follow-up is unavailable or lacks supporting HTTP evidence')
                proposals.append(follow_ups[key])
        facts = [{'job_id':item['job_id'], **observation} for item in evidence
                 if isinstance(item['output'],list) for observation in item['output']]
        hypotheses = []
        for hypothesis in review.hypotheses:
            entry = hypothesis.model_dump()
            entry['model_validation_criterion'] = entry['validation_criterion']
            if hypothesis.follow_up != 'none':
                entry['validation_criterion'] = follow_ups[hypothesis.follow_up]['validation_criterion']
            hypotheses.append(entry)
        payload = {**review.model_dump(), 'observations':facts,
                   'interpretations':review.observations, 'hypotheses':hypotheses,
                   'verification': 'unverified',
                   'evidence_job_ids': sorted(allowed), 'proposed_investigations': proposals}
        await self._emit(state, {'type': 'investigation_review', 'status':'done',
            'action':'Evidence reviewed; follow-up investigations remain proposals', 'review': payload})
        await self._write_decision_log(state, decision_type='investigation_review',
            observation=json.dumps(payload), action_taken='Receipt-bound evidence review; no follow-up dispatched')

    # ────────────────────────────────────────────────────────────────────
    #  Approval waiting
    # ────────────────────────────────────────────────────────────────────

    async def _wait_for_approval(self, state: SessionRunState,
                                  req: ApprovalRequest) -> str:
        """Block until human responds (or stop is requested)."""
        while req.decision is None and not state.stop_requested:
            await asyncio.sleep(0.5)
        return req.decision or "reject"

    # ────────────────────────────────────────────────────────────────────
    #  Event emission
    # ────────────────────────────────────────────────────────────────────

    async def _emit(self, state: SessionRunState,
                     event: "AutoActivityEvent | dict"):
        """Push an event into the stream queue + tail buffer."""
        ev_dict = event.to_dict() if isinstance(event, AutoActivityEvent) else event
        from security.redaction import redact
        ev_dict = redact(ev_dict)
        ev_dict = {**ev_dict, "session_id": state.session_id, "run_id": state.run_id, "run_state": state.run_state}
        state.activity_log.append(ev_dict)
        await self._persist(state)
        # Keep tail bounded
        if len(state.activity_log) > 200:
            state.activity_log = state.activity_log[-200:]
        for queue in list(state.subscribers):
            if queue.full():
                queue.get_nowait()
                queue.put_nowait({"type": "stream_gap", "reconnect": True})
            else:
                queue.put_nowait(ev_dict)

    # ────────────────────────────────────────────────────────────────────
    #  Decision-log persistence
    # ────────────────────────────────────────────────────────────────────

    async def _write_decision_log(self, state: SessionRunState, *,
                                    decision_type: str,
                                    reasoning: str = "",
                                    action_taken: str = "",
                                    risk_color: str = "",
                                    observation: str = "",
                                    human_involved: bool = False,
                                    human_decision: str = "none", actor_id: Optional[str] = None):
        """Write a DecisionLog row (best-effort — DB failure is non-fatal)."""
        if not settings.DECISION_LOG_ENABLED:
            return
        try:
            from memory.database_models import (  # noqa: PLC0415
                async_session, DecisionLog,
            )
            async with async_session() as db:
                row = DecisionLog(
                    session_id=state.session_id,
                    user_id=actor_id or state.user_id,
                    step_number=state.steps_taken,
                    decision_type=decision_type,
                    agent="autonomous_engine",
                    reasoning=reasoning[:2000],
                    action_taken=action_taken[:2000],
                    risk_color=risk_color,
                    human_involved=human_involved,
                    human_decision=human_decision,
                    observation=observation[:2000],
                    metadata_={"goal": state.goal, "target": state.target},
                )
                db.add(row)
                await db.commit()
        except Exception as exc:  # noqa: BLE001
            log.debug("decision_log write failed", error=str(exc))


# Singleton
autonomous_engine = AutonomousEngine()
