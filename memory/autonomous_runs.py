"""Durable autonomous run checkpoints.

The ``autonomous_runs`` row remains the single durable run record.  Each save
also writes a versioned, digest-bound checkpoint inside ``snapshot.checkpoint``.
The checkpoint is deliberately data-only: restoring it rehydrates in-memory run
state and the knowledge base, but never replays a command or an authorization.

``RunStore.recover`` remains the fail-closed startup reconciliation: it marks
unfinished rows blocked without touching the nested checkpoint, so an explicit
owner-initiated restore can still validate and continue the campaign.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import Text, cast, or_, select

from config.settings import settings
from memory.database_models import AutonomousRun, async_session
from security.redaction import redact

TERMINAL = {"completed", "blocked", "failed"}
CHECKPOINT_SCHEMA = "aria.autonomous.checkpoint.v1"
MAX_MODEL_CALLS = 20
MAX_JOB_TEXT = 100
MAX_COMMAND_TEXT = 2000
MAX_COMMANDS = 100
MAX_REASON_TEXT = 2000
MAX_TOOLS = 50
MAX_TOOL_TEXT = 50
HEX64 = re.compile(r"^[0-9a-f]{64}$")
JOB_TERMINAL = {"succeeded", "failed", "cancelled"}

CHECKPOINT_FIELDS = (
    "schema", "run_id", "session_id", "owner_id", "scope_digest", "user_id",
    "goal", "target",
    "skill_level", "objective", "objective_truncated", "completion_criteria",
    "required_observations", "completed_observations", "observation_job_ids",
    "evidence_job_ids", "executed_commands", "executed_command_hashes",
    "steps_taken", "max_steps", "successful_steps", "model_calls",
    "remaining_steps", "remaining_model_calls", "run_state", "reason_code",
    "reason", "failure_detail", "started_at", "checkpointed_at",
    "auth_revision", "worker_epoch", "capabilities", "risk_threshold",
    "current_phase", "last_action_id", "last_action_command", "active",
    "pending_authorization", "digest",
)

RUN_STATES = {
    "planning", "awaiting_approval", "executing", "completed", "blocked",
    "failed", "cancelling", "restored",
}
RISK_THRESHOLDS = {"green_only", "green_orange", "manual"}
RESTORABLE_BLOCKED_REASONS = {
    "restart_reconciliation", "run_interrupted",
    "specialist_integration_failed", "specialist_context_unavailable",
    "campaign_supervisor_required",
}


class CheckpointError(Exception):
    """Base class for a checkpoint that cannot be used safely."""

    code = "checkpoint_error"

    def __init__(self, message: str = "", *, code: str | None = None):
        super().__init__(message or self.code)
        if code:
            self.code = code


class CheckpointAccessError(CheckpointError):
    code = "checkpoint_access_denied"


class CheckpointIntegrityError(CheckpointError):
    code = "checkpoint_integrity"


class CheckpointConflict(CheckpointError):
    code = "checkpoint_conflict"


class CheckpointStateError(CheckpointError):
    code = "checkpoint_state"


def canonical_digest(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, default=str).encode("utf-8")
    ).hexdigest()


def command_digest(command: str) -> str:
    return hashlib.sha256(str(command).encode("utf-8")).hexdigest()


def _payload_digest(payload: dict) -> str:
    return canonical_digest({key: value for key, value in payload.items()
                             if key != "digest"})


def _clean_text(value, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return " ".join(value.replace("\x00", " ").split())[:limit]


def _int(value, default: int = 0) -> int:
    return value if type(value) is int else default


def _float(value, default: float = 0.0) -> float:
    if type(value) in (int, float) and math.isfinite(value):
        return float(value)
    return default


def _bounded_list(value, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value:
        text = _clean_text(item, item_limit)
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def build_checkpoint(snapshot: dict) -> dict:
    """Build the digest-bound checkpoint envelope from a status snapshot.

    All textual values arrive already redacted by ``RunStore.save``.  Bounds
    here are defensive: a checkpoint is a storage contract, not a trust source.
    """
    observation_job_ids: dict[str, list[str]] = {}
    raw_observations = snapshot.get("observation_job_ids")
    if isinstance(raw_observations, dict):
        for observation, job_ids in raw_observations.items():
            key = _clean_text(observation, 50)
            if not key:
                continue
            observation_job_ids[key] = _bounded_list(job_ids, MAX_COMMANDS, MAX_JOB_TEXT)
    evidence_job_ids = _bounded_list(snapshot.get("evidence_job_ids"),
                                     MAX_COMMANDS, MAX_JOB_TEXT)
    executed_commands = _bounded_list(snapshot.get("executed_commands"),
                                      MAX_COMMANDS, MAX_COMMAND_TEXT)
    specialist_investigation_ids = _bounded_list(
        snapshot.get("specialist_investigation_ids"), 20, MAX_JOB_TEXT)
    hashes: list[str] = []
    raw_hashes = snapshot.get("executed_command_hashes")
    if isinstance(raw_hashes, (list, tuple)):
        for value in raw_hashes:
            text = value.lower() if isinstance(value, str) else ""
            if HEX64.fullmatch(text) and text not in hashes:
                hashes.append(text)
            if len(hashes) >= MAX_COMMANDS:
                break
    tools: list[str] = []
    capabilities = snapshot.get("capabilities")
    if isinstance(capabilities, dict):
        tools = _bounded_list(capabilities.get("tools"), MAX_TOOLS, MAX_TOOL_TEXT)
    capability_versions: dict[str, int] = {}
    if isinstance(capabilities, dict):
        for name in ("authenticated_http_version", "specialist_http_version"):
            value = capabilities.get(name)
            if type(value) is int and 0 <= value <= 100:
                capability_versions[name] = value
    typed = capabilities.get('typed_adapters') if isinstance(capabilities, dict) else None
    typed_versions = {}
    if isinstance(typed, dict):
        typed_versions = {key:value for key,value in typed.items()
                          if isinstance(key,str) and 0 < len(key) <= 100
                          and type(value) is int and value == 1}
        typed_versions = dict(sorted(typed_versions.items())[:10])
    steps_taken = max(0, _int(snapshot.get("steps_taken")))
    max_steps = max(0, _int(snapshot.get("max_steps")))
    model_calls = max(0, _int(snapshot.get("model_calls")))
    checkpoint = {
        "schema": CHECKPOINT_SCHEMA,
        "run_id": _clean_text(snapshot.get("run_id"), MAX_JOB_TEXT),
        "session_id": _clean_text(snapshot.get("session_id"), MAX_JOB_TEXT),
        "owner_id": _clean_text(snapshot.get("owner_id"), MAX_JOB_TEXT),
        "scope_digest": _clean_text(snapshot.get("scope_digest"), 64).lower(),
        "user_id": _clean_text(snapshot.get("user_id"), MAX_JOB_TEXT),
        "goal": _clean_text(snapshot.get("goal"), 50),
        "target": _clean_text(snapshot.get("target"), 500),
        "skill_level": _clean_text(snapshot.get("skill_level"), 20) or "intermediate",
        "objective": _clean_text(
            snapshot.get("original_objective", snapshot.get("objective")),
            settings.AUTONOMOUS_OBJECTIVE_MAX_CHARS),
        "objective_truncated": bool(snapshot.get("objective_truncated", False)),
        "completion_criteria": _clean_text(snapshot.get("completion_criteria"), 2000),
        "required_observations": _bounded_list(snapshot.get("required_observations"), 20, 50),
        "completed_observations": _bounded_list(snapshot.get("completed_observations"), 20, 50),
        "observation_job_ids": observation_job_ids,
        "evidence_job_ids": evidence_job_ids,
        "executed_commands": executed_commands,
        "executed_command_hashes": hashes,
        "steps_taken": steps_taken,
        "max_steps": max_steps,
        "successful_steps": max(0, _int(snapshot.get("successful_steps"))),
        "model_calls": model_calls,
        "remaining_steps": max(0, max_steps - steps_taken),
        "remaining_model_calls": max(0, MAX_MODEL_CALLS - model_calls),
        "run_state": _clean_text(snapshot.get("run_state"), 30) or "blocked",
        "reason_code": _clean_text(snapshot.get("reason_code"), 100),
        "reason": _clean_text(snapshot.get("reason"), MAX_REASON_TEXT),
        "failure_detail": _clean_text(snapshot.get("failure_detail"), MAX_REASON_TEXT),
        "started_at": _float(snapshot.get("started_at")),
        "checkpointed_at": datetime.utcnow().isoformat(),
        "auth_revision": max(0, _int(snapshot.get("auth_revision"))),
        "worker_epoch": max(0, _int(snapshot.get("worker_epoch"))),
        "capabilities": {"tools": tools, **capability_versions,
                         **({'typed_adapters':typed_versions} if typed_versions else {})},
        "risk_threshold": _clean_text(
            snapshot.get("risk_threshold", snapshot.get("auto_risk_threshold")),
            20) or "manual",
        "current_phase": _clean_text(snapshot.get("current_phase"), 30) or "recon",
        "last_action_id": _clean_text(snapshot.get("last_action_id"), MAX_JOB_TEXT),
        "last_action_command": _clean_text(snapshot.get("last_action_command"), MAX_COMMAND_TEXT),
        # Optional SPEC-13 fields remain readable in pre-SPEC-13 checkpoints.
        "campaign_id": _clean_text(snapshot.get("campaign_id"), MAX_JOB_TEXT),
        "specialist_phase_done": bool(snapshot.get("specialist_phase_done", False)),
        "specialist_investigation_ids": specialist_investigation_ids,
        "active": bool(snapshot.get("active", False)),
        # A checkpoint never carries an approval/authorization identifier.
        "pending_authorization": None,
    }
    checkpoint["digest"] = _payload_digest(checkpoint)
    return checkpoint


def _require(condition, message: str):
    if not condition:
        raise CheckpointIntegrityError(message)


def _validate_timestamp(value, field: str) -> str:
    _require(isinstance(value, str) and value, f"Invalid checkpoint {field}")
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise CheckpointIntegrityError(f"Invalid checkpoint {field}") from None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    if parsed.timestamp() > time.time() + 300:
        raise CheckpointIntegrityError(f"Checkpoint {field} is in the future")
    return value


def validate_checkpoint(checkpoint, *, expected_run_id: str = "",
                        expected_session_id: str = "",
                        expected_owner_id: str = "",
                        max_steps_limit: int | None = None,
                        max_model_calls: int = MAX_MODEL_CALLS) -> dict:
    """Validate structure, bounds and integrity of a stored checkpoint.

    Contextual checks (current scope, owner, authorization revision, receipts)
    are performed by the caller.  This function never trusts stored lengths,
    counters or hashes without re-checking them.
    """
    _require(isinstance(checkpoint, dict), "Checkpoint is missing or malformed")
    missing = set(CHECKPOINT_FIELDS).difference(checkpoint)
    _require(not missing, "Checkpoint is incomplete: " + ", ".join(sorted(missing)))
    _require(checkpoint.get("schema") == CHECKPOINT_SCHEMA,
             "Checkpoint schema is unsupported")
    digest = checkpoint.get("digest")
    _require(isinstance(digest, str) and HEX64.fullmatch(digest),
             "Checkpoint digest is missing or malformed")
    _require(hmac.compare_digest(digest, _payload_digest(checkpoint)),
             "Checkpoint integrity digest does not match its content")

    for field in ("run_id", "session_id", "owner_id", "goal", "objective",
                  "completion_criteria", "run_state"):
        _require(isinstance(checkpoint[field], str) and checkpoint[field],
                 f"Invalid checkpoint {field}")
    if expected_run_id:
        _require(hmac.compare_digest(checkpoint["run_id"], expected_run_id),
                 "Checkpoint belongs to another run")
    if expected_session_id:
        _require(hmac.compare_digest(checkpoint["session_id"], expected_session_id),
                 "Checkpoint belongs to another engagement")
    if expected_owner_id:
        _require(hmac.compare_digest(checkpoint["owner_id"], expected_owner_id),
                 "Checkpoint belongs to another owner")

    _require(checkpoint["run_state"] in RUN_STATES, "Checkpoint run state is invalid")
    _require(checkpoint["skill_level"] in {"beginner", "intermediate", "expert"},
             "Checkpoint skill level is invalid")
    _require(checkpoint["risk_threshold"] in RISK_THRESHOLDS,
             "Checkpoint risk threshold is invalid")
    _require(checkpoint["pending_authorization"] is None,
             "Checkpoint contains an execution authorization")
    _require(isinstance(checkpoint["scope_digest"], str)
             and HEX64.fullmatch(checkpoint["scope_digest"]),
             "Checkpoint scope digest is invalid")

    for field in ("target", "reason", "failure_detail", "last_action_id",
                  "last_action_command"):
        _require(isinstance(checkpoint[field], str), f"Invalid checkpoint {field}")
    for field, limit in (("objective", settings.AUTONOMOUS_OBJECTIVE_MAX_CHARS),
                         ("completion_criteria", 2000), ("reason", MAX_REASON_TEXT),
                         ("failure_detail", MAX_REASON_TEXT)):
        _require(len(checkpoint[field]) <= limit, f"Checkpoint {field} is oversized")

    for field in ("required_observations", "completed_observations",
                  "evidence_job_ids", "executed_commands"):
        _require(isinstance(checkpoint[field], list), f"Invalid checkpoint {field}")
    _require(len(checkpoint["completed_observations"]) <= 20,
             "Checkpoint observation list is oversized")
    _require(len(set(checkpoint["completed_observations"])) ==
             len(checkpoint["completed_observations"]),
             "Checkpoint observation list contains duplicates")
    _require(len(checkpoint["evidence_job_ids"]) <= MAX_COMMANDS,
             "Checkpoint evidence list is oversized")
    _require(len(set(checkpoint["evidence_job_ids"])) ==
             len(checkpoint["evidence_job_ids"]),
             "Checkpoint evidence list contains duplicates")
    for job_id in checkpoint["evidence_job_ids"]:
        _require(isinstance(job_id, str) and 0 < len(job_id) <= MAX_JOB_TEXT,
                 "Invalid checkpoint evidence job")
    _require(len(checkpoint["executed_commands"]) <= MAX_COMMANDS,
             "Checkpoint command list is oversized")
    for command in checkpoint["executed_commands"]:
        _require(isinstance(command, str) and 0 < len(command) <= MAX_COMMAND_TEXT,
                 "Invalid checkpoint command")

    observations = checkpoint["observation_job_ids"]
    _require(isinstance(observations, dict), "Invalid checkpoint observation index")
    _require(set(observations) == set(checkpoint["completed_observations"]),
             "Checkpoint observation index is inconsistent")
    indexed_jobs: list[str] = []
    for observation, job_ids in observations.items():
        _require(isinstance(observation, str) and observation,
                 "Invalid checkpoint observation name")
        _require(isinstance(job_ids, list) and job_ids,
                 "Checkpoint observation has no worker receipt")
        _require(len(job_ids) <= MAX_COMMANDS, "Checkpoint observation jobs are oversized")
        for job_id in job_ids:
            _require(isinstance(job_id, str) and 0 < len(job_id) <= MAX_JOB_TEXT,
                     "Invalid checkpoint observation job")
            indexed_jobs.append(job_id)
    _require(len(set(indexed_jobs)) == len(indexed_jobs),
             "Checkpoint observation job is referenced twice")
    _require(set(indexed_jobs) == set(checkpoint["evidence_job_ids"]),
             "Checkpoint evidence index is inconsistent")

    hashes = checkpoint["executed_command_hashes"]
    _require(isinstance(hashes, list), "Invalid checkpoint command digest list")
    _require(len(hashes) == len(checkpoint["executed_commands"]),
             "Checkpoint command digests are incomplete")
    _require(all(isinstance(item, str) and HEX64.fullmatch(item) for item in hashes),
             "Checkpoint command digest is malformed")

    for field in ("steps_taken", "max_steps", "successful_steps", "model_calls",
                  "remaining_steps", "remaining_model_calls", "auth_revision",
                  "worker_epoch"):
        _require(type(checkpoint[field]) is int and checkpoint[field] >= 0,
                 f"Invalid checkpoint {field}")
    _require(checkpoint["max_steps"] >= 1, "Checkpoint has no step budget")
    limit = settings.AUTONOMOUS_MAX_STEPS if max_steps_limit is None else max_steps_limit
    _require(checkpoint["max_steps"] <= limit, "Checkpoint step budget exceeds policy")
    _require(checkpoint["steps_taken"] <= checkpoint["max_steps"],
             "Checkpoint step counters are inconsistent")
    _require(checkpoint["successful_steps"] <= checkpoint["steps_taken"],
             "Checkpoint success counter is inconsistent")
    _require(checkpoint["model_calls"] <= max_model_calls,
             "Checkpoint model-call budget exceeds policy")
    _require(checkpoint["remaining_steps"] ==
             checkpoint["max_steps"] - checkpoint["steps_taken"],
             "Checkpoint remaining step limit is inconsistent")
    _require(checkpoint["remaining_model_calls"] ==
             max_model_calls - checkpoint["model_calls"],
             "Checkpoint remaining model-call limit is inconsistent")

    capabilities = checkpoint["capabilities"]
    allowed_capabilities = {"tools", "authenticated_http_version",
                            "specialist_http_version", "typed_adapters"}
    _require(isinstance(capabilities, dict) and "tools" in capabilities
             and set(capabilities).issubset(allowed_capabilities),
             "Checkpoint capabilities are malformed")
    tools = capabilities["tools"]
    _require(isinstance(tools, list) and len(tools) <= MAX_TOOLS,
             "Checkpoint capability list is malformed")
    _require(all(isinstance(tool, str) and 0 < len(tool) <= MAX_TOOL_TEXT
                 for tool in tools), "Checkpoint capability is malformed")
    for name in allowed_capabilities - {"tools", "typed_adapters"}:
        if name in capabilities:
            _require(type(capabilities[name]) is int
                     and 0 <= capabilities[name] <= 100,
                     "Checkpoint protocol capability is malformed")
    if 'typed_adapters' in capabilities:
        typed = capabilities['typed_adapters']
        _require(isinstance(typed,dict) and len(typed) <= 10
                 and all(isinstance(key,str) and 0 < len(key) <= 100
                         and type(value) is int and value == 1 for key,value in typed.items()),
                 'Checkpoint typed capabilities are malformed')

    if "campaign_id" in checkpoint:
        _require(isinstance(checkpoint["campaign_id"], str)
                 and len(checkpoint["campaign_id"]) <= MAX_JOB_TEXT,
                 "Checkpoint campaign identity is invalid")
    if "specialist_phase_done" in checkpoint:
        _require(type(checkpoint["specialist_phase_done"]) is bool,
                 "Checkpoint specialist phase flag is invalid")
    if "specialist_investigation_ids" in checkpoint:
        ids = checkpoint["specialist_investigation_ids"]
        _require(isinstance(ids, list) and len(ids) <= 20,
                 "Checkpoint specialist list is malformed")
        _require(all(isinstance(item, str) and 0 < len(item) <= MAX_JOB_TEXT
                     for item in ids), "Checkpoint specialist identity is malformed")
        _require(len(set(ids)) == len(ids),
                 "Checkpoint specialist list contains duplicates")

    started_at = checkpoint["started_at"]
    _require(type(started_at) in (int, float) and math.isfinite(started_at)
             and started_at >= 0, "Checkpoint start timestamp is invalid")
    _validate_timestamp(checkpoint["checkpointed_at"], "timestamp")
    _require(type(checkpoint["active"]) is bool, "Checkpoint active flag is invalid")
    _require(type(checkpoint["objective_truncated"]) is bool,
             "Checkpoint objective flag is invalid")
    return checkpoint


def _prepare_snapshot(existing, snapshot: dict) -> dict:
    """Apply transition history, redaction and a fresh checkpoint envelope."""
    transitions = list((existing or {}).get("transitions", []))
    run_state = snapshot.get("run_state", "")
    if not transitions or transitions[-1].get("state") != run_state:
        transitions.append({"state": run_state,
                            "reason_code": snapshot.get("reason_code", ""),
                            "timestamp": datetime.utcnow().isoformat()})
    clean = {key: value for key, value in snapshot.items()
             if key not in {"checkpoint", "checkpoint_digest", "checkpointed_at",
                            "restore_lease"}}
    safe = redact({**clean, "transitions": transitions})
    checkpoint = build_checkpoint(safe)
    safe["checkpoint"] = checkpoint
    safe["checkpoint_digest"] = checkpoint["digest"]
    safe["checkpointed_at"] = checkpoint["checkpointed_at"]
    return safe


class SQLRunBackend:
    """SQL persistence for autonomous run checkpoints."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory or async_session

    async def save(self, snapshot):
        async with self._session_factory() as db:
            row = await db.get(AutonomousRun, snapshot["run_id"])
            if row is None:
                row = AutonomousRun(id=snapshot["run_id"],
                                    session_id=snapshot["session_id"])
                db.add(row)
            row.state = snapshot["run_state"]
            row.snapshot = _prepare_snapshot(row.snapshot, snapshot)
            row.updated_at = datetime.utcnow()
            await db.commit()

    async def latest(self, session_id):
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousRun).where(
                AutonomousRun.session_id == session_id).order_by(
                AutonomousRun.updated_at.desc(), AutonomousRun.id.desc()).limit(1)
            )).scalar_one_or_none()
            return row.snapshot if row else {"active": False}

    async def recover(self):
        async with self._session_factory() as db:
            rows = (await db.execute(select(AutonomousRun).where(or_(
                AutonomousRun.state.notin_(TERMINAL),
                cast(AutonomousRun.snapshot["restore_lease"], Text).isnot(None),
            )).with_for_update())).scalars().all()
            for row in rows:
                snapshot = dict(row.snapshot or {})
                # A crash between claim_restore and commit_restore leaves a
                # lease on an already-blocked row.  Reconciliation must clear
                # it, not only leases on rows it still marks blocked.
                snapshot.pop("restore_lease", None)
                if row.state not in TERMINAL:
                    snapshot.update({
                        "active": False, "run_state": "blocked",
                        "reason_code": "restart_reconciliation",
                        "waiting_approval": False, "pending_action_id": None,
                        "reason": ("Server restarted. Inspect durable worker jobs before "
                                   "starting another run; no command was replayed. "
                                   "A validated checkpoint can be restored explicitly."),
                    })
                    row.state = "blocked"
                row.snapshot = snapshot
                row.updated_at = datetime.utcnow()
            await db.commit()

    async def claim_restore(self, session_id: str, run_id: str | None = None,
                            token: str | None = None,
                            lease_seconds: int = 60) -> dict:
        """Lock the campaign's run rows and claim a short restore lease.

        A lease prevents two recovery attempts from validating/committing the
        same checkpoint concurrently.  It is intentionally short-lived; startup
        reconciliation clears it after a crash.  It is not an execution lease.
        """
        token = token or str(uuid.uuid4())
        async with self._session_factory() as db:
            rows = (await db.execute(select(AutonomousRun).where(
                AutonomousRun.session_id == session_id).order_by(
                AutonomousRun.updated_at.desc(), AutonomousRun.id.desc()
            ).with_for_update())).scalars().all()
            if not rows:
                raise CheckpointIntegrityError("No durable run checkpoint exists")
            if run_id:
                target = next((row for row in rows if row.id == run_id), None)
                if target is None:
                    raise CheckpointIntegrityError("Requested checkpoint does not exist")
                if rows[0].id != target.id:
                    raise CheckpointConflict(
                        "Checkpoint is stale; a newer run exists for this engagement",
                        code="checkpoint_stale")
            else:
                target = rows[0]
            snapshot = dict(target.snapshot or {})
            # The engine lock is process-local.  A persisted active flag is
            # the cross-process fence: never restore a checkpoint that another
            # process may still be driving, even after its restore lease is gone.
            if bool(snapshot.get("active")):
                raise CheckpointConflict(
                    "Another autonomous run is active for this engagement",
                    code="run_active")
            lease = snapshot.get("restore_lease")
            if isinstance(lease, dict):
                try:
                    expires_at = float(lease.get("expires_at", 0))
                except (TypeError, ValueError):
                    expires_at = 0
                if expires_at > time.time():
                    raise CheckpointConflict(
                        "Checkpoint restoration is already in progress",
                        code="restore_in_progress")
            snapshot["restore_lease"] = {"token": token,
                                         "expires_at": time.time() + lease_seconds}
            target.snapshot = snapshot
            await db.commit()
            return {"run_id": target.id, "session_id": target.session_id,
                    "snapshot": snapshot, "token": token}

    async def commit_restore(self, session_id: str, run_id: str, token: str,
                             snapshot: dict) -> dict:
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousRun).where(
                AutonomousRun.id == run_id).with_for_update())).scalar_one_or_none()
            current = dict((row.snapshot if row else None) or {})
            lease = current.get("restore_lease")
            if (row is None or row.session_id != session_id
                    or not isinstance(lease, dict) or lease.get("token") != token):
                raise CheckpointConflict("Checkpoint restore claim was lost",
                                         code="restore_conflict")
            row.state = snapshot["run_state"]
            row.snapshot = _prepare_snapshot(current, snapshot)
            row.updated_at = datetime.utcnow()
            await db.commit()
            return row.snapshot

    async def release_restore(self, session_id: str, run_id: str, token: str) -> None:
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousRun).where(
                AutonomousRun.id == run_id).with_for_update())).scalar_one_or_none()
            if row is None or row.session_id != session_id:
                return
            snapshot = dict(row.snapshot or {})
            lease = snapshot.get("restore_lease")
            if isinstance(lease, dict) and lease.get("token") == token:
                snapshot.pop("restore_lease", None)
                row.snapshot = snapshot
                await db.commit()


class RunStore:
    def __init__(self, backend=None, jobs=None):
        self._backend = backend or SQLRunBackend()
        self._jobs = jobs

    async def save(self, snapshot):
        return await self._backend.save(snapshot)

    async def latest(self, session_id):
        return await self._backend.latest(session_id)

    async def recover(self):
        return await self._backend.recover()

    async def claim_restore(self, session_id, run_id=None, token=None,
                            lease_seconds=60):
        return await self._backend.claim_restore(session_id, run_id, token,
                                                 lease_seconds)

    async def commit_restore(self, session_id, run_id, token, snapshot):
        return await self._backend.commit_restore(session_id, run_id, token, snapshot)

    async def release_restore(self, session_id, run_id, token):
        return await self._backend.release_restore(session_id, run_id, token)

    async def restore_jobs(self, session_id, last_action_id=""):
        """Read durable worker receipts without submitting or cancelling."""
        store = self._jobs
        if store is None:
            from memory.worker_jobs import SQLJobStore  # noqa: PLC0415
            store = SQLJobStore()
        jobs = await store.list(session_id)
        active = [job for job in jobs
                  if isinstance(job, dict) and job.get("state") not in JOB_TERMINAL]
        last = None
        if last_action_id:
            last = next((job for job in jobs if isinstance(job, dict)
                         and job.get("job_id") == last_action_id), None)
        return active, last


run_store = RunStore()
