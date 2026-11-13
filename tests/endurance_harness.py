"""SPEC-15 accelerated endurance harness; synthetic work only.

The harness drives the *real* campaign supervisor, campaign schedule/ledger
helpers and campaign execution guard against a deterministic synthetic engine,
worker and model provider.  It never contacts a network service, a model
provider or a real worker.  Simulated time is advanced deliberately; a test
using this harness is an accelerated simulation, not evidence of real-time
eight-hour reliability.

Responsibilities are kept separate on purpose:

* :class:`SyntheticEngine` models a bounded autonomous run and its durable
  checkpoint.  It only advances while the real supervisor considers the
  campaign live.
* :class:`SyntheticWorker` dispatches synthetic jobs through the production
  ``require_campaign_execution`` guard and records duplicate dispatches.
* :class:`MemoryAccounting` / :class:`PostgresAccounting` reserve and settle
  provider usage through the campaign ledger helpers (memory) or the real
  engagement accounting path (PostgreSQL).
"""
from __future__ import annotations

import copy
import json
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi import HTTPException

from memory import campaign_store as campaigns
from memory.campaign_store import (
    MODEL_STATES,
    TERMINAL_STATES,
    CampaignBudget,
    CampaignSchedule,
    CampaignSpec,
    evaluate_campaign_reservation,
    apply_settlement,
    validate_budget,
    validate_usage,
)
from orchestrator.campaign_execution import (
    CampaignExecutionDenied,
    require_campaign_execution,
)
from orchestrator.specialist_integration import (
    SpecialistIntegration,
    SpecialistIntegrationError,
)
from tests.test_campaigns import MemoryCampaignStore

UTC = timezone.utc
OWNER = "endurance-owner"
SESSION = "endurance-session"
DIGEST = "a" * 64
CAPABILITIES = {"tools": ["curl", "nmap"]}


# ── Simulated time ───────────────────────────────────────────────────────────
class SimulatedClock:
    """A manually advanced clock used by both the harness and the guard."""

    def __init__(self, start: datetime):
        self.start = start
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=float(seconds))
        return self.now


class _DateTimeMeta(type):
    """Keep ``isinstance(value, datetime)`` true for real datetimes.

    The guard module also uses ``datetime`` for type checks.  Replacing it must
    not make genuine ``datetime`` values fail ``isinstance``.
    """

    def __instancecheck__(cls, instance):
        return isinstance(instance, datetime)


class _SimulatedDateTime(datetime, metaclass=_DateTimeMeta):
    """``datetime`` replacement so production lease expiry follows sim time."""

    clock: SimulatedClock | None = None

    @classmethod
    def now(cls, tz=None):
        value = cls.clock()
        if tz is None:
            return value.astimezone(UTC).replace(tzinfo=None)
        return value.astimezone(tz)


@contextmanager
def simulated_datetime(clock: SimulatedClock):
    """Patch only the guard's ``datetime.now``; all other arithmetic is real."""
    _SimulatedDateTime.clock = clock
    with patch("orchestrator.campaign_execution.datetime", _SimulatedDateTime):
        try:
            yield
        finally:
            _SimulatedDateTime.clock = None


@contextmanager
def simulated_runtime_settings(*, tick_seconds: float,
                               lease_seconds: int | None = None):
    """Align production cadence settings with the accelerated tick.

    Runtime accumulation is capped at ``3 × CAMPAIGN_TICK_SECONDS`` to protect
    against clock jumps.  A simulation using a larger tick must raise that cap
    or it would silently under-count simulated work time.
    """
    from config.settings import settings

    previous_tick = settings.CAMPAIGN_TICK_SECONDS
    previous_lease = settings.CAMPAIGN_LEASE_SECONDS
    settings.CAMPAIGN_TICK_SECONDS = float(tick_seconds)
    if lease_seconds is not None:
        settings.CAMPAIGN_LEASE_SECONDS = int(lease_seconds)
    try:
        yield
    finally:
        settings.CAMPAIGN_TICK_SECONDS = previous_tick
        settings.CAMPAIGN_LEASE_SECONDS = previous_lease


# ── Durable campaign store for offline simulations ───────────────────────────
class EnduranceCampaignStore(MemoryCampaignStore):
    """In-memory campaign backend with the SQL accounting entry points."""

    async def reserve_usage(self, campaign_id: str, *, tokens: int,
                            cost_microusd: int,
                            check_only: bool = False) -> dict:
        async with self._lock:
            row = self.rows.get(campaign_id)
            if row is None or row["state"] in TERMINAL_STATES or (
                    not check_only and row["state"] not in MODEL_STATES):
                raise HTTPException(
                    409, {"code": "campaign_budget_unavailable",
                          "message": "Campaign is not accepting model calls"})
            try:
                usage = validate_usage(row["usage"])
                budget = validate_budget(row["budget"])
                updated = evaluate_campaign_reservation(
                    usage, budget, tokens=tokens,
                    cost_microusd=cost_microusd, check_only=check_only)
            except campaigns.CampaignValidationError:
                raise HTTPException(
                    409, {"code": "campaign_budget_unavailable",
                          "message": "Campaign budget cannot be verified"}) from None
            except campaigns.CampaignBudgetError as exc:
                status_code = (409 if exc.code in {
                    "campaign_accounting_inconsistent",
                    "campaign_budget_unavailable"} else 429)
                raise HTTPException(
                    status_code, {"code": exc.code, "message": str(exc)}) from None
            if not check_only:
                row["usage"] = updated
                row["updated_at"] = campaigns.utc_naive(self.clock())
            remaining_tokens = max(
                0, budget["max_tokens"] - updated["reserved_tokens"])
            remaining_cost = max(
                0, budget["max_cost_microusd"] - updated["reserved_cost_microusd"])
            return {
                "campaign_id": campaign_id,
                "reserved_tokens": updated["reserved_tokens"],
                "reserved_cost_microusd": updated["reserved_cost_microusd"],
                "remaining_tokens": remaining_tokens,
                "remaining_cost_microusd": remaining_cost,
            }

    async def settle_usage(self, campaign_id: str, *, reserved_tokens: int,
                           reserved_cost_microusd: int,
                           reported_tokens, reported_cost_microusd,
                           success: bool) -> dict:
        async with self._lock:
            row = self.rows.get(campaign_id)
            if row is None:
                raise CampaignExecutionDenied(
                    "campaign_supervisor_required",
                    "Campaign ledger is unavailable")
            row["usage"] = apply_settlement(
                row["usage"], reserved_tokens=reserved_tokens,
                reserved_cost_microusd=reserved_cost_microusd,
                reported_tokens=reported_tokens,
                reported_cost_microusd=reported_cost_microusd,
                success=success)
            row["updated_at"] = campaigns.utc_naive(self.clock())
            return self._copy(row)


# ── Synthetic provider accounting ────────────────────────────────────────────
def _denial_code(exc: HTTPException) -> str:
    detail = exc.detail
    if isinstance(detail, dict):
        return str(detail.get("code") or f"http_{exc.status_code}")
    return f"http_{exc.status_code}"


@dataclass
class _CallRecord:
    at: datetime
    campaign_id: str
    tokens: int
    reported_tokens: object
    success: bool


class MemoryAccounting:
    """Reserve, "physically" call, then settle against the durable ledger."""

    def __init__(self, store: EnduranceCampaignStore, clock: SimulatedClock,
                 *, report_tokens="auto", tokens_per_call: int = 2000,
                 cost_per_call_microusd: int = 0):
        self.store = store
        self.clock = clock
        self.report_tokens = report_tokens
        self.tokens_per_call = tokens_per_call
        self.cost_per_call_microusd = cost_per_call_microusd
        self.reservations: list[dict] = []
        self.provider_calls: list[_CallRecord] = []
        self.denials: list[dict] = []
        self.settlements: list[dict] = []

    async def call(self, campaign_id: str, prompt: str = "",
                   *, success: bool = True) -> dict:
        tokens = self.tokens_per_call
        try:
            reservation = await self.store.reserve_usage(
                campaign_id, tokens=tokens,
                cost_microusd=self.cost_per_call_microusd)
        except HTTPException as exc:
            self.denials.append({
                "at": self.clock(), "campaign_id": campaign_id,
                "status": exc.status_code, "code": _denial_code(exc),
            })
            raise
        self.reservations.append({"at": self.clock(), **reservation})
        reported = (tokens if self.report_tokens == "auto"
                    else self.report_tokens)
        self.provider_calls.append(_CallRecord(
            at=self.clock(), campaign_id=campaign_id, tokens=tokens,
            reported_tokens=reported, success=success))
        await self.store.settle_usage(
            campaign_id, reserved_tokens=tokens,
            reserved_cost_microusd=self.cost_per_call_microusd,
            reported_tokens=reported,
            reported_cost_microusd=(None if reported is None
                                    else self.cost_per_call_microusd),
            success=success)
        self.settlements.append({
            "at": self.clock(), "campaign_id": campaign_id,
            "reserved_tokens": tokens, "reported_tokens": reported,
            "success": success})
        return {"reserved_tokens": tokens, "reported_tokens": reported}


class PostgresAccounting:
    """Route synthetic physical calls through the real engagement accounting.

    ``ModelAccounting.reserve`` enforces the engagement ledger and the campaign
    ledger in one database transaction.  A denial therefore prevents the
    simulated physical call, which is what an endurance run must prove.
    """

    def __init__(self, *, session_id: str, owner_id: str,
                 clock: SimulatedClock, model: str = "endurance-synthetic",
                 report_tokens="auto"):
        self.session_id = session_id
        self.owner_id = owner_id
        self.clock = clock
        self.model = model
        self.report_tokens = report_tokens
        self.provider_calls: list[_CallRecord] = []
        self.denials: list[dict] = []
        self.attempts: list[dict] = []

    async def call(self, campaign_id: str, prompt: str = "",
                   *, success: bool = True) -> dict:
        from llm.engagement_budget import (
            engagement_context, model_accounting,
        )
        token = engagement_context.set(
            {"session_id": self.session_id, "owner": self.owner_id})
        try:
            attempt = await model_accounting.reserve(
                self.owner_id, "local", self.model, prompt, "")
        except HTTPException as exc:
            self.denials.append({
                "at": self.clock(), "campaign_id": campaign_id,
                "status": exc.status_code, "code": _denial_code(exc),
            })
            raise
        finally:
            engagement_context.reset(token)
        reserved = int(attempt["reserved_tokens"])
        self.attempts.append(attempt)
        reported = reserved if self.report_tokens == "auto" else self.report_tokens
        self.provider_calls.append(_CallRecord(
            at=self.clock(), campaign_id=campaign_id, tokens=reserved,
            reported_tokens=reported, success=success))
        await model_accounting.settle(attempt, {
            "success": success,
            "tokens_used": reported,
            "cost_microusd": 0 if reported is not None else None,
        })
        return {"reserved_tokens": reserved, "reported_tokens": reported}


# ── Synthetic worker with an enforced execution boundary ─────────────────────
class SyntheticWorker:
    """Idempotent synthetic worker; every dispatch passes the real guard."""

    def __init__(self, store, context_loader, clock: SimulatedClock):
        self.store = store
        self.context_loader = context_loader
        self.clock = clock
        self.jobs: dict[str, dict] = {}
        self.dispatches: list[dict] = []
        self.duplicates: list[dict] = []
        self.denied: list[dict] = []

    async def dispatch(self, *, campaign_id: str, token: str,
                       session_id: str, owner_id: str, scope_digest: str,
                       auth_revision: int, worker_epoch: int,
                       work_key: str, command: str) -> dict:
        try:
            await require_campaign_execution(
                campaign_id=campaign_id, token=token,
                session_id=session_id, owner_id=owner_id,
                scope_digest=scope_digest, auth_revision=auth_revision,
                worker_epoch=worker_epoch,
                loader=self.store.get,
                context_loader=self.context_loader)
        except CampaignExecutionDenied as exc:
            self.denied.append({
                "at": self.clock(), "work_key": work_key,
                "code": exc.code, "command": command})
            raise
        if work_key in self.jobs:
            self.duplicates.append({
                "at": self.clock(), "work_key": work_key,
                "command": command})
            return self.jobs[work_key]
        receipt = {
            "job_id": str(uuid.uuid4()),
            "work_key": work_key,
            "command": command,
            "state": "succeeded",
            "exit_code": 0,
            "stdout": json.dumps({"synthetic": True, "work_key": work_key}),
            "at": self.clock(),
        }
        self.jobs[work_key] = receipt
        self.dispatches.append(receipt)
        return receipt


# ── Synthetic specialist integration ─────────────────────────────────────────
class SyntheticSpecialistCoordinator:
    """Specialist dispatcher that enforces the real campaign execution guard.

    It never calls a model.  Every dispatch still passes
    ``require_campaign_execution`` with the durable synthetic campaign row and
    the harness engagement context, so a stale supervisor token, revoked
    authorization or changed scope denies the investigation exactly as it
    would in production.
    """

    def __init__(self, *, team_store, guard_store, context_loader, clock):
        self.team_store = team_store
        self.guard_store = guard_store
        self.context_loader = context_loader
        self.clock = clock
        self.calls: list[dict] = []
        self.denials: list[dict] = []

    async def run(self, session_id: str, owner_id: str, task_id: str,
                  request_id: str, skill: str, *, campaign_id: str = "",
                  campaign_supervisor_token: str = "", scope_digest: str = "",
                  auth_revision=None, worker_epoch=None) -> dict:
        task = self.team_store.tasks.get(task_id)
        if task is None:
            raise CampaignExecutionDenied(
                "campaign_supervisor_required", "Synthetic specialist task is missing")
        try:
            await require_campaign_execution(
                campaign_id=campaign_id, token=campaign_supervisor_token,
                session_id=session_id, owner_id=owner_id,
                scope_digest=scope_digest, auth_revision=auth_revision,
                worker_epoch=worker_epoch, loader=self.guard_store.get,
                context_loader=self.context_loader)
        except CampaignExecutionDenied as exc:
            self.denials.append({"at": self.clock(), "task_id": task_id,
                                 "code": exc.code})
            raise
        self.calls.append({"at": self.clock(), "task_id": task_id,
                           "campaign_id": campaign_id})
        evidence = list(task.get("evidence_inputs") or [])[:1]
        task.update(
            state="awaiting_review", run_id=request_id,
            attempts=int(task.get("attempts", 0) or 0) + 1,
            result={
                "evidence_references": evidence,
                "observations": [{
                    "observation": "Synthetic saved-response observation",
                    "evidence_references": evidence, "verified": False}],
                "hypotheses": [{
                    "description": "Synthetic unverified hypothesis",
                    "evidence_references": evidence, "verified": False}],
                "uncertainty": ["Synthetic specialist output is never verified"],
            })
        return {"entity_id": task_id, "data": copy.deepcopy(task),
                "duplicate": False}


class SpecialistRig:
    """Bounded specialist phase wired to a synthetic durable team ledger."""

    def __init__(self, *, guard_store, context_loader, clock,
                 advertised=None, scope=None):
        from tests.test_specialist_integration import MemoryTeamStore

        self.team_store = MemoryTeamStore()
        self.coordinator = SyntheticSpecialistCoordinator(
            team_store=self.team_store, guard_store=guard_store,
            context_loader=context_loader, clock=clock)
        self.service = SpecialistIntegration(
            store=self.team_store, coordinator=self.coordinator)
        self.advertised = advertised or {}
        self.scope = scope or {"targets": ["192.0.2.15"]}


# ── Synthetic bounded autonomous run ─────────────────────────────────────────
@dataclass
class EnginePlan:
    """Deterministic behaviour of one synthetic bounded run."""

    required_successful_steps: int = 12
    step_interval_seconds: int = 2700
    max_steps: int = 12
    # step number -> retryable reason that ends the run without progress.
    fail_at_step: dict[int, str] = field(default_factory=dict)
    # Provider-call number -> behaviour (auto reporting is the default).
    report_tokens: object = "auto"
    reject_restore: bool = False
    complete_goal: str = "discovery"
    # Run the bounded specialist review phase after this successful step.
    specialist_after_step: int | None = None


class SyntheticEngine:
    """Simulates the bounded autonomous run contract used by the supervisor.

    It shares no process state with the production engine.  Its durable
    checkpoint dict can be shared between instances to model a crash and
    restart in a new supervisor process.
    """

    def __init__(self, *, store, accounting, worker, context_loader,
                 clock: SimulatedClock, plan: EnginePlan | None = None,
                 checkpoints: dict | None = None, capabilities=None,
                 specialist: SpecialistRig | None = None):
        self.store = store
        self.accounting = accounting
        self.worker = worker
        self.context_loader = context_loader
        self.clock = clock
        self.plan = plan or EnginePlan()
        self.checkpoints = (checkpoints if checkpoints is not None else {})
        self.capabilities = capabilities or dict(CAPABILITIES)
        self.specialist = specialist
        self.live: dict[str, dict] = {}
        self.last_status: dict[str, dict] = {}
        self.calls: list[tuple[str, dict]] = []
        self.steps: list[dict] = []
        self.failures: list[dict] = []

    # ── Supervisor-facing lifecycle ─────────────────────────────────────────
    def get_status(self, session_id: str):
        if session_id in self.live:
            return self._status(self.live[session_id])
        return copy.deepcopy(self.last_status.get(session_id, {"active": False}))

    async def start(self, **kwargs):
        session_id = kwargs["session_id"]
        owner_id = kwargs["user_id"]
        context = await self.context_loader(owner_id, session_id)
        self.calls.append(("start", dict(kwargs)))
        checkpoint = self.checkpoints.get(session_id)
        if checkpoint is None:
            checkpoint = {
                "run_id": "run-" + uuid.uuid4().hex[:12],
                "steps_taken": 0,
                "successful_steps": 0,
                "model_calls": 0,
                "completed_observations": [],
                "observation_job_ids": {},
                "evidence_job_ids": [],
                "executed_commands": [],
                "run_state": "planning",
                "active": True,
            }
            self.checkpoints[session_id] = checkpoint
        run = {
            **checkpoint,
            "session_id": session_id,
            "owner_id": owner_id,
            "campaign_id": kwargs.get("campaign_id", ""),
            "token": kwargs.get("campaign_supervisor_token", ""),
            "scope_digest": context.get("scope_digest", DIGEST),
            "auth_revision": int(context.get("auth_revision", 0)),
            "worker_epoch": int(context.get("worker_epoch", 0)),
            "max_steps": int(kwargs.get("max_steps") or self.plan.max_steps),
            "elapsed": 0.0,
            "active": True,
            "run_state": "planning",
            "reason_code": "",
            "reason": "",
            "stop_requested": False,
            "pause_requested": False,
            "current_phase": "recon",
            "waiting_approval": False,
        }
        self.live[session_id] = run
        self.last_status.pop(session_id, None)
        return {"status": "started", "session_id": session_id}

    async def restore(self, session_id: str, user_id: str, **kwargs):
        self.calls.append(("restore", dict(kwargs, session_id=session_id)))
        if self.plan.reject_restore:
            return {"status": "rejected", "reason_code": "checkpoint_state",
                    "reason": "Synthetic uncertain checkpoint requires review."}
        checkpoint = self.checkpoints.get(session_id)
        context = await self.context_loader(user_id, session_id)
        if checkpoint is None:
            return {"status": "rejected", "reason_code": "checkpoint_state",
                    "reason": "Synthetic checkpoint is missing."}
        run = {
            **copy.deepcopy(checkpoint),
            "session_id": session_id,
            "owner_id": context.get("owner_id") or user_id,
            "campaign_id": kwargs.get("campaign_id", ""),
            "token": kwargs.get("campaign_supervisor_token", ""),
            "scope_digest": context.get("scope_digest", DIGEST),
            "auth_revision": int(context.get("auth_revision", 0)),
            "worker_epoch": int(context.get("worker_epoch", 0)),
            "max_steps": int(checkpoint.get("max_steps") or self.plan.max_steps),
            "elapsed": 0.0,
            "active": True,
            "run_state": "planning",
            "reason_code": "",
            "reason": "",
            "stop_requested": False,
            "pause_requested": False,
            "current_phase": "recon",
            "waiting_approval": False,
        }
        self.live[session_id] = run
        self.last_status.pop(session_id, None)
        return {"status": "restored", "session_id": session_id}

    async def request_graceful_stop(self, session_id: str, user_id: str = ""):
        self.calls.append(("graceful", {"session_id": session_id}))
        run = self.live.get(session_id)
        if run is not None:
            run["pause_requested"] = True
            run["stop_requested"] = True
            self._end(session_id, run, "blocked", "run_interrupted",
                      "Synthetic run yielded to a graceful campaign pause.")
        return {"status": "pause_pending"}

    async def request_stop(self, session_id: str, user_id: str = ""):
        self.calls.append(("stop", {"session_id": session_id}))
        run = self.live.get(session_id)
        if run is not None:
            run["stop_requested"] = True
            self._end(session_id, run, "blocked", "cancelled",
                      "Synthetic run stopped by the supervisor.")
        return {"status": "stopped"}

    async def detach_session(self, session_id: str):
        self.calls.append(("detach", {"session_id": session_id}))
        run = self.live.get(session_id)
        if run is not None:
            run["stop_requested"] = True
            self._end(session_id, run, "blocked", "run_interrupted",
                      "Synthetic run detached.")

    # ── Simulation ─────────────────────────────────────────────────────────
    async def advance(self, tick_seconds: float) -> None:
        for session_id in list(self.live):
            run = self.live.get(session_id)
            if run is None or not run["active"]:
                continue
            if run["stop_requested"] or run["pause_requested"]:
                self._end(session_id, run, "blocked", "run_interrupted",
                          "Synthetic run yielded to a campaign pause.")
                continue
            run["elapsed"] += tick_seconds
            while (run["active"]
                   and run["elapsed"] >= self.plan.step_interval_seconds):
                run["elapsed"] -= self.plan.step_interval_seconds
                await self._step(run)

    async def _step(self, run: dict) -> None:
        step = int(run["steps_taken"]) + 1
        failure = self.plan.fail_at_step.get(step)
        if failure:
            self.failures.append({
                "at": self.clock(), "step": step, "reason": failure})
            self._end(run["session_id"], run, "blocked", failure,
                      f"Synthetic worker failure at step {step}.")
            return
        prompt = f"synthetic plan step {step}"
        try:
            await self.accounting.call(run["campaign_id"], prompt)
        except HTTPException as exc:
            code = _denial_code(exc)
            self.failures.append({
                "at": self.clock(), "step": step, "reason": code})
            self._end(run["session_id"], run, "blocked", code,
                      f"Synthetic provider admission denied at step {step}.")
            return
        run["model_calls"] = int(run.get("model_calls", 0)) + 1
        work_key = f"{run['run_id']}:step:{step}"
        command = f"curl -s http://192.0.2.15/step-{step}"
        try:
            receipt = await self.worker.dispatch(
                campaign_id=run["campaign_id"], token=run["token"],
                session_id=run["session_id"],
                owner_id=run["owner_id"],
                scope_digest=run["scope_digest"],
                auth_revision=run["auth_revision"],
                worker_epoch=run["worker_epoch"],
                work_key=work_key, command=command)
        except CampaignExecutionDenied as exc:
            self.failures.append({
                "at": self.clock(), "step": step, "reason": exc.code})
            self._end(run["session_id"], run, "blocked", exc.code,
                      "Synthetic worker dispatch was denied by the campaign "
                      "execution boundary.")
            return
        observation = ("port_discovery" if step == 1 else
                       "http_response" if step == 2 else f"observation_{step}")
        run["steps_taken"] = step
        run["successful_steps"] = int(run.get("successful_steps", 0)) + 1
        run["executed_commands"] = [
            *run.get("executed_commands", []), command]
        run["evidence_job_ids"] = [
            *run.get("evidence_job_ids", []), receipt["job_id"]]
        run["observation_job_ids"] = {
            **run.get("observation_job_ids", {}),
            observation: [*run.get("observation_job_ids", {}).get(observation, []),
                          receipt["job_id"]],
        }
        if observation not in run["completed_observations"]:
            run["completed_observations"] = [
                *run["completed_observations"], observation]
        run["current_phase"] = "recon" if step < 3 else "vulnerability_analysis"
        self.steps.append({
            "at": self.clock(), "step": step, "work_key": work_key,
            "job_id": receipt["job_id"]})
        self._checkpoint(run)
        if (self.specialist is not None
                and self.plan.specialist_after_step is not None
                and step >= self.plan.specialist_after_step
                and not run.get("specialist_phase_done")):
            try:
                await self._specialist_phase(run)
            except SpecialistIntegrationError as exc:
                self.failures.append({
                    "at": self.clock(), "step": step, "reason": exc.code})
                self._end(run["session_id"], run, "blocked", exc.code,
                          f"Synthetic specialist phase failed: {exc}")
                return
        if int(run["successful_steps"]) >= self.plan.required_successful_steps:
            self._end(run["session_id"], run, "completed", "",
                      "Synthetic goal evidence satisfied.")
        elif step >= int(run.get("max_steps") or self.plan.max_steps):
            self._end(run["session_id"], run, "blocked",
                      "step_budget_exhausted",
                      "Synthetic bounded run exhausted its step budget.")

    async def _specialist_phase(self, run: dict) -> None:
        rig = self.specialist
        selection = await rig.service.candidates(
            session_id=run["session_id"], owner_id=run["owner_id"],
            campaign_id=run["campaign_id"], scope_digest=run["scope_digest"],
            scope=rig.scope, advertised=rig.advertised,
            observation_job_ids=run.get("observation_job_ids") or {})
        ensured = await rig.service.ensure(
            session_id=run["session_id"], owner_id=run["owner_id"],
            campaign_id=run["campaign_id"], scope_digest=run["scope_digest"],
            candidates=selection["candidates"])
        task_ids = sorted(set(run.get("specialist_task_ids", []))
                          | set(ensured["task_ids"]))
        run["specialist_task_ids"] = task_ids
        run["specialist_created"] = (int(run.get("specialist_created", 0))
                                     + int(ensured["created"]))
        # Persist identities before any specialist dispatch, matching the
        # production engine: a crash leaves a deterministic ledger that a
        # restore can reuse without creating a second investigation.
        self._checkpoint(run)
        outcome = await rig.service.run_pending(
            session_id=run["session_id"], owner_id=run["owner_id"],
            task_ids=task_ids, skill_level="expert", max_tasks=3,
            campaign_id=run["campaign_id"],
            campaign_supervisor_token=run["token"],
            scope_digest=run["scope_digest"],
            auth_revision=run["auth_revision"],
            worker_epoch=run["worker_epoch"])
        run["specialist_executed"] = [
            *run.get("specialist_executed", []), *outcome["executed"]]
        run["specialist_skipped"] = [
            *run.get("specialist_skipped", []), *outcome["skipped"]]
        run["specialist_errors"] = [
            *run.get("specialist_errors", []), *outcome["errors"]]
        run["specialist_phase_done"] = True
        self._checkpoint(run)

    def _end(self, session_id: str, run: dict, state: str, code: str,
             reason: str) -> None:
        run.update(active=False, run_state=state, reason_code=code,
                   reason=reason)
        self._checkpoint(run)
        self.last_status[session_id] = self._status(run)
        self.live.pop(session_id, None)

    def _checkpoint(self, run: dict) -> None:
        self.checkpoints[run["session_id"]] = {
            "run_id": run["run_id"],
            "steps_taken": int(run.get("steps_taken", 0)),
            "successful_steps": int(run.get("successful_steps", 0)),
            "model_calls": int(run.get("model_calls", 0)),
            "completed_observations": list(run.get("completed_observations", [])),
            "observation_job_ids": copy.deepcopy(
                run.get("observation_job_ids", {})),
            "evidence_job_ids": list(run.get("evidence_job_ids", [])),
            "executed_commands": list(run.get("executed_commands", [])),
            "specialist_phase_done": bool(run.get("specialist_phase_done")),
            "specialist_task_ids": list(run.get("specialist_task_ids", [])),
            "specialist_executed": list(run.get("specialist_executed", [])),
            "specialist_skipped": list(run.get("specialist_skipped", [])),
            "specialist_errors": list(run.get("specialist_errors", [])),
            "run_state": run.get("run_state", "planning"),
            "active": bool(run.get("active")),
            "max_steps": int(run.get("max_steps") or self.plan.max_steps),
            "reason_code": run.get("reason_code", ""),
            "reason": run.get("reason", ""),
        }

    @staticmethod
    def _status(run: dict) -> dict:
        steps = int(run.get("steps_taken", 0))
        max_steps = int(run.get("max_steps", 12))
        model_calls = int(run.get("model_calls", 0))
        return {
            "schema_version": 1,
            "session_id": run.get("session_id"),
            "run_id": run.get("run_id"),
            "owner_id": run.get("owner_id"),
            "scope_digest": run.get("scope_digest"),
            "auth_revision": int(run.get("auth_revision", 0)),
            "worker_epoch": int(run.get("worker_epoch", 0)),
            "run_state": run.get("run_state", "planning"),
            "reason_code": run.get("reason_code", ""),
            "reason": run.get("reason", ""),
            "successful_steps": int(run.get("successful_steps", 0)),
            "steps_taken": steps,
            "max_steps": max_steps,
            "remaining_steps": max(0, max_steps - steps),
            "model_calls": model_calls,
            "planning_attempts": model_calls,
            "remaining_model_calls": max(0, 20 - model_calls),
            "active": bool(run.get("active")) and run.get(
                "run_state") not in TERMINAL_STATES,
            "completed_observations": list(
                run.get("completed_observations", [])),
            "observation_job_ids": copy.deepcopy(
                run.get("observation_job_ids", {})),
            "evidence_job_ids": list(run.get("evidence_job_ids", [])),
            "executed_commands": list(run.get("executed_commands", [])),
            "current_phase": run.get("current_phase", "recon"),
            "specialist_phase_done": bool(run.get("specialist_phase_done")),
            "specialist_task_ids": list(run.get("specialist_task_ids", [])),
            "waiting_approval": False,
            "pending_action_id": None,
            "stop_requested": bool(run.get("stop_requested")),
            "pause_requested": bool(run.get("pause_requested")),
            "activity_tail": [],
        }

    def crash(self) -> None:
        """Lose all process-local run state; the durable checkpoint remains."""
        self.live.clear()
        self.last_status.clear()


# ── Harness facade ───────────────────────────────────────────────────────────
class EnduranceHarness:
    """Accelerated whole-workflow simulation driven by the real supervisor."""

    def __init__(self, *, start: datetime, tick_seconds: float = 300,
                 daily_runtime_seconds: int = 3600,
                 window=("09:00", "17:00"),
                 weekdays=(0, 1, 2, 3, 4),
                 budget_tokens: int = 200000,
                 max_retries: int = 3,
                 plan: EnginePlan | None = None,
                 supervisor_factory=None,
                 lease_seconds: int = 600,
                 specialist: bool = False):
        from orchestrator.campaign_supervisor import CampaignSupervisor

        self.clock = SimulatedClock(start)
        self.tick_seconds = tick_seconds
        self.lease_seconds = lease_seconds
        self.store = EnduranceCampaignStore(clock=self.clock)
        self.context = {
            "owner_id": OWNER, "scope": {"targets": ["192.0.2.15"]},
            "target": "192.0.2.15", "scope_digest": DIGEST,
            "auth_revision": 4, "worker_epoch": 2, "worker_blocked": False,
        }
        self.context_error: Exception | None = None
        self.worker = SyntheticWorker(self.store, self._context, self.clock)
        self.accounting = MemoryAccounting(self.store, self.clock)
        self.plan = plan or EnginePlan()
        self.specialist_rig = (
            SpecialistRig(guard_store=self.store, context_loader=self._context,
                          clock=self.clock,
                          scope=copy.deepcopy(self.context["scope"]))
            if specialist else None)
        self.engine = SyntheticEngine(
            store=self.store, accounting=self.accounting, worker=self.worker,
            context_loader=self._context, clock=self.clock, plan=self.plan,
            specialist=self.specialist_rig)
        self.supervisor_factory = supervisor_factory or (
            lambda: CampaignSupervisor(
                store=self.store, engine=self.engine,
                context_loader=self._context,
                capabilities=self._capabilities,
                planner_preflight=self._planner_preflight,
                worker_resume=self._worker_resume,
                clock=self.clock))
        self.supervisor = self.supervisor_factory()
        self.spec = CampaignSpec(
            session_id=SESSION, owner_id=OWNER, goal="discovery",
            target="192.0.2.15", skill_level="expert",
            objective="Synthetic SPEC-15 endurance campaign",
            max_steps=self.plan.max_steps, auto_risk_threshold="green_orange",
            schedule=CampaignSchedule(
                timezone="UTC", weekdays=list(weekdays),
                window_start=window[0], window_end=window[1],
                daily_runtime_seconds=daily_runtime_seconds),
            budget=CampaignBudget(
                max_tokens=budget_tokens, max_cost_microusd=2000000),
            max_retries=max_retries, scope_digest=DIGEST,
            auth_revision=4, worker_epoch=2,
            required_tools=["curl", "nmap"])
        self.campaign_id: str | None = None
        self.trace: list[dict] = []
        self.window_violations: list[dict] = []

    async def _context(self, owner_id, session_id):
        if self.context_error is not None:
            raise self.context_error
        return copy.deepcopy(self.context)

    async def _capabilities(self):
        return copy.deepcopy(CAPABILITIES)

    async def _planner_preflight(self, owner_id, session_id):
        return {"ready": True}

    async def _worker_resume(self, owner_id, session_id):
        return None

    @contextmanager
    def simulation(self):
        """Activate simulated time and production cadence for this harness."""
        with simulated_runtime_settings(
                tick_seconds=self.tick_seconds,
                lease_seconds=self.lease_seconds):
            with simulated_datetime(self.clock):
                yield self

    async def create(self) -> dict:
        row = await self.store.create(self.spec)
        self.campaign_id = row["id"]
        # Start the simulation at the campaign's first due instant.
        row["next_action_at"] = campaigns.utc_naive(self.clock())
        self.store.rows[row["id"]] = row
        return row

    async def tick(self) -> None:
        now = self.clock()
        await self.supervisor.tick(now)
        await self.engine.advance(self.tick_seconds)
        self.clock.advance(self.tick_seconds)
        self._record_window_activity(now)

    async def run(self, ticks: int) -> None:
        for _ in range(max(0, int(ticks))):
            await self.tick()

    def _record_window_activity(self, now: datetime) -> None:
        schedule = self.spec.schedule
        if campaigns.within_window(now, schedule):
            return
        latest_calls = [call for call in self.accounting.provider_calls
                        if call.at == now]
        latest_dispatches = [item for item in self.worker.dispatches
                             if item["at"] == now]
        if latest_calls or latest_dispatches:
            self.window_violations.append({
                "at": now, "provider_calls": len(latest_calls),
                "worker_dispatches": len(latest_dispatches)})

    def crash(self, downtime_seconds: float | None = None) -> None:
        """Simulate an abrupt supervisor/engine process death.

        The old supervisor object is discarded without releasing its lease;
        simulated time advances past the lease so the next recovery must
        reconcile the campaign instead of resuming it directly.
        """
        self.engine.crash()
        self.supervisor = self.supervisor_factory()
        if downtime_seconds is None:
            downtime_seconds = self.lease_seconds + 5
        self.clock.advance(downtime_seconds)

    async def recover(self) -> list[str]:
        recovered = await self.supervisor.recover(self.clock())
        self.trace.append({"kind": "recover", "at": self.clock(),
                           "recovered": list(recovered)})
        return recovered

    async def restart_supervisor(self) -> None:
        """New process, same durable store and engine checkpoints."""
        self.supervisor = self.supervisor_factory()

    async def row(self) -> dict:
        return await self.store.get(self.campaign_id)

    def summary(self) -> dict:
        specialist = self.specialist_rig
        return {
            "campaign_id": self.campaign_id,
            "simulated_start": self.clock.start.isoformat(),
            "simulated_end": self.clock.now.isoformat(),
            "simulated_seconds": int(
                (self.clock.now - self.clock.start).total_seconds()),
            "ticks": int((self.clock.now - self.clock.start).total_seconds()
                         // self.tick_seconds),
            "provider_calls": len(self.accounting.provider_calls),
            "provider_denials": len(self.accounting.denials),
            "worker_dispatches": len(self.worker.dispatches),
            "duplicate_dispatches": len(self.worker.duplicates),
            "denied_dispatches": len(self.worker.denied),
            "window_violations": len(self.window_violations),
            "synthetic_steps": len(self.engine.steps),
            "specialist_calls": (len(specialist.coordinator.calls)
                                 if specialist else 0),
            "specialist_denials": (len(specialist.coordinator.denials)
                                   if specialist else 0),
            "specialist_tasks": (len(specialist.team_store.tasks)
                                 if specialist else 0),
        }


def monday_start(year: int = 2026, month: int = 11, day: int = 16,
                 hour: int = 9) -> datetime:
    """Return a UTC Monday inside the default synthetic work window."""
    start = datetime(year, month, day, hour, 0, tzinfo=UTC)
    if start.weekday() != 0:
        raise ValueError("start must be a Monday for the default schedule")
    return start
