"""Durable autonomous campaign supervisor.

The supervisor decides *when* an existing, bounded SPEC-11 run may start or
resume.  It never creates new authorization, never changes per-run step or
model-call limits, never replays worker jobs and never talks to a model itself.

Every action is guarded by a PostgreSQL campaign lease.  A campaign that loses
its supervisor (crash, restart, another process) is moved back to ``scheduled``
with a bounded backoff and must pass the full authorization/checkpoint
preflight before anything runs again.
"""
from __future__ import annotations

import asyncio
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import HTTPException

from config.settings import settings
from memory import campaign_store as campaigns
from memory.campaign_observability import (
    CampaignMonitor, accounting_inconsistencies, correlation_scope,
    default_checkpoint_loader, default_model_summary_provider,
    default_specialist_summary_provider, default_worker_summary_provider,
    operations_view,
)
from memory.campaign_store import (
    CampaignBudgetError,
    CampaignConflict,
    CampaignNotFound,
    CampaignSchedule,
    CampaignValidationError,
    accumulate_runtime,
    budget_remaining,
    campaign_status,
    clear_active_since,
    daily_runtime_seconds,
    local_day_key,
    next_window_open,
    required_tools_for_goal,
    retry_next_action,
    retry_state,
    set_active_since,
    validate_budget,
    validate_retry,
    validate_usage,
    within_window,
)

log = structlog.get_logger("campaign_supervisor")
UTC = timezone.utc

# Failures that preserve a valid checkpoint and may be retried with backoff.
RETRYABLE_REASONS = frozenset({
    "worker_unavailable", "worker_timeout", "worker_cancelled",
    "worker_failed", "worker_exit_nonzero", "execution_failed",
    "run_error", "run_interrupted", "restart_reconciliation",
    "provider_timeout", "provider_request_failed", "local_model_request_failed",
    "all_exhausted", "local_model_unavailable",
    "provider_authorization_or_storage_unavailable",
    "no_executable_proposal", "invalid_planner_output",
    "run_active", "restore_in_progress", "checkpoint_conflict",
    "supervisor_error", "supervisor_restart",
    "specialist_integration_failed", "specialist_context_unavailable",
    "campaign_supervisor_required",
})

# Failures that require an operator; the campaign stops automatically.
TERMINAL_REASONS = frozenset({
    "unsupported_goal", "capability_unavailable",
    "knowledge_restore_failed", "knowledge_persist_failed",
    "human_rejected", "step_budget_exhausted", "model_call_budget",
    "model_not_configured", "model_tariff_missing", "model_budget_exhausted",
    "model_budget_denied", "validation_budget_exhausted",
    "campaign_budget_exhausted", "campaign_budget_unavailable",
    "specialist_budget_exhausted",
    "authorization_expired", "authorization_unavailable", "worker_blocked",
    "worker_epoch_changed", "scope_changed", "authorization_changed",
    "unsafe_state", "cancelled",
    "engagement_busy", "checkpoint_access_denied", "checkpoint_integrity",
    "checkpoint_state", "retry_exhausted", "invalid_campaign_state",
    "campaign_accounting_inconsistent",
})


class PreflightError(Exception):
    """A campaign could not be safely started or resumed."""

    def __init__(self, code: str, message: str = "",
                 retryable: Optional[bool] = None):
        self.code = code
        self.message = message or code
        self.retryable = (code in RETRYABLE_REASONS
                          if retryable is None else bool(retryable))
        super().__init__(self.message)


def _reason_code(code: str) -> str:
    code = str(code or "").strip()
    return code if code in RETRYABLE_REASONS or code in TERMINAL_REASONS else "unsafe_state"


class CampaignSupervisor:
    def __init__(self, *, store=None, engine=None, context_loader=None,
                 capabilities=None, planner_preflight=None, clock=None,
                 worker_resume=None):
        self.store = store or campaigns.campaign_store
        self.engine = engine
        self.context_loader = context_loader
        self.capabilities = capabilities
        self.planner_preflight = planner_preflight
        self.worker_resume = worker_resume
        self._clock = clock or (lambda: datetime.now(UTC))
        self._task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._recovered = False
        self._claimed: set[str] = set()
        self._token = (f"{socket.gethostname()[:18]}-{os.getpid()}-"
                       f"{uuid.uuid4().hex[:24]}"[:64])

    # ── Process lifecycle ────────────────────────────────────────────────
    def start(self) -> None:
        if not settings.CAMPAIGN_SUPERVISOR_ENABLED or self._task is not None:
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="campaign-supervisor")
        log.info("campaign supervisor started")

    async def stop(self) -> None:
        if self._task is None:
            return
        if self._stop_event is not None:
            self._stop_event.set()
        self._task.cancel()
        await asyncio.gather(self._task, return_exceptions=True)
        self._task = None
        for campaign_id in list(self._claimed):
            await self._safe_release(campaign_id)
        self._claimed.clear()
        log.info("campaign supervisor stopped")

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def _run(self) -> None:
        while not (self._stop_event and self._stop_event.is_set()):
            try:
                if not self._recovered:
                    await self.recover()
                    self._recovered = True
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one bad campaign must not stop the loop.
                log.exception("campaign supervisor tick failed")
            if self._stop_event is None:
                return
            try:
                await asyncio.wait_for(self._stop_event.wait(),
                                       timeout=settings.CAMPAIGN_TICK_SECONDS)
            except asyncio.TimeoutError:
                continue

    # ── Durable recovery ─────────────────────────────────────────────────
    async def recover(self, now: Optional[datetime] = None) -> list[str]:
        now = now or self._clock()
        with correlation_scope(f"campaign-recover-{uuid.uuid4().hex[:12]}"):
            recovered = await self.store.recover(now)
        if recovered:
            log.info("campaign supervisor recovered records", count=len(recovered))
        return recovered

    async def tick(self, now: Optional[datetime] = None) -> list[str]:
        now = now or self._clock()
        handled: list[str] = []
        for row in await self.store.due(now):
            try:
                # One correlation id per campaign per tick ties together the
                # bounded operational ring and the immutable audit row.
                with correlation_scope(
                        f"campaign-{str(row.get('id'))[:8]}-{uuid.uuid4().hex[:12]}"):
                    if await self._process(row, now):
                        handled.append(row["id"])
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("campaign processing failed", campaign=row.get("id"))
                await self._safe_release(row["id"])
        return handled

    async def _process(self, row: dict, now: datetime) -> bool:
        claimed = await self.store.claim(
            row["id"], self._token, now, settings.CAMPAIGN_LEASE_SECONDS)
        if claimed is None:
            return False
        self._claimed.add(row["id"])
        current = await self.store.get(row["id"])
        if (current is None or current["state"] in campaigns.TERMINAL_STATES
                or not self._is_due(current, now)):
            await self.store.release(row["id"], self._token)
            return False
        try:
            state = current["state"]
            if state == "cancelling":
                await self._finalize_cancel(current, now)
            elif state == "pausing":
                await self._finalize_pause(current, now)
            elif state in {"starting", "running"}:
                await self._supervise_running(current, now)
            elif state == "scheduled" or (state == "paused" and current["auto_resume"]):
                await self._run_scheduled(current, now)
            else:
                await self.store.release(row["id"], self._token)
            return True
        except CampaignValidationError:
            await self._force_fail(
                current, now,
                "Durable campaign state is invalid; the supervisor refused to act.")
            return True
        except Exception:
            await self._safe_release(row["id"])
            raise

    async def _safe_release(self, campaign_id: str) -> None:
        try:
            await self.store.release(campaign_id, self._token)
        except Exception:  # noqa: BLE001
            log.warning("campaign lease release failed", campaign=campaign_id)
        self._claimed.discard(campaign_id)

    @staticmethod
    def _is_due(row: dict, now: datetime) -> bool:
        """Re-check eligibility after the lease lock; the due snapshot is racy."""
        state = row["state"]
        if state in {"starting", "running", "pausing", "cancelling"}:
            return True
        next_at = row.get("next_action_at")
        if state == "scheduled":
            return next_at is None or next_at <= campaigns.utc_naive(now)
        if state == "paused":
            return (bool(row.get("auto_resume")) and next_at is not None
                    and next_at <= campaigns.utc_naive(now))
        return False

    # ── Public operator operations ───────────────────────────────────────
    async def create(self, spec, now: Optional[datetime] = None) -> dict:
        now = now or self._clock()
        try:
            row = await self.store.create(spec)
        except CampaignConflict:
            raise
        return campaign_status(row, now)

    async def pause(self, campaign_id: str, owner_id: str,
                    now: Optional[datetime] = None) -> dict:
        now = now or self._clock()
        row = await self._owned(campaign_id, owner_id)
        if row["state"] == "paused":
            return self._status(row, now)
        if row["state"] in campaigns.TERMINAL_STATES or row["state"] == "cancelling":
            raise CampaignConflict("Campaign is not running")
        updated = await self.store.transition(
            campaign_id, self._token, now,
            {"scheduled", "starting", "running", "pausing"},
            {"state": "pausing", "pause_reason": "operator_requested",
             "auto_resume": False, "reason_code": "pause_requested",
             "reason": "Pause requested by the engagement owner.",
             "next_action_at": None},
            event="campaign_pause_requested", event_reason_code="pause_requested",
            event_reason="Owner requested a graceful campaign pause.",
            require_lease=False,
        )
        if updated is None:
            raise CampaignConflict("Campaign state changed; retry the pause")
        return self._status(updated, now)

    async def resume(self, campaign_id: str, owner_id: str,
                     now: Optional[datetime] = None) -> dict:
        now = now or self._clock()
        row = await self._owned(campaign_id, owner_id)
        if row["state"] != "paused":
            raise CampaignConflict("Only a paused campaign can be resumed")
        usage = validate_usage(row["usage"])
        schedule = CampaignSchedule.model_validate(row["schedule"])
        day = local_day_key(now, schedule)
        exhausted_today = daily_runtime_seconds(usage, day) >= schedule.daily_runtime_seconds
        if within_window(now, schedule) and not exhausted_today:
            next_at = now
        else:
            next_at = next_window_open(now, schedule, strictly_later=exhausted_today)
        retry = validate_retry(row["retry"])
        updated = await self.store.transition(
            campaign_id, self._token, now, {"paused"},
            {"state": "scheduled", "auto_resume": True,
             "pause_reason": "", "reason_code": "operator_resumed",
             "reason": "Campaign resumed by the engagement owner.",
             "next_action_at": next_at,
             "retry": retry_state(0, retry["max"], "")},
            event="campaign_resumed", event_reason_code="operator_resumed",
            event_reason="Owner resumed the campaign.",
            require_lease=False,
        )
        if updated is None:
            raise CampaignConflict("Campaign state changed; retry the resume")
        return self._status(updated, now)

    async def cancel(self, campaign_id: str, owner_id: str,
                     now: Optional[datetime] = None) -> dict:
        now = now or self._clock()
        row = await self._owned(campaign_id, owner_id)
        if row["state"] in campaigns.TERMINAL_STATES:
            return self._status(row, now)
        updated = await self.store.transition(
            campaign_id, self._token, now, campaigns.LIVE_STATES,
            {"state": "cancelling", "auto_resume": False,
             "pause_reason": "", "reason_code": "operator_cancelled",
             "reason": "Cancellation requested by the engagement owner.",
             "next_action_at": now},
            event="campaign_cancel_requested",
            event_reason_code="operator_cancelled",
            event_reason="Owner requested campaign cancellation.",
            require_lease=False,
        )
        if updated is None:
            raise CampaignConflict("Campaign state changed; retry the cancellation")
        return self._status(updated, now)

    async def status(self, campaign_id: str, owner_id: str,
                     now: Optional[datetime] = None) -> dict:
        now = now or self._clock()
        row = await self._owned(campaign_id, owner_id)
        return self._status(row, now)

    async def latest_status(self, session_id: str, owner_id: str,
                            now: Optional[datetime] = None) -> Optional[dict]:
        now = now or self._clock()
        row = await self.store.latest_for_session(session_id)
        if row is None or row["owner_id"] != owner_id:
            return None
        return self._status(row, now)

    async def _owned(self, campaign_id: str, owner_id: str) -> dict:
        row = await self.store.get(campaign_id)
        if row is None or row["owner_id"] != owner_id:
            raise CampaignNotFound("Campaign was not found")
        return row

    def run_status(self, session_id: str) -> Optional[dict]:
        """Return the bounded in-memory run view used by status and health."""
        try:
            status = self._engine().get_status(session_id)
        except Exception:  # noqa: BLE001 - monitoring must not break status
            return None
        if not isinstance(status, dict) or not status.get("run_id"):
            return None
        return {
            "run_id": status.get("run_id"),
            "run_state": status.get("run_state"),
            "active": status.get("active"),
            "reason_code": status.get("reason_code", ""),
            "reason": status.get("reason", ""),
            "steps_taken": status.get("steps_taken", 0),
            "max_steps": status.get("max_steps", 0),
            "successful_steps": status.get("successful_steps", 0),
            "model_calls": status.get("model_calls", 0),
            "remaining_steps": status.get("remaining_steps", 0),
            "remaining_model_calls": status.get("remaining_model_calls", 0),
            "waiting_approval": status.get("waiting_approval", False),
            "pending_action_id": status.get("pending_action_id", ""),
            "current_phase": status.get("current_phase", ""),
            "specialist_investigation_ids": list(
                status.get("specialist_investigation_ids") or [])[:20],
            "completed_observations": list(
                status.get("completed_observations") or [])[:20],
        }

    def _monitor(self) -> CampaignMonitor:
        return CampaignMonitor(
            store=self.store,
            run_status_provider=self.run_status,
            checkpoint_loader=default_checkpoint_loader(),
            worker_summary_provider=default_worker_summary_provider(),
            specialist_summary_provider=default_specialist_summary_provider(),
            model_summary_provider=default_model_summary_provider(),
        )

    async def health(self, campaign_id: str, owner_id: str,
                     now: Optional[datetime] = None) -> dict:
        row = await self._owned(campaign_id, owner_id)
        return await self._monitor().health(row, owner_id, now)

    async def health_for_row(self, row: dict, owner_id: str,
                             now: Optional[datetime] = None) -> dict:
        """Build health for a row the caller already authorized and loaded."""
        return await self._monitor().health(row, owner_id, now)

    async def latest_health(self, session_id: str, owner_id: str,
                            now: Optional[datetime] = None) -> Optional[dict]:
        row = await self.store.latest_for_session(session_id)
        if row is None or row["owner_id"] != owner_id:
            return None
        return await self._monitor().health(row, owner_id, now)

    async def events(self, campaign_id: str, owner_id: str, *,
                     after: int = 0, limit: int = 50) -> dict:
        row = await self._owned(campaign_id, owner_id)
        return operations_view(row.get("operations"), after=after, limit=limit)

    async def latest_events(self, session_id: str, owner_id: str, *,
                            after: int = 0, limit: int = 50) -> Optional[dict]:
        row = await self.store.latest_for_session(session_id)
        if row is None or row["owner_id"] != owner_id:
            return None
        return operations_view(row.get("operations"), after=after, limit=limit)

    def _status(self, row: dict, now: datetime) -> dict:
        return campaign_status(row, now, run_status=self.run_status(row["session_id"]))

    # ── Scheduled execution ──────────────────────────────────────────────
    async def _run_scheduled(self, row: dict, now: datetime) -> None:
        usage = validate_usage(row["usage"])
        schedule = CampaignSchedule.model_validate(row["schedule"])
        budget = validate_budget(row["budget"])
        day = local_day_key(now, schedule)
        if daily_runtime_seconds(usage, day) >= schedule.daily_runtime_seconds:
            next_at = next_window_open(now, schedule, strictly_later=True)
            await self._pause_without_run(
                row, now, usage, next_at, "daily_runtime_exhausted",
                "Daily campaign runtime limit reached; resumes in the next allowed window.",
                auto_resume=True)
            return
        if not within_window(now, schedule):
            next_at = next_window_open(now, schedule)
            if next_at is None:
                await self._fail(row, now, usage, "unsafe_state",
                                 "No valid execution window is available.")
                return
            await self._transition(
                row, now, {row["state"]},
                {"next_action_at": next_at, "auto_resume": True,
                 "reason_code": "window_wait",
                 "reason": "Waiting for the next scheduled execution window."},
                event="campaign_window_wait",
                reason_code="window_wait",
                reason="Campaign is outside its execution window.",
                release=True)
            return
        remaining_tokens, remaining_cost = budget_remaining(usage, budget)
        if usage["stopped"] or remaining_tokens <= 0 or remaining_cost <= 0:
            await self._fail(row, now, usage, "campaign_budget_exhausted",
                             "Campaign model budget is exhausted.")
            return
        try:
            await self._preflight(row)
        except PreflightError as exc:
            await self._recoverable_failure(row, now, usage, exc.code,
                                            exc.message, exc.retryable)
            return

        starting = await self._transition(
            row, now, {row["state"]},
            {"state": "starting", "auto_resume": False,
             "next_action_at": None, "reason_code": "starting",
             "reason": "Campaign passed preflight and is starting a bounded run."},
            event="campaign_starting", reason_code="starting",
            reason="Preflight passed; starting or restoring the bounded run.")
        if starting is None:
            return
        row = starting

        try:
            await self.store.bind_session(
                row["session_id"], row["owner_id"], row["id"])
        except CampaignConflict:
            await self._fail(row, now, usage, "engagement_busy",
                             "Another campaign is bound to this engagement.")
            return
        except CampaignNotFound:
            await self._fail(row, now, usage, "authorization_unavailable",
                             "Engagement is no longer available.")
            return
        except Exception:  # noqa: BLE001
            await self._recoverable_failure(
                row, now, usage, "supervisor_error",
                "Campaign session binding failed.", True)
            return

        try:
            result = await self._start_or_restore(row)
        except PreflightError as exc:
            await self._unbind(row)
            await self._recoverable_failure(row, now, usage, exc.code,
                                            exc.message, exc.retryable)
            return
        except Exception:  # noqa: BLE001
            await self._unbind(row)
            await self._recoverable_failure(
                row, now, usage, "supervisor_error",
                "Campaign could not start or restore its bounded run.", True)
            return

        engine_status = self._run_status(row["session_id"])
        if not isinstance(result, dict):
            await self._unbind(row)
            await self._recoverable_failure(
                row, now, usage, "supervisor_error",
                "Engine returned no usable status.", True)
            return
        result_status = result.get("status")
        if result_status == "already_running":
            await self._unbind(row)
            await self._recoverable_failure(
                row, now, usage, "run_active",
                "A bounded run is already active for this engagement.", True)
            return
        if result_status == "rejected":
            await self._unbind(row)
            code = _reason_code(result.get("reason_code"))
            await self._recoverable_failure(
                row, now, usage, code,
                str(result.get("reason") or "Checkpoint restore was rejected."),
                code in RETRYABLE_REASONS)
            return
        if not isinstance(engine_status, dict) or not engine_status.get("run_id"):
            await self._unbind(row)
            await self._recoverable_failure(
                row, now, usage, "supervisor_error",
                "Engine state is unavailable after start or restore.", True)
            return
        if not engine_status.get("active"):
            await self._run_ended(row, now, usage, engine_status)
            return
        await self._mark_running(row, now, usage, engine_status)

    async def _pause_without_run(self, row, now, usage, next_at, code,
                                 detail, *, auto_resume: bool) -> None:
        values = {
            "state": "paused",
            "pause_reason": code,
            "auto_resume": auto_resume,
            "reason_code": code,
            "reason": detail,
            "next_action_at": next_at if auto_resume else None,
            "usage": clear_active_since(usage),
        }
        await self._transition(row, now, {row["state"]}, values,
                               event="campaign_paused", reason_code=code,
                               reason=detail, release=True)
        await self._unbind(row)

    async def _mark_running(self, row, now, usage, status) -> None:
        usage["last_steps"] = int(status.get("steps_taken", 0) or 0)
        usage["last_successful_steps"] = int(status.get("successful_steps", 0) or 0)
        usage["last_model_calls"] = int(status.get("model_calls", 0) or 0)
        usage = set_active_since(usage, now)
        retry = validate_retry(row["retry"])
        resumed = bool(row.get("has_started"))
        await self._transition(
            row, now, {"starting"},
            {"state": "running", "run_id": status.get("run_id"),
             "has_started": True, "auto_resume": False,
             "started_at": row.get("started_at") or now,
             "next_action_at": None, "pause_reason": "",
             "reason_code": "", "reason": "", "usage": usage, "retry": retry},
            event="campaign_resumed" if resumed else "campaign_started",
            reason_code="running",
            reason=("Campaign resumed its validated checkpoint."
                    if resumed else "Campaign started a bounded autonomous run."))

    # ── Supervision of a live run ────────────────────────────────────────
    async def _supervise_running(self, row: dict, now: datetime) -> None:
        usage = validate_usage(row["usage"])
        schedule = CampaignSchedule.model_validate(row["schedule"])
        usage = accumulate_runtime(
            usage, now, schedule,
            cap_seconds=max(60, int(settings.CAMPAIGN_TICK_SECONDS * 3)))
        status = self._run_status(row["session_id"])
        if not isinstance(status, dict) or not status.get("run_id"):
            await self._recoverable_failure(
                row, now, usage, "supervisor_restart",
                "Supervisor restarted while the campaign was live; the run "
                "must be validated and resumed.", True)
            return
        if not status.get("active"):
            await self._run_ended(row, now, usage, status)
            return

        try:
            context = await self._context(row["owner_id"], row["session_id"])
        except HTTPException as exc:
            code = ("authorization_expired" if exc.status_code == 403
                    else "authorization_unavailable")
            await self._abort_unsafe(row, now, usage, code,
                                     "Engagement authorization is no longer valid.")
            return
        except Exception:  # noqa: BLE001
            await self._abort_unsafe(
                row, now, usage, "authorization_unavailable",
                "Engagement authorization could not be verified.")
            return
        if context.get("owner_id") != row["owner_id"]:
            await self._abort_unsafe(row, now, usage, "authorization_expired",
                                     "Engagement ownership changed.")
            return
        if context.get("scope_digest") != row["scope_digest"]:
            await self._abort_unsafe(row, now, usage, "scope_changed",
                                     "Engagement scope changed during the campaign.")
            return
        if context.get("worker_blocked"):
            await self._abort_unsafe(row, now, usage, "worker_blocked",
                                     "Engagement execution is fenced.")
            return
        if int(context.get("auth_revision", -1)) != int(status.get("auth_revision", -2)):
            await self._abort_unsafe(row, now, usage, "authorization_expired",
                                     "Run credentials were revoked.")
            return
        if int(context.get("worker_epoch", -1)) != int(status.get("worker_epoch", -2)):
            await self._abort_unsafe(row, now, usage, "worker_epoch_changed",
                                     "Run was invalidated by worker cancellation.")
            return

        budget = validate_budget(row["budget"])
        remaining_tokens, remaining_cost = budget_remaining(usage, budget)
        if accounting_inconsistencies(usage):
            await self._abort_unsafe(
                row, now, usage, "campaign_accounting_inconsistent",
                "Campaign model accounting is inconsistent; further provider "
                "calls are denied and the campaign stopped.")
            return
        if usage["stopped"] or remaining_tokens <= 0 or remaining_cost <= 0:
            code = ("campaign_accounting_inconsistent"
                    if usage["stop_reason"] in {"unknown_usage",
                                                "accounting_inconsistent"}
                    else "campaign_budget_exhausted")
            detail = ("Campaign accounting stopped after unknown provider usage."
                      if code == "campaign_accounting_inconsistent"
                      else "Campaign model budget is exhausted.")
            await self._abort_unsafe(row, now, usage, code, detail)
            return

        day = local_day_key(now, schedule)
        if daily_runtime_seconds(usage, day) >= schedule.daily_runtime_seconds:
            await self._begin_pause(
                row, now, usage, "daily_runtime_exhausted",
                "Daily campaign runtime limit reached; the current step may finish.",
                auto_resume=True)
            return
        if not within_window(now, schedule):
            await self._begin_pause(
                row, now, usage, "schedule_window_closed",
                "The execution window closed; the current step may finish.",
                auto_resume=True)
            return

        previous_successful = int(usage.get("last_successful_steps", 0) or 0)
        usage["last_steps"] = int(status.get("steps_taken", 0) or 0)
        usage["last_successful_steps"] = int(status.get("successful_steps", 0) or 0)
        usage["last_model_calls"] = int(status.get("model_calls", 0) or 0)
        progressed = usage["last_successful_steps"] > previous_successful
        operation = None
        values = {"state": "running", "usage": usage}
        if progressed:
            operation = {
                "event": "campaign_step_succeeded",
                "reason_code": "step_succeeded",
                "message": (f"Run advanced to {usage['last_successful_steps']} "
                            "successful step(s)."),
                "attributes": {
                    "step": usage["last_steps"],
                    "successful_steps": usage["last_successful_steps"],
                    "model_calls": usage["last_model_calls"],
                },
            }
            # Durable progress clears the restart/failure streak.  Recovery
            # counts a supervisor restart as a retry, so without this a long
            # endurance run would exhaust its retry budget after repeated
            # restarts even though every run continued to produce evidence.
            retry = validate_retry(row["retry"])
            values["retry"] = retry_state(0, retry["max"], "")
        await self._transition(
            row, now, {row["state"]}, values,
            event="", reason_code="", reason="", operation=operation)

    async def _begin_pause(self, row, now, usage, code: str, detail: str,
                           *, auto_resume: bool) -> None:
        status = self._run_status(row["session_id"])
        if isinstance(status, dict) and status.get("active"):
            try:
                await self._engine().request_graceful_stop(row["session_id"],
                                                           row["owner_id"])
            except Exception:  # noqa: BLE001 - fail closed if it cannot be paused.
                await self._abort_unsafe(
                    row, now, usage, "authorization_unavailable",
                    "Campaign could not be paused safely; the run was stopped.")
                return
        next_at = (next_window_open(now, schedule_of(row), strictly_later=True)
                   if auto_resume else None)
        await self._transition(
            row, now, {row["state"]},
            {"state": "pausing", "pause_reason": code,
             "auto_resume": auto_resume, "reason_code": "pause_pending",
             "reason": detail, "next_action_at": None, "usage": usage},
            event="campaign_pausing", reason_code=code, reason=detail)

    async def _finalize_pause(self, row, now) -> None:
        usage = validate_usage(row["usage"])
        schedule = CampaignSchedule.model_validate(row["schedule"])
        usage = accumulate_runtime(
            usage, now, schedule,
            cap_seconds=max(60, int(settings.CAMPAIGN_TICK_SECONDS * 3)))
        status = self._run_status(row["session_id"])
        if isinstance(status, dict) and status.get("active"):
            try:
                if not status.get("stop_requested"):
                    await self._engine().request_graceful_stop(
                        row["session_id"], row["owner_id"])
            except Exception:  # noqa: BLE001
                await self._abort_unsafe(
                    row, now, usage, "authorization_unavailable",
                    "Campaign pause could not be confirmed; the run was stopped.")
                return
            await self._transition(
                row, now, {"pausing"},
                {"state": "pausing", "usage": usage},
                event="", reason_code="", reason="")
            return
        usage = clear_active_since(usage)
        pause_reason = row.get("pause_reason") or "operator_requested"
        auto_resume = bool(row.get("auto_resume"))
        if pause_reason == "daily_runtime_exhausted":
            next_at = next_window_open(now, schedule, strictly_later=True)
        elif auto_resume:
            next_at = next_window_open(now, schedule)
        else:
            next_at = None
        await self._transition(
            row, now, {"pausing"},
            {"state": "paused", "pause_reason": pause_reason,
             "auto_resume": auto_resume and next_at is not None,
             "reason_code": "paused",
             "reason": ("Campaign paused at the owner's request."
                        if pause_reason == "operator_requested"
                        else "Campaign paused by its schedule."),
             "next_action_at": next_at if auto_resume else None,
             "usage": usage},
            event="campaign_paused", reason_code="paused",
            reason="Campaign run stopped and its checkpoint remains resumable.",
            release=True)
        await self._unbind(row)

    async def _finalize_cancel(self, row, now) -> None:
        usage = validate_usage(row["usage"])
        schedule = CampaignSchedule.model_validate(row["schedule"])
        usage = clear_active_since(accumulate_runtime(
            usage, now, schedule,
            cap_seconds=max(60, int(settings.CAMPAIGN_TICK_SECONDS * 3))))
        status = self._run_status(row["session_id"])
        if isinstance(status, dict) and status.get("active"):
            try:
                await self._engine().request_stop(row["session_id"],
                                                  user_id=row["owner_id"])
            except Exception:  # noqa: BLE001 - explicit operator cancellation.
                try:
                    await self._engine().detach_session(row["session_id"])
                except Exception:  # noqa: BLE001
                    log.warning("campaign cancellation detach failed",
                                campaign=row["id"])
        await self._transition(
            row, now, {"cancelling"},
            {"state": "cancelled", "reason_code": "operator_cancelled",
             "reason": "Campaign cancelled by the engagement owner.",
             "usage": usage},
            event="campaign_cancelled", reason_code="operator_cancelled",
            reason="Owner cancelled the campaign.")
        await self._unbind(row)

    async def _run_ended(self, row, now, usage, status) -> None:
        run_state = status.get("run_state")
        if run_state == "completed":
            await self._complete(row, now, usage, status)
            return
        code = _reason_code(status.get("reason_code") or "run_interrupted")
        detail = str(status.get("reason") or "Bounded run ended without completion.")
        if code in RETRYABLE_REASONS:
            await self._recoverable_failure(row, now, usage, code, detail, True,
                                            status=status)
        else:
            await self._fail(row, now, usage, code, detail)
            await self._unbind(row)

    async def _complete(self, row, now, usage, status) -> None:
        usage = clear_active_since(usage)
        await self._transition(
            row, now, {row["state"]},
            {"state": "completed", "run_id": status.get("run_id"),
             "has_started": True, "reason_code": "completed",
             "reason": "Campaign completed with durable worker evidence.",
             "usage": usage, "retry": retry_state(0, validate_retry(row["retry"])["max"], "")},
            event="campaign_completed", reason_code="completed",
            reason="Bounded autonomous run completed and the campaign stopped.")
        await self._unbind(row)

    async def _recoverable_failure(self, row, now, usage, code: str,
                                   detail: str, retryable: bool, *,
                                   status: Optional[dict] = None) -> None:
        code = _reason_code(code)
        retry = validate_retry(row["retry"])
        progress = False
        if isinstance(status, dict):
            progress = (int(status.get("successful_steps", 0) or 0)
                        > int(usage.get("last_successful_steps", 0) or 0))
            usage["last_steps"] = int(status.get("steps_taken", 0) or 0)
            usage["last_successful_steps"] = int(status.get("successful_steps", 0) or 0)
            usage["last_model_calls"] = int(status.get("model_calls", 0) or 0)
        usage = clear_active_since(usage)
        if not retryable:
            await self._fail(row, now, usage, code, detail)
            await self._unbind(row)
            return
        count = (0 if progress else retry["count"]) + 1
        if count > retry["max"]:
            await self._fail(
                row, now, usage, "retry_exhausted",
                f"Automatic retry limit reached after {code}: {detail}")
            await self._unbind(row)
            return
        schedule = CampaignSchedule.model_validate(row["schedule"])
        next_at = retry_next_action(now, schedule, count)
        if next_at is None:
            await self._fail(row, now, usage, "retry_exhausted",
                             "No execution window remains for a retry.")
            await self._unbind(row)
            return
        await self._transition(
            row, now, {row["state"]},
            {"state": "scheduled", "auto_resume": False,
             "next_action_at": next_at,
             "retry": retry_state(count, retry["max"], code),
             "reason_code": code, "reason": detail,
             "usage": usage},
            event="campaign_retry_scheduled", reason_code=code,
            reason=f"Bounded retry {count}/{retry['max']} scheduled after {code}.",
            release=True)
        await self._unbind(row)

    async def _fail(self, row, now, usage, code: str, detail: str) -> None:
        usage = clear_active_since(usage)
        await self._transition(
            row, now, {row["state"]},
            {"state": "failed", "reason_code": _reason_code(code),
             "reason": detail, "usage": usage},
            event="campaign_failed", reason_code=_reason_code(code),
            reason=detail)
        await self._unbind(row)

    async def _force_fail(self, row: dict, now: datetime, detail: str) -> None:
        """Terminalize a campaign whose durable JSON can no longer be trusted."""
        status = self._run_status(row["session_id"])
        if isinstance(status, dict) and status.get("active"):
            try:
                await self._engine().request_stop(row["session_id"],
                                                  user_id=row["owner_id"])
            except Exception:  # noqa: BLE001
                try:
                    await self._engine().detach_session(row["session_id"])
                except Exception:  # noqa: BLE001
                    pass
        await self._transition(
            row, now, {row["state"]},
            {"state": "failed", "reason_code": "unsafe_state", "reason": detail},
            event="campaign_failed", reason_code="unsafe_state", reason=detail)
        await self._unbind(row)

    async def _abort_unsafe(self, row, now, usage, code: str, detail: str) -> None:
        usage = clear_active_since(usage)
        status = self._run_status(row["session_id"])
        if isinstance(status, dict) and status.get("active"):
            try:
                await self._engine().request_stop(row["session_id"],
                                                  user_id=row["owner_id"])
            except Exception:  # noqa: BLE001
                try:
                    await self._engine().detach_session(row["session_id"])
                except Exception:  # noqa: BLE001
                    log.warning("campaign unsafe detach failed", campaign=row["id"])
        await self._transition(
            row, now, {row["state"]},
            {"state": "failed", "reason_code": _reason_code(code),
             "reason": detail, "usage": usage},
            event="campaign_failed", reason_code=_reason_code(code),
            reason=detail)
        await self._unbind(row)

    # ── Preflight ────────────────────────────────────────────────────────
    async def _preflight(self, row: dict) -> None:
        usage = validate_usage(row["usage"])
        budget = validate_budget(row["budget"])
        remaining_tokens, remaining_cost = budget_remaining(usage, budget)
        if accounting_inconsistencies(usage):
            raise PreflightError(
                "campaign_accounting_inconsistent",
                "Campaign model accounting is inconsistent; further calls are denied.",
                False)
        if usage["stopped"] or remaining_tokens <= 0 or remaining_cost <= 0:
            if usage["stop_reason"] in {"unknown_usage", "accounting_inconsistent"}:
                raise PreflightError(
                    "campaign_accounting_inconsistent",
                    "Campaign accounting stopped after unknown provider usage.",
                    False)
            raise PreflightError("campaign_budget_exhausted",
                                 "Campaign model budget is exhausted.", False)
        try:
            await self.store.check_budget(row["id"], row["session_id"],
                                          row["owner_id"])
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            code = detail.get("code", "campaign_budget_unavailable")
            raise PreflightError(_reason_code(code),
                                 str(detail.get("message") or code),
                                 code == "campaign_budget_exhausted") from None
        except Exception:
            raise PreflightError("campaign_budget_unavailable",
                                 "Campaign budget cannot be verified.", False) from None

        try:
            await self._worker_resume(row["owner_id"], row["session_id"])
            context = await self._context(row["owner_id"], row["session_id"])
        except HTTPException as exc:
            code = ("authorization_expired" if exc.status_code == 403
                    else "authorization_unavailable")
            raise PreflightError(code, "Engagement authorization is not valid.",
                                 code != "authorization_expired") from None
        except CampaignValidationError:
            raise
        except Exception:
            raise PreflightError("authorization_unavailable",
                                 "Engagement authorization could not be verified.",
                                 True) from None
        if context.get("owner_id") != row["owner_id"]:
            raise PreflightError("authorization_expired",
                                 "Campaign owner no longer owns the engagement.", False)
        if context.get("scope_digest") != row["scope_digest"]:
            raise PreflightError("scope_changed",
                                 "Engagement scope changed since campaign creation.", False)
        if context.get("worker_blocked"):
            raise PreflightError("worker_blocked",
                                 "Engagement execution is still fenced by unresolved jobs.",
                                 False)
        try:
            capabilities = await self._capabilities()
        except Exception:
            raise PreflightError("worker_unavailable",
                                 "Worker capability discovery failed.", True) from None
        if not isinstance(capabilities, dict):
            raise PreflightError("worker_unavailable",
                                 "Worker capability discovery failed.", True)
        tools = capabilities.get("tools")
        if not isinstance(tools, list) or any(not isinstance(tool, str) for tool in tools):
            raise PreflightError("worker_unavailable",
                                 "Worker advertised an invalid tool list.", True)
        missing = set(required_tools_for_goal(row["goal"])).difference(tools)
        if missing:
            raise PreflightError(
                "capability_unavailable",
                "Worker lacks required capabilities: " + ", ".join(sorted(missing)),
                False)
        try:
            preflight = await self._planner_preflight(row["owner_id"],
                                                      row["session_id"])
        except Exception:
            raise PreflightError("provider_authorization_or_storage_unavailable",
                                 "Model planner preflight failed.", True) from None
        if not isinstance(preflight, dict) or not preflight.get("ready"):
            code = _reason_code(
                (preflight or {}).get("code") if isinstance(preflight, dict) else "")
            raise PreflightError(code,
                                 str((preflight or {}).get("message") or code),
                                 code in RETRYABLE_REASONS)

    async def _start_or_restore(self, row: dict) -> dict:
        engine = self._engine()
        if row.get("has_started"):
            result = await engine.restore(session_id=row["session_id"],
                                          user_id=row["owner_id"], resume=True,
                                          campaign_id=row["id"],
                                          campaign_supervisor_token=self._token)
        else:
            result = await engine.start(
                session_id=row["session_id"], user_id=row["owner_id"],
                goal=row["goal"], target=row["target"],
                skill_level=row["skill_level"], max_steps=row["max_steps"],
                auto_risk_threshold=row["auto_risk_threshold"],
                objective=row["objective"], campaign_id=row["id"],
                campaign_supervisor_token=self._token,
            )
        if not isinstance(result, dict):
            raise PreflightError("supervisor_error",
                                 "Engine returned no usable result.", True)
        return result

    async def _unbind(self, row: dict) -> None:
        try:
            await self.store.unbind_session(row["session_id"], row["owner_id"],
                                            row["id"])
        except Exception:  # noqa: BLE001 - marker is fail-closed by design.
            log.warning("campaign session unbind failed", campaign=row.get("id"))

    async def _transition(self, row, now, expected, values, *,
                          event: str = "", reason_code: str = "",
                          reason: str = "", release: bool = False,
                          operation: Optional[dict] = None):
        values = dict(values)
        if release:
            values["release_lease"] = True
        updated = await self.store.transition(
            row["id"], self._token, now, set(expected), values,
            event=event, event_reason_code=reason_code, event_reason=reason,
            operation=operation)
        if updated is None:
            log.warning("campaign transition skipped after state or lease change",
                        campaign=row.get("id"))
        return updated

    # ── Injectable collaborators ─────────────────────────────────────────
    def _engine(self):
        if self.engine is not None:
            return self.engine
        from agents.autonomous_engine import autonomous_engine
        return autonomous_engine

    async def _context(self, owner_id: str, session_id: str) -> dict:
        if self.context_loader is not None:
            return await self.context_loader(owner_id, session_id)
        from memory.execution_authorization import authoritative_context
        return await authoritative_context(owner_id, session_id)

    async def _worker_resume(self, owner_id: str, session_id: str) -> None:
        if self.worker_resume is not None:
            await self.worker_resume(owner_id, session_id)
            return
        from memory.worker_jobs import worker_jobs
        await worker_jobs.resume_session(owner_id, session_id)

    async def _capabilities(self) -> dict:
        if self.capabilities is not None:
            return await self.capabilities()
        from memory.worker_jobs import worker_jobs
        return await worker_jobs.client.capabilities()

    async def _planner_preflight(self, owner_id: str, session_id: str) -> dict:
        if self.planner_preflight is not None:
            return await self.planner_preflight(owner_id, session_id)
        from llm.pool_manager import pool_manager
        return await pool_manager.planner_preflight(owner_id, session_id)

    def _run_status(self, session_id: str):
        try:
            return self._engine().get_status(session_id)
        except Exception:  # noqa: BLE001
            return None


def schedule_of(row: dict) -> CampaignSchedule:
    return CampaignSchedule.model_validate(row["schedule"])


campaign_supervisor = CampaignSupervisor()
