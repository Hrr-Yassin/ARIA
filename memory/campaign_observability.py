"""SPEC-14 operational observability for durable autonomous campaigns.

This module is deliberately read-mostly.  Monitoring never starts, resumes or
extends a campaign and never changes a budget: it only explains what the
durable state already says.  Operational events live in one bounded ring on
the campaign row so storage cannot grow with supervisor ticks, while the
existing ``DecisionLog`` remains the immutable audit ledger for state changes.

Every event and every free-text field passes through the deployment redactor
before it is persisted or returned.  Metric labels are a closed vocabulary;
unknown states are folded into ``unknown`` so the monitoring surface cannot be
turned into a high-cardinality label store.
"""
from __future__ import annotations

import re
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

from config.settings import settings
from security.redaction import deployment_secrets, redact

UTC = timezone.utc
OPERATIONS_SCHEMA = "aria.campaign.operations.v1"
HEALTH_SCHEMA = "aria.campaign.health.v1"
WORKER_SUMMARY_SCHEMA = "aria.worker.summary.v1"
SPECIALIST_SUMMARY_SCHEMA = "aria.specialist.summary.v1"
MODEL_SUMMARY_SCHEMA = "aria.model.usage.v1"

MAX_EVENTS = 50
MAX_EVENT_MESSAGE = 400
MAX_EVENT_REASON = 120
MAX_ATTRIBUTES = 8
MAX_ATTRIBUTE_STRING = 100
MAX_SEQUENCE = 1_000_000_000
MAX_TASK_IDS = 20

CORRELATION = re.compile(r"^[A-Za-z0-9._:-]{8,64}$")

# Closed vocabulary.  A new operational event must be added here so the
# bounded ring can never accumulate arbitrary, caller-defined labels.
EVENT_TYPES = frozenset({
    "campaign_created", "campaign_started", "campaign_starting",
    "campaign_resumed", "campaign_paused", "campaign_pausing",
    "campaign_pause_requested", "campaign_resume_requested",
    "campaign_cancel_requested", "campaign_cancelled", "campaign_completed",
    "campaign_failed", "campaign_stopped", "campaign_retry_scheduled",
    "campaign_retry_exhausted", "campaign_recovered", "campaign_recovery_failed",
    "campaign_window_wait", "campaign_step_succeeded", "campaign_heartbeat",
    "campaign_budget_alert", "campaign_accounting_stopped",
    "campaign_health_alert", "campaign_operation",
})
ALERT_CODES = frozenset({
    "invalid_durable_state", "heartbeat_missing", "heartbeat_stale",
    "lease_expired", "progress_stalled", "repeated_failures",
    "retry_exhausted", "campaign_failed", "campaign_completed",
    "unknown_provider_usage", "accounting_stopped", "accounting_inconsistent",
    "budget_exhausted", "daily_runtime_exhausted", "outside_window",
    "pause_requested", "worker_unavailable", "worker_unresolved",
    "specialist_blocked", "specialist_failed", "model_usage_invalid",
    "engagement_usage_invalid", "engagement_stopped", "operations_invalid",
    "checkpoint_invalid",
})
ATTRIBUTE_KEYS = frozenset({
    "step", "steps", "successful_steps", "model_calls", "reason_code",
    "retry_count", "retry_max", "from_state", "to_state", "task_state",
    "job_state", "provider", "attempt_id", "run_id", "worker_epoch",
    "scope_digest", "auth_revision", "code", "source",
})

TERMINAL_STATES = frozenset({"completed", "cancelled", "stopped", "failed"})
LIVE_RUN_STATES = frozenset({"starting", "running", "pausing", "cancelling"})

_correlation: ContextVar[Optional[str]] = ContextVar(
    "aria_campaign_operation_correlation", default=None)


# ── Correlation ──────────────────────────────────────────────────────────

def correlation_id(value=None) -> str:
    """Return a safe correlation id, generating one when necessary."""
    if isinstance(value, str) and CORRELATION.fullmatch(value):
        return value
    return uuid.uuid4().hex


def current_correlation_id() -> Optional[str]:
    return _correlation.get()


@contextmanager
def correlation_scope(value=None):
    """Correlate every durable operation created inside the block."""
    token = _correlation.set(correlation_id(value))
    try:
        yield _correlation.get()
    finally:
        _correlation.reset(token)


# ── Sanitisation ─────────────────────────────────────────────────────────

def _safe_text(value, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    text = " ".join(value.replace("\x00", " ").split())
    return redact(text, deployment_secrets())[:limit]


def _safe_int(value, *, maximum: int = MAX_SEQUENCE) -> Optional[int]:
    if type(value) is not int:
        return None
    return max(0, min(value, maximum))


def _parse_time(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and len(value) <= 64:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _age_seconds(value, now: datetime) -> Optional[int]:
    parsed = _parse_time(value)
    if parsed is None:
        return None
    return max(0, int((now - parsed).total_seconds()))


def _safe_attributes(value) -> dict:
    if not isinstance(value, dict):
        return {}
    clean: dict[str, object] = {}
    for key, item in list(value.items())[:MAX_ATTRIBUTES]:
        if key not in ATTRIBUTE_KEYS:
            continue
        if type(item) is bool:
            clean[key] = item
        elif type(item) is int:
            clean[key] = _safe_int(item)
        elif isinstance(item, str):
            text = _safe_text(item, MAX_ATTRIBUTE_STRING)
            if text:
                clean[key] = text
    return clean


def _empty_operations() -> dict:
    return {"schema": OPERATIONS_SCHEMA, "generation": 0,
            "last_activity_at": None, "last_successful_at": None,
            "events": []}


def _valid_operations(value) -> bool:
    if not isinstance(value, dict) or value.get("schema") != OPERATIONS_SCHEMA:
        return False
    if not isinstance(value.get("events", []), list):
        return False
    if value.get("generation") is not None and type(value.get("generation")) is not int:
        return False
    return True


def sanitize_event(value) -> Optional[dict]:
    """Return one bounded event or ``None`` when it cannot be trusted."""
    if not isinstance(value, dict):
        return None
    event = value.get("event")
    if event not in EVENT_TYPES:
        return None
    sequence = _safe_int(value.get("sequence"))
    if sequence is None:
        return None
    correlation = value.get("correlation_id")
    if not isinstance(correlation, str) or not CORRELATION.fullmatch(correlation):
        correlation = ""
    timestamp = _parse_time(value.get("timestamp"))
    if timestamp is None:
        return None
    message = _safe_text(value.get("message"), MAX_EVENT_MESSAGE)
    reason_code = _safe_text(value.get("reason_code"), MAX_EVENT_REASON)
    attributes = _safe_attributes(value.get("attributes"))
    return {
        "id": str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"aria-campaign-operation:{sequence}:{event}:{correlation}")),
        "sequence": sequence,
        "event": event,
        "from_state": _safe_text(value.get("from_state"), 40),
        "to_state": _safe_text(value.get("to_state"), 40),
        "reason_code": reason_code,
        "message": message,
        "correlation_id": correlation,
        "timestamp": timestamp.isoformat(),
        "attributes": attributes,
    }


def sanitize_operations(value) -> dict:
    """Canonicalise the ring, dropping malformed or unsafe entries."""
    if not isinstance(value, dict):
        return _empty_operations()
    generation = value.get("generation")
    generation = generation if type(generation) is int and generation >= 0 else 0
    raw_events = value.get("events")
    events: list[dict] = []
    if isinstance(raw_events, list):
        for item in raw_events[-MAX_EVENTS:]:
            clean = sanitize_event(item)
            if clean is not None:
                events.append(clean)
    events.sort(key=lambda item: item["sequence"])
    events = events[-MAX_EVENTS:]
    last_activity = _parse_time(value.get("last_activity_at"))
    last_success = _parse_time(value.get("last_successful_at"))
    return {
        "schema": OPERATIONS_SCHEMA,
        "generation": generation,
        "last_activity_at": last_activity.isoformat() if last_activity else None,
        "last_successful_at": last_success.isoformat() if last_success else None,
        "events": events,
    }


def operation_event(*, event: str, sequence: int, campaign_id: str = "",
                    from_state: str = "", to_state: str = "",
                    reason_code: str = "", message: str = "",
                    attributes=None, correlation: Optional[str] = None,
                    now: Optional[datetime] = None) -> dict:
    timestamp = _parse_time(now) or datetime.now(UTC)
    correlation = correlation_id(correlation or current_correlation_id())
    safe_event = event if event in EVENT_TYPES else "campaign_operation"
    return {
        "id": str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"aria-campaign-operation:{sequence}:{safe_event}:{correlation}")),
        "sequence": sequence,
        "event": safe_event,
        "from_state": _safe_text(from_state, 40),
        "to_state": _safe_text(to_state, 40),
        "reason_code": _safe_text(reason_code, MAX_EVENT_REASON),
        "message": _safe_text(message, MAX_EVENT_MESSAGE),
        "correlation_id": correlation,
        "timestamp": timestamp.isoformat(),
        "attributes": _safe_attributes(attributes),
    }


def append_operation(operations, *, event: str, campaign_id: str = "",
                     from_state: str = "", to_state: str = "",
                     reason_code: str = "", message: str = "",
                     attributes=None, correlation: Optional[str] = None,
                     now: Optional[datetime] = None,
                     dedupe_seconds: int = 0) -> dict:
    """Append one event to the bounded ring, preserving monotonic sequence.

    ``dedupe_seconds`` suppresses repeated identical alerts (for example a
    budget denial polled every few seconds) without suppressing real state
    changes.
    """
    # ``None`` means "start a new ring"; malformed stored data is faulted.
    invalid = operations is not None and not _valid_operations(operations)
    ring = sanitize_operations(operations)
    timestamp = _parse_time(now) or datetime.now(UTC)
    safe_event = event if event in EVENT_TYPES else "campaign_operation"
    safe_reason = _safe_text(reason_code, MAX_EVENT_REASON)
    events = list(ring["events"])
    if invalid:
        events.append(operation_event(
            event="campaign_health_alert", sequence=_next_sequence(events),
            from_state=from_state, to_state=to_state,
            reason_code="operations_invalid",
            message="Stored operational events were invalid and were reset.",
            attributes={"code": "operations_invalid"}, now=timestamp))
    if dedupe_seconds > 0 and events:
        previous = events[-1]
        same = (previous["event"] == safe_event
                and previous["reason_code"] == safe_reason)
        age = _age_seconds(previous["timestamp"], timestamp)
        if same and age is not None and age < dedupe_seconds:
            return {**ring, "events": events[-MAX_EVENTS:]}
    entry = operation_event(
        event=safe_event, sequence=_next_sequence(events),
        campaign_id=campaign_id, from_state=from_state, to_state=to_state,
        reason_code=safe_reason, message=message, attributes=attributes,
        correlation=correlation, now=timestamp)
    events.append(entry)
    last_success = ring.get("last_successful_at")
    if safe_event == "campaign_step_succeeded":
        last_success = timestamp.isoformat()
    return {
        "schema": OPERATIONS_SCHEMA,
        "generation": int(ring.get("generation", 0)) + int(invalid),
        "last_activity_at": timestamp.isoformat(),
        "last_successful_at": last_success,
        "events": events[-MAX_EVENTS:],
    }


def _next_sequence(events: list[dict]) -> int:
    if not events:
        return 1
    return min(MAX_SEQUENCE, int(events[-1]["sequence"]) + 1)


def operations_summary(value) -> dict:
    ring = sanitize_operations(value)
    events = ring["events"]
    return {
        "schema": OPERATIONS_SCHEMA,
        "generation": ring["generation"],
        "invalid": not _valid_operations(value),
        "retained": len(events),
        "max_events": MAX_EVENTS,
        "last_sequence": events[-1]["sequence"] if events else 0,
        "last_activity_at": ring["last_activity_at"],
        "last_successful_at": ring["last_successful_at"],
    }


def operations_view(value, *, after: int = 0, limit: int = MAX_EVENTS) -> dict:
    ring = sanitize_operations(value)
    cursor = _safe_int(after) or 0
    limit = max(1, min(int(limit) if type(limit) is int else MAX_EVENTS,
                      MAX_EVENTS))
    events = [item for item in ring["events"] if item["sequence"] > cursor]
    truncated = len(events) > limit
    events = events[:limit]
    return {
        "schema": OPERATIONS_SCHEMA,
        "generation": ring["generation"],
        "cursor": cursor,
        "next_cursor": events[-1]["sequence"] if events else cursor,
        "events": events,
        "retained": len(ring["events"]),
        "max_events": MAX_EVENTS,
        "truncated": truncated,
        "bounded": True,
    }


# ── Accounting consistency ───────────────────────────────────────────────

def _metric_int(value) -> Optional[int]:
    return value if type(value) is int and value >= 0 else None


def accounting_inconsistencies(usage, engagement=None) -> list[dict]:
    """Describe ledger states that must deny further provider calls.

    Reservations are conservative ceilings.  Reported usage above a ceiling
    means the ledger cannot be trusted; malformed values mean it cannot be
    read.  Both fail closed at the reservation boundary.
    """
    issues: list[dict] = []
    if not isinstance(usage, dict):
        return [{"code": "campaign_usage_unreadable",
                 "detail": "Campaign usage ledger is missing"}]
    reserved_tokens = _metric_int(usage.get("reserved_tokens", 0))
    reported_tokens = _metric_int(usage.get("reported_tokens", 0))
    reserved_cost = _metric_int(usage.get("reserved_cost_microusd", 0))
    reported_cost = _metric_int(usage.get("reported_cost_microusd", 0))
    for field, value in (("reserved_tokens", reserved_tokens),
                         ("reported_tokens", reported_tokens),
                         ("reserved_cost_microusd", reserved_cost),
                         ("reported_cost_microusd", reported_cost)):
        if value is None:
            issues.append({"code": "campaign_usage_unreadable",
                           "detail": f"Campaign usage field {field} is invalid"})
    if (reserved_tokens is not None and reported_tokens is not None
            and reported_tokens > reserved_tokens):
        issues.append({"code": "reported_tokens_exceed_reserved",
                       "detail": "Provider reported more tokens than the reserved ceiling"})
    if (reserved_cost is not None and reported_cost is not None
            and reported_cost > reserved_cost):
        issues.append({"code": "reported_cost_exceeds_reserved",
                       "detail": "Provider reported more cost than the reserved ceiling"})
    if isinstance(engagement, dict):
        engagement_reserved = _metric_int(engagement.get("reserved_tokens", 0))
        engagement_reported = _metric_int(engagement.get("reported_tokens", 0))
        if (engagement_reserved is not None and engagement_reported is not None
                and engagement_reported > engagement_reserved):
            issues.append({"code": "engagement_reported_exceeds_reserved",
                           "detail": "Engagement provider usage exceeds its reserved ceiling"})
        if engagement.get("invalid"):
            issues.append({"code": "engagement_usage_unreadable",
                           "detail": "Engagement model usage could not be read"})
        if engagement.get("stopped") and engagement.get("stop_reason") in {
                "unknown_usage", "accounting_inconsistent"}:
            issues.append({"code": "engagement_accounting_stopped",
                           "detail": "Engagement accounting stopped after unknown usage"})
    return issues


# ── Bounded subsystem summaries ──────────────────────────────────────────

WORKER_STATES = ("prepared", "dispatching", "queued", "running",
                 "cancel_requested", "succeeded", "failed", "cancelled",
                 "unknown")
TASK_STATES = ("queued", "running", "awaiting_review", "blocked",
               "completed", "cancelled", "failed", "missing")
ACTIVE_WORKER_STATES = frozenset({"prepared", "dispatching", "queued",
                                  "running", "cancel_requested", "unknown"})
ACTIVE_TASK_STATES = frozenset({"queued", "running", "awaiting_review"})


def sanitize_worker_summary(value) -> dict:
    counts = {state: 0 for state in WORKER_STATES}
    if not isinstance(value, dict):
        return {"schema": WORKER_SUMMARY_SCHEMA, "available": False,
                "counts": counts, "active": 0, "unresolved": 0}
    available = value.get("available", True) is not False
    raw = value.get("counts")
    if isinstance(raw, dict):
        for state, count in raw.items():
            label = state if state in counts else "unknown"
            number = _metric_int(count) or 0
            counts[label] += number
    return {
        "schema": WORKER_SUMMARY_SCHEMA,
        "available": available,
        "counts": counts,
        "active": sum(counts[state] for state in ACTIVE_WORKER_STATES),
        "unresolved": counts["unknown"] + counts["cancel_requested"],
    }


def sanitize_specialist_summary(value) -> dict:
    counts = {state: 0 for state in TASK_STATES}
    if not isinstance(value, dict):
        return {"schema": SPECIALIST_SUMMARY_SCHEMA, "available": False,
                "counts": counts, "active": 0, "total": 0}
    available = value.get("available", True) is not False
    raw = value.get("counts")
    if isinstance(raw, dict):
        for state, count in raw.items():
            label = state if state in counts else "missing"
            counts[label] += _metric_int(count) or 0
    return {
        "schema": SPECIALIST_SUMMARY_SCHEMA,
        "available": available,
        "counts": counts,
        "active": sum(counts[state] for state in ACTIVE_TASK_STATES),
        "total": sum(counts.values()),
    }


def sanitize_model_summary(value) -> dict:
    fields = ("calls", "reserved_tokens", "reserved_cost_microusd",
              "reported_tokens", "reported_cost_microusd",
              "unknown_usage_calls", "unknown_cost_calls")
    empty = {field: 0 for field in fields}
    if not isinstance(value, dict):
        return {"schema": MODEL_SUMMARY_SCHEMA, "available": False,
                "invalid": True, "usage": empty, "stopped": False,
                "stop_reason": "", "task_ledgers": 0}
    raw = value.get("usage") if isinstance(value.get("usage"), dict) else {}
    usage = {field: _metric_int(raw.get(field, 0)) or 0 for field in fields}
    return {
        "schema": MODEL_SUMMARY_SCHEMA,
        "available": value.get("available", True) is not False,
        "invalid": bool(value.get("invalid")),
        "usage": usage,
        "stopped": bool(value.get("stopped", False)),
        "stop_reason": _safe_text(value.get("stop_reason"), 40),
        "task_ledgers": _metric_int(value.get("task_ledgers")) or 0,
    }


# ── Health view ──────────────────────────────────────────────────────────

def _sanitize_run(status) -> Optional[dict]:
    if not isinstance(status, dict) or not status.get("run_id"):
        return None
    task_ids = status.get("specialist_investigation_ids")
    if not isinstance(task_ids, (list, tuple)):
        task_ids = []
    task_ids = [_safe_text(item, 100) for item in task_ids[:MAX_TASK_IDS]
                if isinstance(item, str) and item]
    return {
        "source": "supervisor",
        "run_id": _safe_text(status.get("run_id"), 100),
        "run_state": _safe_text(status.get("run_state"), 40),
        "active": bool(status.get("active", False)),
        "reason_code": _safe_text(status.get("reason_code"), 100),
        "reason": _safe_text(status.get("reason"), 500),
        "steps_taken": _metric_int(status.get("steps_taken")) or 0,
        "max_steps": _metric_int(status.get("max_steps")) or 0,
        "successful_steps": _metric_int(status.get("successful_steps")) or 0,
        "model_calls": _metric_int(status.get("model_calls")) or 0,
        "remaining_steps": _metric_int(status.get("remaining_steps")) or 0,
        "remaining_model_calls": _metric_int(
            status.get("remaining_model_calls")) or 0,
        "waiting_approval": bool(status.get("waiting_approval", False)),
        "pending_action_id": _safe_text(status.get("pending_action_id"), 100),
        "current_phase": _safe_text(status.get("current_phase"), 40),
        "specialist_investigation_ids": task_ids,
    }


def _sanitize_checkpoint(snapshot) -> Optional[dict]:
    if not isinstance(snapshot, dict):
        return None
    checkpoint = snapshot.get("checkpoint")
    if not isinstance(checkpoint, dict) or not checkpoint.get("run_id"):
        return None
    task_ids = checkpoint.get("specialist_investigation_ids")
    if not isinstance(task_ids, (list, tuple)):
        task_ids = []
    task_ids = [_safe_text(item, 100) for item in task_ids[:MAX_TASK_IDS]
                if isinstance(item, str) and item]
    return {
        "source": "durable_checkpoint",
        "run_id": _safe_text(checkpoint.get("run_id"), 100),
        "run_state": _safe_text(checkpoint.get("run_state"), 40),
        "active": bool(checkpoint.get("active", False)),
        "reason_code": _safe_text(checkpoint.get("reason_code"), 100),
        "reason": _safe_text(checkpoint.get("reason"), 500),
        "steps_taken": _metric_int(checkpoint.get("steps_taken")) or 0,
        "max_steps": _metric_int(checkpoint.get("max_steps")) or 0,
        "successful_steps": _metric_int(checkpoint.get("successful_steps")) or 0,
        "model_calls": _metric_int(checkpoint.get("model_calls")) or 0,
        "waiting_approval": bool(snapshot.get("waiting_approval", False)),
        "pending_action_id": _safe_text(snapshot.get("pending_action_id"), 100),
        "current_phase": _safe_text(checkpoint.get("current_phase"), 40),
        "specialist_investigation_ids": task_ids,
    }


def _alert(code: str, severity: str, detail: str) -> dict:
    return {"code": code if code in ALERT_CODES else "campaign_operation",
            "severity": severity, "detail": _safe_text(detail, 300)}


def build_campaign_health(row: dict, now: datetime, *, run_status=None,
                          checkpoint=None, worker_summary=None,
                          specialist_summary=None, model_summary=None,
                          heartbeat_stale_seconds: Optional[int] = None,
                          progress_stale_seconds: Optional[int] = None) -> dict:
    """Build the owner-facing operational view from durable state only."""
    # Local import avoids a module cycle: campaign_store imports this module
    # for bounded event persistence.
    from memory.campaign_store import (
        CampaignValidationError, campaign_status, validate_retry, validate_usage,
    )

    now = _parse_time(now) or datetime.now(UTC)
    heartbeat_stale_seconds = (heartbeat_stale_seconds
                               if type(heartbeat_stale_seconds) is int
                               else settings.CAMPAIGN_HEARTBEAT_STALE_SECONDS)
    progress_stale_seconds = (progress_stale_seconds
                              if type(progress_stale_seconds) is int
                              else settings.CAMPAIGN_PROGRESS_STALE_SECONDS)
    run = _sanitize_run(run_status) or _sanitize_checkpoint(checkpoint)
    alerts: list[dict] = []
    state = str(row.get("state") or "")
    terminal = state in TERMINAL_STATES

    try:
        status = campaign_status(row, now, run_status=run)
    except Exception:  # noqa: BLE001 - monitoring must never break on bad state
        status = {"invalid": True, "state": state,
                  "error": "Campaign durable state is invalid"}
    invalid_state = bool(status.get("invalid"))
    try:
        usage = validate_usage(row.get("usage"))
    except CampaignValidationError:
        usage = None
        invalid_state = True
    try:
        retry = validate_retry(row.get("retry"))
    except CampaignValidationError:
        retry = {"count": 0, "max": settings.CAMPAIGN_MAX_RETRIES,
                 "last_reason": ""}
        invalid_state = True
    if invalid_state:
        alerts.append(_alert("invalid_durable_state", "critical",
                             "Campaign durable state is invalid; the supervisor "
                             "will refuse to act."))

    operations = operations_summary(row.get("operations"))
    if operations["invalid"]:
        alerts.append(_alert("operations_invalid", "warning",
                             "Operational event history was invalid and was reset."))

    worker = sanitize_worker_summary(worker_summary)
    specialist = sanitize_specialist_summary(specialist_summary)
    model = sanitize_model_summary(model_summary)

    if model.get("invalid"):
        alerts.append(_alert("model_usage_invalid", "warning",
                             "Engagement model usage could not be read; further "
                             "calls will be denied."))
    engagement_usage = ({"reserved_tokens": model["usage"]["reserved_tokens"],
                         "reported_tokens": model["usage"]["reported_tokens"],
                         "reserved_cost_microusd": model["usage"]["reserved_cost_microusd"],
                         "reported_cost_microusd": model["usage"]["reported_cost_microusd"],
                         "stopped": model.get("stopped", False),
                         "stop_reason": model.get("stop_reason", ""),
                         "invalid": model.get("invalid", False)}
                        if model.get("available") else None)
    issues = accounting_inconsistencies(usage or {}, engagement_usage)
    if issues:
        alerts.append(_alert(
            "accounting_inconsistent", "critical",
            "Model accounting is inconsistent; provider calls fail closed."))

    # Progress comes from a live run when available, otherwise from the
    # durable checkpoint, and finally from the last recorded counters.
    source = run or {}
    steps = _metric_int(source.get("steps_taken"))
    successful = _metric_int(source.get("successful_steps"))
    max_steps = _metric_int(source.get("max_steps"))
    model_calls = _metric_int(source.get("model_calls"))
    if usage is not None:
        steps = steps if steps is not None else usage["last_steps"]
        successful = (successful if successful is not None
                      else usage["last_successful_steps"])
        model_calls = (model_calls if model_calls is not None
                       else usage["last_model_calls"])
    else:
        steps = steps or 0
        successful = successful or 0
        model_calls = model_calls or 0
    max_steps = max_steps if max_steps is not None else int(row.get("max_steps") or 0)
    remaining_steps = (status.get("run") or {}).get("remaining_steps")
    waiting_approval = bool(source.get("waiting_approval", False))
    last_success = None
    if operations.get("last_successful_at"):
        last_success = operations["last_successful_at"]
    step_events = [item for item in sanitize_operations(
        row.get("operations"))["events"]
                   if item["event"] == "campaign_step_succeeded"]
    last_event = step_events[-1] if step_events else None
    if _metric_int(remaining_steps) is None:
        remaining_steps = max(0, max_steps - steps) if max_steps else 0
    progress = {
        "steps_taken": steps,
        "successful_steps": successful,
        "max_steps": max_steps,
        "remaining_steps": remaining_steps,
        "model_calls": model_calls,
        "remaining_model_calls": _metric_int(source.get("remaining_model_calls")),
        "waiting_approval": waiting_approval,
        "current_phase": source.get("current_phase") or "",
        "last_successful_action": ({
            "event": last_event["event"],
            "at": last_event["timestamp"],
            "step": last_event["attributes"].get("step"),
            "correlation_id": last_event["correlation_id"],
        } if last_event else {
            "event": "steps_recorded" if successful else "",
            "at": last_success,
            "step": successful or None,
            "correlation_id": "",
        }),
    }

    heartbeat_age = _age_seconds(row.get("last_heartbeat_at"), now)
    lease_expires = _parse_time(row.get("lease_expires_at"))
    lease_expired = bool(row.get("lease_holder") and lease_expires
                         and lease_expires <= now)
    next_action = _parse_time(row.get("next_action_at"))
    due_scheduled = (state == "scheduled"
                     and (next_action is None or next_action <= now))
    due_paused = (state == "paused" and bool(row.get("auto_resume"))
                  and next_action is not None and next_action <= now)
    live_now = state in LIVE_RUN_STATES or due_scheduled or due_paused
    heartbeat_stale = bool(live_now and (heartbeat_age is None
                                         or heartbeat_age > heartbeat_stale_seconds))
    if not terminal and row.get("last_heartbeat_at") is None and state in LIVE_RUN_STATES:
        alerts.append(_alert("heartbeat_missing", "critical",
                             "A live campaign has no supervisor heartbeat."))
    elif heartbeat_stale:
        alerts.append(_alert("heartbeat_stale", "critical",
                             "Supervisor heartbeat is older than the stale threshold."))
    if lease_expired:
        alerts.append(_alert("lease_expired", "critical",
                             "Supervisor lease expired; recovery will reconcile the campaign."))
    if terminal and state == "failed":
        alerts.append(_alert("campaign_failed", "critical",
                             "Campaign stopped in a failed state."))
    if terminal and state == "completed":
        alerts.append(_alert("campaign_completed", "info",
                             "Campaign completed with durable worker evidence."))

    progress_anchor = (operations.get("last_successful_at")
                       or operations.get("last_activity_at")
                       or row.get("updated_at"))
    progress_age = _age_seconds(progress_anchor, now)
    stalled = bool(state in {"starting", "running", "pausing"}
                   and not waiting_approval and not terminal
                   and (progress_age is None or progress_age > progress_stale_seconds))
    if stalled:
        alerts.append(_alert("progress_stalled", "warning",
                             "No successful step or durable progress within the "
                             "stale threshold; inspect the run and worker receipts."))
    if retry.get("count", 0) >= 2:
        alerts.append(_alert("repeated_failures", "warning",
                             f"Campaign retried {retry.get('count')} times "
                             f"without durable progress."))
    if state == "failed" and row.get("reason_code") == "retry_exhausted":
        alerts.append(_alert("retry_exhausted", "critical",
                             "Automatic retries were exhausted; operator review required."))

    budget = (status.get("budget") or {}) if isinstance(status.get("budget"), dict) else {}
    if usage is not None:
        budget = {**budget,
                  "reported_tokens": usage["reported_tokens"],
                  "reported_cost_microusd": usage["reported_cost_microusd"],
                  "stop_reason": usage["stop_reason"]}
        if usage["unknown_usage_calls"]:
            alerts.append(_alert(
                "unknown_provider_usage", "critical" if usage["stopped"] else "warning",
                f"{usage['unknown_usage_calls']} provider call(s) reported no token usage."))
        if usage["stopped"]:
            alerts.append(_alert("accounting_stopped", "critical",
                                 "Campaign accounting is stopped; further model "
                                 "calls are denied."))
    if budget.get("stopped") or (budget.get("remaining_tokens") == 0
                                 or budget.get("remaining_cost_microusd") == 0):
        alerts.append(_alert("budget_exhausted", "critical",
                             "Campaign model budget is exhausted."))

    runtime = status.get("runtime") or {}
    if (runtime.get("daily_seconds") is not None
            and runtime.get("daily_limit_seconds") is not None
            and runtime["daily_seconds"] >= runtime["daily_limit_seconds"]):
        alerts.append(_alert("daily_runtime_exhausted", "info",
                             "Daily runtime limit reached; the campaign resumes "
                             "in the next window when auto-resume is enabled."))
    schedule = status.get("schedule") or {}
    if schedule and not schedule.get("within_window") and not terminal:
        alerts.append(_alert("outside_window", "info",
                             "The campaign is outside its execution window."))
    if row.get("pause_reason") or (state == "paused" and row.get("reason_code")):
        alerts.append(_alert("pause_requested", "info",
                             row.get("reason") or row.get("pause_reason")
                             or "Campaign is paused."))

    if worker.get("available"):
        if worker["active"]:
            alerts.append(_alert("worker_unresolved", "warning" if worker["unresolved"]
                                 else "info",
                                 f"{worker['active']} worker job(s) are not terminal."))
        if worker["unresolved"]:
            alerts.append(_alert("worker_unresolved", "warning",
                                 "Worker cancellation or receipt state is unresolved."))
    else:
        alerts.append(_alert("worker_unavailable", "warning",
                             "Worker job receipts could not be read."))
    if specialist.get("available"):
        if specialist["counts"].get("blocked"):
            alerts.append(_alert("specialist_blocked", "warning",
                                 "A specialist task is blocked."))
        if specialist["counts"].get("failed"):
            alerts.append(_alert("specialist_failed", "warning",
                                 "A specialist task failed."))
    if model.get("stopped"):
        alerts.append(_alert("engagement_stopped", "warning",
                             "The engagement model ledger is stopped."))

    # Keep one alert per code, highest severity first.
    rank = {"critical": 0, "warning": 1, "info": 2}
    unique: dict[str, dict] = {}
    for item in alerts:
        current = unique.get(item["code"])
        if current is None or rank[item["severity"]] < rank[current["severity"]]:
            unique[item["code"]] = item
    alerts = sorted(unique.values(), key=lambda item: (rank[item["severity"]],
                                                       item["code"]))

    pending = {
        "waiting_approval": waiting_approval,
        "pending_action_id": source.get("pending_action_id") or "",
        "worker_jobs": {"active": worker.get("active", 0)},
        "specialist_tasks": {"active": specialist.get("active", 0),
                             "blocked": specialist["counts"].get("blocked", 0)},
        "next_scheduled_action": status.get("next_execution_at"),
    }

    metrics = {
        "steps_taken": steps,
        "successful_steps": successful,
        "model_calls": model_calls,
        "retry_count": retry.get("count", 0),
        "runtime_seconds": (runtime.get("total_seconds") if runtime else
                            (usage["runtime_seconds"] if usage else 0)),
        "daily_runtime_seconds": runtime.get("daily_seconds") if runtime else None,
        "worker_active": worker.get("active", 0),
        "worker_unresolved": worker.get("unresolved", 0),
        "specialist_active": specialist.get("active", 0),
        "specialist_total": specialist.get("total", 0),
        "operations_retained": operations["retained"],
        "llm": model.get("usage", {}),
    }

    return {
        "schema": HEALTH_SCHEMA,
        "campaign_id": row.get("id"),
        "session_id": row.get("session_id"),
        "state": state,
        "terminal": terminal,
        "goal": _safe_text(row.get("goal"), 100),
        "target": _safe_text(row.get("target"), 500),
        "generated_at": now.isoformat(),
        "progress": progress,
        "heartbeat": {
            "last_heartbeat_at": status.get("supervisor", {}).get("last_heartbeat_at"),
            "age_seconds": heartbeat_age,
            "stale_after_seconds": heartbeat_stale_seconds,
            "stale": heartbeat_stale,
            "lease_held": bool(row.get("lease_holder")),
            "lease_expires_at": status.get("supervisor", {}).get("lease_expires_at"),
            "lease_expired": lease_expired,
        },
        "runtime": runtime,
        "budget": budget,
        "schedule": schedule,
        "pause": {
            "pause_reason": _safe_text(row.get("pause_reason"), 100),
            "reason_code": _safe_text(row.get("reason_code"), 100),
            "reason": _safe_text(row.get("reason"), 500),
            "auto_resume": bool(row.get("auto_resume")),
        },
        "failures": {
            "count": retry.get("count", 0),
            "max": retry.get("max", 0),
            "last_reason": _safe_text(retry.get("last_reason"), 100),
            "repeated": retry.get("count", 0) >= 2,
        },
        "pending_work": pending,
        "metrics": metrics,
        "accounting": {
            "consistent": not issues and usage is not None,
            "issues": issues[:8],
            "stop_reason": usage["stop_reason"] if usage else "",
            "unknown_usage_calls": usage["unknown_usage_calls"] if usage else 0,
            "unknown_cost_calls": usage["unknown_cost_calls"] if usage else 0,
        },
        "operations": operations,
        "alerts": alerts[:12],
        "run": run,
        "next_execution_at": status.get("next_execution_at"),
        "limitations": [
            "Monitoring is read-only and never grants execution.",
            "Worker and specialist summaries are bounded counts, not evidence.",
            "Unknown provider usage is charged at its conservative reservation.",
        ],
    }


def sanitize_health(value: dict) -> dict:
    """Apply a final defensive redaction pass to a built health view."""
    if not isinstance(value, dict):
        return {"schema": HEALTH_SCHEMA, "invalid": True}
    return redact(value, deployment_secrets())


# ── Monitor ──────────────────────────────────────────────────────────────

class CampaignMonitor:
    """Read-only monitoring facade with injectable, bounded providers."""

    def __init__(self, *, store=None, run_status_provider=None,
                 checkpoint_loader=None, worker_summary_provider=None,
                 specialist_summary_provider=None, model_summary_provider=None,
                 clock=None):
        self.store = store
        self.run_status_provider = run_status_provider
        self.checkpoint_loader = checkpoint_loader
        self.worker_summary_provider = worker_summary_provider
        self.specialist_summary_provider = specialist_summary_provider
        self.model_summary_provider = model_summary_provider
        self._clock = clock or (lambda: datetime.now(UTC))

    async def _store(self):
        if self.store is not None:
            return self.store
        from memory.campaign_store import campaign_store
        return campaign_store

    def _owned(self, row: Optional[dict], owner_id: str) -> dict:
        if row is None or row.get("owner_id") != owner_id:
            raise LookupError("Campaign was not found")
        return row

    async def health(self, row: dict, owner_id: str,
                     now: Optional[datetime] = None) -> dict:
        row = self._owned(row, owner_id)
        now = _parse_time(now) or self._clock()
        run_status = None
        if self.run_status_provider is not None:
            try:
                candidate = self.run_status_provider(row.get("session_id"))
                run_status = candidate if isinstance(candidate, dict) else None
            except Exception:  # noqa: BLE001 - monitoring is best effort
                run_status = None
        checkpoint = None
        if run_status is None and self.checkpoint_loader is not None:
            try:
                checkpoint = await self.checkpoint_loader(row.get("session_id"))
            except Exception:  # noqa: BLE001
                checkpoint = None
        worker_summary = None
        if self.worker_summary_provider is not None:
            try:
                worker_summary = await self.worker_summary_provider(
                    row.get("session_id"))
            except Exception:  # noqa: BLE001
                worker_summary = {"available": False}
        task_ids = []
        if isinstance(run_status, dict):
            raw_ids = run_status.get("specialist_investigation_ids")
            if isinstance(raw_ids, (list, tuple)):
                task_ids = [item for item in raw_ids[:MAX_TASK_IDS]
                            if isinstance(item, str) and item]
        elif isinstance(checkpoint, dict):
            cp = checkpoint.get("checkpoint")
            if isinstance(cp, dict):
                raw_ids = cp.get("specialist_investigation_ids")
                if isinstance(raw_ids, (list, tuple)):
                    task_ids = [item for item in raw_ids[:MAX_TASK_IDS]
                                if isinstance(item, str) and item]
        specialist_summary = None
        if self.specialist_summary_provider is not None:
            try:
                specialist_summary = await self.specialist_summary_provider(
                    row.get("session_id"), owner_id, task_ids)
            except Exception:  # noqa: BLE001
                specialist_summary = {"available": False}
        model_summary = None
        if self.model_summary_provider is not None:
            try:
                model_summary = await self.model_summary_provider(
                    row.get("session_id"), owner_id)
            except Exception:  # noqa: BLE001
                model_summary = {"available": False, "invalid": True}
        return sanitize_health(build_campaign_health(
            row, now, run_status=run_status, checkpoint=checkpoint,
            worker_summary=worker_summary,
            specialist_summary=specialist_summary,
            model_summary=model_summary))

    async def health_for_campaign(self, campaign_id: str, owner_id: str,
                                  now: Optional[datetime] = None) -> dict:
        store = await self._store()
        row = await store.get(campaign_id)
        return await self.health(row, owner_id, now)

    async def health_for_session(self, session_id: str, owner_id: str,
                                 now: Optional[datetime] = None) -> dict:
        store = await self._store()
        row = await store.latest_for_session(session_id)
        return await self.health(row, owner_id, now)

    async def events_for_campaign(self, campaign_id: str, owner_id: str,
                                  *, after: int = 0, limit: int = MAX_EVENTS) -> dict:
        store = await self._store()
        row = await store.get(campaign_id)
        row = self._owned(row, owner_id)
        return operations_view(row.get("operations"), after=after, limit=limit)

    async def events_for_session(self, session_id: str, owner_id: str,
                                 *, after: int = 0, limit: int = MAX_EVENTS) -> dict:
        store = await self._store()
        row = await store.latest_for_session(session_id)
        row = self._owned(row, owner_id)
        return operations_view(row.get("operations"), after=after, limit=limit)


def default_worker_summary_provider():
    from memory.worker_jobs import SQLJobStore
    store = SQLJobStore()

    async def summary(session_id):
        return await store.summary(session_id)
    return summary


def default_specialist_summary_provider():
    from memory.team_tasks import team_store

    async def summary(session_id, owner_id, task_ids):
        return await team_store.task_summary(session_id, owner_id, task_ids)
    return summary


def default_model_summary_provider():
    from llm.engagement_budget import model_accounting

    async def summary(session_id, owner_id):
        return await model_accounting.usage_summary(session_id, owner_id)
    return summary


def default_checkpoint_loader():
    from memory.autonomous_runs import run_store

    async def loader(session_id):
        return await run_store.latest(session_id)
    return loader
