"""Durable autonomous campaign schedules, supervisor leases and budgets.

A campaign is the long-lived authorization envelope around one or more
bounded SPEC-11 autonomous runs.  It never extends per-run step or model-call
limits: it only decides *when* an unchanged run may start, resume or stop.

Schedules are stored with an IANA timezone.  Durable timestamps in PostgreSQL
are naive UTC (matching the rest of the schema) and are converted at the
boundary.  Every model call is checked against the campaign's reservation
ledger before the provider is contacted; unknown or malformed state denies the
call instead of guessing.
"""
from __future__ import annotations

import re
import uuid
from datetime import date, datetime, time as dt_time, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

import structlog
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError

from config.settings import settings
from memory.campaign_observability import (
    accounting_inconsistencies, append_operation, correlation_id,
)
from memory.database_models import (
    AutonomousCampaign, DecisionLog, PentestSession, async_session,
)
from security.redaction import deployment_secrets, redact

log = structlog.get_logger("campaign_store")

UTC = timezone.utc
TERMINAL_STATES = frozenset({"completed", "cancelled", "stopped", "failed"})
LIVE_STATES = frozenset({"scheduled", "starting", "running", "pausing",
                         "paused", "cancelling"})
# Only these states may consume provider budget.  ``pausing`` is included so a
# graceful pause does not deny the step already in flight.
MODEL_STATES = frozenset({"starting", "running", "pausing"})
MAX_REASON = 200
MAX_DETAIL = 2000
MAX_DAILY_ENTRIES = 31
UNSET = object()
DAY_KEY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
# Why the campaign ledger stopped accepting provider calls.  Unknown or
# inconsistent accounting must fail closed, not look like an ordinary budget
# exhaustion.
STOP_REASONS = frozenset({"", "provider_overrun", "unknown_usage",
                          "accounting_inconsistent"})


class CampaignError(Exception):
    """Base class for a campaign that cannot be used safely."""

    code = "campaign_error"


class CampaignValidationError(CampaignError):
    code = "campaign_validation"


class CampaignConflict(CampaignError):
    code = "campaign_conflict"


class CampaignNotFound(CampaignError):
    code = "campaign_not_found"


class CampaignLeaseError(CampaignError):
    code = "campaign_lease"


class CampaignBudgetError(CampaignError):
    code = "campaign_budget_unavailable"

    def __init__(self, message: str, code: Optional[str] = None):
        if code:
            self.code = code
        super().__init__(message)


def _clean_text(value, limit: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    text = " ".join(value.replace("\x00", " ").split())
    return redact(text, deployment_secrets())[:limit]


def _require_int(value, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise CampaignValidationError(f"Campaign {field} is invalid")
    return value


def _parse_weekdays(value) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        raise CampaignValidationError("Campaign weekdays must be a list")
    days: list[int] = []
    for day in value:
        if type(day) is not int or not 0 <= day <= 6:
            raise CampaignValidationError("Campaign weekdays must be between 0 and 6")
        if day in days:
            raise CampaignValidationError("Campaign weekdays must be unique")
        days.append(day)
    if not days:
        raise CampaignValidationError("Campaign requires at least one weekday")
    return tuple(sorted(days))


def parse_allowed_weekdays(value: str) -> tuple[int, ...]:
    """Parse the deployment-wide weekday allow-list, failing closed."""
    try:
        days = tuple(sorted({int(part.strip()) for part in str(value).split(",")
                             if part.strip()}))
    except (TypeError, ValueError):
        raise CampaignValidationError("Campaign weekdays configuration is invalid") from None
    if not days or any(day < 0 or day > 6 for day in days) or len(days) > 5:
        raise CampaignValidationError("Campaign weekdays configuration is invalid")
    return days


def _parse_hhmm(value: str) -> dt_time:
    match = HHMM.fullmatch(str(value or ""))
    if not match:
        raise CampaignValidationError("Campaign window times must use HH:MM")
    return dt_time(int(match.group(1)), int(match.group(2)))


class CampaignSchedule(BaseModel):
    """One bounded daily execution window in an IANA timezone."""

    model_config = ConfigDict(extra="forbid")

    timezone: str = Field(min_length=1, max_length=64)
    weekdays: list[int] = Field(min_length=1, max_length=5)
    window_start: str = Field(default="09:00", max_length=5)
    window_end: str = Field(default="17:00", max_length=5)
    daily_runtime_seconds: int = Field(default=28800, ge=60, le=28800)

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except Exception:
            raise ValueError("Campaign timezone must be a valid IANA timezone") from None
        return value

    @field_validator("weekdays")
    @classmethod
    def valid_weekdays(cls, value):
        days = _parse_weekdays(value)
        allowed = set(parse_allowed_weekdays(settings.CAMPAIGN_ALLOWED_WEEKDAYS))
        if not set(days).issubset(allowed):
            raise ValueError("Campaign weekdays are outside the configured allow-list")
        return list(days)

    @field_validator("window_start", "window_end")
    @classmethod
    def valid_window_time(cls, value: str) -> str:
        _parse_hhmm(value)
        return value

    @model_validator(mode="after")
    def valid_window(self):
        start = _parse_hhmm(self.window_start)
        end = _parse_hhmm(self.window_end)
        if start >= end:
            raise ValueError("Campaign execution window must end after it starts")
        if not 60 <= self.daily_runtime_seconds <= settings.CAMPAIGN_MAX_DAILY_RUNTIME_SECONDS:
            raise ValueError("Campaign daily runtime exceeds the configured policy")
        return self


class CampaignBudget(BaseModel):
    """Conservative campaign-level model budget."""

    model_config = ConfigDict(extra="forbid")

    max_tokens: int = Field(default=200000, ge=1, le=100000000)
    max_cost_microusd: int = Field(default=2000000, ge=0, le=1000000000)


class CampaignSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=36)
    owner_id: str = Field(min_length=1, max_length=36)
    goal: str = Field(pattern=r"^(discovery|http_check)$")
    target: str = Field(default="", max_length=500)
    skill_level: str = Field(default="intermediate",
                             pattern=r"^(beginner|intermediate|expert)$")
    objective: str = Field(default="", max_length=settings.AUTONOMOUS_OBJECTIVE_MAX_CHARS)
    max_steps: int = Field(default=12, ge=1, le=settings.AUTONOMOUS_MAX_STEPS)
    auto_risk_threshold: str = Field(default="green_orange",
                                     pattern=r"^(green_only|green_orange|manual)$")
    schedule: CampaignSchedule
    budget: CampaignBudget
    max_retries: int = Field(default=3, ge=0, le=10)
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    auth_revision: int = Field(default=0, ge=0)
    worker_epoch: int = Field(default=0, ge=0)
    required_tools: list[str] = Field(default_factory=list, max_length=10)


def required_tools_for_goal(goal: str) -> tuple[str, ...]:
    if goal == "discovery":
        return ("curl", "nmap")
    if goal == "http_check":
        return ("curl",)
    return ()


def default_schedule() -> dict:
    return {
        "timezone": settings.CAMPAIGN_DEFAULT_TIMEZONE,
        "weekdays": list(parse_allowed_weekdays(settings.CAMPAIGN_ALLOWED_WEEKDAYS)),
        "window_start": "09:00",
        "window_end": "17:00",
        "daily_runtime_seconds": settings.CAMPAIGN_MAX_DAILY_RUNTIME_SECONDS,
    }


def default_budget() -> dict:
    return {
        "max_tokens": settings.CAMPAIGN_MAX_TOKENS,
        "max_cost_microusd": settings.CAMPAIGN_MAX_COST_MICROUSD,
    }


def _schedule_model(value) -> CampaignSchedule:
    try:
        return CampaignSchedule.model_validate(value)
    except Exception as exc:
        raise CampaignValidationError("Campaign schedule is invalid") from exc


def _zone(schedule: CampaignSchedule) -> ZoneInfo:
    return ZoneInfo(schedule.timezone)


def _window_for_date(local_date: date,
                     schedule: CampaignSchedule) -> tuple[datetime, datetime]:
    zone = _zone(schedule)
    start = datetime.combine(local_date, _parse_hhmm(schedule.window_start),
                             tzinfo=zone)
    end = datetime.combine(local_date, _parse_hhmm(schedule.window_end),
                           tzinfo=zone)
    return start, end


def utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def utc_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def within_window(now: datetime, schedule) -> bool:
    schedule = schedule if isinstance(schedule, CampaignSchedule) else _schedule_model(schedule)
    local = utc_aware(now).astimezone(_zone(schedule))
    if local.weekday() not in schedule.weekdays:
        return False
    start, end = _window_for_date(local.date(), schedule)
    return start <= local < end


def window_deadline(now: datetime, schedule) -> Optional[datetime]:
    """Return the current window's UTC end, or None when the window is closed."""
    schedule = schedule if isinstance(schedule, CampaignSchedule) else _schedule_model(schedule)
    local = utc_aware(now).astimezone(_zone(schedule))
    if local.weekday() not in schedule.weekdays:
        return None
    start, end = _window_for_date(local.date(), schedule)
    if start <= local < end:
        return end.astimezone(UTC)
    return None


def next_window_open(now: datetime, schedule, *,
                     strictly_later: bool = False) -> Optional[datetime]:
    """Return the next UTC instant the campaign may start.

    ``strictly_later`` skips the current local day; it is used after the daily
    runtime limit so a campaign cannot restart until the next allowed window.
    """
    schedule = schedule if isinstance(schedule, CampaignSchedule) else _schedule_model(schedule)
    local = utc_aware(now).astimezone(_zone(schedule))
    for offset in range(0, 15):
        day = local.date() + timedelta(days=offset)
        if day.weekday() not in schedule.weekdays:
            continue
        start, end = _window_for_date(day, schedule)
        if offset == 0:
            if strictly_later or local >= end:
                continue
            if local < start:
                return start.astimezone(UTC)
            return utc_aware(now)
        return start.astimezone(UTC)
    return None


def local_day_key(now: datetime, schedule) -> str:
    schedule = schedule if isinstance(schedule, CampaignSchedule) else _schedule_model(schedule)
    return utc_aware(now).astimezone(_zone(schedule)).date().isoformat()


def _default_usage() -> dict:
    return {
        "reserved_tokens": 0,
        "reserved_cost_microusd": 0,
        "calls": 0,
        "reported_tokens": 0,
        "reported_cost_microusd": 0,
        "unknown_usage_calls": 0,
        "unknown_cost_calls": 0,
        "runtime_seconds": 0,
        "daily": {},
        "last_steps": 0,
        "last_successful_steps": 0,
        "last_model_calls": 0,
        "active_since": None,
        "stopped": False,
        "stop_reason": "",
    }


def validate_usage(value) -> dict:
    """Return a canonical usage ledger or fail closed."""
    if not isinstance(value, dict):
        raise CampaignValidationError("Campaign usage ledger is missing")
    usage = _default_usage()
    for field in ("reserved_tokens", "reserved_cost_microusd", "calls",
                  "reported_tokens", "reported_cost_microusd",
                  "unknown_usage_calls", "unknown_cost_calls", "runtime_seconds",
                  "last_steps", "last_successful_steps", "last_model_calls"):
        if field in value:
            usage[field] = _require_int(value[field], field)
    daily = value.get("daily", {})
    if not isinstance(daily, dict):
        raise CampaignValidationError("Campaign daily runtime ledger is invalid")
    cleaned: dict[str, int] = {}
    for key, seconds in daily.items():
        if not isinstance(key, str) or not DAY_KEY.fullmatch(key):
            raise CampaignValidationError("Campaign daily runtime key is invalid")
        cleaned[key] = _require_int(seconds, "daily runtime")
    usage["daily"] = dict(sorted(cleaned.items())[-MAX_DAILY_ENTRIES:])
    active_since = value.get("active_since")
    if active_since is not None:
        if not isinstance(active_since, str) or len(active_since) > 64:
            raise CampaignValidationError("Campaign active timestamp is invalid")
        try:
            datetime.fromisoformat(active_since)
        except ValueError:
            raise CampaignValidationError("Campaign active timestamp is invalid") from None
    usage["active_since"] = active_since
    stopped = value.get("stopped", False)
    if type(stopped) is not bool:
        raise CampaignValidationError("Campaign stop flag is invalid")
    usage["stopped"] = stopped
    stop_reason = value.get("stop_reason", "")
    if stop_reason not in STOP_REASONS:
        raise CampaignValidationError("Campaign stop reason is invalid")
    usage["stop_reason"] = stop_reason
    return usage


def validate_budget(value) -> dict:
    if not isinstance(value, dict):
        raise CampaignValidationError("Campaign budget is missing")
    max_tokens = _require_int(value.get("max_tokens"), "token budget", minimum=1)
    max_cost = _require_int(value.get("max_cost_microusd"), "cost budget")
    return {"max_tokens": max_tokens, "max_cost_microusd": max_cost}


def daily_runtime_seconds(usage: dict, day_key: str) -> int:
    return int((usage.get("daily") or {}).get(day_key, 0))


def validate_retry(value) -> dict:
    if not isinstance(value, dict):
        raise CampaignValidationError("Campaign retry state is invalid")
    count = _require_int(value.get("count", 0), "retry count")
    maximum = _require_int(value.get("max", settings.CAMPAIGN_MAX_RETRIES),
                           "retry maximum")
    if maximum > 10:
        raise CampaignValidationError("Campaign retry maximum is invalid")
    return {"count": count, "max": maximum,
            "last_reason": _clean_text(value.get("last_reason", ""), 100)}


def retry_delay_seconds(count: int) -> int:
    if count <= 0:
        return 0
    return min(settings.CAMPAIGN_RETRY_BASE_SECONDS * (2 ** min(count - 1, 16)),
               settings.CAMPAIGN_RETRY_MAX_SECONDS)


def retry_next_action(now: datetime, schedule, count: int) -> Optional[datetime]:
    """Place a bounded retry inside the next available execution window."""
    schedule = schedule if isinstance(schedule, CampaignSchedule) else _schedule_model(schedule)
    candidate = utc_aware(now) + timedelta(seconds=retry_delay_seconds(count))
    if not within_window(candidate, schedule):
        return next_window_open(candidate, schedule)
    return candidate


def accumulate_runtime(usage: dict, now: datetime, schedule, *,
                       cap_seconds: int = 300) -> dict:
    """Attribute heartbeat deltas to the current local day.

    The delta is capped so a suspended process or clock jump cannot exhaust the
    daily allowance retroactively.  Runtime is never inferred without an
    ``active_since`` marker, which is only written while a run is live.
    """
    usage = validate_usage(usage)
    schedule = schedule if isinstance(schedule, CampaignSchedule) else _schedule_model(schedule)
    active_since = usage.get("active_since")
    if not active_since:
        return usage
    try:
        started = datetime.fromisoformat(active_since)
    except ValueError:
        raise CampaignValidationError("Campaign active timestamp is invalid") from None
    now = utc_aware(now)
    started = utc_aware(started)
    delta = int((now - started).total_seconds())
    delta = max(0, min(delta, max(0, int(cap_seconds))))
    if delta:
        day = local_day_key(now, schedule)
        usage["runtime_seconds"] += delta
        usage["daily"][day] = usage["daily"].get(day, 0) + delta
        usage["daily"] = dict(sorted(usage["daily"].items())[-MAX_DAILY_ENTRIES:])
    usage["active_since"] = now.isoformat()
    return usage


def retry_state(count: int, maximum: int, reason: str) -> dict:
    return {"count": max(0, int(count)), "max": max(0, int(maximum)),
            "last_reason": _clean_text(reason, 100)}


def _terminalize(row, now: datetime) -> None:
    row.active_key = None
    row.auto_resume = False
    row.next_action_at = None
    row.lease_holder = None
    row.lease_expires_at = None
    row.ended_at = row.ended_at or utc_naive(now)


def budget_remaining(usage: dict, budget: dict) -> tuple[int, int]:
    return (max(0, budget["max_tokens"] - usage["reserved_tokens"]),
            max(0, budget["max_cost_microusd"] - usage["reserved_cost_microusd"]))


def evaluate_campaign_reservation(usage: dict, budget: dict, *,
                                  tokens: int, cost_microusd: int,
                                  check_only: bool = False) -> dict:
    """Apply a conservative reservation or raise ``CampaignBudgetError``."""
    usage = validate_usage(usage)
    budget = validate_budget(budget)
    tokens = _require_int(tokens, "reservation tokens")
    cost = _require_int(cost_microusd, "reservation cost")
    issues = accounting_inconsistencies(usage)
    if issues:
        raise CampaignBudgetError(
            "Campaign model accounting is inconsistent; further calls are denied",
            code="campaign_accounting_inconsistent")
    if usage["stopped"]:
        code = ("campaign_accounting_inconsistent"
                if usage["stop_reason"] in {"unknown_usage",
                                            "accounting_inconsistent"}
                else "campaign_budget_exhausted")
        message = ("Campaign model accounting stopped after unknown provider usage"
                   if code == "campaign_accounting_inconsistent"
                   else "Campaign model budget was stopped after a provider overrun")
        raise CampaignBudgetError(message, code=code)
    if (usage["reserved_tokens"] + tokens > budget["max_tokens"]
            or usage["reserved_cost_microusd"] + cost > budget["max_cost_microusd"]):
        raise CampaignBudgetError("Campaign model budget is exhausted",
                                  code="campaign_budget_exhausted")
    if check_only:
        return usage
    usage["reserved_tokens"] += tokens
    usage["reserved_cost_microusd"] += cost
    usage["calls"] += 1
    return usage


def apply_settlement(usage: dict, *, reserved_tokens: int,
                     reserved_cost_microusd: int,
                     reported_tokens: Optional[int],
                     reported_cost_microusd: Optional[int],
                     success: bool) -> dict:
    """Record physical-call usage in the campaign ledger.

    Reservations are never refunded.  A successful call that does not report
    token usage, or any call that reports usage above its reserved ceiling,
    stops further campaign calls rather than silently trusting the ledger.
    """
    usage = validate_usage(usage)
    reserved_tokens = _require_int(reserved_tokens, "attempt reserved tokens")
    reserved_cost = _require_int(reserved_cost_microusd,
                                 "attempt reserved cost")
    if reported_tokens is not None:
        reported_tokens = _require_int(reported_tokens, "reported tokens")
        usage["reported_tokens"] += reported_tokens
    if reported_cost_microusd is not None:
        reported_cost = _require_int(reported_cost_microusd, "reported cost")
        usage["reported_cost_microusd"] += reported_cost
    if reported_tokens is None:
        usage["unknown_usage_calls"] += 1
    if reported_cost_microusd is None:
        usage["unknown_cost_calls"] += 1
    if (reported_tokens is not None and reported_tokens > reserved_tokens) or (
            reported_cost_microusd is not None
            and reported_cost_microusd > reserved_cost):
        usage["stopped"] = True
        usage["stop_reason"] = "provider_overrun"
    elif success and reported_tokens is None:
        usage["stopped"] = True
        usage["stop_reason"] = "unknown_usage"
    return usage


def set_active_since(usage: dict, now: datetime) -> dict:
    usage = validate_usage(usage)
    usage["active_since"] = utc_aware(now).isoformat()
    return usage


def clear_active_since(usage: dict) -> dict:
    usage = validate_usage(usage)
    usage["active_since"] = None
    return usage


async def reserve_campaign_usage(db, *, campaign_id: str, session_id: str,
                                 owner_id: str, tokens: int,
                                 cost_microusd: int,
                                 check_only: bool = False) -> dict:
    """Atomically enforce the campaign ledger inside the caller's transaction.

    Raising ``HTTPException`` rolls back the caller's unit of work, so a campaign
    denial also prevents the per-session reservation and the physical call.
    """
    if not all(isinstance(item, str) and item for item in
               (campaign_id, session_id, owner_id)):
        raise HTTPException(409, {"code": "campaign_budget_unavailable",
                                  "message": "Campaign budget cannot be verified"})
    row = (await db.execute(select(AutonomousCampaign).where(
        AutonomousCampaign.id == campaign_id,
        AutonomousCampaign.session_id == session_id,
        AutonomousCampaign.owner_id == owner_id,
    ).with_for_update())).scalar_one_or_none()
    if row is None:
        raise HTTPException(409, {"code": "campaign_budget_unavailable",
                                  "message": "Campaign budget cannot be verified"})
    if row.state in TERMINAL_STATES or (not check_only and row.state not in MODEL_STATES):
        raise HTTPException(409, {"code": "campaign_budget_unavailable",
                                  "message": "Campaign is not accepting model calls"})
    try:
        usage = validate_usage(row.usage)
        budget = validate_budget(row.budget)
        updated = evaluate_campaign_reservation(
            usage, budget, tokens=tokens, cost_microusd=cost_microusd,
            check_only=check_only)
    except CampaignValidationError:
        raise HTTPException(409, {"code": "campaign_budget_unavailable",
                                  "message": "Campaign budget cannot be verified"}) from None
    except CampaignBudgetError as exc:
        status_code = (409 if exc.code in {"campaign_accounting_inconsistent",
                                           "campaign_budget_unavailable"}
                       else 429)
        raise HTTPException(status_code,
                            {"code": exc.code, "message": str(exc)}) from None
    remaining_tokens, remaining_cost = budget_remaining(updated, budget)
    if check_only:
        return {"ready": True, "remaining_tokens": remaining_tokens,
                "remaining_cost_microusd": remaining_cost}
    row.usage = updated
    row.updated_at = utc_naive(datetime.now(UTC))
    return {"campaign_id": campaign_id,
            "reserved_tokens": updated["reserved_tokens"],
            "reserved_cost_microusd": updated["reserved_cost_microusd"],
            "remaining_tokens": remaining_tokens,
            "remaining_cost_microusd": remaining_cost}


def _iso(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return utc_aware(value).isoformat()


def campaign_status(row: dict, now: datetime, *,
                    run_status: Optional[dict] = None) -> dict:
    """Build the owner-facing supervisor view without mutating anything."""
    now = utc_aware(now)
    base = {
        "campaign_id": row.get("id"),
        "session_id": row.get("session_id"),
        "state": row.get("state"),
        "goal": row.get("goal"),
        "target": row.get("target"),
        "skill_level": row.get("skill_level"),
        "max_steps": row.get("max_steps"),
        "auto_risk_threshold": row.get("auto_risk_threshold"),
        "has_started": bool(row.get("has_started")),
        "auto_resume": bool(row.get("auto_resume")),
        "run_id": row.get("run_id"),
        "pause_reason": row.get("pause_reason") or "",
        "reason_code": row.get("reason_code") or "",
        "reason": row.get("reason") or "",
        "created_at": _iso(row.get("created_at")),
        "updated_at": _iso(row.get("updated_at")),
        "started_at": _iso(row.get("started_at")),
        "ended_at": _iso(row.get("ended_at")),
        "supervisor": {
            "lease_held": bool(row.get("lease_holder")),
            "lease_expires_at": _iso(row.get("lease_expires_at")),
            "last_heartbeat_at": _iso(row.get("last_heartbeat_at")),
            "next_action_at": _iso(row.get("next_action_at")),
        },
        "run": run_status,
    }
    try:
        schedule = _schedule_model(row.get("schedule"))
        usage = validate_usage(row.get("usage"))
        budget = validate_budget(row.get("budget"))
        retry = validate_retry(row.get("retry"))
    except CampaignValidationError:
        return {**base, "invalid": True,
                "error": "Campaign durable state is invalid; supervisor will not act"}
    day = local_day_key(now, schedule)
    remaining_tokens, remaining_cost = budget_remaining(usage, budget)
    open_now = within_window(now, schedule)
    deadline = window_deadline(now, schedule)
    base.update({
        "schedule": {
            **schedule.model_dump(),
            "within_window": open_now,
            "window_ends_at": _iso(deadline),
            "next_window_open": _iso(next_window_open(now, schedule)),
        },
        "runtime": {
            "total_seconds": usage["runtime_seconds"],
            "daily_seconds": daily_runtime_seconds(usage, day),
            "daily_limit_seconds": schedule.daily_runtime_seconds,
            "local_date": day,
            "active_since": usage["active_since"],
        },
        "budget": {
            "max_tokens": budget["max_tokens"],
            "max_cost_microusd": budget["max_cost_microusd"],
            "reserved_tokens": usage["reserved_tokens"],
            "reserved_cost_microusd": usage["reserved_cost_microusd"],
            "remaining_tokens": remaining_tokens,
            "remaining_cost_microusd": remaining_cost,
            "calls": usage["calls"],
            "reported_tokens": usage["reported_tokens"],
            "reported_cost_microusd": usage["reported_cost_microusd"],
            "unknown_usage_calls": usage["unknown_usage_calls"],
            "unknown_cost_calls": usage["unknown_cost_calls"],
            "stopped": usage["stopped"],
            "stop_reason": usage["stop_reason"],
        },
        "retry": retry,
        "next_execution_at": _iso(row.get("next_action_at")),
    })
    return base


def _row_dict(row) -> dict:
    return {
        "id": row.id,
        "session_id": row.session_id,
        "owner_id": row.owner_id,
        "state": row.state,
        "active_key": row.active_key,
        "goal": row.goal,
        "target": row.target,
        "skill_level": row.skill_level,
        "objective": row.objective,
        "max_steps": row.max_steps,
        "auto_risk_threshold": row.auto_risk_threshold,
        "scope_digest": row.scope_digest,
        "auth_revision": row.auth_revision,
        "worker_epoch": row.worker_epoch,
        "schedule": dict(row.schedule or {}),
        "budget": dict(row.budget or {}),
        "usage": dict(row.usage or {}),
        "retry": dict(row.retry or {}),
        "operations": dict(row.operations or {}),
        "run_id": row.run_id,
        "has_started": bool(row.has_started),
        "auto_resume": bool(row.auto_resume),
        "lease_holder": row.lease_holder,
        "lease_expires_at": row.lease_expires_at,
        "last_heartbeat_at": row.last_heartbeat_at,
        "next_action_at": row.next_action_at,
        "pause_reason": row.pause_reason or "",
        "reason_code": row.reason_code or "",
        "reason": row.reason or "",
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "started_at": row.started_at,
        "ended_at": row.ended_at,
    }


def _append_operation(row, *, event: str, from_state: str = "",
                      to_state: str = "", reason_code: str = "",
                      message: str = "", attributes: Optional[dict] = None,
                      now: Optional[datetime] = None,
                      dedupe_seconds: int = 0) -> bool:
    """Append a bounded operational event to the campaign ring.

    Returns ``True`` when the ring changed.  Invalid stored state is reset and
    faults a ``operations_invalid`` alert inside the ring, while the immutable
    DecisionLog audit row is written separately by callers.
    """
    if not event:
        return False
    updated = append_operation(
        row.operations, event=event, campaign_id=row.id,
        from_state=from_state, to_state=to_state, reason_code=reason_code,
        message=message, attributes=attributes, now=now,
        dedupe_seconds=dedupe_seconds)
    if updated == row.operations:
        return False
    row.operations = updated
    return True


def _event(db, *, session_id: str, owner_id: str, campaign_id: str,
           event: str, from_state: str = "", to_state: str = "",
           reason_code: str = "", reason: str = "", run_id: str = "",
           usage: Optional[dict] = None) -> None:
    db.add(DecisionLog(
        session_id=session_id,
        user_id=owner_id,
        decision_type="campaign_event",
        agent="campaign_supervisor",
        reasoning=_clean_text(f"campaign {event}: {from_state}->{to_state}", 500),
        action_taken=_clean_text(event, 100),
        metadata_={
            "campaign_id": campaign_id,
            "event": event,
            "from_state": from_state,
            "to_state": to_state,
            "reason_code": _clean_text(reason_code, 100),
            "reason": _clean_text(reason, MAX_DETAIL),
            "run_id": _clean_text(run_id, 100),
            "usage": usage or {},
            "correlation_id": correlation_id(),
            "timestamp": datetime.now(UTC).isoformat(),
        },
    ))


class SQLCampaignBackend:
    """PostgreSQL persistence for campaign schedules, leases and budgets."""

    def __init__(self, session_factory=None):
        self._session_factory = session_factory or async_session

    async def create(self, spec: CampaignSpec) -> dict:
        campaign_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        schedule = spec.schedule
        next_open = next_window_open(now, schedule)
        usage = _default_usage()
        retry = {"count": 0, "max": spec.max_retries, "last_reason": ""}
        operations = append_operation(
            None, event="campaign_created", campaign_id=campaign_id,
            to_state="scheduled", reason_code="scheduled",
            message="Durable campaign schedule created.",
            attributes={"run_id": "", "retry_max": spec.max_retries},
            now=now)
        row = AutonomousCampaign(
            id=campaign_id,
            session_id=spec.session_id,
            owner_id=spec.owner_id,
            state="scheduled",
            active_key=spec.session_id,
            goal=spec.goal,
            target=spec.target,
            skill_level=spec.skill_level,
            objective=_clean_text(spec.objective,
                                  settings.AUTONOMOUS_OBJECTIVE_MAX_CHARS),
            max_steps=spec.max_steps,
            auto_risk_threshold=spec.auto_risk_threshold,
            scope_digest=spec.scope_digest,
            auth_revision=spec.auth_revision,
            worker_epoch=spec.worker_epoch,
            schedule=schedule.model_dump(),
            budget=spec.budget.model_dump(),
            usage=usage,
            retry=retry,
            operations=operations,
            has_started=False,
            auto_resume=False,
            next_action_at=utc_naive(next_open) if next_open else utc_naive(now),
            pause_reason="",
            reason_code="",
            reason="",
            created_at=utc_naive(now),
            updated_at=utc_naive(now),
        )
        async with self._session_factory() as db:
            db.add(row)
            _event(db, session_id=spec.session_id, owner_id=spec.owner_id,
                   campaign_id=campaign_id, event="campaign_created",
                   to_state="scheduled", reason_code="scheduled",
                   usage=usage)
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()
                raise CampaignConflict(
                    "An active campaign already exists for this engagement") from None
            return _row_dict(row)

    async def get(self, campaign_id: str) -> Optional[dict]:
        async with self._session_factory() as db:
            row = await db.get(AutonomousCampaign, campaign_id)
            return _row_dict(row) if row else None

    async def latest_for_session(self, session_id: str) -> Optional[dict]:
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.session_id == session_id).order_by(
                AutonomousCampaign.created_at.desc(),
                AutonomousCampaign.id.desc()).limit(1))).scalar_one_or_none()
            return _row_dict(row) if row else None

    async def latest_active_for_session(self, session_id: str) -> Optional[dict]:
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.session_id == session_id,
                AutonomousCampaign.state.notin_(TERMINAL_STATES)).order_by(
                AutonomousCampaign.created_at.desc(),
                AutonomousCampaign.id.desc()).limit(1))).scalar_one_or_none()
            return _row_dict(row) if row else None

    async def list_in_states(self, states, limit: int = 200) -> list[dict]:
        async with self._session_factory() as db:
            rows = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.state.in_(tuple(states))).order_by(
                AutonomousCampaign.updated_at.asc()).limit(limit))).scalars().all()
            return [_row_dict(row) for row in rows]

    async def due(self, now: datetime, limit: int = 200) -> list[dict]:
        now = utc_naive(now)
        async with self._session_factory() as db:
            rows = (await db.execute(select(AutonomousCampaign).where(or_(
                AutonomousCampaign.state.in_(("starting", "running", "pausing",
                                              "cancelling")),
                and_(AutonomousCampaign.state == "scheduled",
                     or_(AutonomousCampaign.next_action_at.is_(None),
                         AutonomousCampaign.next_action_at <= now)),
                and_(AutonomousCampaign.state == "paused",
                     AutonomousCampaign.auto_resume.is_(True),
                     AutonomousCampaign.next_action_at.isnot(None),
                     AutonomousCampaign.next_action_at <= now),
            )).order_by(AutonomousCampaign.next_action_at.asc(),
                        AutonomousCampaign.updated_at.asc()).limit(limit))).scalars().all()
            return [_row_dict(row) for row in rows]

    async def claim(self, campaign_id: str, token: str, now: datetime,
                    lease_seconds: int) -> Optional[dict]:
        now = utc_naive(now)
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.id == campaign_id).with_for_update()
            )).scalar_one_or_none()
            if row is None or row.state in TERMINAL_STATES:
                return None
            if (row.lease_holder and row.lease_holder != token
                    and row.lease_expires_at is not None
                    and row.lease_expires_at > now):
                return None
            row.lease_holder = token
            row.lease_expires_at = now + timedelta(seconds=lease_seconds)
            row.last_heartbeat_at = now
            row.updated_at = now
            await db.commit()
            return _row_dict(row)

    async def release(self, campaign_id: str, token: str) -> None:
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.id == campaign_id).with_for_update()
            )).scalar_one_or_none()
            if row is None or row.lease_holder != token:
                return
            row.lease_holder = None
            row.lease_expires_at = None
            row.updated_at = utc_naive(datetime.now(UTC))
            await db.commit()

    async def check_budget(self, campaign_id: str, session_id: str,
                           owner_id: str) -> dict:
        """Read-only ledger admission used by the supervisor preflight."""
        async with self._session_factory() as db:
            return await reserve_campaign_usage(
                db, campaign_id=campaign_id, session_id=session_id,
                owner_id=owner_id, tokens=0, cost_microusd=0, check_only=True)

    async def recover(self, now: Optional[datetime] = None) -> list[str]:
        """Reconcile campaigns whose supervisor lease expired.

        A campaign is never restarted by recovery; it is moved to ``scheduled``
        with a bounded backoff so the normal restore preflight runs.  Live
        leases owned by another process are left untouched.
        """
        now = utc_aware(now or datetime.now(UTC))
        naive_now = utc_naive(now)
        recovered: list[str] = []
        async with self._session_factory() as db:
            rows = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.state.in_(tuple(LIVE_STATES))).with_for_update()
            )).scalars().all()
            for row in rows:
                if (row.lease_holder and row.lease_expires_at is not None
                        and row.lease_expires_at > naive_now):
                    continue
                previous = row.state
                try:
                    usage = validate_usage(row.usage)
                    schedule = _schedule_model(row.schedule)
                    retry = validate_retry(row.retry)
                except CampaignValidationError:
                    row.state = "failed"
                    row.reason_code = "unsafe_state"
                    row.reason = "Durable campaign state is invalid; supervisor refused to act."
                    _terminalize(row, now)
                    _event(db, session_id=row.session_id, owner_id=row.owner_id,
                           campaign_id=row.id, event="campaign_recovery_failed",
                           from_state=previous, to_state=row.state,
                           reason_code=row.reason_code, reason=row.reason)
                    _append_operation(
                        row, event="campaign_recovery_failed",
                        from_state=previous, to_state=row.state,
                        reason_code=row.reason_code, message=row.reason,
                        now=now)
                    recovered.append(row.id)
                    continue
                event_name = ""
                if row.state in {"starting", "running"}:
                    usage = clear_active_since(accumulate_runtime(
                        usage, now, schedule,
                        cap_seconds=max(60, int(settings.CAMPAIGN_TICK_SECONDS * 3))))
                    count = retry["count"] + 1
                    if count > retry["max"]:
                        row.state = "failed"
                        row.reason_code = "retry_exhausted"
                        row.reason = ("Supervisor restarted repeatedly without durable "
                                      "progress; automatic resume stopped.")
                        _terminalize(row, now)
                        event_name = "campaign_retry_exhausted"
                    else:
                        row.state = "scheduled"
                        next_at = retry_next_action(now, schedule, count)
                        row.next_action_at = (utc_naive(next_at) if next_at
                                              else naive_now)
                        row.auto_resume = False
                        row.reason_code = "supervisor_restart"
                        row.reason = ("Supervisor restarted while the campaign was live; "
                                      "resume requires checkpoint validation.")
                        event_name = "campaign_recovered"
                    row.retry = retry_state(count, retry["max"], "supervisor_restart")
                elif row.state == "pausing":
                    usage = accumulate_runtime(
                        usage, now, schedule,
                        cap_seconds=max(60, int(settings.CAMPAIGN_TICK_SECONDS * 3)))
                    usage = clear_active_since(usage)
                    row.state = "paused"
                    row.auto_resume = (row.pause_reason or "") != "operator_requested"
                    next_at = (next_window_open(now, schedule)
                               if row.auto_resume else None)
                    row.next_action_at = utc_naive(next_at) if next_at else None
                    row.reason_code = "supervisor_restart"
                    row.reason = "Supervisor restarted while pausing; run remains paused."
                    event_name = "campaign_recovered"
                elif row.state == "cancelling":
                    usage = clear_active_since(usage)
                    row.state = "cancelled"
                    row.reason_code = "operator_cancelled"
                    row.reason = "Cancellation confirmed during supervisor recovery."
                    _terminalize(row, now)
                    event_name = "campaign_cancelled"
                elif row.state in {"scheduled", "paused"}:
                    row.lease_holder = None
                    row.lease_expires_at = None
                    row.updated_at = naive_now
                    recovered.append(row.id)
                    continue
                row.usage = usage
                row.lease_holder = None
                row.lease_expires_at = None
                row.last_heartbeat_at = naive_now
                row.updated_at = naive_now
                _event(db, session_id=row.session_id, owner_id=row.owner_id,
                       campaign_id=row.id, event=event_name or "campaign_recovered",
                       from_state=previous, to_state=row.state,
                       reason_code=row.reason_code, reason=row.reason,
                       usage=usage)
                _append_operation(
                    row, event=event_name or "campaign_recovered",
                    from_state=previous, to_state=row.state,
                    reason_code=row.reason_code, message=row.reason,
                    attributes={"retry_count": int((row.retry or {}).get("count", 0))},
                    now=now)
                recovered.append(row.id)
            await db.commit()
        return recovered

    async def transition(self, campaign_id: str, token: str, now: datetime,
                         expected_states, values: dict, *, event: str = "",
                         event_reason_code: str = "",
                         event_reason: str = "",
                         operation: Optional[dict] = None,
                         require_lease: bool = True) -> Optional[dict]:
        now = utc_naive(now)
        expected = set(expected_states)
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.id == campaign_id).with_for_update()
            )).scalar_one_or_none()
            if (row is None or row.state not in expected
                    or (require_lease and row.lease_holder != token)):
                return None
            previous = row.state
            for field in ("state", "run_id", "has_started", "auto_resume",
                          "pause_reason", "reason_code", "reason",
                          "next_action_at", "started_at", "ended_at",
                          "usage", "retry"):
                if field not in values:
                    continue
                value = values[field]
                if field == "state":
                    if value not in LIVE_STATES | TERMINAL_STATES:
                        raise CampaignValidationError("Campaign state is invalid")
                    row.state = value
                elif field == "usage":
                    row.usage = validate_usage(value)
                elif field == "retry":
                    row.retry = validate_retry(value)
                elif field in {"has_started", "auto_resume"}:
                    if type(value) is not bool:
                        raise CampaignValidationError("Campaign flag is invalid")
                    setattr(row, field, value)
                elif field in {"next_action_at", "started_at", "ended_at"}:
                    setattr(row, field, utc_naive(value) if value else None)
                elif field == "pause_reason":
                    row.pause_reason = _clean_text(value, MAX_REASON)
                elif field == "reason_code":
                    row.reason_code = _clean_text(value, 100)
                elif field == "reason":
                    row.reason = _clean_text(value, MAX_DETAIL)
                elif field == "run_id":
                    row.run_id = _clean_text(value, 100) or None
            if row.state in TERMINAL_STATES:
                row.active_key = None
                row.auto_resume = False
                row.next_action_at = None
                row.lease_holder = None
                row.lease_expires_at = None
                row.ended_at = row.ended_at or now
            if values.get("release_lease"):
                row.lease_holder = None
                row.lease_expires_at = None
            row.updated_at = now
            row.last_heartbeat_at = now
            if event:
                _event(db, session_id=row.session_id, owner_id=row.owner_id,
                       campaign_id=row.id, event=event, from_state=previous,
                       to_state=row.state, reason_code=event_reason_code,
                       reason=event_reason, run_id=row.run_id or "",
                       usage=dict(row.usage or {}))
                _append_operation(
                    row, event=event, from_state=previous, to_state=row.state,
                    reason_code=event_reason_code, message=event_reason,
                    attributes={"run_id": row.run_id or ""}, now=now)
            if isinstance(operation, dict) and operation.get("event"):
                dedupe = operation.get("dedupe_seconds", 0)
                dedupe = (max(0, min(dedupe, 3600))
                          if type(dedupe) is int else 0)
                _append_operation(
                    row, event=str(operation["event"]),
                    from_state=operation.get("from_state", previous),
                    to_state=operation.get("to_state", row.state),
                    reason_code=operation.get("reason_code", ""),
                    message=operation.get("message", ""),
                    attributes=operation.get("attributes"),
                    now=now, dedupe_seconds=dedupe)
            await db.commit()
            return _row_dict(row)

    async def record_activity(self, campaign_id: str, token: str,
                              now: datetime, *, runtime_seconds: int = 0,
                              day_key: str = "", progress: Optional[dict] = None,
                              active_since=UNSET, usage_updates: Optional[dict] = None,
                              next_action_at=UNSET,
                              operation: Optional[dict] = None) -> Optional[dict]:
        """Accumulate bounded runtime/progress without touching the state."""
        now = utc_naive(now)
        runtime = max(0, min(int(runtime_seconds or 0), 86400))
        async with self._session_factory() as db:
            row = (await db.execute(select(AutonomousCampaign).where(
                AutonomousCampaign.id == campaign_id).with_for_update()
            )).scalar_one_or_none()
            if row is None or row.lease_holder != token or row.state in TERMINAL_STATES:
                return None
            usage = validate_usage(row.usage)
            if runtime:
                usage["runtime_seconds"] += runtime
                if not day_key:
                    raise CampaignValidationError("Campaign runtime day is required")
                if not DAY_KEY.fullmatch(str(day_key)):
                    raise CampaignValidationError("Campaign runtime day is invalid")
                usage["daily"][day_key] = usage["daily"].get(day_key, 0) + runtime
                usage["daily"] = dict(sorted(usage["daily"].items())[-MAX_DAILY_ENTRIES:])
            for field in ("last_steps", "last_successful_steps", "last_model_calls"):
                if progress and field in progress:
                    usage[field] = _require_int(progress[field], field)
            if usage_updates:
                if "stopped" in usage_updates:
                    if type(usage_updates["stopped"]) is not bool:
                        raise CampaignValidationError("Campaign stop flag is invalid")
                    usage["stopped"] = usage_updates["stopped"]
                for field in ("unknown_usage_calls", "unknown_cost_calls", "calls",
                              "reserved_tokens", "reserved_cost_microusd",
                              "reported_tokens", "reported_cost_microusd"):
                    if field in usage_updates:
                        usage[field] = max(usage[field],
                                           _require_int(usage_updates[field], field))
                if "stop_reason" in usage_updates:
                    reason = usage_updates["stop_reason"]
                    if reason not in STOP_REASONS:
                        raise CampaignValidationError(
                            "Campaign stop reason is invalid")
                    usage["stop_reason"] = reason
            if active_since is not UNSET:
                if active_since is None:
                    usage["active_since"] = None
                elif isinstance(active_since, datetime):
                    usage["active_since"] = utc_aware(active_since).isoformat()
                else:
                    raise CampaignValidationError("Campaign active timestamp is invalid")
            row.usage = validate_usage(usage)
            if next_action_at is not UNSET:
                row.next_action_at = utc_naive(next_action_at) if next_action_at else None
            row.updated_at = now
            row.last_heartbeat_at = now
            if isinstance(operation, dict) and operation.get("event"):
                dedupe = operation.get("dedupe_seconds", 0)
                dedupe = (max(0, min(dedupe, 3600))
                          if type(dedupe) is int else 0)
                _append_operation(
                    row, event=str(operation["event"]),
                    from_state=operation.get("from_state", row.state),
                    to_state=operation.get("to_state", row.state),
                    reason_code=operation.get("reason_code", ""),
                    message=operation.get("message", ""),
                    attributes=operation.get("attributes"),
                    now=now, dedupe_seconds=dedupe)
            await db.commit()
            return _row_dict(row)

    async def bind_session(self, session_id: str, owner_id: str,
                           campaign_id: str) -> None:
        async with self._session_factory() as db:
            session = (await db.execute(select(PentestSession).where(
                PentestSession.id == session_id,
                PentestSession.user_id == owner_id).with_for_update()
            )).scalar_one_or_none()
            if session is None:
                raise CampaignNotFound("Engagement was not found")
            metadata = dict(session.metadata_ or {})
            existing = metadata.get("active_campaign_id")
            if existing and existing != campaign_id:
                previous = await db.get(AutonomousCampaign, existing)
                if previous is not None and previous.state not in TERMINAL_STATES:
                    raise CampaignConflict(
                        "Another campaign is already bound to this engagement")
                # A terminal campaign left a stale marker after an interrupted
                # unbind; it must not block a newly authorized campaign.
            metadata["active_campaign_id"] = campaign_id
            session.metadata_ = metadata
            await db.commit()

    async def unbind_session(self, session_id: str, owner_id: str,
                             campaign_id: str) -> None:
        async with self._session_factory() as db:
            session = (await db.execute(select(PentestSession).where(
                PentestSession.id == session_id,
                PentestSession.user_id == owner_id).with_for_update()
            )).scalar_one_or_none()
            if session is None:
                return
            metadata = dict(session.metadata_ or {})
            if metadata.get("active_campaign_id") == campaign_id:
                metadata.pop("active_campaign_id", None)
                session.metadata_ = metadata
                await db.commit()


campaign_store = SQLCampaignBackend()
