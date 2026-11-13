"""SPEC-12 campaign schedule, supervisor and budget regressions (offline)."""
import asyncio
import copy
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from agents.autonomous_engine import AutonomousEngine, SessionRunState
from api.auth import TokenData, get_current_user
from api.main import app
from config.settings import settings
from memory import campaign_store as campaigns
from memory.campaign_store import (
    CampaignBudget, CampaignBudgetError, CampaignConflict, CampaignSchedule,
    CampaignSpec, campaign_status, evaluate_campaign_reservation,
    next_window_open, retry_delay_seconds, within_window,
)
from orchestrator.campaign_supervisor import CampaignSupervisor
from tests.support import OfflineCase

UTC = timezone.utc
OWNER = "owner-1"
SESSION = "session-1"
DIGEST = "a" * 64
MONDAY = datetime(2026, 11, 9, 9, 0, tzinfo=UTC)


def make_spec(*, session_id=SESSION, owner_id=OWNER, timezone_name="UTC",
              weekdays=(0, 1, 2, 3, 4), window=("09:00", "17:00"),
              daily=28800, max_retries=2, max_tokens=200000,
              max_cost=2000000) -> CampaignSpec:
    return CampaignSpec(
        session_id=session_id, owner_id=owner_id, goal="discovery",
        target="192.0.2.10", skill_level="expert", objective="Synthetic test",
        max_steps=12, auto_risk_threshold="green_orange",
        schedule=CampaignSchedule(timezone=timezone_name, weekdays=list(weekdays),
                                  window_start=window[0], window_end=window[1],
                                  daily_runtime_seconds=daily),
        budget=CampaignBudget(max_tokens=max_tokens, max_cost_microusd=max_cost),
        max_retries=max_retries, scope_digest=DIGEST, auth_revision=4,
        worker_epoch=2, required_tools=["curl", "nmap"],
    )


class MemoryCampaignStore:
    """Small in-memory mirror of the SQL campaign backend."""

    def __init__(self, clock=None):
        self.rows = {}
        self.events = []
        self.bound = {}
        self._lock = asyncio.Lock()
        self.clock = clock or (lambda: datetime.now(UTC))

    def _copy(self, row):
        return copy.deepcopy(row)

    async def create(self, spec):
        async with self._lock:
            if any(row["session_id"] == spec.session_id
                   and row["state"] not in campaigns.TERMINAL_STATES
                   for row in self.rows.values()):
                raise CampaignConflict("Active campaign exists")
            now = self.clock()
            campaign_id = str(uuid.uuid4())
            usage = campaigns.validate_usage({})
            row = {
                "id": campaign_id, "session_id": spec.session_id,
                "owner_id": spec.owner_id, "state": "scheduled",
                "active_key": spec.session_id, "goal": spec.goal,
                "target": spec.target, "skill_level": spec.skill_level,
                "objective": spec.objective, "max_steps": spec.max_steps,
                "auto_risk_threshold": spec.auto_risk_threshold,
                "scope_digest": spec.scope_digest, "auth_revision": spec.auth_revision,
                "worker_epoch": spec.worker_epoch,
                "schedule": spec.schedule.model_dump(),
                "budget": spec.budget.model_dump(), "usage": usage,
                "retry": {"count": 0, "max": spec.max_retries, "last_reason": ""},
                "operations": campaigns.append_operation(
                    None, event="campaign_created", campaign_id=campaign_id,
                    to_state="scheduled", reason_code="scheduled", now=now),
                "run_id": None, "has_started": False, "auto_resume": False,
                "lease_holder": None, "lease_expires_at": None,
                "last_heartbeat_at": campaigns.utc_naive(now),
                "next_action_at": campaigns.utc_naive(now),
                "pause_reason": "", "reason_code": "", "reason": "",
                "created_at": campaigns.utc_naive(now),
                "updated_at": campaigns.utc_naive(now),
                "started_at": None, "ended_at": None,
            }
            self.rows[campaign_id] = row
            self.events.append(("campaign_created", campaign_id))
            return self._copy(row)

    async def get(self, campaign_id):
        row = self.rows.get(campaign_id)
        return self._copy(row) if row else None

    async def latest_for_session(self, session_id):
        rows = [row for row in self.rows.values() if row["session_id"] == session_id]
        rows.sort(key=lambda row: row["created_at"], reverse=True)
        return self._copy(rows[0]) if rows else None

    async def latest_active_for_session(self, session_id):
        rows = [row for row in self.rows.values()
                if row["session_id"] == session_id
                and row["state"] not in campaigns.TERMINAL_STATES]
        rows.sort(key=lambda row: row["created_at"], reverse=True)
        return self._copy(rows[0]) if rows else None

    async def due(self, now, limit=200):
        now = campaigns.utc_naive(now)
        result = []
        for row in self.rows.values():
            if row["state"] in {"starting", "running", "pausing", "cancelling"}:
                result.append(self._copy(row))
            elif row["state"] == "scheduled" and (
                    row["next_action_at"] is None or row["next_action_at"] <= now):
                result.append(self._copy(row))
            elif (row["state"] == "paused" and row["auto_resume"]
                  and row["next_action_at"] is not None
                  and row["next_action_at"] <= now):
                result.append(self._copy(row))
        return result[:limit]

    async def claim(self, campaign_id, token, now, lease_seconds):
        async with self._lock:
            row = self.rows.get(campaign_id)
            now = campaigns.utc_naive(now)
            if row is None or row["state"] in campaigns.TERMINAL_STATES:
                return None
            if (row["lease_holder"] and row["lease_holder"] != token
                    and row["lease_expires_at"] is not None
                    and row["lease_expires_at"] > now):
                return None
            row["lease_holder"] = token
            row["lease_expires_at"] = now + timedelta(seconds=lease_seconds)
            row["last_heartbeat_at"] = now
            row["updated_at"] = now
            return self._copy(row)

    async def release(self, campaign_id, token):
        async with self._lock:
            row = self.rows.get(campaign_id)
            if row is not None and row["lease_holder"] == token:
                row["lease_holder"] = None
                row["lease_expires_at"] = None

    async def transition(self, campaign_id, token, now, expected_states, values,
                         *, event="", event_reason_code="", event_reason="",
                         operation=None, require_lease=True):
        async with self._lock:
            row = self.rows.get(campaign_id)
            now = campaigns.utc_naive(now)
            if (row is None or row["state"] not in set(expected_states)
                    or (require_lease and row["lease_holder"] != token)):
                return None
            previous = row["state"]
            for field in ("state", "run_id", "has_started", "auto_resume",
                          "pause_reason", "reason_code", "reason",
                          "next_action_at", "started_at", "ended_at", "usage", "retry"):
                if field not in values:
                    continue
                value = values[field]
                if field == "usage":
                    row["usage"] = campaigns.validate_usage(value)
                elif field == "retry":
                    row["retry"] = campaigns.validate_retry(value)
                elif field in {"next_action_at", "started_at", "ended_at"}:
                    row[field] = campaigns.utc_naive(value) if value else None
                else:
                    row[field] = value
            if row["state"] in campaigns.TERMINAL_STATES:
                row["active_key"] = None
                row["auto_resume"] = False
                row["next_action_at"] = None
                row["ended_at"] = row["ended_at"] or now
            if values.get("release_lease"):
                row["lease_holder"] = None
                row["lease_expires_at"] = None
            row["updated_at"] = now
            row["last_heartbeat_at"] = now
            if event:
                self.events.append((event, campaign_id, dict(row["usage"])))
                row["operations"] = campaigns.append_operation(
                    row.get("operations"), event=event, campaign_id=campaign_id,
                    from_state=previous, to_state=row["state"],
                    reason_code=event_reason_code, message=event_reason, now=now)
            if isinstance(operation, dict) and operation.get("event"):
                row["operations"] = campaigns.append_operation(
                    row.get("operations"), event=str(operation["event"]),
                    campaign_id=campaign_id,
                    from_state=operation.get("from_state", previous),
                    to_state=operation.get("to_state", row["state"]),
                    reason_code=operation.get("reason_code", ""),
                    message=operation.get("message", ""),
                    attributes=operation.get("attributes"), now=now)
            return self._copy(row)

    async def bind_session(self, session_id, owner_id, campaign_id):
        existing = self.bound.get(session_id)
        if existing and existing != campaign_id:
            row = self.rows.get(existing)
            if row is not None and row["state"] not in campaigns.TERMINAL_STATES:
                raise CampaignConflict("Another campaign is bound")
        self.bound[session_id] = campaign_id

    async def unbind_session(self, session_id, owner_id, campaign_id):
        if self.bound.get(session_id) == campaign_id:
            self.bound.pop(session_id, None)

    async def check_budget(self, campaign_id, session_id, owner_id):
        row = self.rows.get(campaign_id)
        if row is None:
            raise HTTPException(409, {"code": "campaign_budget_unavailable"})
        if row["state"] in campaigns.TERMINAL_STATES:
            raise HTTPException(409, {"code": "campaign_budget_unavailable"})
        try:
            usage = campaigns.validate_usage(row["usage"])
            budget = campaigns.validate_budget(row["budget"])
            campaigns.evaluate_campaign_reservation(
                usage, budget, tokens=0, cost_microusd=0, check_only=True)
        except CampaignBudgetError as exc:
            raise HTTPException(429, {"code": exc.code}) from None
        except campaigns.CampaignValidationError:
            raise HTTPException(409, {"code": "campaign_budget_unavailable"}) from None
        return {"ready": True}

    async def recover(self, now):
        recovered = []
        for row in self.rows.values():
            if (row["lease_holder"] and row["lease_expires_at"] is not None
                    and row["lease_expires_at"] > campaigns.utc_naive(now)):
                continue
            if row["state"] not in {"starting", "running", "pausing", "cancelling"}:
                continue
            previous = row["state"]
            usage = campaigns.validate_usage(row["usage"])
            schedule = CampaignSchedule.model_validate(row["schedule"])
            usage = campaigns.accumulate_runtime(
                usage, now, schedule,
                cap_seconds=max(60, int(settings.CAMPAIGN_TICK_SECONDS * 3)))
            usage["active_since"] = None
            if row["state"] in {"starting", "running"}:
                retry = campaigns.validate_retry(row["retry"])
                count = retry["count"] + 1
                row["retry"] = campaigns.retry_state(count, retry["max"],
                                                     "supervisor_restart")
                if count > retry["max"]:
                    row["state"] = "failed"
                    row["reason_code"] = "retry_exhausted"
                    row["active_key"] = None
                    row["ended_at"] = campaigns.utc_naive(now)
                else:
                    row["state"] = "scheduled"
                    row["reason_code"] = "supervisor_restart"
                    row["next_action_at"] = campaigns.utc_naive(
                        campaigns.retry_next_action(now, schedule, count))
            elif row["state"] == "pausing":
                row["state"] = "paused"
                row["auto_resume"] = row["pause_reason"] != "operator_requested"
                row["next_action_at"] = (
                    campaigns.utc_naive(campaigns.next_window_open(now, schedule))
                    if row["auto_resume"] else None)
            else:
                row["state"] = "cancelled"
                row["reason_code"] = "operator_cancelled"
                row["active_key"] = None
                row["ended_at"] = campaigns.utc_naive(now)
            row["usage"] = usage
            row["lease_holder"] = None
            row["lease_expires_at"] = None
            row["operations"] = campaigns.append_operation(
                row.get("operations"), event=("campaign_retry_exhausted"
                                              if row["state"] == "failed"
                                              else "campaign_recovered"),
                campaign_id=row["id"], from_state=previous,
                to_state=row["state"], reason_code=row.get("reason_code", ""),
                now=now)
            self.events.append(("campaign_recovered", row["id"], previous))
            recovered.append(row["id"])
        return recovered


class FakeEngine:
    def __init__(self, *, start_result=None, restore_result=None):
        self.start_result = start_result or {"status": "started"}
        self.restore_result = restore_result or {"status": "restored"}
        self.calls = []
        self.stop_requested = False
        self.status = {
            "run_id": "run-1", "run_state": "planning", "active": False,
            "reason_code": "", "reason": "", "steps_taken": 0, "max_steps": 12,
            "successful_steps": 0, "model_calls": 0, "remaining_steps": 12,
            "remaining_model_calls": 20, "auth_revision": 4, "worker_epoch": 2,
            "stop_requested": False, "pause_requested": False,
            "completed_observations": [],
        }

    def get_status(self, session_id):
        return copy.deepcopy(self.status)

    async def start(self, **kwargs):
        self.calls.append(("start", kwargs))
        if self.start_result.get("status") == "started":
            self.status.update(active=True, run_state="planning")
        else:
            self.status.update(active=False, run_state="blocked",
                               reason_code=self.start_result.get("reason_code", "worker_unavailable"))
        return copy.deepcopy(self.start_result)

    async def restore(self, **kwargs):
        self.calls.append(("restore", kwargs))
        if self.restore_result.get("status") == "restored":
            self.status.update(active=True, run_state="planning")
        return copy.deepcopy(self.restore_result)

    async def request_graceful_stop(self, session_id, user_id=""):
        self.calls.append(("graceful", session_id))
        self.status["stop_requested"] = True
        return {"status": "pause_pending"}

    async def request_stop(self, session_id, user_id=""):
        self.calls.append(("stop", session_id))
        self.status.update(active=False, run_state="blocked", reason_code="cancelled")
        return {"status": "stopped"}

    async def detach_session(self, session_id):
        self.calls.append(("detach", session_id))
        self.status.update(active=False)


def context_for(row, **overrides):
    context = {
        "owner_id": row["owner_id"], "scope_digest": row["scope_digest"],
        "auth_revision": 4, "worker_epoch": 2, "worker_blocked": False,
        "scope": {"targets": [row["target"]]}, "target": row["target"],
    }
    context.update(overrides)
    return context


class CampaignScheduleTests(unittest.IsolatedAsyncioTestCase):
    def test_timezone_and_dst_window_boundaries(self):
        schedule = CampaignSchedule(
            timezone="America/New_York", weekdays=[0, 1, 2, 3, 4],
            window_start="09:00", window_end="17:00")
        # Monday 2026-01-12 is EST (UTC-5): 14:00 UTC is 09:00 local.
        self.assertFalse(within_window(
            datetime(2026, 1, 12, 13, 59, tzinfo=UTC), schedule))
        self.assertTrue(within_window(
            datetime(2026, 1, 12, 14, 0, tzinfo=UTC), schedule))
        # Spring forward 2026-03-08: Monday 2026-03-09 is EDT (UTC-4).
        self.assertFalse(within_window(
            datetime(2026, 3, 9, 12, 59, tzinfo=UTC), schedule))
        self.assertTrue(within_window(
            datetime(2026, 3, 9, 13, 0, tzinfo=UTC), schedule))
        # Fall back 2026-11-01: Monday 2026-11-02 is EST again.
        self.assertFalse(within_window(
            datetime(2026, 11, 2, 13, 59, tzinfo=UTC), schedule))
        self.assertTrue(within_window(
            datetime(2026, 11, 2, 14, 0, tzinfo=UTC), schedule))

    def test_next_window_open_skips_closed_weekdays(self):
        schedule = CampaignSchedule(
            timezone="America/New_York", weekdays=[0, 1, 2, 3, 4],
            window_start="09:00", window_end="17:00")
        # Friday after close -> Monday 09:00 EST = 14:00 UTC.
        friday = datetime(2026, 11, 13, 22, 0, tzinfo=UTC)
        self.assertEqual(next_window_open(friday, schedule),
                         datetime(2026, 11, 16, 14, 0, tzinfo=UTC))
        # Saturday -> Monday.
        saturday = datetime(2026, 11, 14, 15, 0, tzinfo=UTC)
        self.assertEqual(next_window_open(saturday, schedule),
                         datetime(2026, 11, 16, 14, 0, tzinfo=UTC))
        # Inside a window the current instant is returned.
        monday = datetime(2026, 11, 16, 15, 0, tzinfo=UTC)
        self.assertEqual(next_window_open(monday, schedule), monday)

    def test_schedule_rejects_unsafe_configuration(self):
        with self.assertRaises(ValueError):
            CampaignSchedule(timezone="UTC", weekdays=[5, 6],
                             window_start="09:00", window_end="17:00")
        with self.assertRaises(ValueError):
            CampaignSchedule(timezone="UTC", weekdays=[0],
                             window_start="17:00", window_end="09:00")
        with self.assertRaises(ValueError):
            CampaignSchedule(timezone="Not/AZone", weekdays=[0])
        with self.assertRaises(ValueError):
            CampaignSchedule(timezone="UTC", weekdays=[0, 1, 2, 3, 4, 5])
        with self.assertRaises(ValueError):
            CampaignSchedule(timezone="UTC", weekdays=[0],
                             daily_runtime_seconds=28801)

    def test_runtime_and_budget_helpers(self):
        schedule = CampaignSchedule(timezone="Asia/Tokyo", weekdays=[0, 1, 2, 3, 4])
        usage = campaigns.validate_usage({})
        usage = campaigns.validate_usage(
            campaigns.set_active_since(usage, MONDAY))
        usage = campaigns.accumulate_runtime(
            usage, MONDAY + timedelta(seconds=10), schedule, cap_seconds=60)
        day = campaigns.local_day_key(MONDAY, schedule)
        self.assertEqual(usage["runtime_seconds"], 10)
        self.assertEqual(usage["daily"][day], 10)
        # A clock jump cannot exhaust the daily allowance.
        usage = campaigns.accumulate_runtime(
            usage, MONDAY + timedelta(days=1), schedule, cap_seconds=60)
        self.assertEqual(usage["runtime_seconds"], 70)

        budget = campaigns.validate_budget({"max_tokens": 100,
                                            "max_cost_microusd": 1000})
        reserved = evaluate_campaign_reservation(
            campaigns.validate_usage({}), budget, tokens=60, cost_microusd=500)
        self.assertEqual(reserved["reserved_tokens"], 60)
        checked = evaluate_campaign_reservation(
            reserved, budget, tokens=40, cost_microusd=500, check_only=True)
        self.assertEqual(checked["reserved_tokens"], 60)
        with self.assertRaises(CampaignBudgetError) as error:
            evaluate_campaign_reservation(
                reserved, budget, tokens=41, cost_microusd=1)
        self.assertEqual(error.exception.code, "campaign_budget_exhausted")
        with self.assertRaises(CampaignBudgetError):
            evaluate_campaign_reservation(
                {**reserved, "stopped": True}, budget, tokens=0, cost_microusd=0)
        with self.assertRaises(campaigns.CampaignValidationError):
            campaigns.validate_usage({"reserved_tokens": -1})

    def test_campaign_status_exposes_supervisor_state(self):
        row = {
            "id": "c1", "session_id": SESSION, "owner_id": OWNER,
            "state": "paused", "goal": "discovery", "target": "192.0.2.10",
            "skill_level": "expert", "max_steps": 12,
            "auto_risk_threshold": "green_orange", "has_started": True,
            "auto_resume": True, "run_id": "run-1",
            "pause_reason": "schedule_window_closed", "reason_code": "paused",
            "reason": "", "created_at": MONDAY, "updated_at": MONDAY,
            "started_at": MONDAY, "ended_at": None, "lease_holder": "x",
            "lease_expires_at": MONDAY, "last_heartbeat_at": MONDAY,
            "next_action_at": MONDAY + timedelta(days=1),
            "schedule": CampaignSchedule(timezone="UTC", weekdays=[0, 1, 2, 3, 4],
                                         daily_runtime_seconds=60).model_dump(),
            "budget": {"max_tokens": 10, "max_cost_microusd": 20},
            "usage": {"reserved_tokens": 4, "reserved_cost_microusd": 5},
            "retry": {"count": 1, "max": 2, "last_reason": "worker_timeout"},
        }
        result = campaign_status(row, MONDAY)
        self.assertFalse(result.get("invalid", False))
        self.assertEqual(result["budget"]["remaining_tokens"], 6)
        self.assertEqual(result["budget"]["remaining_cost_microusd"], 15)
        self.assertEqual(result["retry"]["count"], 1)
        self.assertTrue(result["schedule"]["within_window"])
        self.assertIn("last_heartbeat_at", result["supervisor"])
        self.assertEqual(result["next_execution_at"],
                         campaigns.utc_aware(row["next_action_at"]).isoformat())


class CampaignSupervisorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.now = MONDAY + timedelta(hours=1)
        self.store = MemoryCampaignStore(clock=lambda: self.now)
        self.engine = FakeEngine()
        self.context = None
        self.context_error = None
        self.worker_resume = AsyncMock()
        self.supervisor = CampaignSupervisor(
            store=self.store, engine=self.engine,
            context_loader=self._context,
            capabilities=AsyncMock(return_value={"tools": ["curl", "nmap"]}),
            planner_preflight=AsyncMock(return_value={"ready": True}),
            worker_resume=self.worker_resume,
            clock=lambda: self.now,
        )

    async def _context(self, owner_id, session_id):
        row = await self.store.latest_for_session(session_id)
        if self.context_error is not None:
            raise self.context_error
        if self.context is not None:
            return self.context
        return context_for(row)

    async def _create(self):
        row = await self.store.create(make_spec())
        row["next_action_at"] = campaigns.utc_naive(self.now)
        self.store.rows[row["id"]] = row
        return row

    async def test_start_inside_window_binds_budget_and_runs(self):
        row = await self._create()
        await self.supervisor.tick(self.now)
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "running")
        self.assertTrue(current["has_started"])
        self.assertEqual(current["run_id"], "run-1")
        self.assertIsNotNone(current["usage"]["active_since"])
        self.assertEqual(self.store.bound[SESSION], row["id"])
        start_calls = [call for call in self.engine.calls if call[0] == "start"]
        self.assertEqual(len(start_calls), 1)
        self.assertEqual(start_calls[0][1]["max_steps"], 12)
        self.assertEqual(start_calls[0][1]["campaign_supervisor_token"],
                         self.supervisor._token)
        self.assertTrue(self.worker_resume.await_count >= 1)
        self.assertTrue(any(event[0] == "campaign_started"
                            for event in self.store.events))

    async def test_durable_progress_clears_retry_streak(self):
        row = await self._create()
        await self.supervisor.tick(self.now)
        running = await self.store.get(row["id"])
        running["retry"] = campaigns.retry_state(2, 2, "supervisor_restart")
        self.store.rows[row["id"]] = running
        self.engine.status.update(steps_taken=3, successful_steps=2)
        await self.supervisor.tick(self.now + timedelta(seconds=5))
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "running")
        self.assertEqual(current["usage"]["last_successful_steps"], 2)
        self.assertEqual(current["retry"]["count"], 0)
        self.assertEqual(current["retry"]["max"], 2)
        self.assertTrue(any(event["event"] == "campaign_step_succeeded"
                            for event in current["operations"]["events"]))

    async def test_outside_window_only_reschedules(self):
        self.now = MONDAY.replace(hour=8)
        row = await self._create()
        await self.supervisor.tick(self.now)
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "scheduled")
        self.assertEqual(current["next_action_at"],
                         campaigns.utc_naive(MONDAY))
        self.assertFalse(any(call[0] == "start" for call in self.engine.calls))

    async def test_daily_runtime_limit_pauses_until_next_day(self):
        row = await self._create()
        day = campaigns.local_day_key(self.now, make_spec().schedule)
        row["usage"] = campaigns.validate_usage(
            {"daily": {day: 28800}, "runtime_seconds": 28800})
        self.store.rows[row["id"]] = row
        await self.supervisor.tick(self.now)
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "paused")
        self.assertTrue(current["auto_resume"])
        self.assertEqual(current["pause_reason"], "daily_runtime_exhausted")
        self.assertEqual(current["next_action_at"],
                         campaigns.utc_naive(MONDAY + timedelta(days=1)))
        self.assertFalse(any(call[0] == "start" for call in self.engine.calls))

    async def test_operator_pause_is_graceful_and_resume_restores(self):
        row = await self._create()
        await self.supervisor.tick(self.now)
        await self.supervisor.pause(row["id"], OWNER)
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "pausing")
        self.assertEqual(current["pause_reason"], "operator_requested")
        self.assertFalse(current["auto_resume"])

        await self.supervisor.tick(self.now + timedelta(seconds=5))
        self.assertTrue(any(call[0] == "graceful" for call in self.engine.calls))
        self.assertEqual((await self.store.get(row["id"]))["state"], "pausing")

        self.engine.status.update(active=False, run_state="blocked",
                                  reason_code="run_interrupted",
                                  stop_requested=True)
        await self.supervisor.tick(self.now + timedelta(seconds=10))
        paused = await self.store.get(row["id"])
        self.assertEqual(paused["state"], "paused")
        self.assertFalse(paused["auto_resume"])
        self.assertIsNone(paused["next_action_at"])
        self.assertNotIn(SESSION, self.store.bound)

        await self.supervisor.resume(row["id"], OWNER)
        resumed = await self.store.get(row["id"])
        self.assertEqual(resumed["state"], "scheduled")
        self.assertEqual(resumed["retry"]["count"], 0)
        await self.supervisor.tick(self.now + timedelta(seconds=15))
        self.assertEqual((await self.store.get(row["id"]))["state"], "running")
        restore_calls = [call for call in self.engine.calls
                         if call[0] == "restore"]
        self.assertTrue(restore_calls)
        self.assertEqual(restore_calls[-1][1]["campaign_supervisor_token"],
                         self.supervisor._token)
        self.assertEqual(len([call for call in self.engine.calls
                              if call[0] == "start"]), 1)

    async def test_operator_cancel_fences_and_is_terminal(self):
        row = await self._create()
        await self.supervisor.tick(self.now)
        await self.supervisor.cancel(row["id"], OWNER)
        self.assertEqual((await self.store.get(row["id"]))["state"], "cancelling")
        self.engine.status.update(active=True)
        await self.supervisor.tick(self.now + timedelta(seconds=5))
        cancelled = await self.store.get(row["id"])
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertIsNone(cancelled["active_key"])
        self.assertTrue(any(call[0] == "stop" for call in self.engine.calls))
        self.assertEqual(await self.store.due(self.now + timedelta(days=1)), [])

    async def test_authorization_expiry_fails_closed_before_start(self):
        row = await self._create()
        self.context_error = HTTPException(403, "Engagement access denied")
        await self.supervisor.tick(self.now)
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "failed")
        self.assertEqual(current["reason_code"], "authorization_expired")
        self.assertFalse(any(call[0] == "start" for call in self.engine.calls))

    async def test_scope_change_stops_a_running_campaign(self):
        row = await self._create()
        await self.supervisor.tick(self.now)
        self.context = context_for(row, scope_digest="b" * 64)
        await self.supervisor.tick(self.now + timedelta(seconds=5))
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "failed")
        self.assertEqual(current["reason_code"], "scope_changed")
        self.assertTrue(any(call[0] == "stop" for call in self.engine.calls))

    async def test_uncertain_checkpoint_is_not_retried(self):
        row = await self._create()
        row["has_started"] = True
        self.store.rows[row["id"]] = row
        self.engine.restore_result = {
            "status": "rejected", "reason_code": "checkpoint_state",
            "reason": "Execution state is uncertain; operator review required.",
        }
        await self.supervisor.tick(self.now)
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "failed")
        self.assertEqual(current["reason_code"], "checkpoint_state")
        self.assertEqual(current["retry"]["count"], 0)
        self.assertEqual(await self.store.due(self.now + timedelta(days=1)), [])

    async def test_retry_backoff_and_exhaustion(self):
        row = await self._create()
        self.engine.start_result = {"status": "started"}
        self.engine.status.update(active=False, run_state="blocked",
                                  reason_code="worker_unavailable")
        # FakeEngine.start sets active True for "started"; force a failed run end.
        async def start_then_fail(**kwargs):
            self.engine.calls.append(("start", kwargs))
            self.engine.status.update(active=False, run_state="blocked",
                                      reason_code="worker_unavailable")
            return {"status": "started"}
        self.engine.start = start_then_fail
        await self.supervisor.tick(self.now)
        first = await self.store.get(row["id"])
        self.assertEqual(first["state"], "scheduled")
        self.assertEqual(first["retry"]["count"], 1)
        self.assertEqual(first["next_action_at"],
                         campaigns.utc_naive(
                             self.now + timedelta(seconds=retry_delay_seconds(1))))

        second_now = first["next_action_at"].replace(tzinfo=UTC)
        self.now = second_now
        await self.supervisor.tick(self.now)
        second = await self.store.get(row["id"])
        self.assertEqual(second["retry"]["count"], 2)
        self.now = second["next_action_at"].replace(tzinfo=UTC)
        await self.supervisor.tick(self.now)
        exhausted = await self.store.get(row["id"])
        self.assertEqual(exhausted["state"], "failed")
        self.assertEqual(exhausted["reason_code"], "retry_exhausted")
        self.assertIn("worker_unavailable", exhausted["reason"])
        self.assertEqual(len([call for call in self.engine.calls
                              if call[0] == "start"]), 3)

    async def test_budget_exhaustion_stops_before_any_worker_call(self):
        row = await self._create()
        row["usage"] = campaigns.validate_usage(
            {"reserved_tokens": 200000, "reserved_cost_microusd": 1})
        self.store.rows[row["id"]] = row
        await self.supervisor.tick(self.now)
        current = await self.store.get(row["id"])
        self.assertEqual(current["state"], "failed")
        self.assertEqual(current["reason_code"], "campaign_budget_exhausted")
        self.assertFalse(self.engine.calls)
        self.assertFalse(self.supervisor.capabilities.await_count)

    async def test_duplicate_active_campaign_is_rejected(self):
        await self._create()
        with self.assertRaises(CampaignConflict):
            await self.store.create(make_spec())
        row = await self.store.latest_active_for_session(SESSION)
        await self.store.transition(
            row["id"], self.supervisor._token, self.now, campaigns.LIVE_STATES,
            {"state": "cancelled"}, require_lease=False)
        second = await self.store.create(make_spec())
        self.assertNotEqual(second["id"], row["id"])

    async def test_lease_prevents_duplicate_supervisor_work(self):
        row = await self._create()
        claimed = await self.store.claim(row["id"], "other-supervisor", self.now,
                                         settings.CAMPAIGN_LEASE_SECONDS)
        self.assertIsNotNone(claimed)
        await self.supervisor.tick(self.now)
        self.assertFalse(any(call[0] == "start" for call in self.engine.calls))
        await self.store.release(row["id"], "other-supervisor")
        await self.supervisor.tick(self.now)
        self.assertEqual((await self.store.get(row["id"]))["state"], "running")

    async def test_recovery_never_restarts_immediately(self):
        row = await self._create()
        row.update(state="running", has_started=True, run_id="run-1",
                   lease_holder="dead-process",
                   lease_expires_at=campaigns.utc_naive(self.now - timedelta(seconds=1)),
                   usage=campaigns.validate_usage(
                       {**campaigns.validate_usage(row["usage"]),
                        "active_since": self.now.isoformat()}))
        self.store.rows[row["id"]] = row
        await self.supervisor.recover(self.now)
        recovered = await self.store.get(row["id"])
        self.assertEqual(recovered["state"], "scheduled")
        self.assertEqual(recovered["retry"]["count"], 1)
        self.assertEqual(recovered["reason_code"], "supervisor_restart")
        self.assertIsNone(recovered["usage"]["active_since"])
        self.assertGreater(recovered["next_action_at"],
                           campaigns.utc_naive(self.now))
        self.assertFalse(any(call[0] == "restore" for call in self.engine.calls))

    async def test_recovery_confirms_cancelled_and_paused_states(self):
        paused = await self.store.create(make_spec(session_id="session-2"))
        self.store.rows[paused["id"]].update(
            state="pausing", pause_reason="operator_requested",
            lease_holder="dead", active_key="session-2")
        cancelled = await self.store.create(make_spec(session_id="session-3"))
        self.store.rows[cancelled["id"]].update(
            state="cancelling", lease_holder="dead", active_key="session-3")
        await self.supervisor.recover(self.now)
        self.assertEqual((await self.store.get(paused["id"]))["state"], "paused")
        self.assertEqual((await self.store.get(cancelled["id"]))["state"],
                         "cancelled")


class CampaignEnginePauseTests(unittest.IsolatedAsyncioTestCase):
    async def test_graceful_stop_does_not_fence_worker_jobs(self):
        engine = AutonomousEngine()
        state = SessionRunState(session_id=SESSION, user_id=OWNER,
                                owner_id=OWNER, goal="discovery",
                                target="192.0.2.10", skill_level="expert")
        engine._runs[SESSION] = state
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value={"owner_id": OWNER})), \
             patch.object(engine, "_persist", AsyncMock()) as persist, \
             patch("agents.autonomous_engine.worker_jobs.cancel_session",
                   AsyncMock()) as fence:
            result = await engine.request_graceful_stop(SESSION, OWNER)
        self.assertEqual(result["status"], "pause_pending")
        self.assertTrue(state.pause_requested)
        self.assertTrue(state.stop_requested)
        persist.assert_awaited_once()
        fence.assert_not_awaited()

    async def test_graceful_stop_status_is_observable(self):
        engine = AutonomousEngine()
        state = SessionRunState(session_id=SESSION, user_id=OWNER,
                                owner_id=OWNER, goal="discovery",
                                target="192.0.2.10", skill_level="expert")
        state.pause_requested = True
        engine._runs[SESSION] = state
        self.assertTrue(engine.get_status(SESSION)["pause_requested"])


class CampaignApiTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    def _owner(self):
        return TokenData(user_id="owner", username="owner", role="pentester",
                         skill_level="expert")

    def _session(self):
        return {"session_id": "engagement", "target": "192.0.2.1",
                "user_id": "owner", "scope": {"targets": ["192.0.2.1"]}}

    async def test_campaign_routes_are_owner_only(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        routes = [("POST", "campaign/start", {}), ("GET", "campaign", None),
                  ("POST", "campaign/pause", {}), ("POST", "campaign/resume", {}),
                  ("POST", "campaign/cancel", {})]
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value={**self._session(), "user_id": "another"})):
            for method, path, body in routes:
                with self.subTest(path=path):
                    response = await self.client.request(
                        method, "/api/pentest/engagement/" + path, json=body)
                    self.assertEqual(response.status_code, 403)

    async def test_admin_cannot_manage_another_owners_campaign(self):
        admin = TokenData(user_id="admin", username="admin", role="admin",
                          skill_level="expert")
        app.dependency_overrides[get_current_user] = lambda: admin
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())):
            response = await self.client.get("/api/pentest/engagement/campaign")
            self.assertEqual(response.status_code, 403)

    async def test_owner_start_contract_uses_campaign_defaults(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        context = {"owner_id": "owner", "scope_digest": DIGEST,
                   "auth_revision": 2, "worker_epoch": 0,
                   "scope": {"targets": ["192.0.2.1"]}, "target": "192.0.2.1"}
        created = {"campaign_id": "c1", "state": "scheduled"}
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())), \
             patch("api.routers.pentest.authoritative_context",
                   AsyncMock(return_value=context)), \
             patch("api.routers.pentest.get_skill_level_from_db",
                   AsyncMock(return_value="expert")), \
             patch("api.routers.pentest.campaign_supervisor.create",
                   AsyncMock(return_value=created)) as create:
            response = await self.client.post(
                "/api/pentest/engagement/campaign/start",
                json={"goal": "http_check", "weekdays": [0, 1],
                      "window_start": "10:00", "window_end": "11:00",
                      "daily_runtime_seconds": 3600})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), created)
        spec = create.await_args.args[0]
        self.assertEqual(spec.owner_id, "owner")
        self.assertEqual(spec.goal, "http_check")
        self.assertEqual(spec.schedule.weekdays, [0, 1])
        self.assertEqual(spec.required_tools, ["curl"])
        self.assertEqual(spec.scope_digest, DIGEST)

    async def test_campaign_start_rejects_an_unsafe_window(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        context = {"owner_id": "owner", "scope_digest": DIGEST,
                   "auth_revision": 2, "worker_epoch": 0,
                   "scope": {"targets": ["192.0.2.1"]}, "target": "192.0.2.1"}
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())), \
             patch("api.routers.pentest.authoritative_context",
                   AsyncMock(return_value=context)), \
             patch("api.routers.pentest.get_skill_level_from_db",
                   AsyncMock(return_value="expert")), \
             patch("api.routers.pentest.campaign_supervisor.create",
                   AsyncMock()) as create:
            response = await self.client.post(
                "/api/pentest/engagement/campaign/start",
                json={"goal": "discovery", "weekdays": [5, 6],
                      "window_start": "17:00", "window_end": "09:00"})
        self.assertEqual(response.status_code, 400)
        create.assert_not_awaited()

    async def test_autonomous_start_is_blocked_while_campaign_active(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())), \
             patch("memory.campaign_store.campaign_store.latest_active_for_session",
                   AsyncMock(return_value={"id": "c1"})), \
             patch("api.routers.pentest.autonomous_engine.start",
                   AsyncMock()) as start:
            response = await self.client.post(
                "/api/pentest/engagement/autonomous/start", json={})
        self.assertEqual(response.status_code, 409)
        start.assert_not_awaited()
