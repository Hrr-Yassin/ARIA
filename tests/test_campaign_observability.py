"""SPEC-14 observability, fail-closed accounting and monitoring privacy (offline)."""
import copy
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from api.auth import TokenData, get_current_user
from api.main import app
from config.settings import settings
from memory import campaign_store as campaigns
from memory.campaign_observability import (
    ALERT_CODES, EVENT_TYPES, MAX_EVENTS, CampaignMonitor,
    accounting_inconsistencies, append_operation, build_campaign_health,
    correlation_scope, current_correlation_id, operations_summary,
    operations_view, sanitize_operations,
)
from memory.campaign_store import (
    CampaignBudgetError, CampaignSchedule, apply_settlement,
    evaluate_campaign_reservation,
)
from orchestrator.campaign_supervisor import CampaignSupervisor
from tests.support import OfflineCase
from tests.test_campaigns import FakeEngine, MemoryCampaignStore, make_spec

UTC = timezone.utc
OWNER = "owner"
SESSION = "engagement"
NOW = datetime(2026, 11, 12, 10, 0, tzinfo=UTC)  # Thursday, inside 09:00-17:00


def _schedule(**overrides):
    values = dict(timezone="UTC", weekdays=[0, 1, 2, 3, 4],
                  window_start="09:00", window_end="17:00",
                  daily_runtime_seconds=28800)
    values.update(overrides)
    return CampaignSchedule(**values)


def _usage(**overrides):
    return campaigns.validate_usage(overrides)


def _row(**overrides):
    schedule = _schedule()
    operations = append_operation(
        None, event="campaign_created", campaign_id="c1",
        to_state="scheduled", reason_code="scheduled", now=NOW - timedelta(hours=1))
    operations = append_operation(
        operations, event="campaign_step_succeeded", campaign_id="c1",
        to_state="running", reason_code="step_succeeded", now=NOW - timedelta(minutes=1),
        message="Run advanced to 2 successful step(s).",
        attributes={"step": 3, "successful_steps": 2, "model_calls": 4})
    row = {
        "id": "c1", "session_id": SESSION, "owner_id": OWNER,
        "state": "running", "goal": "discovery", "target": "192.0.2.10",
        "skill_level": "expert", "max_steps": 12,
        "auto_risk_threshold": "green_orange", "has_started": True,
        "auto_resume": False, "run_id": "run-1", "pause_reason": "",
        "reason_code": "", "reason": "",
        "created_at": NOW - timedelta(hours=2), "updated_at": NOW - timedelta(seconds=5),
        "started_at": NOW - timedelta(minutes=10), "ended_at": None,
        "schedule": schedule.model_dump(),
        "budget": campaigns.default_budget(),
        "usage": _usage(last_steps=3, last_successful_steps=2, last_model_calls=4),
        "retry": {"count": 0, "max": 3, "last_reason": ""},
        "lease_holder": "supervisor-lease",
        "lease_expires_at": NOW + timedelta(seconds=30),
        "last_heartbeat_at": NOW - timedelta(seconds=5),
        "next_action_at": NOW,
        "operations": operations,
    }
    row.update(overrides)
    return row


def _run_status(**overrides):
    status = {
        "run_id": "run-1", "run_state": "planning", "active": True,
        "reason_code": "", "reason": "", "steps_taken": 3, "max_steps": 12,
        "successful_steps": 2, "model_calls": 4, "remaining_steps": 9,
        "remaining_model_calls": 16, "waiting_approval": False,
        "pending_action_id": "", "current_phase": "recon",
        "specialist_investigation_ids": ["task-1"],
        "completed_observations": [],
    }
    status.update(overrides)
    return status


def _alerts(health):
    return {alert["code"]: alert["severity"] for alert in health["alerts"]}


class CampaignHealthTests(OfflineCase):
    async def test_health_reports_state_progress_heartbeat_and_pending_work(self):
        health = build_campaign_health(
            _row(), NOW, run_status=_run_status(),
            worker_summary={"counts": {"queued": 1, "running": 1,
                                       "succeeded": 2}},
            specialist_summary={"counts": {"running": 1}},
            model_summary={
                "usage": {"calls": 2, "reserved_tokens": 1000,
                          "reserved_cost_microusd": 50,
                          "reported_tokens": 400,
                          "reported_cost_microusd": 20},
                "task_ledgers": 1})
        self.assertEqual(health["schema"], "aria.campaign.health.v1")
        self.assertEqual(health["state"], "running")
        self.assertFalse(health["terminal"])
        self.assertEqual(health["progress"]["steps_taken"], 3)
        self.assertEqual(health["progress"]["successful_steps"], 2)
        self.assertEqual(health["progress"]["remaining_steps"], 9)
        self.assertEqual(health["progress"]["last_successful_action"]["step"], 3)
        self.assertEqual(health["progress"]["last_successful_action"]["event"],
                         "campaign_step_succeeded")
        self.assertEqual(health["heartbeat"]["age_seconds"], 5)
        self.assertTrue(health["heartbeat"]["lease_held"])
        self.assertFalse(health["heartbeat"]["stale"])
        self.assertEqual(health["budget"]["reserved_tokens"], 0)
        self.assertEqual(health["budget"]["reported_tokens"], 0)
        self.assertEqual(health["metrics"]["worker_active"], 2)
        self.assertEqual(health["metrics"]["specialist_active"], 1)
        self.assertEqual(health["metrics"]["llm"]["reserved_tokens"], 1000)
        self.assertEqual(health["pending_work"]["next_scheduled_action"],
                         health["next_execution_at"])
        self.assertTrue(health["accounting"]["consistent"])
        self.assertNotIn("critical", _alerts(health).values())
        self.assertNotIn("executed_commands", health["run"])
        self.assertNotIn("executed_command_hashes", health["run"])

    async def test_health_detects_stalled_heartbeat_lease_and_repeated_failures(self):
        stale = _row(
            last_heartbeat_at=NOW - timedelta(seconds=600),
            lease_expires_at=NOW - timedelta(seconds=30),
            updated_at=NOW - timedelta(hours=2),
            retry={"count": 3, "max": 3, "last_reason": "worker_unavailable"},
            operations=append_operation(
                None, event="campaign_retry_scheduled", campaign_id="c1",
                now=NOW - timedelta(hours=2)))
        health = build_campaign_health(stale, NOW, run_status=_run_status())
        alerts = _alerts(health)
        self.assertEqual(alerts["heartbeat_stale"], "critical")
        self.assertEqual(alerts["lease_expired"], "critical")
        self.assertEqual(alerts["progress_stalled"], "warning")
        self.assertEqual(alerts["repeated_failures"], "warning")
        self.assertTrue(health["heartbeat"]["lease_expired"])
        self.assertIsNotNone(health["heartbeat"]["age_seconds"])

        missing = _row(state="starting", last_heartbeat_at=None,
                       lease_holder=None, lease_expires_at=None)
        missing_health = build_campaign_health(missing, NOW, run_status=None)
        self.assertEqual(_alerts(missing_health)["heartbeat_missing"], "critical")

    async def test_waiting_approval_is_pending_work_not_a_stall(self):
        row = _row(updated_at=NOW - timedelta(hours=2),
                   operations=append_operation(
                       None, event="campaign_created", now=NOW - timedelta(hours=2)))
        health = build_campaign_health(
            row, NOW, run_status=_run_status(waiting_approval=True,
                                             pending_action_id="action-7"))
        alerts = _alerts(health)
        self.assertNotIn("progress_stalled", alerts)
        self.assertTrue(health["pending_work"]["waiting_approval"])
        self.assertEqual(health["pending_work"]["pending_action_id"], "action-7")

    async def test_health_surfaces_budget_and_daily_runtime_exhaustion(self):
        schedule = _schedule()
        usage = _usage(
            reserved_tokens=200000, reserved_cost_microusd=2000000,
            daily={NOW.date().isoformat(): 28800},
            last_steps=4, last_successful_steps=1)
        health = build_campaign_health(
            _row(schedule=schedule.model_dump(), usage=usage,
                 budget={"max_tokens": 200000, "max_cost_microusd": 2000000}),
            NOW, run_status=_run_status())
        alerts = _alerts(health)
        self.assertEqual(alerts["budget_exhausted"], "critical")
        self.assertEqual(alerts["daily_runtime_exhausted"], "info")
        self.assertEqual(health["budget"]["remaining_tokens"], 0)

    async def test_health_detects_unknown_usage_and_stopped_accounting(self):
        usage = _usage(reserved_tokens=100, reported_tokens=80,
                       unknown_usage_calls=2, stopped=True,
                       stop_reason="unknown_usage")
        health = build_campaign_health(
            _row(usage=usage,
                 budget={"max_tokens": 200000, "max_cost_microusd": 2000000}),
            NOW, run_status=_run_status())
        alerts = _alerts(health)
        self.assertEqual(alerts["unknown_provider_usage"], "critical")
        self.assertEqual(alerts["accounting_stopped"], "critical")
        self.assertTrue(health["accounting"]["consistent"])
        self.assertEqual(health["accounting"]["stop_reason"], "unknown_usage")
        with self.assertRaises(CampaignBudgetError) as error:
            evaluate_campaign_reservation(
                usage, {"max_tokens": 200000, "max_cost_microusd": 2000000},
                tokens=10, cost_microusd=1)
        self.assertEqual(error.exception.code, "campaign_accounting_inconsistent")

    async def test_inconsistent_accounting_is_detected_and_denies_reservation(self):
        usage = _usage(reserved_tokens=100, reported_tokens=120)
        self.assertTrue(accounting_inconsistencies(usage))
        health = build_campaign_health(_row(usage=usage), NOW,
                                       run_status=_run_status())
        self.assertEqual(_alerts(health)["accounting_inconsistent"], "critical")
        self.assertFalse(health["accounting"]["consistent"])
        with self.assertRaises(CampaignBudgetError) as error:
            evaluate_campaign_reservation(
                usage, {"max_tokens": 200000, "max_cost_microusd": 2000000},
                tokens=1, cost_microusd=0)
        self.assertEqual(error.exception.code, "campaign_accounting_inconsistent")

    async def test_health_tolerates_corrupt_state_and_missing_subsystems(self):
        row = _row(usage={"reserved_tokens": "not-an-integer"},
                   operations="not-a-ring")
        health = build_campaign_health(
            row, NOW, worker_summary={"available": False},
            specialist_summary={"available": False},
            model_summary={"available": False, "invalid": True})
        alerts = _alerts(health)
        self.assertEqual(alerts["invalid_durable_state"], "critical")
        self.assertEqual(alerts["operations_invalid"], "warning")
        self.assertEqual(alerts["worker_unavailable"], "warning")
        self.assertEqual(alerts["model_usage_invalid"], "warning")
        self.assertFalse(health["accounting"]["consistent"])
        self.assertEqual(health["metrics"]["llm"]["calls"], 0)
        self.assertEqual(health["progress"]["steps_taken"], 0)

    async def test_crash_recovery_health_uses_checkpoint_without_replay(self):
        snapshot = {
            "active": False, "waiting_approval": False,
            "checkpoint": {
                "run_id": "run-1", "run_state": "blocked",
                "active": False, "reason_code": "restart_reconciliation",
                "reason": "Server restarted; no command was replayed.",
                "steps_taken": 5, "max_steps": 12, "successful_steps": 3,
                "model_calls": 6, "current_phase": "recon",
                "specialist_investigation_ids": ["task-1"],
            },
            "executed_commands": ["curl http://user:secret@192.0.2.10"],
            "executed_command_hashes": ["deadbeef"],
        }
        row = _row(
            state="scheduled", run_id="run-1", has_started=True,
            lease_holder=None, lease_expires_at=None,
            reason_code="supervisor_restart",
            reason="Supervisor restarted while the campaign was live.",
            retry={"count": 1, "max": 3, "last_reason": "supervisor_restart"},
            next_action_at=NOW + timedelta(minutes=5),
            operations=append_operation(
                None, event="campaign_recovered", campaign_id="c1",
                from_state="running", to_state="scheduled",
                reason_code="supervisor_restart",
                message="Supervisor restarted while the campaign was live.",
                attributes={"retry_count": 1}, now=NOW - timedelta(minutes=1)))
        health = build_campaign_health(row, NOW, checkpoint=snapshot)
        self.assertEqual(health["run"]["source"], "durable_checkpoint")
        self.assertEqual(health["run"]["steps_taken"], 5)
        self.assertEqual(health["progress"]["successful_steps"], 3)
        self.assertEqual(health["failures"]["count"], 1)
        self.assertFalse(health["failures"]["repeated"])
        self.assertEqual(health["operations"]["retained"], 1)
        self.assertNotIn("progress_stalled", _alerts(health))
        self.assertNotIn("executed_commands", health["run"])
        self.assertNotIn("executed_command_hashes", health["run"])
        self.assertEqual(health["next_execution_at"],
                         (NOW + timedelta(minutes=5)).isoformat())

    async def test_monitoring_is_read_only(self):
        row = _row()
        before = copy.deepcopy(row)
        build_campaign_health(row, NOW, run_status=_run_status(),
                              worker_summary={"counts": {"running": 1}},
                              specialist_summary={"counts": {"running": 1}},
                              model_summary={"usage": {}})
        self.assertEqual(row, before)


class AccountingSettlementTests(OfflineCase):
    def test_failed_unknown_usage_is_counted_without_stopping(self):
        usage = apply_settlement(
            _usage(), reserved_tokens=100, reserved_cost_microusd=10,
            reported_tokens=None, reported_cost_microusd=None, success=False)
        self.assertEqual(usage["unknown_usage_calls"], 1)
        self.assertEqual(usage["unknown_cost_calls"], 1)
        self.assertFalse(usage["stopped"])
        evaluate_campaign_reservation(
            usage, {"max_tokens": 200000, "max_cost_microusd": 2000000},
            tokens=1, cost_microusd=0)

    def test_successful_unknown_usage_stops_further_calls(self):
        usage = apply_settlement(
            _usage(), reserved_tokens=100, reserved_cost_microusd=10,
            reported_tokens=None, reported_cost_microusd=None, success=True)
        self.assertTrue(usage["stopped"])
        self.assertEqual(usage["stop_reason"], "unknown_usage")
        with self.assertRaises(CampaignBudgetError) as error:
            evaluate_campaign_reservation(
                usage, {"max_tokens": 200000, "max_cost_microusd": 2000000},
                tokens=1, cost_microusd=0)
        self.assertEqual(error.exception.code, "campaign_accounting_inconsistent")

    def test_provider_overrun_stops_and_remains_terminal(self):
        usage = apply_settlement(
            _usage(), reserved_tokens=100, reserved_cost_microusd=10,
            reported_tokens=101, reported_cost_microusd=1, success=True)
        self.assertTrue(usage["stopped"])
        self.assertEqual(usage["stop_reason"], "provider_overrun")
        self.assertEqual(usage["reported_tokens"], 101)
        # A second settlement cannot revive the ledger.
        usage = apply_settlement(
            usage, reserved_tokens=100, reserved_cost_microusd=10,
            reported_tokens=90, reported_cost_microusd=1, success=True)
        self.assertTrue(usage["stopped"])
        self.assertEqual(usage["reported_tokens"], 191)

    def test_reported_usage_within_ceiling_is_recorded(self):
        usage = apply_settlement(
            _usage(reserved_tokens=100, reserved_cost_microusd=10),
            reserved_tokens=100, reserved_cost_microusd=10,
            reported_tokens=40, reported_cost_microusd=4, success=True)
        self.assertEqual(usage["reported_tokens"], 40)
        self.assertEqual(usage["reported_cost_microusd"], 4)
        self.assertFalse(usage["stopped"])
        self.assertFalse(accounting_inconsistencies(usage))


class OperationalEventTests(OfflineCase):
    def test_events_are_bounded_redacted_and_correlated(self):
        secret = "hunter2-super-secret"
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvd25lciJ9.signature"
        message = (f"password={secret} Authorization: Bearer {token} "
                   f"https://owner:{secret}@example.test/ {settings.SECRET_KEY}")
        with correlation_scope("campaign-1234-abcdef123456") as correlation:
            ring = None
            for index in range(MAX_EVENTS + 10):
                ring = append_operation(
                    ring, event="campaign_health_alert",
                    reason_code="budget_exhausted", message=message,
                    attributes={"password": secret, "step": index,
                                "unexpected": "drop-me"},
                    now=NOW + timedelta(seconds=index))
        self.assertEqual(current_correlation_id(), None)
        self.assertEqual(len(ring["events"]), MAX_EVENTS)
        sequences = [event["sequence"] for event in ring["events"]]
        self.assertEqual(sequences, sorted(sequences))
        self.assertEqual(sequences[-1], MAX_EVENTS + 10)
        for event in ring["events"]:
            self.assertEqual(event["correlation_id"], correlation)
            self.assertNotIn(secret, event["message"])
            self.assertNotIn(token, event["message"])
            self.assertNotIn(settings.SECRET_KEY, event["message"])
            self.assertEqual(set(event["attributes"]), {"step"})
        summary = operations_summary(ring)
        self.assertEqual(summary["retained"], MAX_EVENTS)
        self.assertFalse(summary["invalid"])

        view = operations_view(ring, after=sequences[-3], limit=MAX_EVENTS)
        self.assertEqual(len(view["events"]), 2)
        self.assertTrue(view["bounded"])
        clamped = operations_view(ring, after=0, limit=10_000)
        self.assertLessEqual(len(clamped["events"]), MAX_EVENTS)

    def test_invalid_rings_are_reset_and_faulted(self):
        ring = append_operation("broken", event="campaign_created", now=NOW)
        self.assertEqual(ring["generation"], 1)
        self.assertEqual(len(ring["events"]), 2)
        self.assertEqual(ring["events"][0]["reason_code"], "operations_invalid")
        self.assertEqual(ring["events"][1]["event"], "campaign_created")
        self.assertTrue(operations_summary("broken")["invalid"])
        sanitized = sanitize_operations({"schema": "aria.campaign.operations.v1",
                                         "events": [{"event": "not-real",
                                                     "sequence": 1}]})
        self.assertEqual(sanitized["events"], [])

    def test_unknown_events_and_short_correlations_are_folded(self):
        ring = append_operation(None, event="attacker-controlled-label",
                                correlation="short", now=NOW)
        event = ring["events"][0]
        self.assertEqual(event["event"], "campaign_operation")
        self.assertEqual(len(event["correlation_id"]), 32)
        self.assertIn(event["event"], EVENT_TYPES)
        self.assertIn("operations_invalid", ALERT_CODES)

    def test_health_events_are_bounded_and_redacted(self):
        ring = None
        for index in range(MAX_EVENTS + 5):
            ring = append_operation(
                ring, event="campaign_created", reason_code="scheduled",
                message=f"secret=value-{index}", now=NOW)
        health = build_campaign_health(_row(operations=ring), NOW)
        self.assertEqual(health["operations"]["retained"], MAX_EVENTS)
        self.assertLessEqual(len(health["alerts"]), 12)
        self.assertNotIn("value-", str(health["operations"]))


class MonitorTests(OfflineCase):
    async def test_monitor_enforces_owner_and_uses_bounded_providers(self):
        row = _row()
        store = AsyncMock()
        store.get = AsyncMock(return_value=row)
        store.latest_for_session = AsyncMock(return_value=row)
        worker = AsyncMock(return_value={"counts": {"running": 1}})
        specialist = AsyncMock(return_value={"counts": {"running": 1}})
        model = AsyncMock(return_value={"usage": {}})
        monitor = CampaignMonitor(
            store=store, run_status_provider=lambda sid: _run_status(),
            checkpoint_loader=AsyncMock(return_value={"active": False}),
            worker_summary_provider=worker,
            specialist_summary_provider=specialist,
            model_summary_provider=model)
        health = await monitor.health_for_campaign("c1", OWNER, NOW)
        self.assertEqual(health["state"], "running")
        self.assertEqual(health["metrics"]["worker_active"], 1)
        worker.assert_awaited_once_with(SESSION)
        specialist.assert_awaited_once_with(SESSION, OWNER, ["task-1"])
        model.assert_awaited_once_with(SESSION, OWNER)
        with self.assertRaises(LookupError):
            await monitor.health_for_campaign("c1", "another-owner", NOW)
        with self.assertRaises(LookupError):
            await monitor.events_for_campaign("c1", "another-owner")
        events = await monitor.events_for_campaign("c1", OWNER)
        self.assertTrue(events["bounded"])

    async def test_monitor_survives_provider_failures(self):
        row = _row()

        async def broken(*args, **kwargs):
            raise RuntimeError("database unavailable")

        monitor = CampaignMonitor(
            store=AsyncMock(get=AsyncMock(return_value=row),
                            latest_for_session=AsyncMock(return_value=row)),
            run_status_provider=lambda sid: (_ for _ in ()).throw(RuntimeError()),
            checkpoint_loader=broken, worker_summary_provider=broken,
            specialist_summary_provider=broken, model_summary_provider=broken)
        health = await monitor.health_for_campaign("c1", OWNER, NOW)
        alerts = _alerts(health)
        self.assertEqual(alerts["worker_unavailable"], "warning")
        self.assertEqual(alerts["model_usage_invalid"], "warning")
        self.assertEqual(health["state"], "running")


class SupervisorObservabilityTests(OfflineCase):
    async def _supervisor(self, now):
        store = MemoryCampaignStore(clock=lambda: now)
        engine = FakeEngine()
        supervisor = CampaignSupervisor(
            store=store, engine=engine,
            context_loader=AsyncMock(return_value={
                "owner_id": OWNER, "scope_digest": "a" * 64,
                "auth_revision": 4, "worker_epoch": 2,
                "worker_blocked": False}),
            capabilities=AsyncMock(return_value={"tools": ["curl", "nmap"]}),
            planner_preflight=AsyncMock(return_value={"ready": True}),
            worker_resume=AsyncMock(), clock=lambda: now)
        row = await store.create(make_spec(
            session_id=SESSION, owner_id=OWNER, weekdays=(0, 1, 2, 3, 4),
            window=("00:00", "23:59")))
        return store, engine, supervisor, row

    async def test_successful_progress_is_recorded_with_a_correlation_id(self):
        now = NOW
        store, engine, supervisor, row = await self._supervisor(now)
        await supervisor.tick(now)
        self.assertEqual((await store.get(row["id"]))["state"], "running")
        engine.status.update(successful_steps=1, steps_taken=1, model_calls=1)
        await supervisor.tick(now + timedelta(seconds=5))
        stored = await store.get(row["id"])
        steps = [event for event in stored["operations"]["events"]
                 if event["event"] == "campaign_step_succeeded"]
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0]["attributes"]["successful_steps"], 1)
        self.assertTrue(steps[0]["correlation_id"])
        self.assertGreaterEqual(len(steps[0]["correlation_id"]), 16)
        self.assertEqual(stored["usage"]["last_successful_steps"], 1)

    async def test_accounting_stop_terminalizes_with_a_distinct_reason(self):
        now = NOW
        store, engine, supervisor, row = await self._supervisor(now)
        await supervisor.tick(now)
        stored = await store.get(row["id"])
        stored["usage"] = campaigns.validate_usage({
            **stored["usage"], "stopped": True,
            "stop_reason": "unknown_usage"})
        store.rows[row["id"]] = stored
        await supervisor.tick(now + timedelta(seconds=5))
        final = await store.get(row["id"])
        self.assertEqual(final["state"], "failed")
        self.assertEqual(final["reason_code"], "campaign_accounting_inconsistent")
        self.assertIsNone(final["active_key"])


class CampaignMonitoringApiTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    def _owner(self):
        return TokenData(user_id=OWNER, username="owner", role="pentester",
                         skill_level="expert")

    def _session(self, owner=OWNER):
        return {"session_id": SESSION, "target": "192.0.2.10",
                "user_id": owner, "scope": {"targets": ["192.0.2.10"]}}

    async def test_health_and_events_are_owner_only(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session("another-owner"))):
            for path in ("campaign/health", "campaign/events"):
                with self.subTest(path=path):
                    response = await self.client.get(
                        "/api/pentest/engagement/" + path)
                    self.assertEqual(response.status_code, 403)

    async def test_admin_cannot_read_another_owners_health(self):
        admin = TokenData(user_id="admin", username="admin", role="admin",
                          skill_level="expert")
        app.dependency_overrides[get_current_user] = lambda: admin
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())):
            response = await self.client.get(
                "/api/pentest/engagement/campaign/health")
            self.assertEqual(response.status_code, 403)

    async def test_missing_campaign_is_404(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())), \
             patch("memory.campaign_store.campaign_store.latest_for_session",
                   AsyncMock(return_value=None)):
            for path in ("campaign/health", "campaign/events"):
                with self.subTest(path=path):
                    response = await self.client.get(
                        "/api/pentest/engagement/" + path)
                    self.assertEqual(response.status_code, 404)

    async def test_health_can_report_empty_campaign_without_hiding_missing_engagement(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        path = "/api/pentest/engagement/campaign/health?include_absence=true"
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())), \
             patch("memory.campaign_store.campaign_store.latest_for_session",
                   AsyncMock(return_value=None)):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {
                "schema": "aria.campaign.health.v1", "session_id": "engagement", "state": "not_started"})
        for session, status in ((None, 404), (self._session("another-owner"), 403)):
            with patch("api.session_access.session_manager.get_session", AsyncMock(return_value=session)):
                self.assertEqual((await self.client.get(path)).status_code, status)

    async def test_health_and_event_routes_are_bounded(self):
        app.dependency_overrides[get_current_user] = lambda: self._owner()
        row = _row()
        sentinel = {"schema": "aria.campaign.health.v1", "state": "running"}
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())), \
             patch("memory.campaign_store.campaign_store.latest_for_session",
                   AsyncMock(return_value=row)), \
             patch("orchestrator.campaign_supervisor.campaign_supervisor."
                   "health_for_row", AsyncMock(return_value=sentinel)) as health:
            response = await self.client.get(
                "/api/pentest/engagement/campaign/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), sentinel)
        health.assert_awaited_once()

        app.dependency_overrides[get_current_user] = lambda: self._owner()
        with patch("api.session_access.session_manager.get_session",
                   AsyncMock(return_value=self._session())), \
             patch("memory.campaign_store.campaign_store.latest_for_session",
                   AsyncMock(return_value=row)):
            response = await self.client.get(
                "/api/pentest/engagement/campaign/events",
                params={"after": 0, "limit": MAX_EVENTS})
            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertTrue(body["bounded"])
            self.assertLessEqual(len(body["events"]), MAX_EVENTS)
            self.assertTrue(all(event["correlation_id"] for event in body["events"]))
            too_many = await self.client.get(
                "/api/pentest/engagement/campaign/events",
                params={"limit": MAX_EVENTS + 1})
            self.assertEqual(too_many.status_code, 422)
            negative = await self.client.get(
                "/api/pentest/engagement/campaign/events",
                params={"after": -1})
            self.assertEqual(negative.status_code, 422)


class BudgetDenialMappingTests(OfflineCase):
    def test_campaign_budget_error_codes_are_distinct(self):
        usage = _usage(stopped=True, stop_reason="unknown_usage")
        with self.assertRaises(CampaignBudgetError) as error:
            evaluate_campaign_reservation(
                usage, {"max_tokens": 10, "max_cost_microusd": 10},
                tokens=1, cost_microusd=0)
        self.assertEqual(error.exception.code, "campaign_accounting_inconsistent")
        usage = _usage(stopped=True, stop_reason="provider_overrun")
        with self.assertRaises(CampaignBudgetError) as error:
            evaluate_campaign_reservation(
                usage, {"max_tokens": 10, "max_cost_microusd": 10},
                tokens=1, cost_microusd=0)
        self.assertEqual(error.exception.code, "campaign_budget_exhausted")
