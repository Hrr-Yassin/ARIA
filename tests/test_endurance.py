"""SPEC-15 accelerated endurance regressions (synthetic work only).

Every test in this module advances a simulated clock deliberately.  The real
campaign supervisor, schedule helpers, campaign ledger and execution guard run
against a deterministic synthetic engine, worker and provider.  These tests are
an accelerated simulation: they are not evidence of eight-hour wall-clock
reliability.  See ``integration/endurance_soak.py`` for the bounded real-time
soak and ``docs/spec15-endurance-status.md`` for the distinction.
"""
import asyncio
import json
import unittest
from datetime import timedelta

from fastapi import HTTPException

from memory.campaign_observability import MAX_EVENTS, build_campaign_health
from orchestrator.campaign_execution import CampaignExecutionDenied
from orchestrator.campaign_supervisor import CampaignSupervisor
from orchestrator.specialist_integration import SpecialistIntegrationError
from tests.endurance_harness import (
    DIGEST,
    OWNER,
    SESSION,
    EnduranceHarness,
    EnginePlan,
    monday_start,
)


class EnduranceCase(unittest.IsolatedAsyncioTestCase):
    def harness(self, **overrides) -> EnduranceHarness:
        values = dict(start=monday_start(), tick_seconds=300)
        values.update(overrides)
        return EnduranceHarness(**values)

    async def run_for(self, harness: EnduranceHarness, ticks: int) -> None:
        await harness.run(ticks)

    async def run_until(self, harness: EnduranceHarness, predicate,
                        limit: int = 400) -> bool:
        for _ in range(limit):
            if await predicate():
                return True
            await harness.tick()
        return await predicate()

    def assert_safe(self, harness: EnduranceHarness, *,
                    allow_denied: int = 0) -> None:
        summary = harness.summary()
        self.assertEqual(summary["window_violations"], 0, summary)
        self.assertEqual(summary["duplicate_dispatches"], 0, summary)
        self.assertEqual(summary["denied_dispatches"], allow_denied, summary)
        self.assertLessEqual(summary["provider_denials"], 1, summary)
        work_keys = [job["work_key"] for job in harness.worker.dispatches]
        self.assertEqual(len(work_keys), len(set(work_keys)), work_keys)
        commands = [job["command"] for job in harness.worker.dispatches]
        self.assertEqual(len(commands), len(set(commands)), commands)

    async def assert_budget_consistent(self, harness: EnduranceHarness) -> None:
        row = await harness.row()
        budget = harness.spec.budget
        usage = row["usage"]
        self.assertLessEqual(usage["reserved_tokens"], budget.max_tokens)
        self.assertLessEqual(usage["reserved_cost_microusd"],
                             budget.max_cost_microusd)
        self.assertLessEqual(usage["reported_tokens"],
                             usage["reserved_tokens"])
        self.assertEqual(usage["calls"],
                         len(harness.accounting.provider_calls))

    async def test_five_workdays_pause_resume_and_skip_weekend(self):
        harness = self.harness(
            tick_seconds=300,
            daily_runtime_seconds=3600,
            plan=EnginePlan(step_interval_seconds=2700,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            # Monday 09:00 through Sunday, just before Monday 09:00 opens.
            await self.run_for(harness, 2015)

            summary = harness.summary()
            self.assert_safe(harness)
            self.assertGreaterEqual(summary["synthetic_steps"], 5, summary)
            row = await harness.row()
            self.assertNotIn(row["state"], {"failed", "cancelled"}, row)
            self.assertEqual(row["state"], "paused", row)
            self.assertEqual(row["next_action_at"].isoformat(timespec="minutes"),
                             "2026-11-23T09:00")

            # One bounded run per workday, a durable pause at the daily limit,
            # and no provider or worker activity on the weekend.
            calls = harness.accounting.provider_calls
            self.assertTrue(calls)
            self.assertTrue(all(call.at.weekday() < 5 for call in calls),
                            [call.at.isoformat() for call in calls])
            self.assertTrue(all(9 <= call.at.hour < 17 for call in calls),
                            [call.at.isoformat() for call in calls])
            weekdays = {call.at.date() for call in calls}
            self.assertEqual(
                sorted(str(day) for day in weekdays),
                ["2026-11-16", "2026-11-17", "2026-11-18",
                 "2026-11-19", "2026-11-20"])
            paused_days = {
                event["timestamp"][:10] for event in row["operations"]["events"]
                if event["event"] == "campaign_paused"}
            self.assertEqual(
                sorted(paused_days),
                ["2026-11-16", "2026-11-17", "2026-11-18",
                 "2026-11-19", "2026-11-20"], paused_days)
            self.assertEqual(sorted(row["usage"]["daily"]),
                             ["2026-11-16", "2026-11-17", "2026-11-18",
                              "2026-11-19", "2026-11-20"])
            for day, seconds in row["usage"]["daily"].items():
                self.assertLessEqual(seconds, 3600 + 300, (day, seconds))

            # Monday opens again and the same durable pause resumes the run.
            calls_before = len(calls)
            await self.run_for(harness, 14)
            row = await harness.row()
            self.assertGreater(len(calls), calls_before)
            resumed = [
                event for event in row["operations"]["events"]
                if event["event"] == "campaign_resumed"
                and event["timestamp"].startswith("2026-11-23")]
            self.assertTrue(resumed, row["operations"]["events"])

        self.assert_safe(harness)
        await self.assert_budget_consistent(harness)

    async def test_work_completes_within_five_workdays(self):
        harness = self.harness(
            tick_seconds=300,
            daily_runtime_seconds=3600,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 2016)

        row = await harness.row()
        self.assertEqual(row["state"], "completed", row)
        self.assertEqual(row["reason_code"], "completed")
        self.assertEqual(len(harness.accounting.provider_calls), 12)
        self.assertEqual(len(harness.worker.dispatches), 12)
        self.assert_safe(harness)
        self.assertEqual(harness.summary()["worker_dispatches"], 12)
        self.assertFalse(harness.window_violations)
        await self.assert_budget_consistent(harness)

    async def test_crash_during_run_recovers_without_duplicate_dispatch(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=7200,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=6, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 4)
            live = harness.engine.live.get(SESSION)
            self.assertIsNotNone(live)
            run_id = live["run_id"]
            self.assertGreaterEqual(len(harness.worker.dispatches), 1)

            harness.crash()
            await harness.recover()
            recovered = await harness.row()
            self.assertEqual(recovered["state"], "scheduled", recovered)
            self.assertEqual(recovered["reason_code"], "supervisor_restart")
            self.assertEqual(recovered["retry"]["count"], 1)

            await self.run_until(
                harness,
                lambda: self._state_is(harness, "completed"), limit=600)
            row = await harness.row()
            self.assertEqual(row["state"], "completed", row)
            self.assertEqual(row["run_id"], run_id)
            self.assertEqual(row["retry"]["count"], 0, row["retry"])

        self.assert_safe(harness)
        self.assertEqual(len(harness.worker.dispatches), 6)
        self.assertEqual(
            [step["step"] for step in harness.engine.steps], list(range(1, 7)))
        events = [event["event"] for event in row["operations"]["events"]]
        self.assertIn("campaign_recovered", events)
        await self.assert_budget_consistent(harness)

    async def _state_is(self, harness, state):
        return (await harness.row())["state"] == state

    async def _steps_advanced(self, harness, previous):
        return len(harness.engine.steps) > previous

    async def _specialist_called(self, harness):
        return len(harness.specialist_rig.coordinator.calls) > 0

    async def _calls_advanced(self, harness, previous):
        return len(harness.accounting.provider_calls) > previous

    async def test_crash_while_paused_keeps_pause_and_retry_state(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=3600,
            plan=EnginePlan(step_interval_seconds=2700,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_until(
                harness, lambda: self._state_is(harness, "paused"), limit=40)
            paused = await harness.row()
            self.assertEqual(paused["state"], "paused", paused)
            self.assertEqual(paused["pause_reason"], "daily_runtime_exhausted")
            self.assertEqual(paused["retry"]["count"], 0)
            paused_at = paused["next_action_at"]
            calls_before = len(harness.accounting.provider_calls)

            harness.crash()
            await harness.recover()
            recovered = await harness.row()
            self.assertEqual(recovered["state"], "paused", recovered)
            self.assertEqual(recovered["retry"]["count"], 0)
            self.assertEqual(recovered["next_action_at"], paused_at)
            self.assertEqual(len(harness.accounting.provider_calls),
                             calls_before)

            # Original pause targeted Tuesday 09:00; run past on-call resume.
            await self.run_until(
                harness,
                lambda: self._state_is(harness, "running"), limit=320)
            resumed = await harness.row()
            self.assertEqual(resumed["state"], "running", resumed)
            await self.run_until(
                harness,
                lambda: self._calls_advanced(harness, calls_before), limit=20)
            self.assertGreater(len(harness.accounting.provider_calls),
                               calls_before)

        self.assert_safe(harness)
        await self.assert_budget_consistent(harness)

    async def test_repeated_recovery_with_progress_does_not_exhaust_retries(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800,
            max_retries=2,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            for cycle in range(4):
                steps_before = len(harness.engine.steps)
                await self.run_until(
                    harness,
                    lambda: self._steps_advanced(harness, steps_before),
                    limit=40)
                # Let the supervisor durably observe the new successful step.
                await harness.tick()
                current = await harness.row()
                self.assertNotEqual(current["state"], "failed", current)
                self.assertEqual(current["retry"]["count"], 0,
                                 (cycle, current["retry"]))
                harness.crash()
                await harness.recover()
                recovered = await harness.row()
                self.assertNotEqual(recovered["state"], "failed", recovered)
                self.assertLessEqual(recovered["retry"]["count"], cycle + 1)

            await self.run_until(
                harness,
                lambda: self._state_is(harness, "completed"), limit=400)
            row = await harness.row()
            self.assertEqual(row["state"], "completed", row)

        self.assert_safe(harness)
        self.assertGreaterEqual(len(harness.worker.dispatches), 12)
        await self.assert_budget_consistent(harness)

    async def test_budget_exhaustion_stops_before_any_further_dispatch(self):
        harness = self.harness(
            budget_tokens=5000, max_retries=2,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 30)

        row = await harness.row()
        self.assertEqual(row["state"], "failed", row)
        self.assertEqual(row["reason_code"], "campaign_budget_exhausted")
        self.assertEqual(len(harness.accounting.provider_calls), 2)
        self.assertEqual(len(harness.worker.dispatches), 2)
        self.assertEqual(len(harness.accounting.denials), 1)
        denial = harness.accounting.denials[0]
        self.assertEqual(denial["status"], 429)
        self.assertEqual(denial["code"], "campaign_budget_exhausted")
        self.assertEqual(row["usage"]["reserved_tokens"], 4000)
        self.assertLessEqual(row["usage"]["reserved_tokens"], 5000)
        self.assertFalse(row["usage"]["stopped"])
        self.assertEqual(row["usage"]["calls"], 2)
        self.assert_safe(harness)
        self.assertEqual(harness.summary()["provider_denials"], 1)

    async def test_unknown_provider_usage_terminalizes_the_campaign(self):
        harness = self.harness(
            tick_seconds=300,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        harness.accounting.report_tokens = None
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 20)

        row = await harness.row()
        self.assertEqual(row["state"], "failed", row)
        self.assertEqual(row["reason_code"], "campaign_accounting_inconsistent")
        self.assertEqual(len(harness.accounting.provider_calls), 1)
        self.assertEqual(len(harness.worker.dispatches), 1)
        self.assertTrue(row["usage"]["stopped"])
        self.assertEqual(row["usage"]["stop_reason"], "unknown_usage")
        self.assertEqual(row["usage"]["unknown_usage_calls"], 1)
        self.assert_safe(harness)

    async def test_authorization_expiry_stops_a_live_run(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 4)
            self.assertIsNotNone(harness.engine.live.get(SESSION))
            calls = len(harness.accounting.provider_calls)
            dispatches = len(harness.worker.dispatches)
            harness.context_error = HTTPException(403, "Engagement access denied")
            await harness.tick()

        row = await harness.row()
        self.assertEqual(row["state"], "failed", row)
        self.assertEqual(row["reason_code"], "authorization_expired")
        self.assertEqual(len(harness.accounting.provider_calls), calls)
        self.assertEqual(len(harness.worker.dispatches), dispatches)
        self.assertFalse(harness.engine.live)
        self.assert_safe(harness)

    async def test_scope_change_stops_a_live_run_before_dispatch(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 4)
            dispatches = len(harness.worker.dispatches)
            harness.context["scope_digest"] = "b" * 64
            await harness.tick()

        row = await harness.row()
        self.assertEqual(row["state"], "failed", row)
        self.assertEqual(row["reason_code"], "scope_changed")
        self.assertEqual(len(harness.worker.dispatches), dispatches)
        self.assertEqual(len(harness.worker.denied), 0)
        self.assert_safe(harness)

    async def test_worker_fence_stops_a_live_run(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 4)
            dispatches = len(harness.worker.dispatches)
            harness.context["worker_blocked"] = True
            await harness.tick()

        row = await harness.row()
        self.assertEqual(row["state"], "failed", row)
        self.assertEqual(row["reason_code"], "worker_blocked")
        self.assertEqual(len(harness.worker.dispatches), dispatches)
        self.assertEqual(len(harness.worker.denied), 0)
        self.assert_safe(harness)

    async def test_stale_supervisor_token_is_denied_after_takeover(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=6, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 4)
            old_token = harness.supervisor._token
            live = harness.engine.live.get(SESSION)
            self.assertIsNotNone(live)
            self.assertEqual(live["token"], old_token)

            # An expired lease denies the old token even before a takeover.
            harness.clock.advance(harness.lease_seconds + 1)
            with self.assertRaises(CampaignExecutionDenied) as expired:
                await self._dispatch(harness, old_token, "expired-lease")
            self.assertEqual(expired.exception.code,
                             "campaign_supervisor_required")

            harness.crash()
            await harness.recover()
            await harness.tick()
            await harness.tick()
            replacement = harness.supervisor._token
            self.assertNotEqual(replacement, old_token)
            with self.assertRaises(CampaignExecutionDenied) as takeover:
                await self._dispatch(harness, old_token, "stale-token")
            self.assertEqual(takeover.exception.code,
                             "campaign_supervisor_required")

            await self.run_until(
                harness,
                lambda: self._state_is(harness, "completed"), limit=400)
            row = await harness.row()
            self.assertEqual(row["state"], "completed", row)

        self.assert_safe(harness, allow_denied=2)
        denied = [item["code"] for item in harness.worker.denied]
        self.assertEqual(denied, ["campaign_supervisor_required"] * 2)
        self.assertEqual(len(harness.worker.dispatches), 6)
        self.assertEqual(row["retry"]["count"], 0, row["retry"])

    async def _dispatch(self, harness, token, work_key):
        return await harness.worker.dispatch(
            campaign_id=harness.campaign_id, token=token,
            session_id=SESSION, owner_id=OWNER, scope_digest=DIGEST,
            auth_revision=4, worker_epoch=2, work_key=work_key,
            command=f"curl -s http://192.0.2.15/{work_key}")

    async def test_specialist_investigations_are_idempotent_across_recovery(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800, specialist=True,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=6, max_steps=12,
                            specialist_after_step=2))
        await harness.create()
        with harness.simulation():
            await self.run_until(
                harness,
                lambda: self._specialist_called(harness),
                limit=40)
            coordinator = harness.specialist_rig.coordinator
            self.assertEqual(len(coordinator.calls), 1)
            checkpoint = harness.engine.checkpoints[SESSION]
            task_ids = list(checkpoint["specialist_task_ids"])
            self.assertEqual(len(task_ids), 1)
            self.assertEqual(len(harness.specialist_rig.team_store.tasks), 1)
            self.assertTrue(checkpoint["specialist_phase_done"])

            # Model a crash after the durable tasks were created but before the
            # phase was marked complete.  Restore must reuse the same ledger
            # entries and must not call the specialist a second time.
            checkpoint["specialist_phase_done"] = False
            harness.crash()
            await harness.recover()
            await self.run_until(
                harness,
                lambda: self._state_is(harness, "completed"), limit=400)

            row = await harness.row()
            self.assertEqual(row["state"], "completed", row)
            restored = harness.engine.checkpoints[SESSION]
            self.assertTrue(restored["specialist_phase_done"])
            self.assertEqual(restored["specialist_task_ids"], task_ids)
            self.assertEqual(len(coordinator.calls), 1)
            task = harness.specialist_rig.team_store.tasks[task_ids[0]]
            self.assertEqual(task["state"], "awaiting_review")
            self.assertFalse(any(
                item.get("verified") for item in task["result"]["hypotheses"]))

        self.assert_safe(harness)
        summary = harness.summary()
        self.assertEqual(summary["specialist_calls"], 1)
        self.assertEqual(summary["specialist_tasks"], 1)

    async def test_specialist_dispatch_requires_a_live_supervisor_lease(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800, specialist=True,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=6, max_steps=12,
                            specialist_after_step=2))
        await harness.create()
        with harness.simulation():
            await self.run_until(
                harness,
                lambda: self._specialist_called(harness),
                limit=40)
            rig = harness.specialist_rig
            task_id = next(iter(rig.team_store.tasks))
            # Make the task claimable again without disturbing the ledger.
            rig.team_store.tasks[task_id]["state"] = "queued"
            with self.assertRaises(SpecialistIntegrationError) as denied:
                await rig.service.run_pending(
                    session_id=SESSION, owner_id=OWNER, task_ids=[task_id],
                    skill_level="expert", max_tasks=1,
                    campaign_id=harness.campaign_id,
                    campaign_supervisor_token="stale-supervisor-token",
                    scope_digest=DIGEST, auth_revision=4, worker_epoch=2)
            self.assertEqual(denied.exception.code,
                             "campaign_supervisor_required")
            self.assertEqual(len(rig.coordinator.calls), 1)
            self.assertEqual(rig.coordinator.denials[-1]["code"],
                             "campaign_supervisor_required")

            with self.assertRaises(SpecialistIntegrationError) as missing:
                await rig.service.run_pending(
                    session_id=SESSION, owner_id=OWNER, task_ids=[task_id],
                    skill_level="expert", max_tasks=1,
                    campaign_id=harness.campaign_id,
                    campaign_supervisor_token="",
                    scope_digest=DIGEST, auth_revision=4, worker_epoch=2)
            self.assertEqual(missing.exception.code,
                             "campaign_supervisor_required")
            self.assertEqual(len(rig.coordinator.calls), 1)

    async def test_operation_ring_and_durable_state_stay_bounded(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=3600,
            plan=EnginePlan(step_interval_seconds=2700,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 2016)

        row = await harness.row()
        events = row["operations"]["events"]
        self.assertLessEqual(len(events), MAX_EVENTS)
        sequences = [event["sequence"] for event in events]
        self.assertEqual(sequences, list(range(sequences[0], sequences[0]
                                               + len(sequences))))
        checkpoint = harness.engine.checkpoints[SESSION]
        self.assertLessEqual(len(checkpoint["executed_commands"]), 12)
        self.assertLessEqual(len(checkpoint["evidence_job_ids"]), 12)
        self.assertEqual(len(harness.worker.jobs),
                         len(harness.worker.dispatches))
        encoded = json.dumps(row, default=str)
        self.assertLess(len(encoded), 60000, len(encoded))
        self.assertLessEqual(
            len(json.dumps(harness.engine.checkpoints[SESSION])), 20000)

        # Monitoring consumes the same durable state without executing work.
        harness.context["worker_blocked"] = False
        health = build_campaign_health(
            row, harness.clock(),
            worker_summary={"counts": {
                                "succeeded": len(harness.worker.dispatches),
                                "failed": 0, "running": 0, "unknown": 0},
                            "active": 0, "unresolved": 0},
            specialist_summary={"counts": {"queued": 0, "running": 0,
                                           "awaiting_review": 0, "blocked": 0,
                                           "completed": 0, "cancelled": 0,
                                           "failed": 0, "missing": 0},
                                "active": 0, "total": 0},
            model_summary={"calls": 5, "reserved_tokens": 10000,
                           "reserved_cost_microusd": 0,
                           "reported_tokens": 10000,
                           "reported_cost_microusd": 0,
                           "unknown_usage_calls": 0,
                           "unknown_cost_calls": 0, "stopped": False,
                           "stop_reason": ""})
        self.assertEqual(health["schema"], "aria.campaign.health.v1")
        self.assertFalse(health["terminal"])
        self.assertEqual(health["operations"]["max_events"], MAX_EVENTS)
        self.assertLessEqual(health["operations"]["retained"], MAX_EVENTS)
        alert_codes = {alert["code"] for alert in health["alerts"]}
        self.assertNotIn("progress_stalled", alert_codes)
        self.assertNotIn("repeated_failures", alert_codes)
        self.assertTrue(health["accounting"]["consistent"])

    async def test_stalled_progress_is_reported_from_durable_state(self):
        harness = self.harness(
            tick_seconds=300, daily_runtime_seconds=28800,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=12, max_steps=12))
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 4)
            row = await harness.row()
            self.assertEqual(row["state"], "running")
            now = harness.clock()
            stalled = dict(row)
            stalled["operations"] = json.loads(json.dumps(row["operations"]))
            stalled["operations"]["last_successful_at"] = (
                now - timedelta(seconds=3600)).isoformat()
            stalled["operations"]["last_activity_at"] = (
                now - timedelta(seconds=3600)).isoformat()
            stalled["last_heartbeat_at"] = now.replace(tzinfo=None)
            health = build_campaign_health(
                stalled, now, progress_stale_seconds=1800,
                heartbeat_stale_seconds=120)
            self.assertIn("progress_stalled",
                          {alert["code"] for alert in health["alerts"]})
            # Building health never changed durable state.
            self.assertEqual((await harness.row())["state"], "running")

    async def test_unresolved_worker_resume_stays_fail_closed(self):
        async def blocked_resume(owner_id, session_id):
            raise HTTPException(409, "Worker cancellation is unresolved")

        harness = self.harness(
            max_retries=0,
            plan=EnginePlan(step_interval_seconds=900,
                            required_successful_steps=6, max_steps=12))
        harness.supervisor_factory = lambda: CampaignSupervisor(
            store=harness.store, engine=harness.engine,
            context_loader=harness._context,
            capabilities=harness._capabilities,
            planner_preflight=harness._planner_preflight,
            worker_resume=blocked_resume, clock=harness.clock)
        harness.supervisor = harness.supervisor_factory()
        await harness.create()
        with harness.simulation():
            await self.run_for(harness, 3)

        row = await harness.row()
        self.assertEqual(row["state"], "failed", row)
        self.assertEqual(len(harness.accounting.provider_calls), 0)
        self.assertEqual(len(harness.worker.dispatches), 0)
        self.assertFalse(harness.engine.live)
        # The worker fence is never treated as a runnable campaign.
        self.assertIn(row["reason_code"],
                      {"retry_exhausted", "authorization_unavailable"})


if __name__ == "__main__":
    unittest.main()
