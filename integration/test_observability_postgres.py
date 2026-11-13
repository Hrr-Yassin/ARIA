"""SPEC-14 durable observability and accounting integration tests (synthetic).

Requires a disposable database ending in *_test:
    ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test \
        python -m unittest integration.test_observability_postgres -v
"""
import asyncio
import hashlib
import os
import subprocess
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone

ENABLED = os.environ.get("ARIA_INTEGRATION") == "1"
UTC = timezone.utc


@unittest.skipUnless(ENABLED, "set ARIA_INTEGRATION=1 with a disposable *_test database")
class CampaignObservabilityPostgres(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        url = make_url(os.environ["DATABASE_URL"])
        if not (url.database or "").endswith("_test"):
            raise RuntimeError("integration requires a disposable database named *_test")
        subprocess.run([sys.executable, "-B", "-m", "alembic", "upgrade", "head"],
                       check=True)

    async def asyncSetUp(self):
        from memory.database_models import engine
        self.token = uuid.uuid4().hex[:8]
        await engine.dispose()

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    async def _session(self):
        from memory.database_models import PentestSession, User, async_session
        owner_id = "spec14-o-" + uuid.uuid4().hex[:12]
        session_id = "spec14-s-" + uuid.uuid4().hex[:12]
        async with async_session() as db:
            db.add(User(id=owner_id, username="u-" + uuid.uuid4().hex[:16],
                        password_hash="unused"))
            await db.flush()
            db.add(PentestSession(
                id=session_id, user_id=owner_id, target="192.0.2.14",
                scope={"targets": ["192.0.2.14"]}, metadata_={}))
            await db.commit()
        return owner_id, session_id

    def _spec(self, owner, session_id, **overrides):
        from memory.campaign_store import (
            CampaignBudget, CampaignSchedule, CampaignSpec,
        )
        values = {
            "session_id": session_id,
            "owner_id": owner,
            "goal": "discovery",
            "target": "192.0.2.14",
            "skill_level": "expert",
            "objective": "Synthetic SPEC-14 observability integration test",
            "max_steps": 12,
            "auto_risk_threshold": "green_orange",
            "schedule": CampaignSchedule(
                timezone="UTC", weekdays=[0, 1, 2, 3, 4],
                window_start="00:00", window_end="23:59",
                daily_runtime_seconds=28800),
            "budget": CampaignBudget(max_tokens=1000000,
                                     max_cost_microusd=10000000),
            "max_retries": 3,
            "scope_digest": hashlib.sha256(session_id.encode()).hexdigest(),
            "required_tools": ["curl", "nmap"],
        }
        values.update(overrides)
        return CampaignSpec(**values)

    def _store(self):
        from memory.campaign_store import SQLCampaignBackend
        return SQLCampaignBackend()

    async def _activate(self, store, owner, session_id, **overrides):
        campaign = await store.create(self._spec(owner, session_id, **overrides))
        claim = await store.claim(campaign["id"], "lease-" + self.token,
                                  datetime.now(UTC), 3600)
        self.assertIsNotNone(claim)
        running = await store.transition(
            campaign["id"], "lease-" + self.token, datetime.now(UTC),
            {"scheduled"}, {"state": "running"}, event="campaign_started")
        self.assertIsNotNone(running)
        return running

    async def test_operations_persist_with_correlation_and_stay_bounded(self):
        from memory.campaign_observability import MAX_EVENTS, correlation_scope
        store = self._store()
        owner, session_id = await self._session()
        campaign = await store.create(self._spec(owner, session_id))
        initial = await store.get(campaign["id"])
        self.assertEqual(initial["operations"]["schema"],
                         "aria.campaign.operations.v1")
        self.assertEqual(initial["operations"]["events"][-1]["event"],
                         "campaign_created")
        self.assertTrue(initial["operations"]["events"][-1]["correlation_id"])

        correlation = "durable-" + self.token
        with correlation_scope(correlation):
            claim = await store.claim(campaign["id"], "lease-" + self.token,
                                      datetime.now(UTC), 3600)
            self.assertIsNotNone(claim)
            await store.transition(
                campaign["id"], "lease-" + self.token, datetime.now(UTC),
                {"scheduled"}, {"state": "running"},
                event="campaign_started")
            for step in range(1, MAX_EVENTS + 11):
                activity = await store.record_activity(
                    campaign["id"], "lease-" + self.token, datetime.now(UTC),
                    operation={
                        "event": "campaign_step_succeeded",
                        "reason_code": "step_succeeded",
                        "message": f"Step {step} produced durable evidence.",
                        "attributes": {"step": step},
                    })
                self.assertIsNotNone(activity)

        stored = await store.get(campaign["id"])
        events = stored["operations"]["events"]
        self.assertEqual(len(events), MAX_EVENTS)
        self.assertEqual(events[-1]["sequence"], MAX_EVENTS + 12)
        self.assertEqual(events[-1]["attributes"]["step"], MAX_EVENTS + 10)
        self.assertTrue(all(event["correlation_id"] == correlation
                            for event in events))
        self.assertIsNotNone(stored["operations"]["last_successful_at"])
        self.assertEqual(stored["usage"]["last_steps"], 0)

    async def test_concurrent_operational_updates_are_not_lost(self):
        store = self._store()
        owner, session_id = await self._session()
        campaign = await self._activate(store, owner, session_id)
        now = datetime.now(UTC)

        async def record(step):
            return await store.record_activity(
                campaign["id"], "lease-" + self.token, now,
                operation={
                    "event": "campaign_step_succeeded",
                    "reason_code": "step_succeeded",
                    "attributes": {"step": step},
                })

        results = await asyncio.gather(*[record(step) for step in range(1, 13)])
        self.assertTrue(all(result is not None for result in results))
        stored = await store.get(campaign["id"])
        events = [event for event in stored["operations"]["events"]
                  if event["event"] == "campaign_step_succeeded"]
        self.assertEqual({event["attributes"]["step"] for event in events},
                         set(range(1, 13)))
        sequences = [event["sequence"] for event in events]
        self.assertEqual(len(sequences), len(set(sequences)))

    async def test_settlement_updates_campaign_and_blocks_unknown_usage(self):
        from fastapi import HTTPException
        from llm.engagement_budget import (
            ModelAccounting, ModelLimits, engagement_context, task_context,
        )
        from memory.campaign_store import reserve_campaign_usage
        from memory.database_models import async_session
        store = self._store()
        owner, session_id = await self._session()
        campaign = await self._activate(store, owner, session_id)
        await store.bind_session(session_id, owner, campaign["id"])
        accounting = ModelAccounting()
        await accounting.configure(session_id, owner, ModelLimits(
            max_calls=10, max_tokens=100000, max_cost_microusd=1000000,
            tariffs=[]))
        engagement_token = engagement_context.set(
            {"session_id": session_id, "owner": owner})
        task_token = task_context.set(None)
        try:
            attempt = await accounting.reserve(
                owner, "local", "offline-model", "prompt", "")
            await accounting.settle(attempt, {"success": True})
            with self.assertRaises(HTTPException) as error:
                await accounting.reserve(
                    owner, "local", "offline-model", "next", "")
            self.assertEqual(error.exception.status_code, 409)
        finally:
            task_context.reset(task_token)
            engagement_context.reset(engagement_token)

        stored = await store.get(campaign["id"])
        self.assertEqual(stored["usage"]["unknown_usage_calls"], 1)
        self.assertTrue(stored["usage"]["stopped"])
        self.assertEqual(stored["usage"]["stop_reason"], "unknown_usage")
        summary = await accounting.usage_summary(session_id, owner)
        self.assertTrue(summary["stopped"])
        self.assertEqual(summary["stop_reason"], "unknown_usage")

        async with async_session() as db:
            with self.assertRaises(HTTPException) as denial:
                await reserve_campaign_usage(
                    db, campaign_id=campaign["id"], session_id=session_id,
                    owner_id=owner, tokens=1, cost_microusd=1)
        self.assertEqual(denial.exception.status_code, 409)
        self.assertEqual(denial.exception.detail["code"],
                         "campaign_accounting_inconsistent")

    async def test_recovery_persists_operations_and_health_is_not_stalled(self):
        from memory.campaign_observability import build_campaign_health
        store = self._store()
        owner, session_id = await self._session()
        campaign = await store.create(self._spec(owner, session_id))
        now = datetime.now(UTC)
        await store.claim(campaign["id"], "lease-" + self.token, now, 60)
        await store.transition(
            campaign["id"], "lease-" + self.token, now, {"scheduled"},
            {"state": "running"}, event="campaign_started")
        recovered = await store.recover(now + timedelta(seconds=61))
        self.assertIn(campaign["id"], recovered)
        stored = await store.get(campaign["id"])
        self.assertEqual(stored["state"], "scheduled")
        self.assertEqual(stored["reason_code"], "supervisor_restart")
        self.assertEqual(stored["retry"]["count"], 1)
        self.assertEqual(stored["operations"]["events"][-1]["event"],
                         "campaign_recovered")
        health = build_campaign_health(stored, now + timedelta(seconds=61))
        self.assertEqual(health["failures"]["count"], 1)
        self.assertFalse(health["failures"]["repeated"])
        self.assertNotIn("progress_stalled",
                         {alert["code"] for alert in health["alerts"]})
        self.assertEqual(health["operations"]["retained"],
                         len(stored["operations"]["events"]))
        self.assertEqual(health["state"], "scheduled")

    async def test_worker_and_specialist_summaries_are_fixed_cardinality(self):
        from memory.database_models import DecisionLog, async_session
        from memory.team_tasks import (
            CreateTask, TaskSpec, TeamStore,
        )
        from memory.worker_jobs import SQLJobStore
        owner, session_id = await self._session()
        async with async_session() as db:
            for state in ("succeeded", "failed", "running", "unexpected-state"):
                db.add(DecisionLog(
                    id=str(uuid.uuid4()), session_id=session_id,
                    user_id=owner, decision_type="worker_job",
                    metadata_={"session_id": session_id, "state": state,
                               "job_id": uuid.uuid4().hex}))
            await db.commit()
        summary = await SQLJobStore().summary(session_id)
        self.assertEqual(summary["counts"]["succeeded"], 1)
        self.assertEqual(summary["counts"]["failed"], 1)
        self.assertEqual(summary["counts"]["running"], 1)
        self.assertEqual(summary["counts"]["unknown"], 1)
        self.assertEqual(summary["active"], 2)

        team = TeamStore()
        created = await team.create(session_id, owner, CreateTask(
            request_id=uuid.uuid4(),
            task=TaskSpec(
                owner_role="recon", objective="Synthetic task",
                expected_output="A bounded observation",
                completion_criteria=["Evidence recorded"])))
        task_id = created["entity_id"]
        await team.claim(session_id, owner, task_id, str(uuid.uuid4()))
        task_summary = await team.task_summary(
            session_id, owner, [task_id, "missing-task-id"])
        self.assertEqual(task_summary["counts"]["running"], 1)
        self.assertEqual(task_summary["counts"]["missing"], 1)
        self.assertEqual(task_summary["active"], 1)
        self.assertEqual(task_summary["total"], 2)
        self.assertEqual(set(task_summary["counts"]),
                         {"queued", "running", "awaiting_review", "blocked",
                          "completed", "cancelled", "failed", "missing"})


if __name__ == "__main__":
    unittest.main()
