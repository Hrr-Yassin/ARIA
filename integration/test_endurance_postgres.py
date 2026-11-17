"""SPEC-15 accelerated endurance checks against disposable PostgreSQL.

Every model call, worker dispatch and specialist result here is synthetic.  The
tests drive the real ``CampaignSupervisor``, the real campaign lease/ledger
helpers, the real campaign execution guard and the real engagement accounting
against a disposable database ending in ``*_test``.  They make no network
requests, no provider calls and no real worker submissions.

Campaign creation and lease validation share the fixture's simulated Monday.
The checks do not depend on that Monday remaining ahead of today's wall clock.
This is accelerated simulation, not real-time eight-hour reliability evidence.

Usage:
    ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test \
        python -m unittest integration.test_endurance_postgres -v
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import json
import os
import subprocess
import sys
import unittest
import uuid

# Capture the integration environment before importing ``tests.endurance_harness``:
# the offline ``tests`` package intentionally replaces process secrets and
# DATABASE_URL with isolated defaults when imported.
_ENV_KEYS = ("DATABASE_URL", "SECRET_KEY", "FERNET_KEY", "KALI_AGENT_TOKEN")
_ORIGINAL_ENV = {key: os.environ.get(key) for key in _ENV_KEYS}
ENABLED = os.environ.get("ARIA_INTEGRATION") == "1"
_INTEGRATION_DATABASE_URL = os.environ.get("DATABASE_URL", "")
TARGET = "192.0.2.15"

from fastapi import HTTPException
from sqlalchemy import delete, func, select, text

from llm.engagement_budget import (
    ModelAccounting, ModelLimits, engagement_context,
)
from memory.campaign_observability import HEALTH_SCHEMA, MAX_EVENTS
from memory.campaign_store import (
    TERMINAL_STATES, CampaignBudget, CampaignSchedule, CampaignSpec,
)
from orchestrator.campaign_execution import (
    CampaignExecutionDenied, require_campaign_execution,
)
from orchestrator.campaign_supervisor import CampaignSupervisor
from tests.endurance_harness import (
    EnginePlan, PostgresAccounting, SimulatedClock, SyntheticEngine,
    SyntheticWorker, monday_start, simulated_runtime_settings, simulated_datetime,
)

# Importing the offline tests package sets its own isolated defaults.  Restore
# the integration environment so other integration modules (and alembic
# subprocesses) in the same unittest process remain pointed at the disposable
# database.
for _key, _value in _ORIGINAL_ENV.items():
    if _value is None:
        os.environ.pop(_key, None)
    else:
        os.environ[_key] = _value


class PostgresRig:
    """Synthetic run, worker and provider wired to the real PostgreSQL store."""

    TICK_SECONDS = 300
    LEASE_SECONDS = 600

    def __init__(self, *, owner_id: str, session_id: str, scope: dict,
                 digest: str, plan: EnginePlan, max_retries: int = 3,
                 max_tokens: int = 200_000,
                 max_cost_microusd: int = 2_000_000,
                 report_tokens="auto",
                 use_default_worker_resume: bool = False):
        from memory.campaign_store import SQLCampaignBackend

        self.owner_id = owner_id
        self.session_id = session_id
        self.clock = SimulatedClock(monday_start())
        self.store = SQLCampaignBackend()
        self.context = {
            "owner_id": owner_id,
            "scope": copy.deepcopy(scope),
            "target": TARGET,
            "scope_digest": digest,
            "auth_revision": 0,
            "worker_epoch": 0,
            "worker_blocked": False,
        }
        self.plan = plan
        self.worker = SyntheticWorker(self.store, self._context, self.clock)
        self.accounting = PostgresAccounting(
            session_id=session_id, owner_id=owner_id, clock=self.clock,
            report_tokens=report_tokens)
        self.engine = SyntheticEngine(
            store=self.store, accounting=self.accounting, worker=self.worker,
            context_loader=self._context, clock=self.clock, plan=plan)
        self._worker_resume_impl = (None if use_default_worker_resume
                                    else self._resume_worker)
        self.spec = CampaignSpec(
            session_id=session_id, owner_id=owner_id, goal="discovery",
            target=TARGET, skill_level="expert",
            objective="Synthetic SPEC-15 endurance campaign",
            max_steps=max(plan.max_steps, plan.required_successful_steps),
            auto_risk_threshold="green_orange",
            schedule=CampaignSchedule(
                timezone="UTC", weekdays=[0, 1, 2, 3, 4],
                window_start="09:00", window_end="17:00",
                daily_runtime_seconds=28800),
            budget=CampaignBudget(
                max_tokens=max_tokens, max_cost_microusd=max_cost_microusd),
            max_retries=max_retries, scope_digest=digest,
            auth_revision=0, worker_epoch=0,
            required_tools=["curl", "nmap"])
        self.supervisor = self.new_supervisor()
        self.campaign_id: str | None = None

    # ── Collaborators ───────────────────────────────────────────────────
    async def _context(self, owner_id, session_id):
        return copy.deepcopy(self.context)

    async def _capabilities(self):
        return {"tools": ["curl", "nmap"]}

    async def _planner_preflight(self, owner_id, session_id):
        return {"ready": True}

    async def _resume_worker(self, owner_id, session_id):
        return None

    def new_supervisor(self) -> CampaignSupervisor:
        return CampaignSupervisor(
            store=self.store, engine=self.engine,
            context_loader=self._context, capabilities=self._capabilities,
            planner_preflight=self._planner_preflight,
            worker_resume=self._worker_resume_impl, clock=self.clock)

    # ── Simulation ──────────────────────────────────────────────────────
    async def create(self) -> dict:
        row = await self.store.create(self.spec)
        self.campaign_id = row["id"]
        return row

    async def tick(self) -> None:
        now = self.clock()
        await self.supervisor.tick(now)
        await self.engine.advance(self.TICK_SECONDS)
        self.clock.advance(self.TICK_SECONDS)

    def crash(self) -> None:
        """Lose process-local state; advance simulated time past the lease."""
        self.engine.crash()
        self.supervisor = self.new_supervisor()
        self.clock.advance(self.LEASE_SECONDS + 5)

    async def row(self) -> dict:
        return await self.store.get(self.campaign_id)


@unittest.skipUnless(ENABLED, "set ARIA_INTEGRATION=1 with a disposable *_test database")
class CampaignEndurancePostgres(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        url = make_url(_INTEGRATION_DATABASE_URL)
        if not (url.database or "").endswith("_test"):
            raise RuntimeError("integration requires a disposable database named *_test")
        env = {**os.environ, "DATABASE_URL": _INTEGRATION_DATABASE_URL}
        subprocess.run([sys.executable, "-B", "-m", "alembic", "upgrade", "head"],
                       check=True, env=env)

    async def asyncSetUp(self):
        from memory.database_models import (
            PentestSession, User, async_session, engine,
        )
        await engine.dispose()
        from memory.knowledge_store import scope_identity_digest

        self.owner_id = "spec15-o-" + uuid.uuid4().hex[:12]
        self.session_id = "spec15-s-" + uuid.uuid4().hex[:12]
        self.scope = {"targets": [TARGET]}
        self.digest = scope_identity_digest(self.scope, TARGET)
        async with async_session() as db:
            db.add(User(id=self.owner_id,
                        username="u-" + uuid.uuid4().hex[:20],
                        password_hash="unused"))
            await db.flush()
            db.add(PentestSession(
                id=self.session_id, user_id=self.owner_id, target=TARGET,
                scope=copy.deepcopy(self.scope), metadata_={}))
            await db.commit()
        self.model_accounting = ModelAccounting()
        await self.model_accounting.configure(
            self.session_id, self.owner_id,
            ModelLimits(max_calls=50, max_tokens=10_000_000,
                        max_cost_microusd=1_000_000_000, tariffs=[]))

    async def asyncTearDown(self):
        from memory.database_models import (
            AutonomousCampaign, DecisionLog, PentestSession, User,
            async_session, engine,
        )
        try:
            async with async_session() as db:
                await db.execute(delete(DecisionLog).where(
                    DecisionLog.session_id == self.session_id))
                await db.execute(delete(AutonomousCampaign).where(
                    AutonomousCampaign.session_id == self.session_id))
                await db.execute(delete(PentestSession).where(
                    PentestSession.id == self.session_id))
                await db.execute(delete(User).where(User.id == self.owner_id))
                await db.commit()
        finally:
            await engine.dispose()

    # ── Fixtures ────────────────────────────────────────────────────────
    def _rig(self, plan: EnginePlan | None = None, **overrides) -> PostgresRig:
        return PostgresRig(
            owner_id=self.owner_id, session_id=self.session_id,
            scope=self.scope, digest=self.digest,
            plan=plan or EnginePlan(), **overrides)

    @contextmanager
    def _simulation(self, rig: PostgresRig):
        with simulated_runtime_settings(tick_seconds=rig.TICK_SECONDS,
                lease_seconds=rig.LEASE_SECONDS), \
             simulated_datetime(rig.clock, campaign_store=True):
            yield

    async def _tick_until(self, rig: PostgresRig, predicate, *,
                          limit: int = 8) -> None:
        for _ in range(limit):
            if predicate():
                return
            await rig.tick()
        if not predicate():
            self.fail("synthetic campaign condition was not reached")

    async def _db_metrics(self) -> tuple[int, int]:
        from memory.database_models import DecisionLog, async_session
        async with async_session() as db:
            size = int((await db.execute(text(
                "SELECT pg_total_relation_size('autonomous_campaigns')"
            ))).scalar_one())
            count = int((await db.execute(
                select(func.count()).select_from(DecisionLog).where(
                    DecisionLog.session_id == self.session_id)
            )).scalar_one())
        return size, count

    async def _complete(self, rig: PostgresRig, *, limit: int = 12) -> dict:
        row = await rig.row()
        for _ in range(limit):
            if row["state"] in TERMINAL_STATES:
                return row
            await rig.tick()
            row = await rig.row()
        return row

    # ── Tests ───────────────────────────────────────────────────────────
    async def test_synthetic_campaign_completes_and_durable_state_stays_bounded(self):
        rig = self._rig(EnginePlan(
            required_successful_steps=4, step_interval_seconds=300,
            max_steps=12))
        size_before, logs_before = await self._db_metrics()
        with self._simulation(rig):
            await rig.create()
            row = await self._complete(rig)
        size_after, logs_after = await self._db_metrics()

        self.assertEqual(row["state"], "completed")
        self.assertEqual(row["reason_code"], "completed")
        self.assertEqual(len(rig.accounting.provider_calls), 4)
        self.assertEqual(len(rig.worker.dispatches), 4)
        self.assertEqual(rig.worker.duplicates, [])
        self.assertEqual(rig.worker.denied, [])
        self.assertEqual(len(rig.engine.steps), 4)
        self.assertEqual(row["usage"]["calls"], 4)
        reserved = sum(call.tokens for call in rig.accounting.provider_calls)
        self.assertEqual(row["usage"]["reserved_tokens"], reserved)
        self.assertEqual(row["usage"]["reported_tokens"], reserved)
        self.assertEqual(row["usage"]["unknown_usage_calls"], 0)
        self.assertEqual(row["retry"]["count"], 0)
        self.assertEqual(
            len({job["work_key"] for job in rig.worker.dispatches}), 4)

        events = row["operations"]["events"]
        self.assertLessEqual(len(events), MAX_EVENTS)
        self.assertIn("campaign_completed", {event["event"] for event in events})
        self.assertTrue(any(event["event"] == "campaign_step_succeeded"
                            for event in events))
        sequences = [event["sequence"] for event in events]
        self.assertEqual(sequences, sorted(set(sequences)))

        # One synthetic campaign must not grow the durable store without bound.
        self.assertLess(size_after - size_before, 1_000_000)
        self.assertGreaterEqual(logs_after - logs_before, 4)
        self.assertLessEqual(logs_after - logs_before, 20)
        self.assertLess(len(json.dumps(row, default=str)), 100_000)

        health = await rig.supervisor.health(
            rig.campaign_id, rig.owner_id, rig.clock())
        self.assertEqual(health["schema"], HEALTH_SCHEMA)
        self.assertEqual(health["state"], "completed")
        self.assertTrue(health["accounting"]["consistent"])
        self.assertFalse(health["accounting"]["issues"])
        self.assertEqual(health["metrics"]["operations_retained"], len(events))
        self.assertLessEqual(health["metrics"]["operations_retained"], MAX_EVENTS)
        self.assertIn("campaign_completed",
                      {alert["code"] for alert in health["alerts"]})

    async def test_repeated_lease_crashes_recover_without_duplicate_dispatch(self):
        rig = self._rig(
            EnginePlan(required_successful_steps=10,
                       step_interval_seconds=300, max_steps=12),
            max_retries=2)
        with self._simulation(rig):
            await rig.create()
            await rig.tick()
            await rig.tick()  # The supervisor observes the first durable step.
            first_run_id = rig.engine.checkpoints[self.session_id]["run_id"]

            for _ in range(3):
                before_crash = await rig.row()
                crashed_token = before_crash["lease_holder"]
                self.assertTrue(crashed_token)
                rig.crash()
                recovered = await rig.supervisor.recover(rig.clock())
                self.assertIn(rig.campaign_id, recovered)
                row = await rig.row()
                self.assertEqual(row["state"], "scheduled")
                self.assertEqual(row["reason_code"], "supervisor_restart")
                self.assertEqual(row["retry"]["count"], 1)

                target = len(rig.engine.steps) + 1
                await self._tick_until(
                    rig, lambda value=target: len(rig.engine.steps) >= value,
                    limit=6)
                await rig.tick()  # Observe progress; clear the retry streak.
                row = await rig.row()
                self.assertEqual(row["retry"]["count"], 0)
                self.assertNotIn(row["state"], TERMINAL_STATES)

                # The live lease admits its holder; the crashed token is denied.
                await require_campaign_execution(
                    campaign_id=rig.campaign_id, token=row["lease_holder"],
                    session_id=self.session_id, owner_id=self.owner_id,
                    scope_digest=self.digest, auth_revision=0, worker_epoch=0,
                    loader=rig.store.get, context_loader=rig._context)
                with self.assertRaises(CampaignExecutionDenied) as denial:
                    await require_campaign_execution(
                        campaign_id=rig.campaign_id, token=crashed_token,
                        session_id=self.session_id, owner_id=self.owner_id,
                        scope_digest=self.digest, auth_revision=0,
                        worker_epoch=0, loader=rig.store.get,
                        context_loader=rig._context)
                self.assertEqual(denial.exception.code,
                                 "campaign_supervisor_required")

            row = await self._complete(rig, limit=12)

        self.assertEqual(row["state"], "completed")
        self.assertEqual(row["retry"]["count"], 0)
        self.assertEqual(rig.engine.checkpoints[self.session_id]["run_id"],
                         first_run_id)
        self.assertEqual(len(rig.engine.steps), 10)
        self.assertEqual(len(rig.worker.dispatches), 10)
        self.assertEqual(rig.worker.duplicates, [])
        self.assertEqual(rig.worker.denied, [])
        self.assertEqual(len(rig.accounting.provider_calls), 10)
        self.assertEqual(row["usage"]["calls"], 10)
        self.assertEqual(len({job["work_key"] for job in rig.worker.dispatches}),
                         10)
        events = row["operations"]["events"]
        self.assertLessEqual(len(events), MAX_EVENTS)
        self.assertTrue(any(event["event"] == "campaign_recovered"
                            for event in events))

    async def test_campaign_budget_denial_prevents_every_dispatch(self):
        rig = self._rig(
            EnginePlan(required_successful_steps=4,
                       step_interval_seconds=300, max_steps=12),
            max_tokens=5_000, max_retries=1)
        with self._simulation(rig):
            await rig.create()
            await rig.tick()  # Start, then the first reservation is denied.
            await rig.tick()  # The supervisor records the terminal failure.
            row = await rig.row()

        self.assertEqual(row["state"], "failed")
        self.assertEqual(row["reason_code"], "campaign_budget_exhausted")
        self.assertEqual(len(rig.accounting.provider_calls), 0)
        self.assertEqual(len(rig.accounting.attempts), 0)
        self.assertEqual(len(rig.worker.dispatches), 0)
        self.assertEqual(rig.engine.steps, [])
        self.assertEqual(row["usage"]["calls"], 0)
        self.assertEqual(row["usage"]["reserved_tokens"], 0)
        self.assertEqual(len(rig.accounting.denials), 1)
        denial = rig.accounting.denials[0]
        self.assertEqual(denial["status"], 429)
        self.assertEqual(denial["code"], "campaign_budget_exhausted")

    async def test_unknown_provider_usage_fails_closed(self):
        rig = self._rig(
            EnginePlan(required_successful_steps=4,
                       step_interval_seconds=300, max_steps=12),
            report_tokens=None)
        with self._simulation(rig):
            await rig.create()
            await rig.tick()
            await rig.tick()
            row = await rig.row()

        self.assertEqual(row["state"], "failed")
        self.assertEqual(row["reason_code"], "campaign_accounting_inconsistent")
        self.assertEqual(len(rig.accounting.provider_calls), 1)
        self.assertEqual(len(rig.worker.dispatches), 1)
        self.assertTrue(row["usage"]["stopped"])
        self.assertEqual(row["usage"]["stop_reason"], "unknown_usage")
        self.assertEqual(row["usage"]["unknown_usage_calls"], 1)

        summary = await self.model_accounting.usage_summary(
            self.session_id, self.owner_id)
        self.assertTrue(summary["stopped"])
        self.assertEqual(summary["stop_reason"], "unknown_usage")

        token = engagement_context.set(
            {"session_id": self.session_id, "owner": self.owner_id})
        try:
            with self.assertRaises(HTTPException) as denial:
                await self.model_accounting.reserve(
                    self.owner_id, "local", "endurance-synthetic", "next", "")
        finally:
            engagement_context.reset(token)
        self.assertEqual(denial.exception.status_code, 409)
        self.assertEqual(denial.exception.detail["code"],
                         "model_accounting_inconsistent")
        self.assertEqual(len(rig.accounting.provider_calls), 1)

    async def test_unresolved_worker_cancellation_fails_before_starting(self):
        from memory.database_models import (
            DecisionLog, PentestSession, async_session,
        )

        async with async_session() as db:
            session = await db.get(PentestSession, self.session_id)
            session.metadata_ = {
                **(session.metadata_ or {}), "worker_blocked": True}
            db.add(DecisionLog(
                id=str(uuid.uuid4()), session_id=self.session_id,
                user_id=self.owner_id, decision_type="worker_job",
                metadata_={"session_id": self.session_id,
                           "job_id": uuid.uuid4().hex,
                           "state": "cancel_requested"}))
            await db.commit()

        rig = self._rig(
            EnginePlan(required_successful_steps=4,
                       step_interval_seconds=300, max_steps=12),
            max_retries=0, use_default_worker_resume=True)
        with self._simulation(rig):
            await rig.create()
            await rig.tick()
            row = await rig.row()

        self.assertEqual(row["state"], "failed")
        self.assertEqual(row["reason_code"], "retry_exhausted")
        self.assertIn("authorization_unavailable", row["reason"])
        self.assertEqual(rig.engine.calls, [])
        self.assertEqual(len(rig.accounting.provider_calls), 0)
        self.assertEqual(len(rig.worker.dispatches), 0)

        async with async_session() as db:
            session = await db.get(PentestSession, self.session_id)
            self.assertTrue(session.metadata_["worker_blocked"])


if __name__ == "__main__":
    unittest.main()
