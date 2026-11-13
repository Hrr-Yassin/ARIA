"""SPEC-12 PostgreSQL campaign integration tests; synthetic data only.

Requires a disposable database ending in *_test:
    ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test \
        python -m unittest integration.test_campaign_postgres -v
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
class CampaignPostgres(unittest.IsolatedAsyncioTestCase):
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
        owner_id = "spec12-o-" + uuid.uuid4().hex[:12]
        session_id = "spec12-s-" + uuid.uuid4().hex[:12]
        async with async_session() as db:
            db.add(User(id=owner_id, username="u-" + uuid.uuid4().hex[:16],
                        password_hash="unused"))
            await db.flush()
            db.add(PentestSession(id=session_id, user_id=owner_id,
                                  target="192.0.2.2",
                                  scope={"targets": ["192.0.2.2"]}))
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
            "target": "192.0.2.2",
            "skill_level": "expert",
            "objective": "Synthetic comprehensive campaign integration test",
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

    async def _activate(self, store, owner, session_id, **overrides):
        """Create a campaign and move it into ``running`` under a live lease."""
        from datetime import datetime, timezone
        campaign = await store.create(self._spec(owner, session_id, **overrides))
        claim = await store.claim(campaign["id"], "lease-" + self.token,
                                  datetime.now(timezone.utc), 3600)
        self.assertIsNotNone(claim)
        running = await store.transition(
            campaign["id"], "lease-" + self.token, datetime.now(timezone.utc),
            {"scheduled"}, {"state": "running"}, event="campaign_started")
        self.assertIsNotNone(running)
        return running

    async def test_one_active_campaign_per_engagement(self):
        from memory.campaign_store import CampaignConflict
        store = self._store()
        owner, session_id = await self._session()
        first = await store.create(self._spec(owner, session_id))
        self.assertEqual(first["state"], "scheduled")
        self.assertEqual(first["active_key"], session_id)

        with self.assertRaises(CampaignConflict):
            await store.create(self._spec(owner, session_id))
        second_session_owner, second_session = await self._session()
        await store.create(self._spec(second_session_owner, second_session))

        claim = await store.claim(first["id"], "lease-" + self.token,
                                  datetime.now(UTC), 60)
        await store.transition(first["id"], "lease-" + self.token,
                               datetime.now(UTC), {"scheduled"},
                               {"state": "cancelled"}, event="campaign_cancelled")
        stored = await store.get(first["id"])
        self.assertIsNone(stored["active_key"])
        self.assertIsNotNone(stored["ended_at"])
        self.assertIsNone(await store.latest_active_for_session(session_id))

        replacement = await store.create(self._spec(owner, session_id))
        self.assertEqual(replacement["state"], "scheduled")
        self.assertNotEqual(replacement["id"], first["id"])

    async def test_claim_leases_are_exclusive_and_recoverable(self):
        store = self._store()
        owner, session_id = await self._session()
        campaign = await store.create(self._spec(owner, session_id))
        now = datetime.now(UTC)
        won = await store.claim(campaign["id"], "lease-a-" + self.token,
                                now, 60)
        self.assertIsNotNone(won)
        self.assertIsNone(await store.claim(campaign["id"],
                                            "lease-b-" + self.token, now, 60))

        await store.release(campaign["id"], "lease-a-" + self.token)
        reclaimed = await store.claim(campaign["id"], "lease-b-" + self.token,
                                      now, 60)
        self.assertIsNotNone(reclaimed)
        self.assertEqual(reclaimed["lease_holder"], "lease-b-" + self.token)

        # An expired lease may be claimed by a different supervisor process.
        later = now + timedelta(seconds=61)
        takeover = await store.claim(campaign["id"], "lease-c-" + self.token,
                                     later, 60)
        self.assertIsNotNone(takeover)
        self.assertEqual(takeover["lease_holder"], "lease-c-" + self.token)

    async def test_concurrent_claims_have_exactly_one_winner(self):
        store = self._store()
        owner, session_id = await self._session()
        campaign = await store.create(self._spec(owner, session_id))
        now = datetime.now(UTC)
        results = await asyncio.gather(
            store.claim(campaign["id"], "lease-a-" + self.token, now, 60),
            store.claim(campaign["id"], "lease-b-" + self.token, now, 60),
        )
        winners = [item for item in results if item is not None]
        self.assertEqual(len(winners), 1)
        stored = await store.get(campaign["id"])
        self.assertEqual(stored["lease_holder"], winners[0]["lease_holder"])

    async def test_campaign_budget_reservation_is_atomic(self):
        from fastapi import HTTPException
        from memory.campaign_store import reserve_campaign_usage
        from memory.database_models import async_session
        store = self._store()
        owner, session_id = await self._session()
        campaign = await self._activate(
            store, owner, session_id,
            budget={"max_tokens": 100, "max_cost_microusd": 1000})

        async def reserve(tokens, cost):
            async with async_session() as db:
                result = await reserve_campaign_usage(
                    db, campaign_id=campaign["id"], session_id=session_id,
                    owner_id=owner, tokens=tokens, cost_microusd=cost)
                await db.commit()
                return result

        results = await asyncio.gather(reserve(60, 600), reserve(60, 600),
                                       return_exceptions=True)
        successes = [item for item in results if isinstance(item, dict)]
        denials = [item for item in results
                   if isinstance(item, HTTPException)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0].status_code, 429)
        self.assertEqual(denials[0].detail["code"],
                         "campaign_budget_exhausted")

        stored = await store.get(campaign["id"])
        self.assertEqual(stored["usage"]["reserved_tokens"], 60)
        self.assertEqual(stored["usage"]["reserved_cost_microusd"], 600)
        self.assertEqual(stored["usage"]["calls"], 1)

        # A zero-cost read-only check neither mutates nor over-reserves.
        check = await store.check_budget(campaign["id"], session_id, owner)
        self.assertTrue(check["ready"])
        self.assertEqual(check["remaining_tokens"], 40)
        self.assertEqual((await store.get(campaign["id"]))["usage"]["calls"], 1)

        with self.assertRaises(HTTPException) as error:
            await reserve(41, 0)
        self.assertEqual(error.exception.status_code, 429)

    async def test_campaign_budget_fails_closed_on_bad_or_terminal_state(self):
        from fastapi import HTTPException
        from memory.campaign_store import reserve_campaign_usage
        from memory.database_models import AutonomousCampaign, async_session
        store = self._store()
        owner, session_id = await self._session()
        campaign = await self._activate(store, owner, session_id)

        async with async_session() as db:
            row = await db.get(AutonomousCampaign, campaign["id"])
            row.usage = {"reserved_tokens": "not-an-integer"}
            await db.commit()
        async with async_session() as db:
            with self.assertRaises(HTTPException) as error:
                await reserve_campaign_usage(
                    db, campaign_id=campaign["id"], session_id=session_id,
                    owner_id=owner, tokens=1, cost_microusd=1)
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(error.exception.detail["code"],
                         "campaign_budget_unavailable")

        # A terminal campaign never accepts another model call.
        await store.transition(campaign["id"], "lease-" + self.token,
                               datetime.now(UTC), {"running"},
                               {"state": "completed"}, event="campaign_completed")
        async with async_session() as db:
            with self.assertRaises(HTTPException) as error:
                await reserve_campaign_usage(
                    db, campaign_id=campaign["id"], session_id=session_id,
                    owner_id=owner, tokens=1, cost_microusd=1)
        self.assertEqual(error.exception.status_code, 409)

    async def test_transitions_are_audited_and_terminal_state_frees_the_session(self):
        from sqlalchemy import select
        from memory.campaign_store import CampaignValidationError
        from memory.database_models import DecisionLog, async_session
        store = self._store()
        owner, session_id = await self._session()
        campaign = await self._activate(store, owner, session_id)

        with self.assertRaises(CampaignValidationError):
            await store.transition(campaign["id"], "lease-" + self.token,
                                   datetime.now(UTC), {"running"},
                                   {"state": "not-a-state"})
        # The invalid transition rolled back without changing durable state.
        self.assertEqual((await store.get(campaign["id"]))["state"], "running")

        completed = await store.transition(
            campaign["id"], "lease-" + self.token, datetime.now(UTC),
            {"running"}, {"state": "completed"}, event="campaign_completed",
            event_reason_code="run_completed", event_reason="Synthetic completion")
        self.assertEqual(completed["state"], "completed")
        self.assertIsNone(completed["active_key"])
        self.assertIsNone(completed["lease_holder"])
        self.assertIsNone(completed["next_action_at"])
        self.assertIsNotNone(completed["ended_at"])

        async with async_session() as db:
            events = (await db.execute(select(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == "campaign_event").order_by(
                DecisionLog.created_at.asc()))).scalars().all()
        names = [event.metadata_.get("event") for event in events]
        self.assertIn("campaign_created", names)
        self.assertIn("campaign_started", names)
        self.assertIn("campaign_completed", names)
        completed_event = [event for event in events
                           if event.metadata_.get("event") == "campaign_completed"][0]
        self.assertEqual(completed_event.metadata_["from_state"], "running")
        self.assertEqual(completed_event.metadata_["to_state"], "completed")
        self.assertEqual(completed_event.metadata_["campaign_id"], campaign["id"])

    async def test_recovery_backs_off_instead_of_restarting(self):
        from memory.campaign_store import utc_naive
        store = self._store()
        owner, session_id = await self._session()
        now = datetime.now(UTC)
        campaign = await self._activate(store, owner, session_id)
        usage = dict(campaign["usage"])
        usage["active_since"] = (now - timedelta(seconds=10)).isoformat()
        # Simulate the supervisor process having died: the durable state still
        # says running, but no lease is held any more.
        await store.transition(campaign["id"], "lease-" + self.token, now,
                               {"running"},
                               {"usage": usage, "release_lease": True})

        later = now + timedelta(seconds=65)
        recovered = await store.recover(now=later)
        self.assertIn(campaign["id"], recovered)
        stored = await store.get(campaign["id"])
        self.assertEqual(stored["state"], "scheduled")
        self.assertEqual(stored["reason_code"], "supervisor_restart")
        self.assertEqual(stored["retry"]["count"], 1)
        self.assertIsNone(stored["lease_holder"])
        self.assertIsNotNone(stored["next_action_at"])
        self.assertGreaterEqual(stored["usage"]["runtime_seconds"], 15)
        self.assertIsNone(stored["usage"]["active_since"])

        # Recovery never resumed the run: it only scheduled a validated restart.
        self.assertIsNone(stored["run_id"])
        self.assertTrue(stored["next_action_at"] >= utc_naive(later))

    async def test_recovery_of_pausing_and_cancelling_campaigns(self):
        store = self._store()
        owner, session_id = await self._session()
        now = datetime.now(UTC)
        campaign = await self._activate(store, owner, session_id,
                                        max_retries=0)

        await store.transition(campaign["id"], "lease-" + self.token, now,
                               {"running"},
                               {"state": "pausing",
                                "pause_reason": "daily_limit",
                                "release_lease": True})
        recovered = await store.recover(
            now=now + timedelta(seconds=61))
        self.assertIn(campaign["id"], recovered)
        paused = await store.get(campaign["id"])
        self.assertEqual(paused["state"], "paused")
        self.assertTrue(paused["auto_resume"])
        self.assertIsNone(paused["lease_holder"])
        self.assertIsNotNone(paused["next_action_at"])

        await store.claim(campaign["id"], "lease-2-" + self.token,
                          now + timedelta(seconds=120), 3600)
        await store.transition(campaign["id"], "lease-2-" + self.token,
                               now + timedelta(seconds=120), {"paused"},
                               {"state": "cancelling"})
        recovered = await store.recover(now=now + timedelta(seconds=4000))
        self.assertIn(campaign["id"], recovered)
        cancelled = await store.get(campaign["id"])
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertIsNone(cancelled["active_key"])
        self.assertIsNone(cancelled["lease_holder"])
        self.assertIsNotNone(cancelled["ended_at"])

    async def test_recovery_leaves_a_live_lease_untouched(self):
        store = self._store()
        owner, session_id = await self._session()
        campaign = await self._activate(store, owner, session_id)
        await store.recover(now=datetime.now(UTC))
        stored = await store.get(campaign["id"])
        self.assertEqual(stored["state"], "running")
        self.assertEqual(stored["lease_holder"], "lease-" + self.token)

    async def test_retry_exhaustion_fails_closed(self):
        store = self._store()
        owner, session_id = await self._session()
        now = datetime.now(UTC)
        campaign = await self._activate(store, owner, session_id, max_retries=0)
        await store.release(campaign["id"], "lease-" + self.token)
        await store.recover(now=now + timedelta(seconds=61))
        stored = await store.get(campaign["id"])
        self.assertEqual(stored["state"], "failed")
        self.assertEqual(stored["reason_code"], "retry_exhausted")
        self.assertIsNone(stored["active_key"])

    async def test_due_scheduling_and_paused_auto_resume(self):
        store = self._store()
        owner, session_id = await self._session()
        now = datetime.now(UTC)
        past = now - timedelta(seconds=5)
        campaign = await store.create(self._spec(owner, session_id))
        await store.claim(campaign["id"], "lease-" + self.token, now, 60)
        await store.record_activity(campaign["id"], "lease-" + self.token,
                                    now, next_action_at=past)
        due = await store.due(now)
        self.assertIn(campaign["id"], [item["id"] for item in due])
        await store.release(campaign["id"], "lease-" + self.token)

        await store.claim(campaign["id"], "lease-" + self.token, now, 60)
        await store.transition(
            campaign["id"], "lease-" + self.token, now, {"scheduled"},
            {"state": "paused", "auto_resume": True,
             "next_action_at": past, "release_lease": True})
        due = await store.due(now)
        self.assertIn(campaign["id"], [item["id"] for item in due])

        await store.claim(campaign["id"], "lease-" + self.token, now, 60)
        await store.transition(
            campaign["id"], "lease-" + self.token, now, {"paused"},
            {"state": "paused", "auto_resume": False,
             "next_action_at": past, "release_lease": True})
        due = await store.due(now)
        self.assertNotIn(campaign["id"], [item["id"] for item in due])

    async def test_session_binding_survives_stale_terminal_markers(self):
        from memory.database_models import PentestSession, async_session
        store = self._store()
        owner, session_id = await self._session()
        first = await store.create(self._spec(owner, session_id))
        await store.bind_session(session_id, owner, first["id"])
        async with async_session() as db:
            session = await db.get(PentestSession, session_id)
            self.assertEqual(session.metadata_["active_campaign_id"], first["id"])

        await store.claim(first["id"], "lease-" + self.token, datetime.now(UTC), 60)
        await store.transition(first["id"], "lease-" + self.token,
                               datetime.now(UTC), {"scheduled"},
                               {"state": "cancelled"})
        second = await store.create(self._spec(owner, session_id))
        await store.bind_session(session_id, owner, second["id"])
        async with async_session() as db:
            session = await db.get(PentestSession, session_id)
            self.assertEqual(session.metadata_["active_campaign_id"], second["id"])

        await store.unbind_session(session_id, owner, second["id"])
        async with async_session() as db:
            session = await db.get(PentestSession, session_id)
            self.assertNotIn("active_campaign_id", session.metadata_ or {})

    async def test_status_exposes_schedule_runtime_and_budget(self):
        from memory.campaign_store import campaign_status
        store = self._store()
        owner, session_id = await self._session()
        campaign = await store.create(self._spec(owner, session_id))
        status = campaign_status(campaign, datetime.now(UTC))
        self.assertFalse(status.get("invalid", False))
        self.assertEqual(status["state"], "scheduled")
        self.assertEqual(status["schedule"]["timezone"], "UTC")
        self.assertIn("within_window", status["schedule"])
        self.assertIn("next_window_open", status["schedule"])
        self.assertEqual(status["runtime"]["daily_seconds"], 0)
        self.assertEqual(status["budget"]["remaining_tokens"], 1000000)
        self.assertEqual(status["supervisor"]["next_action_at"],
                         status["next_execution_at"])
        self.assertFalse(status["budget"]["stopped"])

    def _store(self):
        from memory.campaign_store import SQLCampaignBackend
        return SQLCampaignBackend()


if __name__ == "__main__":
    unittest.main()
