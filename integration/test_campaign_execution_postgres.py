"""SPEC-13.2 PostgreSQL campaign execution-boundary tests; synthetic data.

Requires a disposable database ending in *_test:
    ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test \
        python -m unittest integration.test_campaign_execution_postgres -v
"""
import hashlib
import os
import subprocess
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi import HTTPException

ENABLED = os.environ.get("ARIA_INTEGRATION") == "1"
UTC = timezone.utc


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


@unittest.skipUnless(ENABLED, "set ARIA_INTEGRATION=1 with a disposable *_test database")
class CampaignExecutionPostgres(unittest.IsolatedAsyncioTestCase):
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
        from memory.team_tasks import team_store
        self.token = uuid.uuid4().hex[:8]
        self.store = team_store
        await engine.dispose()

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    async def _engagement(self):
        from memory.database_models import (
            DecisionLog, PentestSession, User, async_session,
        )
        from memory.worker_jobs import SQLJobStore
        owner = "spec132-o-" + uuid.uuid4().hex[:12]
        session_id = "spec132-s-" + uuid.uuid4().hex[:12]
        job_id = "spec132-job-" + uuid.uuid4().hex[:12]
        scope = {"targets": ["192.0.2.1"],
                 "web_authenticated_replay": True,
                 "web_specialist_profiles": True}
        async with async_session() as db:
            db.add(User(id=owner, username="u-" + uuid.uuid4().hex[:16],
                        password_hash="unused"))
            await db.flush()
            db.add(PentestSession(id=session_id, user_id=owner,
                                  target="192.0.2.1", scope=scope))
            await db.flush()
            db.add(DecisionLog(
                id=SQLJobStore.key(job_id), session_id=session_id, user_id=owner,
                decision_type="worker_job",
                metadata_={"job_id": job_id, "session_id": session_id,
                           "user_id": owner, "state": "succeeded",
                           "exit_code": 0, "output_hash": _sha("synthetic stdout"),
                           "stderr_hash": _sha("")}))
            await db.commit()
        return owner, session_id, job_id, scope

    def _campaign_spec(self, owner, session_id, scope_digest):
        from memory.campaign_store import (
            CampaignSchedule, CampaignSpec, default_budget, default_schedule,
        )
        return CampaignSpec(
            session_id=session_id, owner_id=owner, goal="http_check",
            target="192.0.2.1", skill_level="expert",
            objective="Synthetic campaign execution boundary test",
            max_steps=12, auto_risk_threshold="green_orange",
            schedule=CampaignSchedule.model_validate(default_schedule()),
            budget=default_budget(),
            max_retries=3, scope_digest=scope_digest,
            required_tools=["curl"])

    async def _campaign(self, owner, session_id, scope_digest, *,
                        token=None, lease_seconds=3600, lease_now=None):
        from memory.campaign_store import campaign_store
        token = token or "lease-" + self.token
        campaign = await campaign_store.create(
            self._campaign_spec(owner, session_id, scope_digest))
        claimed = await campaign_store.claim(
            campaign["id"], token, lease_now or datetime.now(UTC),
            lease_seconds)
        self.assertIsNotNone(claimed)
        running = await campaign_store.transition(
            campaign["id"], token, datetime.now(UTC), {"scheduled"},
            {"state": "running"}, event="campaign_started")
        self.assertIsNotNone(running)
        return campaign["id"], token

    async def _evidence(self, owner, session_id, job_id):
        from memory.team_tasks import EvidenceInput
        event = await self.store.catalog(
            session_id, owner,
            EvidenceInput(request_id=uuid.uuid4(), source_kind="worker",
                          source_id=job_id))
        return event["data"]["id"]

    async def _task(self, owner, session_id, campaign_id, evidence_id, seed):
        from memory.team_tasks import (
            CreateTask, TaskBudget, TaskSpec,
        )
        spec = TaskSpec(
            owner_role="web_intel",
            objective="Review saved evidence only",
            evidence_inputs=[evidence_id],
            budget=TaskBudget(max_attempts=1, max_model_calls=1,
                              max_tokens=10000),
            expected_output="Evidence-linked unverified observations",
            completion_criteria=["Cite saved evidence or uncertainty"],
            phase="vulnerability_analysis", specialty="exposure",
            security_questions=["exposure:http-response"])
        event = await self.store.create_investigation(
            session_id, owner, CreateTask(request_id=uuid.uuid4(), task=spec),
            campaign_id=campaign_id,
            investigation_key=_sha("spec132:" + seed + ":" + str(uuid.uuid4())))
        return event["entity_id"]

    async def _context(self, owner, session_id):
        from memory.execution_authorization import authoritative_context
        return await authoritative_context(owner, session_id)

    async def _run(self, coordinator, specialist, session_id, owner, task_id,
                   campaign_id, token, context, **overrides):
        values = {
            "campaign_id": campaign_id, "campaign_supervisor_token": token,
            "scope_digest": context["scope_digest"],
            "auth_revision": context["auth_revision"],
            "worker_epoch": context["worker_epoch"],
        }
        values.update(overrides)
        with patch.object(coordinator, "specialists",
                          return_value={"web_intel": specialist}):
            return await coordinator.run(
                session_id, owner, task_id, str(uuid.uuid4()), "expert",
                **values)

    async def test_manual_dispatch_is_denied_and_supervised_dispatch_succeeds(self):
        from agents.result_contract import AgentResult
        from orchestrator.campaign_execution import CampaignExecutionDenied
        from orchestrator.team_coordinator import TeamCoordinator

        owner, session_id, job_id, scope = await self._engagement()
        context = await self._context(owner, session_id)
        campaign_id, token = await self._campaign(
            owner, session_id, context["scope_digest"])
        evidence_id = await self._evidence(owner, session_id, job_id)
        task_id = await self._task(owner, session_id, campaign_id,
                                   evidence_id, "manual")

        class Specialist:
            def __init__(inner):
                inner.calls = 0

            async def process(inner, sid, oid, input_data, skill):
                inner.calls += 1
                ref = input_data["team_evidence"][0]["id"]
                return {"agent_result": AgentResult(
                    interpreted_request="Review saved evidence only",
                    evidence_references=[ref],
                    observations=[{"evidence_id": ref,
                                   "observation": "Saved response observed",
                                   "verified": True}],
                    uncertainty=["Synthetic unverified specialist analysis"],
                ).model_dump()}

        specialist = Specialist()
        coordinator = TeamCoordinator()
        with patch.object(coordinator, "specialists",
                          return_value={"web_intel": specialist}):
            with self.assertRaises(CampaignExecutionDenied) as error:
                await coordinator.run(session_id, owner, task_id,
                                      str(uuid.uuid4()), "expert")
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(specialist.calls, 0)
        view = await self.store.view(session_id, owner)
        self.assertEqual(next(item for item in view["tasks"]
                              if item["id"] == task_id)["state"], "queued")

        event = await self._run(coordinator, specialist, session_id, owner,
                                task_id, campaign_id, token, context)
        self.assertEqual(event["data"]["state"], "awaiting_review")
        self.assertEqual(specialist.calls, 1)
        stored = await self.store.view(session_id, owner)
        task = next(item for item in stored["tasks"] if item["id"] == task_id)
        self.assertFalse(any(item["verified"]
                             for item in task["result"]["observations"]))
        self.assertFalse(any(item["verified"]
                             for item in task["result"]["hypotheses"]))

    async def test_terminal_or_expired_campaign_denies_dispatch(self):
        from memory.campaign_store import campaign_store
        from orchestrator.campaign_execution import CampaignExecutionDenied
        from orchestrator.team_coordinator import TeamCoordinator

        owner, session_id, job_id, _ = await self._engagement()
        context = await self._context(owner, session_id)
        evidence_id = await self._evidence(owner, session_id, job_id)
        coordinator = TeamCoordinator()

        terminal_id, terminal_token = await self._campaign(
            owner, session_id, context["scope_digest"])
        await campaign_store.transition(
            terminal_id, terminal_token, datetime.now(UTC), {"running"},
            {"state": "cancelled"}, event="campaign_cancelled")
        terminal_task = await self._task(owner, session_id, terminal_id,
                                         evidence_id, "terminal")
        with self.assertRaises(CampaignExecutionDenied) as error:
            await self._run(coordinator, None, session_id, owner, terminal_task,
                            terminal_id, terminal_token, context)
        self.assertEqual(error.exception.code, "campaign_supervisor_required")

        expired_id, expired_token = await self._campaign(
            owner, session_id, context["scope_digest"],
            lease_now=datetime.now(UTC) - timedelta(hours=2),
            lease_seconds=60)
        expired_task = await self._task(owner, session_id, expired_id,
                                        evidence_id, "expired")
        with self.assertRaises(CampaignExecutionDenied) as error:
            await self._run(coordinator, None, session_id, owner, expired_task,
                            expired_id, expired_token, context)
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        view = await self.store.view(session_id, owner)
        states = {item["id"]: item["state"] for item in view["tasks"]}
        self.assertEqual(states[terminal_task], "queued")
        self.assertEqual(states[expired_task], "queued")

    async def test_lease_takeover_denies_old_token_and_allows_new_owner(self):
        from memory.campaign_store import campaign_store
        from orchestrator.campaign_execution import CampaignExecutionDenied
        from orchestrator.team_coordinator import TeamCoordinator

        owner, session_id, job_id, _ = await self._engagement()
        context = await self._context(owner, session_id)
        evidence_id = await self._evidence(owner, session_id, job_id)
        campaign_id, old_token = await self._campaign(
            owner, session_id, context["scope_digest"], lease_seconds=60)
        task_id = await self._task(owner, session_id, campaign_id,
                                   evidence_id, "takeover")
        new_token = "lease-new-" + self.token
        claimed = await campaign_store.claim(
            campaign_id, new_token, datetime.now(UTC) + timedelta(minutes=2),
            3600)
        self.assertIsNotNone(claimed)
        coordinator = TeamCoordinator()

        with self.assertRaises(CampaignExecutionDenied) as error:
            await self._run(coordinator, None, session_id, owner, task_id,
                            campaign_id, old_token, context)
        self.assertEqual(error.exception.code, "campaign_supervisor_required")

        class Specialist:
            def __init__(inner):
                inner.calls = 0

            async def process(inner, sid, oid, input_data, skill):
                from agents.result_contract import AgentResult
                inner.calls += 1
                ref = input_data["team_evidence"][0]["id"]
                return {"agent_result": AgentResult(
                    interpreted_request="Review saved evidence only",
                    evidence_references=[ref],
                    uncertainty=["Synthetic unverified specialist analysis"],
                ).model_dump()}

        specialist = Specialist()
        event = await self._run(coordinator, specialist, session_id, owner,
                                task_id, campaign_id, new_token, context)
        self.assertEqual(event["data"]["state"], "awaiting_review")
        self.assertEqual(specialist.calls, 1)

    async def test_concurrent_lease_takeover_stops_the_batch_at_the_next_boundary(self):
        from memory.campaign_store import campaign_store
        from orchestrator.specialist_integration import (
            SpecialistIntegration, SpecialistIntegrationError,
        )
        from orchestrator.team_coordinator import TeamCoordinator

        owner, session_id, job_id, _ = await self._engagement()
        context = await self._context(owner, session_id)
        campaign_id, old_token = await self._campaign(
            owner, session_id, context["scope_digest"], lease_seconds=60)
        evidence_id = await self._evidence(owner, session_id, job_id)
        first = await self._task(owner, session_id, campaign_id,
                                 evidence_id, "takeover-batch-1")
        second = await self._task(owner, session_id, campaign_id,
                                  evidence_id, "takeover-batch-2")
        new_token = "lease-new-" + self.token

        class Specialist:
            def __init__(inner):
                inner.calls = 0

            async def process(inner, sid, oid, input_data, skill):
                from agents.result_contract import AgentResult
                inner.calls += 1
                if inner.calls == 1:
                    takeover = await campaign_store.claim(
                        campaign_id, new_token,
                        datetime.now(UTC) + timedelta(seconds=120), 3600)
                    assert takeover is not None
                ref = input_data["team_evidence"][0]["id"]
                return {"agent_result": AgentResult(
                    interpreted_request="Review saved evidence only",
                    evidence_references=[ref],
                    uncertainty=["Synthetic unverified specialist analysis"],
                ).model_dump()}

        specialist = Specialist()
        coordinator = TeamCoordinator()
        service = SpecialistIntegration(store=self.store,
                                        coordinator=coordinator)
        with patch.object(coordinator, "specialists",
                          return_value={"web_intel": specialist}):
            with self.assertRaises(SpecialistIntegrationError) as error:
                await service.run_pending(
                    session_id=session_id, owner_id=owner,
                    task_ids=[first, second], skill_level="expert",
                    max_tasks=10, campaign_id=campaign_id,
                    campaign_supervisor_token=old_token,
                    scope_digest=context["scope_digest"],
                    auth_revision=context["auth_revision"],
                    worker_epoch=context["worker_epoch"])
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(specialist.calls, 1)
        view = await self.store.view(session_id, owner)
        states = {item["id"]: item["state"] for item in view["tasks"]}
        self.assertEqual(states[first], "awaiting_review")
        self.assertEqual(states[second], "queued")

    async def test_scope_change_and_authorization_revision_deny_dispatch(self):
        from memory.database_models import PentestSession, User, async_session
        from orchestrator.campaign_execution import CampaignExecutionDenied
        from orchestrator.team_coordinator import TeamCoordinator

        owner, session_id, job_id, scope = await self._engagement()
        context = await self._context(owner, session_id)
        evidence_id = await self._evidence(owner, session_id, job_id)
        campaign_id, token = await self._campaign(
            owner, session_id, context["scope_digest"])
        task_id = await self._task(owner, session_id, campaign_id,
                                   evidence_id, "scope-revision")
        coordinator = TeamCoordinator()

        async with async_session() as db:
            session = await db.get(PentestSession, session_id)
            session.scope = {**scope, "targets": ["192.0.2.1", "192.0.2.2"]}
            user = await db.get(User, owner)
            user.preferences = {"auth_revision": 1}
            await db.commit()
        changed = await self._context(owner, session_id)
        self.assertNotEqual(changed["scope_digest"], context["scope_digest"])
        with self.assertRaises(CampaignExecutionDenied) as error:
            await self._run(coordinator, None, session_id, owner, task_id,
                            campaign_id, token, changed)
        self.assertEqual(error.exception.code, "scope_changed")

        # Restore the campaign scope but keep the revoked credential revision.
        async with async_session() as db:
            session = await db.get(PentestSession, session_id)
            session.scope = scope
            await db.commit()
        revoked = await self._context(owner, session_id)
        with self.assertRaises(CampaignExecutionDenied) as error:
            await self._run(coordinator, None, session_id, owner, task_id,
                            campaign_id, token, revoked)
        self.assertEqual(error.exception.code, "authorization_changed")

    async def test_budget_exhaustion_stops_before_the_next_task(self):
        from orchestrator.specialist_integration import (
            SpecialistBudgetExhausted, SpecialistIntegration,
        )
        from orchestrator.team_coordinator import TeamCoordinator

        owner, session_id, job_id, _ = await self._engagement()
        context = await self._context(owner, session_id)
        campaign_id, token = await self._campaign(
            owner, session_id, context["scope_digest"])
        evidence_id = await self._evidence(owner, session_id, job_id)
        first = await self._task(owner, session_id, campaign_id,
                                 evidence_id, "budget-1")
        second = await self._task(owner, session_id, campaign_id,
                                  evidence_id, "budget-2")

        class Specialist:
            def __init__(inner):
                inner.calls = 0

            async def process(inner, sid, oid, input_data, skill):
                inner.calls += 1
                raise HTTPException(
                    429, {"code": "campaign_budget_exhausted",
                          "message": "Synthetic campaign budget exhausted"})

        specialist = Specialist()
        coordinator = TeamCoordinator()
        service = SpecialistIntegration(store=self.store,
                                        coordinator=coordinator)
        with patch.object(coordinator, "specialists",
                          return_value={"web_intel": specialist}):
            with self.assertRaises(SpecialistBudgetExhausted):
                await service.run_pending(
                    session_id=session_id, owner_id=owner,
                    task_ids=[first, second], skill_level="expert",
                    max_tasks=10, campaign_id=campaign_id,
                    campaign_supervisor_token=token,
                    scope_digest=context["scope_digest"],
                    auth_revision=context["auth_revision"],
                    worker_epoch=context["worker_epoch"])
        self.assertEqual(specialist.calls, 1)
        view = await self.store.view(session_id, owner)
        states = {item["id"]: item["state"] for item in view["tasks"]}
        self.assertEqual(states[first], "failed")
        self.assertEqual(states[second], "queued")
