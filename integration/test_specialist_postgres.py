"""SPEC-13 PostgreSQL specialist integration tests; synthetic data only.

Requires a disposable database ending in *_test:
    ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test \
        python -m unittest integration.test_specialist_postgres -v
"""
import hashlib
import os
import subprocess
import sys
import unittest
import uuid
from unittest.mock import patch

from fastapi import HTTPException

ENABLED = os.environ.get("ARIA_INTEGRATION") == "1"


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


@unittest.skipUnless(ENABLED, "set ARIA_INTEGRATION=1 with a disposable *_test database")
class SpecialistPostgres(unittest.IsolatedAsyncioTestCase):
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
            ChatLog, DecisionLog, PentestSession, User, async_session,
        )
        from memory.worker_jobs import SQLJobStore
        owner = "spec13-o-" + uuid.uuid4().hex[:12]
        session_id = "spec13-s-" + uuid.uuid4().hex[:12]
        chat_ids = ["spec13-c-" + uuid.uuid4().hex[:12] for _ in range(2)]
        job_id = "spec13-job-" + uuid.uuid4().hex[:12]
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
            for index, chat_id in enumerate(chat_ids):
                db.add(ChatLog(
                    id=chat_id, session_id=session_id, role="tool_output",
                    content=f"Saved synthetic response {index}",
                    msg_type="text",
                    data={"source": "saved_browser_capture_unverified"}))
            db.add(DecisionLog(
                id=SQLJobStore.key(job_id), session_id=session_id, user_id=owner,
                decision_type="worker_job",
                metadata_={"job_id": job_id, "session_id": session_id,
                           "user_id": owner, "state": "succeeded",
                           "exit_code": 0, "output_hash": _sha("synthetic stdout"),
                           "stderr_hash": _sha("")}))
            await db.commit()
        application = {
            "identities": {
                "i1": {"id": "i1", "active": True,
                       "researcher_controlled": True},
                "i2": {"id": "i2", "active": True,
                       "researcher_controlled": True},
            },
            "captures": {
                "c1": {"id": "c1", "evidence_id": chat_ids[0], "expired": False},
                "c2": {"id": "c2", "evidence_id": chat_ids[1], "expired": False},
            },
            "objects": {
                "o1": {"id": "o1", "owner_identity_id": "i1",
                       "evidence_ids": chat_ids},
            },
            "permissions": {
                "p1": {"id": "p1", "object_id": "o1", "identity_id": "i2",
                       "operation": "GET", "expected": "deny"},
            },
            "workflows": {
                "w1": {"id": "w1", "evidence_ids": [chat_ids[0]]},
            },
        }
        return owner, session_id, job_id, application

    async def _add_job(self, owner, session_id):
        from memory.database_models import DecisionLog, async_session
        from memory.worker_jobs import SQLJobStore
        job_id = "spec13-job-" + uuid.uuid4().hex[:12]
        async with async_session() as db:
            db.add(DecisionLog(
                id=SQLJobStore.key(job_id), session_id=session_id,
                user_id=owner, decision_type="worker_job",
                metadata_={"job_id": job_id, "session_id": session_id,
                           "user_id": owner, "state": "succeeded",
                           "exit_code": 0, "output_hash": _sha("synthetic stdout 2"),
                           "stderr_hash": _sha("")}))
            await db.commit()
        return job_id

    async def _candidates(self, campaign_id, session_id, owner, job_id,
                          application):
        from config.settings import settings
        from orchestrator.specialist_integration import select_candidates
        from memory.knowledge_store import scope_identity_digest
        scope = {"targets": ["192.0.2.1"],
                 "web_authenticated_replay": True,
                 "web_specialist_profiles": True}
        with patch.object(settings, "SPECIALIST_MAX_INVESTIGATIONS", 5):
            return select_candidates(
                campaign_id=campaign_id,
                scope_digest=scope_identity_digest(scope, "192.0.2.1"),
                scope=scope,
                advertised={"authenticated_http_version": 1,
                            "specialist_http_version": 1},
                observation_job_ids={"http_response": [job_id]},
                application=application)

    def _service(self, coordinator):
        from orchestrator.specialist_integration import SpecialistIntegration
        return SpecialistIntegration(store=self.store, coordinator=coordinator)

    async def _count_events(self, session_id):
        from sqlalchemy import func, select
        from memory.database_models import DecisionLog, async_session
        async with async_session() as db:
            return await db.scalar(select(func.count()).select_from(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == "team_event"))

    async def _ensure(self, service, owner, session_id, campaign_id,
                      candidates):
        from memory.knowledge_store import scope_identity_digest
        scope = {"targets": ["192.0.2.1"],
                 "web_authenticated_replay": True,
                 "web_specialist_profiles": True}
        return await service.ensure(
            session_id=session_id, owner_id=owner,
            campaign_id=campaign_id,
            scope_digest=scope_identity_digest(scope, "192.0.2.1"),
            candidates=candidates)

    async def test_ensure_deduplicates_and_planner_never_verifies(self):
        from agents.result_contract import AgentResult
        owner, session_id, job_id, application = await self._engagement()
        candidates = await self._candidates(
            "campaign-" + self.token, session_id, owner, job_id, application)
        calls = []

        class Coordinator:
            async def run(inner, sid, oid, task_id, request_id, skill,
                          **campaign):
                calls.append(task_id)
                claim = await self.store.claim(sid, oid, task_id, request_id)
                ref = claim["data"]["evidence_inputs"][0]
                result = AgentResult(
                    interpreted_request="Review saved evidence only",
                    evidence_references=[ref],
                    observations=[{"evidence_id": ref,
                                   "observation": "Saved response observed",
                                   "verified": True}],
                    hypotheses=[{"description": "Possible issue",
                                 "evidence_references": [ref],
                                 "verified": True}],
                    uncertainty=["No independent reproduction"])
                return await self.store.collect(sid, oid, task_id, request_id,
                                                result)

        service = self._service(Coordinator())
        first = await self._ensure(service, owner, session_id,
                                   "campaign-" + self.token, candidates)
        self.assertEqual(first["created"], 5)
        self.assertEqual(len(first["task_ids"]), 5)
        events = await self._count_events(session_id)
        second = await self._ensure(service, owner, session_id,
                                    "campaign-" + self.token, candidates)
        self.assertEqual(second["task_ids"], first["task_ids"])
        self.assertEqual(second["created"], 0)
        self.assertEqual(await self._count_events(session_id), events)

        pending = await service.planner_context(
            session_id=session_id, owner_id=owner,
            task_ids=first["task_ids"],
            verified_observations=[{"observation": "http_response",
                                    "job_id": job_id}])
        self.assertTrue(pending["confirmed_evidence"][0]["verified"])
        self.assertEqual(len(pending["pending_investigations"]), 5)
        self.assertFalse(any(item["verified"] for item in pending["hypotheses"]))
        self.assertFalse(any(item["verified"]
                             for item in pending["unverified_observations"]))

        ran = await service.run_pending(
            session_id=session_id, owner_id=owner,
            task_ids=first["task_ids"], skill_level="expert", max_tasks=1,
            campaign_id="campaign-" + self.token,
            campaign_supervisor_token="supervisor-" + self.token)
        self.assertEqual(len(ran["executed"]), 1)
        stored = await self.store.view(session_id, owner)
        reviewed = next(task for task in stored["tasks"]
                        if task["state"] == "awaiting_review")
        self.assertFalse(any(item["verified"] for item in
                             reviewed["result"]["observations"]))
        self.assertFalse(any(item["verified"] for item in
                             reviewed["result"]["hypotheses"]))
        context = await service.planner_context(
            session_id=session_id, owner_id=owner,
            task_ids=first["task_ids"],
            verified_observations=[{"observation": "http_response",
                                    "job_id": job_id}])
        self.assertTrue(context["hypotheses"])
        self.assertTrue(context["unverified_observations"])
        self.assertFalse(any(item["verified"]
                             for item in context["hypotheses"]))
        self.assertFalse(any(item["verified"] for item in
                             context["unverified_observations"]))
        reviews = [item for item in context["pending_investigations"]
                   if item["status"] == "awaiting_review"]
        self.assertEqual(len(reviews), 1)
        self.assertFalse(reviews[0]["verified"])

    async def test_dependencies_wait_for_human_completion(self):
        owner, session_id, job_id, application = await self._engagement()
        candidates = await self._candidates(
            "campaign-" + self.token, session_id, owner, job_id, application)

        class Coordinator:
            async def run(inner, sid, oid, task_id, request_id, skill,
                          **campaign):
                claim = await self.store.claim(sid, oid, task_id, request_id)
                ref = claim["data"]["evidence_inputs"][0]
                from agents.result_contract import AgentResult
                return await self.store.collect(
                    sid, oid, task_id, request_id,
                    AgentResult(interpreted_request="Review saved evidence",
                                evidence_references=[ref],
                                observations=[{"evidence_id": ref,
                                               "observation": "Observed"}],
                                uncertainty=["Unverified"]))

        service = self._service(Coordinator())
        ensured = await self._ensure(service, owner, session_id,
                                     "campaign-" + self.token, candidates)
        ran = await service.run_pending(
            session_id=session_id, owner_id=owner,
            task_ids=ensured["task_ids"], skill_level="expert", max_tasks=10,
            campaign_id="campaign-" + self.token,
            campaign_supervisor_token="supervisor-" + self.token)
        self.assertEqual(len(ran["executed"]), 2)

        view = await self.store.view(session_id, owner)
        tasks = {task["specialty"]: task for task in view["tasks"]}
        authorization = tasks["authorization"]
        self.assertEqual(authorization["state"], "queued")
        with self.assertRaises(HTTPException) as error:
            await self.store.claim(session_id, owner, authorization["id"],
                                   "before-review-" + self.token)
        self.assertEqual(error.exception.status_code, 409)
        self.assertIn("Dependencies require completed human review",
                      str(error.exception.detail))

        authentication = tasks["authentication"]
        from memory.team_tasks import CoverageInput, Transition
        await self.store.coverage(
            session_id, owner,
            CoverageInput(request_id=uuid.uuid4(),
                          key=authentication["security_questions"][0],
                          question="Authentication boundary reviewed by human",
                          feature="authentication:http-response",
                          status="tested", gap_reason="",
                          evidence_references=authentication["evidence_inputs"]))
        completed = await self.store.transition(
            session_id, owner, authentication["id"],
            Transition(request_id=uuid.uuid4(),
                       expected_revision=authentication["revision"],
                       state="completed",
                       reason="Human reviewed the saved evidence"))
        self.assertEqual(completed["data"]["state"], "completed")

        claim = await self.store.claim(session_id, owner, authorization["id"],
                                       "after-review-" + self.token)
        self.assertEqual(claim["data"]["state"], "running")
        await self.store.block(session_id, owner, authorization["id"],
                               "after-review-" + self.token,
                               "Synthetic cleanup without a finding",
                               failed=True)

    async def test_restart_reconciliation_prevents_duplicate_investigation(self):
        owner, session_id, job_id, application = await self._engagement()
        candidates = await self._candidates(
            "campaign-" + self.token, session_id, owner, job_id, application)
        calls = []

        class Coordinator:
            async def run(inner, sid, oid, task_id, request_id, skill,
                          **campaign):
                calls.append(task_id)
                claim = await self.store.claim(sid, oid, task_id, request_id)
                ref = claim["data"]["evidence_inputs"][0]
                from agents.result_contract import AgentResult
                return await self.store.collect(
                    sid, oid, task_id, request_id,
                    AgentResult(interpreted_request="Review saved evidence",
                                evidence_references=[ref],
                                observations=[{"evidence_id": ref,
                                               "observation": "Observed"}],
                                uncertainty=["Unverified"]))

        service = self._service(Coordinator())
        ensured = await self._ensure(service, owner, session_id,
                                     "campaign-" + self.token, candidates)
        view = await self.store.view(session_id, owner)
        exposure = next(task for task in view["tasks"]
                        if task["specialty"] == "exposure")
        await self.store.claim(session_id, owner, exposure["id"],
                               "interrupted-" + self.token)
        await self.store.recover()
        view = await self.store.view(session_id, owner)
        exposure = next(task for task in view["tasks"]
                        if task["id"] == exposure["id"])
        self.assertEqual(exposure["state"], "blocked")
        events = await self._count_events(session_id)

        again = await self._ensure(service, owner, session_id,
                                   "campaign-" + self.token, candidates)
        self.assertEqual(again["task_ids"], ensured["task_ids"])
        self.assertEqual(await self._count_events(session_id), events)
        await service.run_pending(
            session_id=session_id, owner_id=owner,
            task_ids=again["task_ids"], skill_level="expert", max_tasks=10,
            campaign_id="campaign-" + self.token,
            campaign_supervisor_token="supervisor-" + self.token)
        self.assertNotIn(exposure["id"], calls)

        context = await service.planner_context(
            session_id=session_id, owner_id=owner,
            task_ids=again["task_ids"],
            verified_observations=[{"observation": "http_response",
                                    "job_id": job_id}])
        failed = {item["investigation_id"]: item
                  for item in context["failed_investigations"]}
        self.assertEqual(failed[exposure["id"]]["status"], "blocked")
        self.assertFalse(failed[exposure["id"]]["verified"])

    async def test_changed_evidence_defers_then_creates_a_follow_up_after_review(self):
        from memory.team_tasks import Transition
        owner, session_id, job1, application = await self._engagement()
        campaign = "campaign-" + self.token
        initial = await self._candidates(
            campaign, session_id, owner, job1, application)
        service = self._service(None)
        first = await self._ensure(service, owner, session_id, campaign, initial)
        self.assertEqual(first["created"], 5)
        view = await self.store.view(session_id, owner)
        exposure = next(task for task in view["tasks"]
                        if task["specialty"] == "exposure")
        await self.store.claim(session_id, owner, exposure["id"],
                               "interrupted-" + self.token)
        await self.store.recover()
        events_before = await self._count_events(session_id)

        job2 = await self._add_job(owner, session_id)
        changed = await self._candidates(
            campaign, session_id, owner, job2, application)
        deferred = await self._ensure(
            service, owner, session_id, campaign, changed)
        self.assertEqual(deferred["created"], 0)
        self.assertEqual(len(deferred["deferred"]), 2)
        self.assertEqual(await self._count_events(session_id), events_before)
        self.assertEqual(sorted(deferred["task_ids"]), sorted(first["task_ids"]))

        view = await self.store.view(session_id, owner)
        for question in ("exposure:http-response",
                         "authentication:http-response"):
            task = next(item for item in view["tasks"]
                        if item["security_questions"] == [question])
            await self.store.transition(
                session_id, owner, task["id"],
                Transition(request_id=uuid.uuid4(),
                           expected_revision=task["revision"],
                           state="cancelled",
                           reason="Synthetic review resolution before follow-up"))
        follow_up = await self._ensure(
            service, owner, session_id, campaign, changed)
        self.assertEqual(follow_up["created"], 2)
        self.assertFalse(follow_up["deferred"])

        view = await self.store.view(session_id, owner)
        by_id = {task["id"]: task for task in view["tasks"]}
        changed_questions = {"exposure:http-response",
                             "authentication:http-response"}
        unchanged_ids = {
            task_id for task_id in first["task_ids"]
            if by_id[task_id]["security_questions"][0] not in changed_questions}
        replaced_ids = set(first["task_ids"]) - unchanged_ids
        follow_up_ids = set(follow_up["task_ids"])
        # Unchanged candidates keep their identity; only the reviewed tasks
        # whose evidence changed are replaced by a legitimate follow-up.
        self.assertTrue(unchanged_ids.issubset(follow_up_ids))
        self.assertFalse(replaced_ids & follow_up_ids)
        self.assertEqual(len(follow_up_ids - set(first["task_ids"])), 2)

        new_tasks = [task for task in view["tasks"]
                     if task["state"] == "queued"
                     and task["campaign_id"] == campaign
                     and task["specialty"] in {"exposure", "authentication"}
                     and task["security_questions"] == [
                         f"{task['specialty']}:http-response"]]
        self.assertEqual(len(new_tasks), 2)
        evidence = {entry["id"]: entry for entry in view["evidence"]}
        for task in new_tasks:
            self.assertEqual(len(task["investigation_key"]), 64)
            self.assertTrue(any(evidence[ref]["source_id"] == job2
                                for ref in task["evidence_inputs"]))

    async def test_budget_exhaustion_stops_task_execution(self):
        from orchestrator.specialist_integration import SpecialistBudgetExhausted
        owner, session_id, job_id, application = await self._engagement()
        candidates = await self._candidates(
            "campaign-" + self.token, session_id, owner, job_id, application)
        calls = []

        class Coordinator:
            async def run(inner, sid, oid, task_id, request_id, skill,
                          **campaign):
                calls.append(task_id)
                raise HTTPException(
                    429, {"code": "campaign_budget_exhausted",
                          "message": "Synthetic campaign budget exhausted"})

        service = self._service(Coordinator())
        ensured = await self._ensure(service, owner, session_id,
                                     "campaign-" + self.token, candidates)
        with self.assertRaises(SpecialistBudgetExhausted):
            await service.run_pending(
                session_id=session_id, owner_id=owner,
                task_ids=ensured["task_ids"], skill_level="expert",
                max_tasks=10, campaign_id="campaign-" + self.token,
                campaign_supervisor_token="supervisor-" + self.token)
        self.assertEqual(len(calls), 1)
