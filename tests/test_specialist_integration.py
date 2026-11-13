"""SPEC-13 evidence-driven specialist integration; no network or model calls."""
import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from agents.autonomous_engine import AutonomousEngine, SessionRunState
from agents.orchestrator_agent import orchestrator_agent
from config.settings import settings
from memory.autonomous_runs import build_checkpoint, validate_checkpoint
from memory.team_tasks import CreateTask, EvidenceInput
from orchestrator.specialist_integration import (
    SpecialistBudgetExhausted,
    SpecialistIntegration,
    SpecialistIntegrationError,
    investigation_task_id,
    select_candidates,
)
from tests.support import OfflineCase

DIGEST = "a" * 64
SCOPE = {
    "targets": ["192.0.2.1"],
    "web_authenticated_replay": True,
    "web_specialist_profiles": True,
}
ADVERTISED = {
    "authenticated_http_version": 1,
    "specialist_http_version": 1,
}
APPLICATION = {
    "identities": {
        "i1": {"id": "i1", "active": True, "researcher_controlled": True},
        "i2": {"id": "i2", "active": True, "researcher_controlled": True},
    },
    "captures": {
        "c1": {"id": "c1", "evidence_id": "e1", "expired": False},
        "c2": {"id": "c2", "evidence_id": "e2", "expired": False},
    },
    "objects": {
        "o1": {"id": "o1", "owner_identity_id": "i1",
               "evidence_ids": ["e1", "e2"]},
    },
    "permissions": {
        "p1": {"id": "p1", "object_id": "o1", "identity_id": "i2",
               "operation": "GET", "expected": "deny"},
    },
    "workflows": {"w1": {"id": "w1", "evidence_ids": ["e1"]}},
}


def candidates(**overrides):
    values = dict(campaign_id="campaign-1", scope_digest=DIGEST, scope=SCOPE,
                  advertised=ADVERTISED,
                  observation_job_ids={"http_response": ["job-curl"]},
                  application=APPLICATION, limit=10)
    values.update(overrides)
    # Selection always clamps to the configured campaign ceiling.
    with patch.object(settings, "SPECIALIST_MAX_INVESTIGATIONS", 10):
        return select_candidates(**values)


class SelectionTests(OfflineCase):
    async def test_scope_and_exact_worker_versions_gate_every_specialty(self):
        default = candidates(scope={"targets": ["192.0.2.1"]})
        self.assertEqual([item.specialty for item in default], ["exposure"])

        truthy = candidates(advertised={"authenticated_http_version": True,
                                        "specialist_http_version": True})
        self.assertEqual([item.specialty for item in truthy], ["exposure"])

        full = candidates()
        self.assertEqual([item.specialty for item in full], [
            "exposure", "authentication", "authorization",
            "input_validation", "business_logic"])
        for item in full:
            self.assertIn(item.role, {"web_intel", "vuln", "correlation"})
            self.assertTrue(item.sources)
            self.assertLessEqual(len(item.sources), 5)

    async def test_selection_is_deterministic_and_campaign_bound(self):
        first = candidates()
        second = candidates()
        self.assertEqual([item.key for item in first],
                         [item.key for item in second])
        other = candidates(campaign_id="campaign-2")
        self.assertNotEqual(first[0].key, other[0].key)
        self.assertNotEqual(investigation_task_id("s1", first[0].key),
                            investigation_task_id("s1", other[0].key))

    async def test_scope_rejection_produces_no_mapped_investigations(self):
        selected = candidates(scope={"targets": ["192.0.2.1"]})
        self.assertEqual([item.specialty for item in selected], ["exposure"])
        self.assertFalse(any(item.specialty in {
            "authorization", "authentication", "input_validation",
            "business_logic"} for item in selected))

    async def test_no_campaign_means_no_durable_investigation(self):
        self.assertEqual(candidates(campaign_id=""), [])


class MemoryTeamStore:
    """In-memory equivalent of the durable team ledger contract."""

    def __init__(self):
        self.tasks = {}
        self.evidence = {}
        self.create_calls = []
        self.catalog_calls = []
        self.fail_sources = set()

    async def catalog(self, session_id, owner_id, body: EvidenceInput):
        self.catalog_calls.append((body.source_kind, body.source_id))
        if body.source_id in self.fail_sources:
            raise HTTPException(404, "Owned evidence not found")
        evidence_id = str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"evidence:{session_id}:{body.source_kind}:{body.source_id}"))
        self.evidence[evidence_id] = {
            "id": evidence_id, "source_kind": body.source_kind,
            "source_id": body.source_id, "provenance": "worker_receipt",
        }
        return {"entity_id": evidence_id, "data": self.evidence[evidence_id],
                "duplicate": False}

    async def create(self, session_id, owner_id, body: CreateTask):
        return await self._create(session_id, owner_id, body, {})

    async def create_investigation(self, session_id, owner_id, body: CreateTask,
                                   *, campaign_id, investigation_key):
        return await self._create(session_id, owner_id, body, {
            "campaign_id": campaign_id,
            "investigation_key": investigation_key,
        })

    async def _create(self, session_id, owner_id, body: CreateTask, internal):
        self.create_calls.append(body)
        task_id = str(uuid.uuid5(
            uuid.NAMESPACE_URL, f"aria-task:{session_id}:{body.request_id}"))
        if task_id in self.tasks:
            return {"entity_id": task_id, "data": copy.deepcopy(self.tasks[task_id]),
                    "duplicate": True}
        for dependency in body.task.dependencies:
            if dependency not in self.tasks:
                raise HTTPException(422, "Reference is not in this engagement catalog")
        data = body.task.model_dump(mode="json")
        data.update(internal)
        data.update(id=task_id, session_id=session_id, owner_id=owner_id,
                    state="queued", revision=1, attempts=0, result=None,
                    created_at="now")
        self.tasks[task_id] = data
        return {"entity_id": task_id, "data": copy.deepcopy(data),
                "duplicate": False}

    async def view(self, session_id, owner_id):
        return {"tasks": [copy.deepcopy(item) for item in self.tasks.values()],
                "evidence": list(self.evidence.values()),
                "scope": {}, "target": ""}


class FakeCoordinator:
    def __init__(self, store):
        self.store = store
        self.calls = []
        self.failure = None
        self.campaign = {}

    async def run(self, session_id, owner_id, task_id, request_id, skill,
                  **campaign):
        self.calls.append((task_id, request_id))
        self.campaign = campaign
        if self.failure is not None:
            task = self.store.tasks[task_id]
            task.update(state="failed", reason="Specialist failed")
            raise self.failure
        task = self.store.tasks[task_id]
        task.update(
            state="awaiting_review", run_id=request_id,
            attempts=task["attempts"] + 1,
            result={
                "evidence_references": task["evidence_inputs"][:1],
                "observations": [{
                    "observation": "Saved response observed",
                    "verified": True,
                    "evidence_references": task["evidence_inputs"][:1],
                }],
                "hypotheses": [{
                    "description": "Candidate only",
                    "verified": True,
                    "evidence_references": task["evidence_inputs"][:1],
                }],
                "uncertainty": ["Unverified specialist analysis"],
            })
        return {"entity_id": task_id, "data": copy.deepcopy(task),
                "duplicate": False}


class SpecialistServiceTests(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.store = MemoryTeamStore()
        self.coordinator = FakeCoordinator(self.store)
        self.service = SpecialistIntegration(

            store=self.store, coordinator=self.coordinator,
            application_loader=AsyncMock(return_value=APPLICATION))

    async def ensure(self, selected=None, campaign="campaign-1"):
        return await self.service.ensure(
            session_id="engagement", owner_id="owner",
            campaign_id=campaign, scope_digest=DIGEST,
            candidates=selected if selected is not None else candidates())

    async def run_pending(self, task_ids, **overrides):
        values = dict(
            session_id="engagement", owner_id="owner", task_ids=task_ids,
            skill_level="expert", max_tasks=10, campaign_id="campaign-1",
            campaign_supervisor_token="supervisor-token",
            scope_digest=DIGEST, auth_revision=0, worker_epoch=0)
        values.update(overrides)
        return await self.service.run_pending(**values)

    async def test_ensure_persists_identity_dependencies_and_evidence(self):
        selected = candidates()
        result = await self.ensure(selected)
        self.assertEqual(result["created"], 5)
        self.assertEqual(len(self.store.tasks), 5)
        self.assertEqual(len(result["task_ids"]), 5)
        by_question = {
            task["security_questions"][0]: task
            for task in self.store.tasks.values()}
        authorization = by_question["authorization:o1"]
        authentication = by_question["authentication:http-response"]
        self.assertEqual(authorization["dependencies"], [authentication["id"]])
        self.assertEqual(authorization["specialty"], "authorization")
        self.assertEqual(authorization["phase"], "vulnerability_analysis")
        self.assertEqual(authorization["budget"]["max_attempts"], 1)
        self.assertEqual(authorization["budget"]["max_model_calls"],
                         settings.SPECIALIST_TASK_MODEL_CALLS)
        self.assertEqual(authorization["budget"]["max_tokens"],
                         settings.SPECIALIST_TASK_MAX_TOKENS)
        self.assertTrue(authorization["evidence_inputs"])
        self.assertEqual(len(authorization["evidence_inputs"]),
                         len(set(authorization["evidence_inputs"])))

        again = await self.ensure(selected)
        self.assertEqual(again["task_ids"], result["task_ids"])
        self.assertEqual(len(self.store.tasks), 5)
        self.assertEqual(len(self.store.create_calls), 5)

    async def test_application_map_failure_selects_only_worker_evidence(self):
        service = SpecialistIntegration(
            store=self.store, coordinator=self.coordinator,
            application_loader=AsyncMock(
                side_effect=RuntimeError("map unavailable")))
        result = await service.candidates(
            session_id="engagement", owner_id="owner",
            campaign_id="campaign-1", scope_digest=DIGEST, scope=SCOPE,
            advertised=ADVERTISED,
            observation_job_ids={"http_response": ["job-curl"]})
        self.assertEqual([item.specialty for item in result["candidates"]],
                         ["exposure", "authentication"])
        self.assertTrue(any("Application-map evidence was unavailable" in item
                            for item in result["limitations"]))

    async def test_evidence_unavailable_skips_dependent_investigations(self):
        self.store.fail_sources = {"job-curl"}
        result = await self.ensure()
        self.assertEqual(self.store.tasks, {})
        self.assertEqual(self.store.create_calls, [])
        self.assertTrue(result["limitations"])
        self.assertTrue(any("Saved evidence worker:job-curl" in item
                            for item in result["limitations"]))
        self.assertTrue(any("dependency was unavailable" in item
                            for item in result["limitations"]))

    async def test_run_pending_requires_human_completed_dependencies(self):
        selected = candidates()
        ensured = await self.ensure(selected)
        outcome = await self.run_pending(ensured["task_ids"])
        self.assertEqual(len(outcome["executed"]), 2)
        self.assertTrue(any(item["reason"] == "dependencies_not_human_completed"
                            for item in outcome["skipped"]))
        states = {task["security_questions"][0]: task["state"]
                  for task in self.store.tasks.values()}
        self.assertEqual(states["authentication:http-response"], "awaiting_review")
        self.assertEqual(states["exposure:http-response"], "awaiting_review")
        self.assertEqual(states["authorization:o1"], "queued")

    async def test_restart_blocked_investigation_is_never_reinvestigated(self):
        ensured = await self.ensure()
        task = self.store.tasks[ensured["task_ids"][0]]
        task.update(state="blocked", reason="Restart reconciliation; no replay")
        before = len(self.store.create_calls)

        result = await self.ensure()
        self.assertEqual(result["task_ids"], ensured["task_ids"])
        self.assertEqual(len(self.store.create_calls), before)
        outcome = await self.run_pending(result["task_ids"])
        self.assertNotIn(task["id"], outcome["executed"])
        self.assertEqual(task["state"], "blocked")
        self.assertFalse(any(call[0] == task["id"]
                             for call in self.coordinator.calls))

        context = await self.service.planner_context(
            session_id="engagement", owner_id="owner",
            task_ids=result["task_ids"],
            verified_observations=[{"observation": "http_response",
                                    "job_id": "job-curl"}])
        self.assertEqual(context["failed_investigations"][0]["status"], "blocked")
        self.assertFalse(context["failed_investigations"][0]["verified"])

    async def test_running_investigation_is_left_for_reconciliation(self):
        ensured = await self.ensure()
        task = self.store.tasks[ensured["task_ids"][0]]
        task["state"] = "running"
        outcome = await self.run_pending(ensured["task_ids"])
        self.assertNotIn(task["id"], outcome["executed"])
        self.assertTrue(any(item["task_id"] == task["id"]
                            and item["reason"] == "interrupted_run_requires_review"
                            for item in outcome["skipped"]))

    async def test_budget_failure_is_terminal_and_does_not_continue(self):
        ensured = await self.ensure()
        self.coordinator.failure = HTTPException(
            429, {"code": "campaign_budget_exhausted"})
        with self.assertRaises(SpecialistBudgetExhausted):
            await self.run_pending(ensured["task_ids"])
        self.assertEqual(len(self.coordinator.calls), 1)

    async def test_planner_context_forces_unverified_and_separates_categories(self):
        ensured = await self.ensure()
        await self.run_pending(ensured["task_ids"], max_tasks=1)
        failed_id = next(task_id for task_id in ensured["task_ids"]
                         if self.store.tasks[task_id]["state"] == "queued")
        self.store.tasks[failed_id].update(
            state="blocked", reason="Dependencies require human review")

        context = await self.service.planner_context(
            session_id="engagement", owner_id="owner",
            task_ids=ensured["task_ids"],
            verified_observations=[{"observation": "http_response",
                                    "job_id": "job-curl"}])
        self.assertEqual(context["confirmed_evidence"][0]["verified"], True)
        self.assertTrue(context["hypotheses"])
        self.assertFalse(any(item["verified"] for item in context["hypotheses"]))
        self.assertFalse(any(item["verified"]
                             for item in context["unverified_observations"]))
        self.assertTrue(any(item["status"] == "blocked"
                            for item in context["failed_investigations"]))
        self.assertTrue(context["limitations"])


class EngineSpecialistPhaseTests(OfflineCase):
    def state(self, **overrides):
        values = dict(
            session_id="engagement", user_id="owner", owner_id="owner",
            goal="http_check", target="192.0.2.1", skill_level="expert",
            objective="Investigate the authorized lab target",
            max_steps=12, steps_taken=1, successful_steps=1,
            capabilities={"tools": ["curl"]},
            completed_observations=["http_response"],
            evidence_job_ids=["job-curl"],
            observation_job_ids={"http_response": ["job-curl"]},
            scope_digest=DIGEST, campaign_id="campaign-1",
            campaign_supervisor_token="supervisor-token")
        values.update(overrides)
        return SessionRunState(**values)

    def engine(self):
        engine = AutonomousEngine()
        engine.campaign_loader = AsyncMock(return_value={
            "id": "campaign-1", "session_id": "engagement", "owner_id": "owner",
            "state": "running", "lease_holder": "supervisor-token",
            "lease_expires_at": (datetime.now(timezone.utc).replace(tzinfo=None)
                                 + timedelta(minutes=5)),
        })
        return engine

    def context(self):
        return {"owner_id": "owner", "scope": SCOPE, "target": "192.0.2.1",
                "scope_digest": DIGEST, "auth_revision": 0, "worker_epoch": 0}

    async def test_phase_persists_task_identity_before_running(self):
        engine = self.engine()
        state = self.state()
        observed = {}

        class Service:
            async def candidates(inner, **kwargs):
                return {"candidates": [SimpleNamespace(key="k1")],
                        "limitations": []}

            async def ensure(inner, **kwargs):
                observed["ensured_candidates"] = kwargs["candidates"]
                return {"task_ids": ["task-1"], "created": 1,
                        "duplicates": 0, "limitations": []}

            async def run_pending(inner, **kwargs):
                observed["persisted_before_run"] = (
                    engine._persist.await_count >= 1
                    and state.specialist_investigation_ids == ["task-1"])
                return {"executed": ["task-1"], "skipped": [], "errors": [],
                        "task_ids": ["task-1"]}

        engine._persist = AsyncMock()
        engine._emit = AsyncMock()
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=self.context())), \
             patch("orchestrator.specialist_integration.specialist_integration",
                   Service()):
            allowed = await engine._run_specialist_phase_guarded(state)
        self.assertTrue(allowed)
        self.assertTrue(state.specialist_phase_done)
        self.assertEqual(state.specialist_investigation_ids, ["task-1"])
        self.assertTrue(observed["persisted_before_run"])
        self.assertEqual(len(observed["ensured_candidates"]), 1)

    async def test_budget_and_scope_failures_block_without_completing(self):
        engine = self.engine()
        engine._persist = AsyncMock()
        engine._emit = AsyncMock()

        class BudgetService:
            async def candidates(inner, **kwargs):
                return {"candidates": [], "limitations": []}

            async def ensure(inner, **kwargs):
                return {"task_ids": ["task-1"], "created": 1,
                        "duplicates": 0, "limitations": []}

            async def run_pending(inner, **kwargs):
                raise SpecialistBudgetExhausted("task budget exhausted")

        state = self.state()
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=self.context())), \
             patch("orchestrator.specialist_integration.specialist_integration",
                   BudgetService()):
            self.assertFalse(await engine._run_specialist_phase_guarded(state))
        self.assertEqual(state.run_state, "blocked")
        self.assertEqual(state.reason_code, "specialist_budget_exhausted")
        self.assertFalse(state.specialist_phase_done)

        state = self.state(scope_digest="b" * 64)
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=self.context())):
            with self.assertRaises(SpecialistIntegrationError) as error:
                await engine._run_specialist_phase(state, AsyncMock())
        self.assertEqual(error.exception.code, "scope_changed")

        state = self.state()
        revoked = {**self.context(), "auth_revision": 1}
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=revoked)):
            with self.assertRaises(SpecialistIntegrationError) as error:
                await engine._run_specialist_phase(state, AsyncMock())
        self.assertEqual(error.exception.code, "authorization_changed")

    async def test_no_campaign_never_touches_the_team_ledger(self):
        engine = AutonomousEngine()
        engine._persist = AsyncMock()
        engine._emit = AsyncMock()
        state = self.state(campaign_id="")
        service = AsyncMock()
        self.assertTrue(await engine._run_specialist_phase_guarded(state))
        service.assert_not_awaited()
        self.assertFalse(state.specialist_phase_done)

    async def test_planner_receives_confirmed_hypotheses_and_failures(self):
        engine = AutonomousEngine()
        state = self.state(
            specialist_phase_done=True,
            specialist_investigation_ids=["task-1", "task-2"])
        captured = {}

        class Planner:
            async def process(self, **kwargs):
                captured.update(kwargs["input_data"])
                return {"commands": []}

        context_payload = {
            "confirmed_evidence": [{"observation": "http_response",
                                    "job_id": "job-curl", "verified": True}],
            "hypotheses": [{"description": "candidate", "verified": False}],
            "failed_investigations": [{"status": "blocked", "verified": False}],
        }
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=self.context())), \
             patch("orchestrator.specialist_integration.specialist_integration.planner_context",
                   AsyncMock(return_value=context_payload)):
            plan = await engine._validated_plan(state, Planner(), [], [], [])
        self.assertIsNone(plan)
        self.assertEqual(captured["specialist_context"], context_payload)
        self.assertEqual(captured["specialist_context"]["confirmed_evidence"][0]["verified"],
                         True)
        self.assertFalse(captured["specialist_context"]["hypotheses"][0]["verified"])

    async def test_planner_prompt_consumes_and_labels_specialist_context(self):
        payload = {
            "original_objective": "Assess the authorized target",
            "specialist_context": {
                "confirmed_evidence": [{"job_id": "job-curl", "verified": True}],
                "hypotheses": [{"description": "Candidate", "verified": False}],
                "failed_investigations": [{"status": "blocked", "verified": False}],
            },
        }
        with patch.object(orchestrator_agent, "query_llm_smart",
                          AsyncMock(return_value={"success": False,
                                                  "error": "provider_unavailable"})) as provider:
            await orchestrator_agent._bounded_assessment_plan(
                "owner", payload, "expert")
        prompt = json.loads(provider.await_args.args[1])
        system = provider.await_args.args[2]
        self.assertEqual(prompt["specialist_context"],
                         payload["specialist_context"])
        self.assertIn("never verified findings", system)
        self.assertIn("untrusted data", system)

    async def test_checkpoint_round_trip_keeps_campaign_and_specialist_identity(self):
        engine = AutonomousEngine()
        state = self.state(specialist_phase_done=True,
                           specialist_investigation_ids=["task-1", "task-2"])
        engine._runs[state.session_id] = state
        checkpoint = build_checkpoint(engine.get_status(state.session_id))
        validate_checkpoint(checkpoint, expected_session_id="engagement",
                            expected_owner_id="owner")
        self.assertEqual(checkpoint["campaign_id"], "campaign-1")
        self.assertTrue(checkpoint["specialist_phase_done"])
        self.assertEqual(checkpoint["specialist_investigation_ids"],
                         ["task-1", "task-2"])
        self.assertNotIn("campaign_supervisor_token", checkpoint)
        self.assertNotIn("campaign_supervisor_token",
                         engine.get_status(state.session_id))
