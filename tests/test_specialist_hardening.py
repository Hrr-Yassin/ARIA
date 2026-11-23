"""SPEC-13.1 security hardening regressions for campaign specialist work.

These tests use synthetic evidence and in-memory ledger doubles.  They do not
contact a model, worker or network service.  The PostgreSQL integration suite
exercises the same storage boundary with a disposable database.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from agents.autonomous_engine import AutonomousEngine, SessionRunState
from agents.result_contract import AgentResult
from memory.team_tasks import TeamStore
from orchestrator.specialist_integration import SpecialistIntegration
from tests.support import OfflineCase
from tests.test_specialist_integration import (
    ADVERTISED,
    APPLICATION,
    DIGEST,
    SCOPE,
    FakeCoordinator,
    MemoryTeamStore,
    candidates,
)

UTC = timezone.utc


def engine_state(**overrides):
    values = dict(
        session_id="engagement", user_id="owner", owner_id="owner",
        goal="http_check", target="192.0.2.1", skill_level="expert",
        objective="Investigate the authorized lab target",
        max_steps=12, steps_taken=1, successful_steps=1,
        capabilities={"tools": ["curl"]},
        completed_observations=["http_response"],
        evidence_job_ids=["job-curl"],
        observation_job_ids={"http_response": ["job-curl"]},
        scope_digest=DIGEST, campaign_id="campaign-1")
    values.update(overrides)
    return SessionRunState(**values)


def engine_context():
    return {"owner_id": "owner", "scope": SCOPE, "target": "192.0.2.1",
            "scope_digest": DIGEST, "auth_revision": 0, "worker_epoch": 0}


class RecordingService:
    def __init__(self):
        self.calls = []
        self.run_pending_calls = []

    async def candidates(self, **kwargs):
        self.calls.append("candidates")
        return {"candidates": [], "limitations": []}

    async def ensure(self, **kwargs):
        self.calls.append("ensure")
        return {"task_ids": [], "created": 0, "duplicates": 0,
                "limitations": []}

    async def run_pending(self, **kwargs):
        self.calls.append("run_pending")
        self.run_pending_calls.append(kwargs)
        return {"executed": [], "skipped": [], "errors": [],
                "task_ids": list(kwargs["task_ids"])}


class ManualRestoreSupervisorGateTests(OfflineCase):
    async def test_campaign_bound_state_without_a_supervisor_never_runs_specialists(self):
        """A manual restore cannot execute campaign-bound specialist tasks."""
        engine = AutonomousEngine()
        engine._persist = AsyncMock()
        engine._emit = AsyncMock()
        state = engine_state()  # campaign id came from a durable checkpoint.
        self.assertEqual(state.campaign_supervisor_token, "")
        service = RecordingService()
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=engine_context())), \
             patch("orchestrator.specialist_integration.specialist_integration",
                   service):
            allowed = await engine._run_specialist_phase_guarded(state)
        self.assertFalse(allowed)
        self.assertEqual(state.reason_code, "campaign_supervisor_required")
        self.assertEqual(service.calls, [])
        self.assertFalse(state.specialist_phase_done)


class SupervisorLeaseTests(OfflineCase):
    def leased_row(self, **overrides):
        row = {
            "id": "campaign-1", "session_id": "engagement", "owner_id": "owner",
            "state": "running", "lease_holder": "supervisor-token",
            "lease_expires_at": (datetime.now(UTC).replace(tzinfo=None)
                                 + timedelta(seconds=30)),
        }
        row.update(overrides)
        return row

    async def blocked(self, row=None, *, loader_error=None, token="supervisor-token"):
        engine = AutonomousEngine()
        engine._persist = AsyncMock()
        engine._emit = AsyncMock()
        if loader_error is not None:
            engine.campaign_loader = AsyncMock(side_effect=loader_error)
        else:
            engine.campaign_loader = AsyncMock(return_value=row)
        state = engine_state(campaign_supervisor_token=token)
        service = RecordingService()
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=engine_context())), \
             patch("orchestrator.specialist_integration.specialist_integration",
                   service):
            allowed = await engine._run_specialist_phase_guarded(state)
        self.assertFalse(allowed)
        self.assertEqual(state.reason_code, "campaign_supervisor_required")
        self.assertEqual(service.calls, [])
        return engine, state

    async def test_foreign_expired_or_missing_lease_blocks_execution(self):
        await self.blocked(self.leased_row(lease_holder="other-supervisor"))
        await self.blocked(self.leased_row(
            lease_expires_at=(datetime.now(UTC).replace(tzinfo=None)
                              - timedelta(seconds=1))))
        await self.blocked(None)
        await self.blocked(loader_error=RuntimeError("ledger unavailable"))

    async def test_wrong_campaign_binding_or_state_blocks_execution(self):
        await self.blocked(self.leased_row(state="completed"))
        await self.blocked(self.leased_row(state="paused"))
        await self.blocked(self.leased_row(session_id="other-engagement"))
        await self.blocked(self.leased_row(owner_id="other-owner"))

    async def test_active_supervisor_lease_allows_the_bounded_phase(self):
        engine = AutonomousEngine()
        engine._persist = AsyncMock()
        engine._emit = AsyncMock()
        engine.campaign_loader = AsyncMock(return_value=self.leased_row())
        state = engine_state(campaign_supervisor_token="supervisor-token")
        service = RecordingService()
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=engine_context())), \
             patch("orchestrator.specialist_integration.specialist_integration",
                   service):
            allowed = await engine._run_specialist_phase_guarded(state)
        self.assertTrue(allowed)
        self.assertTrue(state.specialist_phase_done)
        self.assertEqual(service.calls, ["candidates", "ensure", "run_pending"])

    async def test_authorization_and_scope_changes_still_block(self):
        engine = AutonomousEngine()
        engine._persist = AsyncMock()
        engine._emit = AsyncMock()
        engine.campaign_loader = AsyncMock(return_value=self.leased_row())
        state = engine_state(campaign_supervisor_token="supervisor-token")
        service = RecordingService()
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value={**engine_context(),
                                           "worker_epoch": 1})), \
             patch("orchestrator.specialist_integration.specialist_integration",
                   service):
            self.assertFalse(await engine._run_specialist_phase_guarded(state))
        self.assertEqual(state.reason_code, "authorization_changed")
        self.assertEqual(service.calls, [])

        state = engine_state(campaign_supervisor_token="supervisor-token",
                             scope_digest="b" * 64)
        service = RecordingService()
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=engine_context())), \
             patch("orchestrator.specialist_integration.specialist_integration",
                   service):
            self.assertFalse(await engine._run_specialist_phase_guarded(state))
        self.assertEqual(state.reason_code, "scope_changed")
        self.assertEqual(service.calls, [])


class DurableResultBoundaryTests(OfflineCase):
    def task(self):
        return {
            "id": "task-1", "state": "running", "run_id": "run-1",
            "revision": 1, "evidence_inputs": ["e1"],
            "security_questions": ["exposure:http-response"],
        }

    def result(self):
        return AgentResult(
            interpreted_request="Review saved evidence only",
            evidence_references=["e1"],
            observations=[{
                "evidence_id": "e1", "observation": "Saved response observed",
                "verified": True,
            }],
            hypotheses=[{
                "description": "Candidate only", "evidence_references": ["e1"],
                "verified": True,
            }],
            uncertainty=["No independent reproduction"],
        )

    async def test_collect_forces_unverified_at_the_durable_storage_boundary(self):
        task = self.task()
        state = {
            "tasks": {task["id"]: task},
            "evidence": {"e1": {
                "id": "e1", "provenance": "worker_receipt",
                "trust": "untrusted_observation",
            }},
        }
        captured = {}

        class CapturingStore(TeamStore):
            async def mutate(self, sid, owner, request_id, operation, build, *, enqueue_review_challenge=False):
                collection, entity_id, data = await build(None, None, state)
                captured.update(operation=operation, collection=collection,
                                entity_id=entity_id, data=data,
                                request_id=request_id)
                return {"entity_id": entity_id, "data": data,
                        "duplicate": False}

        store = CapturingStore()
        original = self.result()
        event = await store.collect("engagement", "owner", "task-1", "run-1",
                                    original)
        stored = event["data"]["result"]
        self.assertFalse(stored["observations"][0]["verified"])
        self.assertFalse(stored["hypotheses"][0]["verified"])
        self.assertFalse(captured["operation"]["result"]["observations"][0]["verified"])
        self.assertFalse(captured["operation"]["result"]["hypotheses"][0]["verified"])
        self.assertEqual(stored["evidence_references"], ["e1"])
        # A worker receipt remains a receipt; only the LLM conclusion is demoted.
        self.assertEqual(state["evidence"]["e1"]["provenance"], "worker_receipt")
        self.assertEqual(state["evidence"]["e1"]["trust"], "untrusted_observation")
        # The caller's object is not silently mutated.
        self.assertTrue(original.observations[0]["verified"])
        self.assertTrue(original.hypotheses[0]["verified"])

    async def test_collect_does_not_treat_a_blocked_result_as_verified(self):
        task = self.task()
        state = {
            "tasks": {task["id"]: task},
            "evidence": {"e1": {"id": "e1", "provenance": "worker_receipt"}},
        }
        captured = {}

        class CapturingStore(TeamStore):
            async def mutate(self, sid, owner, request_id, operation, build, *, enqueue_review_challenge=False):
                collection, entity_id, data = await build(None, None, state)
                captured["data"] = data
                return {"entity_id": entity_id, "data": data,
                        "duplicate": False}

        blocked = AgentResult(
            interpreted_request="Review only", evidence_references=["e1"],
            observations=[{"evidence_id": "e1", "observation": "Observed",
                           "verified": True}],
            status="blocked", uncertainty=["Blocked without reproduction"])
        await CapturingStore().collect("engagement", "owner", "task-1",
                                       "run-1", blocked)
        self.assertEqual(captured["data"]["state"], "blocked")
        self.assertFalse(captured["data"]["result"]["observations"][0]["verified"])


class EvidenceChangeDeduplicationTests(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.store = MemoryTeamStore()
        self.coordinator = FakeCoordinator(self.store)
        self.service = SpecialistIntegration(
            store=self.store, coordinator=self.coordinator,
            application_loader=AsyncMock(return_value=APPLICATION))

    async def ensure(self, selected):
        return await self.service.ensure(
            session_id="engagement", owner_id="owner",
            campaign_id="campaign-1", scope_digest=DIGEST,
            candidates=selected)

    def by_question(self, question):
        return {task["security_questions"][0]: task
                for task in self.store.tasks.values()}[question]

    async def test_changed_evidence_does_not_duplicate_an_unresolved_review(self):
        first = await self.ensure(candidates())
        self.assertEqual(first["created"], 5)
        # Simulate crash reconciliation and a still-pending review.
        self.by_question("exposure:http-response")["state"] = "blocked"
        self.by_question("authentication:http-response")["state"] = "awaiting_review"
        before_ids = set(self.store.tasks)
        before_creates = len(self.store.create_calls)

        changed = candidates(observation_job_ids={"http_response": ["job-2"]})
        result = await self.ensure(changed)
        self.assertEqual(result["created"], 0)
        self.assertEqual(set(self.store.tasks), before_ids)
        self.assertEqual(len(self.store.create_calls), before_creates)
        self.assertEqual(result["task_ids"], first["task_ids"])
        self.assertEqual(len(result["deferred"]), 2)
        self.assertTrue(any("unresolved review" in item for item in result["limitations"]))
        self.assertEqual(self.by_question("exposure:http-response")["state"], "blocked")

    async def test_new_evidence_creates_a_follow_up_after_resolution(self):
        first = await self.ensure(candidates())
        self.by_question("exposure:http-response")["state"] = "completed"
        self.by_question("authentication:http-response")["state"] = "cancelled"
        old_ids = set(self.store.tasks)
        old_by_question = {question: task["id"]
                           for question, task in
                           ((task["security_questions"][0], task)
                            for task in self.store.tasks.values())}

        changed = candidates(observation_job_ids={"http_response": ["job-2"]})
        result = await self.ensure(changed)
        self.assertEqual(result["created"], 2)
        new_ids = set(self.store.tasks) - old_ids
        self.assertEqual(len(new_ids), 2)
        exposure = self.by_question("exposure:http-response")
        authentication = self.by_question("authentication:http-response")
        self.assertNotEqual(exposure["id"], old_by_question["exposure:http-response"])
        self.assertNotEqual(authentication["id"],
                            old_by_question["authentication:http-response"])
        for task in (exposure, authentication):
            source_ids = {entry["source_id"] for entry in self.store.evidence.values()
                          if entry["id"] in task["evidence_inputs"]}
            self.assertEqual(source_ids, {"job-2"})
        self.assertFalse(result["deferred"])

    async def test_same_evidence_and_campaign_remains_idempotent(self):
        first = await self.ensure(candidates())
        again = await self.ensure(candidates())
        self.assertEqual(again["task_ids"], first["task_ids"])
        self.assertEqual(again["created"], 0)
        self.assertEqual(len(self.store.tasks), 5)
        self.assertFalse(again["deferred"])
