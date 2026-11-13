"""SPEC-13.2 campaign execution-boundary regressions; no network or models."""
import copy
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from agents.result_contract import AgentResult
from memory.team_tasks import normalize_unverified_result
from orchestrator.campaign_execution import CampaignExecutionDenied
from orchestrator.specialist_integration import (
    SpecialistBudgetExhausted,
    SpecialistIntegration,
    SpecialistIntegrationError,
)
from orchestrator.team_coordinator import TeamCoordinator
from tests.support import OfflineCase

UTC = timezone.utc
DIGEST = "a" * 64
TOKEN = "supervisor-token"


def campaign_row(**overrides):
    row = {
        "id": "campaign-1", "session_id": "engagement", "owner_id": "owner",
        "state": "running", "scope_digest": DIGEST,
        "auth_revision": 7, "worker_epoch": 3,
        "lease_holder": TOKEN,
        "lease_expires_at": (datetime.now(UTC).replace(tzinfo=None)
                             + timedelta(minutes=5)),
    }
    row.update(overrides)
    return row


def engagement_context(**overrides):
    context = {
        "owner_id": "owner", "scope": {"targets": ["192.0.2.1"]},
        "target": "192.0.2.1", "scope_digest": DIGEST,
        "auth_revision": 7, "worker_epoch": 3, "worker_blocked": False,
    }
    context.update(overrides)
    return context


def task(task_id="task-1", **overrides):
    value = {
        "id": task_id, "campaign_id": "campaign-1",
        "owner_role": "web_intel",
        "objective": "Review saved evidence only",
        "expected_output": "Evidence-linked unverified observations",
        "completion_criteria": ["Cite saved evidence or uncertainty"],
        "evidence_inputs": ["e1"], "state": "queued",
        "revision": 1, "attempts": 0, "run_id": None,
    }
    value.update(overrides)
    return value


class DispatchStore:
    """Minimal team ledger double for the real coordinator boundary."""

    def __init__(self, tasks, *, hide_until_claim=False):
        self.tasks = {item["id"]: copy.deepcopy(item) for item in tasks}
        self.evidence = [{
            "id": "e1", "source_id": "job-1", "provenance": "worker_receipt",
            "trust": "untrusted_observation",
        }]
        self.claim_calls = 0
        self.block_calls = []
        self.hide_until_claim = hide_until_claim

    async def view(self, session_id, owner_id):
        hidden = self.hide_until_claim and not self.claim_calls
        return {
            "tasks": [] if hidden else [
                copy.deepcopy(item) for item in self.tasks.values()],
            "evidence": [] if hidden else copy.deepcopy(self.evidence),
            "scope": {}, "target": "192.0.2.1",
        }

    async def claim(self, session_id, owner_id, task_id, request_id):
        self.claim_calls += 1
        record = self.tasks.get(task_id)
        if record is None:
            raise HTTPException(404, "Task not found")
        if record["state"] != "queued":
            raise HTTPException(409, "Task is not claimable")
        record.update(state="running", run_id=request_id,
                      attempts=record["attempts"] + 1)
        return {"entity_id": task_id, "data": copy.deepcopy(record),
                "duplicate": False}

    async def collect(self, session_id, owner_id, task_id, run_id, result):
        record = self.tasks[task_id]
        normalized = normalize_unverified_result(result)
        record.update(state="awaiting_review",
                      result=normalized.model_dump())
        return {"entity_id": task_id, "data": copy.deepcopy(record),
                "duplicate": False}

    async def block(self, session_id, owner_id, task_id, run_id, reason,
                    *, failed=False):
        self.block_calls.append((task_id, failed, reason))
        record = self.tasks[task_id]
        record.update(state="failed" if failed else "blocked",
                      reason=reason)
        return {"entity_id": task_id, "data": copy.deepcopy(record),
                "duplicate": False}


class FakeSpecialist:
    def __init__(self, *, failure=None, on_call=None):
        self.calls = []
        self.failure = failure
        self.on_call = on_call

    async def process(self, session_id, owner_id, input_data, skill):
        self.calls.append((session_id, owner_id, input_data, skill))
        if self.on_call is not None:
            callback, self.on_call = self.on_call, None
            callback()
        if self.failure is not None:
            raise self.failure
        return {"agent_result": AgentResult(
            interpreted_request="Review saved evidence only",
            evidence_references=["e1"],
            observations=[{"evidence_id": "e1",
                           "observation": "Saved response observed",
                           "verified": True}],
            hypotheses=[{"description": "Candidate only",
                         "evidence_references": ["e1"],
                         "verified": True}],
            uncertainty=["Synthetic unverified specialist analysis"],
        ).model_dump()}


class CampaignBoundaryCase(OfflineCase):
    def coordinator(self, row, context):
        return TeamCoordinator(
            campaign_loader=AsyncMock(return_value=row),
            context_loader=AsyncMock(return_value=context))

    async def dispatch(self, store, coordinator, specialist, *,
                       task_id="task-1", **overrides):
        values = {
            "campaign_id": "campaign-1",
            "campaign_supervisor_token": TOKEN,
            "scope_digest": DIGEST, "auth_revision": 7, "worker_epoch": 3,
        }
        values.update(overrides)
        with patch("orchestrator.team_coordinator.team_store", store), \
             patch.object(coordinator, "specialists",
                          return_value={"web_intel": specialist}):
            return await coordinator.run(
                "engagement", "owner", task_id, str(uuid.uuid4()),
                "expert", **values)


class ManualExecutionBoundaryTests(CampaignBoundaryCase):
    async def test_manual_api_delegate_task_cannot_run_a_campaign_task(self):
        """The route's delegate_task entry point reaches the same fence."""
        from agents.coordinator_agent import coordinator_agent
        store = DispatchStore([task()])
        with patch("orchestrator.team_coordinator.team_store", store):
            with self.assertRaises(CampaignExecutionDenied) as error:
                await coordinator_agent.delegate_task(
                    "engagement", "owner", "task-1", str(uuid.uuid4()),
                    "expert")
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(store.claim_calls, 0)
        self.assertEqual(store.tasks["task-1"]["state"], "queued")

    async def test_manual_dispatch_cannot_run_a_campaign_task(self):
        store = DispatchStore([task()])
        coordinator = self.coordinator(campaign_row(), engagement_context())
        specialist = FakeSpecialist()
        with self.assertRaises(CampaignExecutionDenied) as error:
            with patch("orchestrator.team_coordinator.team_store", store), \
                 patch.object(coordinator, "specialists",
                              return_value={"web_intel": specialist}):
                await coordinator.run("engagement", "owner", "task-1",
                                      str(uuid.uuid4()), "expert")
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(store.claim_calls, 0)
        self.assertEqual(store.tasks["task-1"]["state"], "queued")
        self.assertEqual(specialist.calls, [])

    async def test_wrong_campaign_identity_or_token_cannot_dispatch(self):
        store = DispatchStore([task()])
        coordinator = self.coordinator(campaign_row(), engagement_context())
        specialist = FakeSpecialist()
        with self.assertRaises(CampaignExecutionDenied) as error:
            await self.dispatch(store, coordinator, specialist,
                                campaign_id="other-campaign")
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        with self.assertRaises(CampaignExecutionDenied) as error:
            await self.dispatch(store, coordinator, specialist,
                                campaign_supervisor_token="")
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(store.claim_calls, 0)
        self.assertEqual(specialist.calls, [])

    async def test_claimed_campaign_task_is_blocked_before_dispatch_if_it_was_not_visible(self):
        """A task that appears between the read and the claim is still fenced."""
        store = DispatchStore([task()], hide_until_claim=True)
        coordinator = self.coordinator(campaign_row(), engagement_context())
        specialist = FakeSpecialist()
        with self.assertRaises(CampaignExecutionDenied) as error:
            with patch("orchestrator.team_coordinator.team_store", store), \
                 patch.object(coordinator, "specialists",
                              return_value={"web_intel": specialist}):
                await coordinator.run("engagement", "owner", "task-1",
                                      str(uuid.uuid4()), "expert",
                                      campaign_id="campaign-1",
                                      campaign_supervisor_token="")
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(store.claim_calls, 1)
        self.assertEqual(store.tasks["task-1"]["state"], "blocked")
        self.assertEqual(specialist.calls, [])


class CampaignLeaseBoundaryTests(CampaignBoundaryCase):
    async def denied(self, row, context=None, **overrides):
        store = DispatchStore([task()])
        coordinator = self.coordinator(row, context or engagement_context())
        specialist = FakeSpecialist()
        with self.assertRaises(CampaignExecutionDenied) as error:
            await self.dispatch(store, coordinator, specialist, **overrides)
        self.assertEqual(store.claim_calls, 0)
        self.assertEqual(specialist.calls, [])
        return error.exception.code

    async def test_terminal_expired_missing_and_foreign_leases_are_denied(self):
        for row in (
                campaign_row(state="completed"),
                campaign_row(state="cancelled"),
                campaign_row(state="paused"),
                campaign_row(lease_holder="other-supervisor"),
                campaign_row(lease_expires_at=(
                    datetime.now(UTC).replace(tzinfo=None)
                    - timedelta(seconds=1))),
                None):
            with self.subTest(row=row):
                self.assertEqual(
                    await self.denied(row), "campaign_supervisor_required")

    async def test_wrong_session_or_owner_is_denied(self):
        for row in (
                campaign_row(session_id="other-engagement"),
                campaign_row(owner_id="other-owner")):
            with self.subTest(row=row):
                self.assertEqual(
                    await self.denied(row), "campaign_supervisor_required")

    async def test_authorization_scope_and_worker_epoch_changes_are_denied(self):
        cases = (
            (engagement_context(auth_revision=8), "authorization_changed"),
            (engagement_context(scope_digest="b" * 64), "scope_changed"),
            (engagement_context(worker_epoch=4), "worker_epoch_changed"),
            (engagement_context(worker_blocked=True), "worker_blocked"),
        )
        for context, code in cases:
            with self.subTest(code=code):
                self.assertEqual(
                    await self.denied(campaign_row(), context), code)

    async def test_expected_run_authorization_must_still_match(self):
        self.assertEqual(
            await self.denied(campaign_row(), auth_revision=6),
            "authorization_changed")

    async def test_live_supervisor_lease_still_dispatches(self):
        store = DispatchStore([task()])
        coordinator = self.coordinator(campaign_row(), engagement_context())
        specialist = FakeSpecialist()
        event = await self.dispatch(store, coordinator, specialist)
        self.assertEqual(event["data"]["state"], "awaiting_review")
        self.assertEqual(len(specialist.calls), 1)
        self.assertEqual(store.claim_calls, 1)
        self.assertFalse(any(
            item.get("verified") for item in
            store.tasks["task-1"]["result"]["observations"]))


class SafeBoundaryTests(CampaignBoundaryCase):
    async def test_lease_takeover_stops_the_next_dispatch(self):
        row = campaign_row()
        store = DispatchStore([task("task-1"), task("task-2")])
        coordinator = self.coordinator(row, engagement_context())
        specialist = FakeSpecialist(
            on_call=lambda: row.update(lease_holder="other-supervisor"))
        service = SpecialistIntegration(store=store, coordinator=coordinator)
        with patch("orchestrator.team_coordinator.team_store", store), \
             patch.object(coordinator, "specialists",
                          return_value={"web_intel": specialist}):
            with self.assertRaises(SpecialistIntegrationError) as error:
                await service.run_pending(
                    session_id="engagement", owner_id="owner",
                    task_ids=["task-1", "task-2"], skill_level="expert",
                    max_tasks=10, campaign_id="campaign-1",
                    campaign_supervisor_token=TOKEN, scope_digest=DIGEST,
                    auth_revision=7, worker_epoch=3)
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(len(specialist.calls), 1)
        self.assertEqual(store.tasks["task-1"]["state"], "awaiting_review")
        self.assertEqual(store.tasks["task-2"]["state"], "queued")
        self.assertEqual(store.claim_calls, 1)

    async def test_budget_exhaustion_stops_before_the_next_dispatch(self):
        store = DispatchStore([task("task-1"), task("task-2")])
        coordinator = self.coordinator(campaign_row(), engagement_context())
        specialist = FakeSpecialist(failure=HTTPException(
            429, {"code": "campaign_budget_exhausted",
                  "message": "Synthetic campaign budget exhausted"}))
        service = SpecialistIntegration(store=store, coordinator=coordinator)
        with patch("orchestrator.team_coordinator.team_store", store), \
             patch.object(coordinator, "specialists",
                          return_value={"web_intel": specialist}):
            with self.assertRaises(SpecialistBudgetExhausted):
                await service.run_pending(
                    session_id="engagement", owner_id="owner",
                    task_ids=["task-1", "task-2"], skill_level="expert",
                    max_tasks=10, campaign_id="campaign-1",
                    campaign_supervisor_token=TOKEN, scope_digest=DIGEST,
                    auth_revision=7, worker_epoch=3)
        self.assertEqual(len(specialist.calls), 1)
        self.assertEqual(store.tasks["task-1"]["state"], "failed")
        self.assertEqual(store.tasks["task-2"]["state"], "queued")
        self.assertEqual(store.claim_calls, 1)

    async def test_run_pending_requires_campaign_binding_for_campaign_tasks(self):
        store = DispatchStore([task()])
        coordinator = self.coordinator(campaign_row(), engagement_context())
        service = SpecialistIntegration(store=store, coordinator=coordinator)
        with patch("orchestrator.team_coordinator.team_store", store):
            with self.assertRaises(SpecialistIntegrationError) as error:
                await service.run_pending(
                    session_id="engagement", owner_id="owner",
                    task_ids=["task-1"], skill_level="expert", max_tasks=10)
        self.assertEqual(error.exception.code, "campaign_supervisor_required")
        self.assertEqual(store.claim_calls, 0)
