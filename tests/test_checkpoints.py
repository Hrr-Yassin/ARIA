"""SPEC-11 durable autonomous checkpoint regressions. No worker or model calls."""
import asyncio
import copy
from unittest.mock import AsyncMock, patch

from agents.autonomous_engine import (
    AutonomousEngine, SessionRunState, command_was_executed,
)
from memory.autonomous_runs import (
    CheckpointConflict, CheckpointIntegrityError, TERMINAL, RunStore,
    _payload_digest, _prepare_snapshot, build_checkpoint, command_digest,
    validate_checkpoint,
)
from memory.knowledge_store import scope_identity_digest
from tests.support import OfflineCase

SCOPE = {"targets": ["192.0.2.1"], "ports": [80]}
TARGET = "192.0.2.1"
CONTEXT = {
    "owner_id": "alice",
    "scope": SCOPE,
    "target": TARGET,
    "scope_digest": scope_identity_digest(SCOPE, TARGET),
    "auth_revision": 0,
    "worker_epoch": 0,
}


class MemoryRunBackend:
    """In-memory copy of the SQL checkpoint backend's locking contract."""

    def __init__(self):
        self.rows = {}
        self.clock = 0
        self.lock = asyncio.Lock()

    def _ordered(self, session_id):
        return sorted((row for row in self.rows.values()
                       if row["session_id"] == session_id),
                      key=lambda row: (row["updated_at"], row["id"]), reverse=True)

    async def save(self, snapshot):
        async with self.lock:
            self.clock += 1
            row = self.rows.get(snapshot["run_id"])
            if row is None:
                row = {"id": snapshot["run_id"], "session_id": snapshot["session_id"],
                       "state": "", "snapshot": {}, "updated_at": 0}
                self.rows[row["id"]] = row
            row["state"] = snapshot["run_state"]
            row["snapshot"] = _prepare_snapshot(row["snapshot"], snapshot)
            row["updated_at"] = self.clock

    async def latest(self, session_id):
        async with self.lock:
            rows = self._ordered(session_id)
            return copy.deepcopy(rows[0]["snapshot"]) if rows else {"active": False}

    async def recover(self):
        async with self.lock:
            for row in self.rows.values():
                snapshot = copy.deepcopy(row["snapshot"])
                had_lease = snapshot.pop("restore_lease", None) is not None
                changed = had_lease
                if row["state"] not in TERMINAL:
                    snapshot.update({
                        "active": False, "run_state": "blocked",
                        "reason_code": "restart_reconciliation",
                        "waiting_approval": False, "pending_action_id": None,
                        "reason": "Server restarted. No command was replayed.",
                    })
                    row["state"] = "blocked"
                    changed = True
                if changed:
                    self.clock += 1
                    row.update(snapshot=snapshot, updated_at=self.clock)

    async def claim_restore(self, session_id, run_id=None, token=None,
                            lease_seconds=60):
        async with self.lock:
            rows = self._ordered(session_id)
            if not rows:
                raise CheckpointConflict("No durable run checkpoint exists",
                                         code="checkpoint_integrity")
            if run_id:
                target = next((row for row in rows if row["id"] == run_id), None)
                if target is None:
                    raise CheckpointConflict("Requested checkpoint does not exist",
                                             code="checkpoint_integrity")
                if rows[0]["id"] != target["id"]:
                    raise CheckpointConflict("Checkpoint is stale",
                                             code="checkpoint_stale")
            else:
                target = rows[0]
            snapshot = copy.deepcopy(target["snapshot"])
            if bool(snapshot.get("active")):
                raise CheckpointConflict(
                    "Another autonomous run is active for this engagement",
                    code="run_active")
            lease = snapshot.get("restore_lease")
            if isinstance(lease, dict) and float(lease.get("expires_at", 0)) > 0:
                raise CheckpointConflict("Restoration already in progress",
                                         code="restore_in_progress")
            self.clock += 1
            token = token or f"lease-{self.clock}"
            snapshot["restore_lease"] = {"token": token, "expires_at": 9999999999}
            target["snapshot"] = snapshot
            return {"run_id": target["id"], "session_id": target["session_id"],
                    "snapshot": copy.deepcopy(snapshot), "token": token}

    async def commit_restore(self, session_id, run_id, token, snapshot):
        async with self.lock:
            row = self.rows.get(run_id)
            lease = (row or {}).get("snapshot", {}).get("restore_lease")
            if (row is None or row["session_id"] != session_id
                    or not isinstance(lease, dict) or lease.get("token") != token):
                raise CheckpointConflict("Restore claim was lost",
                                         code="restore_conflict")
            self.clock += 1
            row["state"] = snapshot["run_state"]
            row["snapshot"] = _prepare_snapshot(row["snapshot"], snapshot)
            row["updated_at"] = self.clock
            return copy.deepcopy(row["snapshot"])

    async def release_restore(self, session_id, run_id, token):
        async with self.lock:
            row = self.rows.get(run_id)
            if row is None or row["session_id"] != session_id:
                return
            lease = row["snapshot"].get("restore_lease")
            if isinstance(lease, dict) and lease.get("token") == token:
                row["snapshot"].pop("restore_lease", None)


class FakeJobs:
    def __init__(self):
        self.rows = []

    async def list(self, session_id):
        return copy.deepcopy([row for row in self.rows
                              if row["session_id"] == session_id])


class FakeKnowledge:
    def __init__(self, records=None):
        # job_id -> (observation, run_id)
        self.records = dict(records or {})
        self.calls = 0

    async def restore(self, session_id, owner_id):
        self.calls += 1
        return {
            "session_id": session_id,
            "observations": len(self.records),
            "restored": 0,
            "skipped": 0,
            "job_ids": sorted(self.records),
            "job_observations": {job: value[0] for job, value in self.records.items()},
            "job_runs": {job: value[1] for job, value in self.records.items()},
        }


def make_snapshot(*, session_id="s1", run_id="run-1", run_state="planning",
                  steps=2, model_calls=1, max_steps=12,
                  completed=("port_discovery",),
                  jobs=(("job-nmap", "port_discovery"),),
                  executed=("nmap -p 80 192.0.2.1",),
                  last_action="", last_action_command="", active=True,
                  owner_id="alice", scope_digest=None, campaign_id="",
                  specialist_phase_done=False, specialist_ids=(),
                  capability_versions=False):
    engine = AutonomousEngine()
    state = SessionRunState(
        session_id=session_id, user_id="alice", owner_id=owner_id,
        goal="discovery", target=TARGET, skill_level="expert",
        objective="Identify exposed services on the authorized target",
        run_id=run_id, max_steps=max_steps, steps_taken=steps,
        successful_steps=steps, model_calls=model_calls,
        run_state=run_state, capabilities={
            "tools": ["curl", "nmap"],
            **({"authenticated_http_version": 1, "specialist_http_version": 1}
               if capability_versions else {})},
        active=active,
        scope_digest=scope_digest or CONTEXT["scope_digest"],
        last_action_id=last_action,
        last_action_command=last_action_command,
        campaign_id=campaign_id,
        specialist_phase_done=specialist_phase_done,
        specialist_investigation_ids=list(specialist_ids),
    )
    state.completed_observations = list(completed)
    state.observation_job_ids = {
        observation: [job for job, kind in jobs if kind == observation]
        for observation in completed
    }
    state.evidence_job_ids = [job for job, _ in jobs]
    state.executed_commands = list(executed)
    state.executed_command_hashes = [command_digest(item) for item in executed]
    engine._runs[session_id] = state
    return engine.get_status(session_id)


def make_store(snapshot, *, jobs=None):
    backend = MemoryRunBackend()
    store = RunStore(backend=backend, jobs=jobs or FakeJobs())
    return store, backend


class CheckpointTests(OfflineCase):
    async def _restore_engine(self, store, knowledge, *, context=None,
                              resume=True, run_id=None, loop=None,
                              campaign_id=""):
        engine = AutonomousEngine()
        loop = loop or AsyncMock()
        context = dict(context or CONTEXT)
        execute = AsyncMock()
        propose = AsyncMock()
        worker_execute = AsyncMock()
        submit = AsyncMock()
        capabilities = AsyncMock()
        preflight = AsyncMock()
        planner = AsyncMock()
        patches = [
            patch("agents.autonomous_engine.run_store", store),
            patch("agents.autonomous_engine.knowledge_store", knowledge),
            patch("agents.autonomous_engine.execution_authorization._context",
                  AsyncMock(return_value=context)),
            patch("agents.autonomous_engine.execution_authorization.execute", execute),
            patch("agents.autonomous_engine.execution_authorization.propose", propose),
            patch("agents.autonomous_engine.worker_jobs.execute", worker_execute),
            patch("agents.autonomous_engine.worker_jobs.client.submit", submit),
            patch("agents.autonomous_engine.worker_jobs.client.capabilities",
                  capabilities),
            patch("llm.pool_manager.pool_manager.planner_preflight", preflight),
            patch("agents.orchestrator_agent.orchestrator_agent.process", planner),
            patch.object(engine, "_write_decision_log", AsyncMock()),
            patch.object(engine, "_run_loop", loop),
        ]
        for item in patches:
            item.start()
        try:
            result = await engine.restore("s1", "alice", run_id=run_id,
                                          resume=resume,
                                          campaign_id=campaign_id)
        finally:
            for item in reversed(patches):
                item.stop()
        return engine, result, {
            "execute": execute, "propose": propose,
            "worker_execute": worker_execute, "submit": submit,
            "capabilities": capabilities, "preflight": preflight,
            "planner": planner, "loop": loop,
        }

    async def test_crash_restore_preserves_progress_and_never_dispatches(self):
        snapshot = make_snapshot()
        store, backend = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()  # simulate the API restart reconciliation
        self.assertEqual(backend.rows["run-1"]["state"], "blocked")
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})

        engine, result, calls = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "restored")
        self.assertTrue(result["active"])
        self.assertEqual(result["steps_taken"], 2)
        self.assertEqual(result["model_calls"], 1)
        self.assertEqual(result["max_steps"], 12)
        self.assertEqual(result["remaining_steps"], 10)
        self.assertEqual(result["remaining_model_calls"], 19)
        self.assertEqual(result["completed_observations"], ["port_discovery"])
        self.assertEqual(result["evidence_job_ids"], ["job-nmap"])
        self.assertEqual(knowledge.calls, 1)
        for name in ("execute", "propose", "worker_execute", "submit",
                     "capabilities", "preflight", "planner"):
            calls[name].assert_not_awaited()

        state = engine._runs["s1"]
        self.assertEqual(state.run_state, "planning")
        self.assertEqual(state.steps_taken, 2)
        self.assertEqual(state.model_calls, 1)
        self.assertEqual(state.executed_commands, ["nmap -p 80 192.0.2.1"])
        self.assertIsNone(state.pending_approval)
        self.assertFalse(engine.get_status("s1")["waiting_approval"])
        self.assertTrue(command_was_executed(state, "nmap -p 80 192.0.2.1"))
        class ReplayPlanner:
            async def process(self, **kwargs):
                return {"commands": [
                    {"command": "nmap -p 80 192.0.2.1", "tool": "nmap"}]}

        feedback = []
        with patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=dict(CONTEXT))):
            plan = await engine._validated_plan(
                state, ReplayPlanner(), "", [], feedback)
        self.assertIsNone(plan)
        self.assertTrue(any("already executed" in item for item in feedback))
        await asyncio.sleep(0)
        calls["loop"].assert_awaited_once()
        await engine.shutdown()

    async def test_review_receipt_marker_and_objective_survive_restart(self):
        snapshot = make_snapshot()
        snapshot['reviewed_evidence_job_ids'] = ['job-nmap']
        objective = 'Preserve the owner objective; follow-up hypotheses remain pending.'
        snapshot['original_objective'] = objective
        store, backend = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({'job-nmap': ('port_discovery', 'run-1')})
        engine, result, calls = await self._restore_engine(store, knowledge, resume=False)
        self.assertEqual(result['status'], 'restored')
        restored_status = engine.get_status('s1')
        self.assertEqual(restored_status['original_objective'], objective)
        self.assertEqual(restored_status['reviewed_evidence_job_ids'], ['job-nmap'])
        self.assertEqual(engine._runs['s1'].objective, objective)
        calls['loop'].assert_not_awaited()
        calls['submit'].assert_not_awaited()
        checkpoint = backend.rows['run-1']['snapshot']['checkpoint']
        self.assertEqual(checkpoint['reviewed_evidence_job_ids'], ['job-nmap'])
        validate_checkpoint(checkpoint)
        await engine.shutdown()

    async def test_review_receipt_marker_rejects_foreign_and_malformed_identities(self):
        checkpoint = build_checkpoint(make_snapshot())
        for reviewed in (True, ['foreign-job'], ['job-nmap', 'job-nmap'], [1]):
            with self.subTest(reviewed=reviewed):
                corrupted = copy.deepcopy(checkpoint)
                corrupted['reviewed_evidence_job_ids'] = reviewed
                corrupted['digest'] = _payload_digest(corrupted)
                with self.assertRaises(CheckpointIntegrityError):
                    validate_checkpoint(corrupted)
        legacy = copy.deepcopy(checkpoint)
        legacy.pop('reviewed_evidence_job_ids')
        legacy['digest'] = _payload_digest(legacy)
        validate_checkpoint(legacy)

    async def test_pause_and_cancellation_acknowledgement_are_durable_and_strict(self):
        snapshot = make_snapshot()
        snapshot.update(pause_requested=True, cancellation_confirmed=False)
        store, backend = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        saved = await store.latest('s1')
        self.assertTrue(saved['checkpoint']['pause_requested'])
        self.assertIs(saved['checkpoint']['cancellation_confirmed'], False)
        validate_checkpoint(saved['checkpoint'])
        for field, value in [('pause_requested', 'yes'), ('cancellation_confirmed', 1)]:
            with self.subTest(field=field):
                corrupted = copy.deepcopy(saved['checkpoint'])
                corrupted[field] = value
                corrupted['digest'] = _payload_digest(corrupted)
                with self.assertRaises(CheckpointIntegrityError):
                    validate_checkpoint(corrupted)

    async def test_final_step_checkpoint_can_restore_processing_without_dispatch(self):
        snapshot = make_snapshot(
            steps=2, max_steps=2,
            completed=('port_discovery', 'http_response'),
            jobs=(('job-nmap', 'port_discovery'), ('job-curl', 'http_response')),
            executed=('nmap -p 80 192.0.2.1', 'curl -I http://192.0.2.1'))
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({'job-nmap': ('port_discovery', 'run-1'),
                                   'job-curl': ('http_response', 'run-1')})
        engine, result, calls = await self._restore_engine(store, knowledge, resume=False)
        self.assertEqual(result['status'], 'restored')
        self.assertEqual(result['remaining_steps'], 0)
        self.assertTrue(engine.get_status('s1')['completion']['complete'])
        for name in ('execute', 'propose', 'worker_execute', 'submit', 'planner', 'loop'):
            calls[name].assert_not_awaited()
        await engine.shutdown()

    async def test_replay_guard_survives_redacted_display_commands(self):
        state = SessionRunState("s1", "alice", "discovery", TARGET, "expert")
        state.executed_commands = ["curl -H Authorization:[REDACTED] http://192.0.2.1"]
        state.executed_command_hashes = [
            command_digest("curl -H Authorization: Bearer secret http://192.0.2.1")]
        self.assertTrue(command_was_executed(
            state, "curl -H Authorization: Bearer secret http://192.0.2.1"))
        self.assertFalse(command_was_executed(state, "curl http://192.0.2.1"))

    async def test_dry_run_rehydrates_without_starting_the_loop(self):
        snapshot = make_snapshot()
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})
        engine, result, calls = await self._restore_engine(
            store, knowledge, resume=False)
        self.assertEqual(result["status"], "restored")
        self.assertFalse(result["active"])
        self.assertFalse(result["resumed"])
        self.assertFalse(engine._runs["s1"].active)
        self.assertEqual(engine._runs["s1"].run_state, "restored")
        calls["loop"].assert_not_awaited()
        calls["execute"].assert_not_awaited()
        calls["submit"].assert_not_awaited()
        await engine.shutdown()

    async def test_corrupted_or_incomplete_checkpoint_is_rejected(self):
        snapshot = make_snapshot()
        store, backend = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})

        row = backend.rows["run-1"]
        original = copy.deepcopy(row["snapshot"])
        row["snapshot"]["checkpoint"]["steps_taken"] += 1
        engine, result, _ = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_integrity")
        await engine.shutdown()

        row["snapshot"] = copy.deepcopy(original)
        row["snapshot"].pop("checkpoint")
        engine, result, _ = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_integrity")
        await engine.shutdown()

    async def test_stale_checkpoint_is_rejected(self):
        first = make_snapshot(run_id="run-1", jobs=(("job-a", "port_discovery"),))
        second = make_snapshot(run_id="run-2", jobs=(("job-b", "port_discovery"),))
        store, _ = make_store(first)
        await store.save(first)
        await store.save(second)
        await store.recover()
        knowledge = FakeKnowledge({"job-a": ("port_discovery", "run-1"),
                                   "job-b": ("port_discovery", "run-2")})
        engine, result, _ = await self._restore_engine(
            store, knowledge, run_id="run-1")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_stale")
        await engine.shutdown()

        engine, result, _ = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "restored")
        self.assertEqual(result["run_id"], "run-2")
        await engine.shutdown()

    async def test_wrong_owner_wrong_scope_and_revoked_authorization_are_rejected(self):
        snapshot = make_snapshot()
        store, backend = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})

        cases = [
            ({"owner_id": "bob"}, "checkpoint_integrity"),
            ({"scope": {"targets": ["198.51.100.2"]}}, "checkpoint_access_denied"),
            ({"auth_revision": 3}, "checkpoint_access_denied"),
            ({"worker_epoch": 1}, "checkpoint_access_denied"),
        ]
        for override, expected in cases:
            with self.subTest(override=override):
                context = {**CONTEXT, **override}
                if "scope" in override:
                    context["scope_digest"] = scope_identity_digest(
                        override["scope"], TARGET)
                engine, result, _ = await self._restore_engine(
                    store, knowledge, context=context)
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["reason_code"], expected)
                await engine.shutdown()

    async def test_unrecorded_or_mismatched_evidence_is_rejected(self):
        snapshot = make_snapshot()
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()

        engine, result, _ = await self._restore_engine(
            store, FakeKnowledge({}), resume=False)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_integrity")
        await engine.shutdown()

        engine, result, _ = await self._restore_engine(
            store, FakeKnowledge({"job-nmap": ("http_response", "run-1")}),
            resume=False)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_integrity")
        await engine.shutdown()

        engine, result, _ = await self._restore_engine(
            store, FakeKnowledge({"job-nmap": ("port_discovery", "other-run")}),
            resume=False)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_integrity")
        await engine.shutdown()

    async def test_uncertain_execution_states_fail_closed(self):
        snapshot = make_snapshot(
            run_state="executing", completed=(), jobs=(),
            executed=(), last_action="job-x",
            last_action_command="nmap -p 80 192.0.2.1")
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge()

        store._jobs.rows = [{"job_id": "job-x", "session_id": "s1",
                             "state": "running"}]
        engine, result, _ = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_state")
        self.assertIn("unresolved worker jobs", result["reason"])
        await engine.shutdown()

        store._jobs.rows = [{"job_id": "job-x", "session_id": "s1",
                             "state": "failed", "exit_code": 1}]
        engine, result, _ = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_state")
        self.assertIn("uncertain", result["reason"])
        await engine.shutdown()

        # A succeeded job whose result was never committed to the checkpoint
        # is still uncertain and must not be replayed automatically.
        store._jobs.rows = [{"job_id": "job-x", "session_id": "s1",
                             "state": "succeeded", "exit_code": 0}]
        knowledge.records = {"job-x": ("port_discovery", "run-1")}
        engine, result, _ = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_state")
        self.assertIn("uncertain", result["reason"])
        await engine.shutdown()

        # No durable job row means the command was never submitted: safe to resume.
        store._jobs.rows = []
        knowledge.records = {}
        engine, result, _ = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "restored")
        self.assertEqual(result["run_state"], "planning")
        await engine.shutdown()

    async def test_completed_checkpoint_restores_terminal_without_a_task(self):
        snapshot = make_snapshot(
            run_state="completed", active=False,
            completed=("port_discovery", "http_response"),
            jobs=(("job-nmap", "port_discovery"), ("job-curl", "http_response")),
            executed=("nmap -p 80 192.0.2.1", "curl -I http://192.0.2.1"))
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({
            "job-nmap": ("port_discovery", "run-1"),
            "job-curl": ("http_response", "run-1"),
        })
        engine, result, calls = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "restored")
        self.assertFalse(result["active"])
        self.assertEqual(result["run_state"], "completed")
        self.assertNotIn("s1", engine._tasks)
        calls["loop"].assert_not_awaited()
        await engine.shutdown()

    async def test_campaign_and_specialist_identity_survive_restore(self):
        snapshot = make_snapshot(
            campaign_id="campaign-1", specialist_phase_done=True,
            specialist_ids=("task-1", "task-2"))
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})
        engine, result, calls = await self._restore_engine(
            store, knowledge, resume=False, campaign_id="campaign-1")
        self.assertEqual(result["status"], "restored")
        self.assertEqual(result["campaign_id"], "campaign-1")
        state = engine._runs["s1"]
        self.assertEqual(state.campaign_id, "campaign-1")
        self.assertTrue(state.specialist_phase_done)
        self.assertEqual(state.specialist_investigation_ids,
                         ["task-1", "task-2"])
        calls["loop"].assert_not_awaited()
        await engine.shutdown()

    async def test_protocol_versions_survive_restore_for_specialist_selection(self):
        from orchestrator.specialist_integration import select_candidates
        snapshot = make_snapshot(
            campaign_id="campaign-1", capability_versions=True,
            completed=("port_discovery", "http_response"),
            jobs=(("job-nmap", "port_discovery"), ("job-curl", "http_response")),
            executed=("nmap -p 80 192.0.2.1", "curl -I http://192.0.2.1"))
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({
            "job-nmap": ("port_discovery", "run-1"),
            "job-curl": ("http_response", "run-1")})
        engine, result, _ = await self._restore_engine(
            store, knowledge, resume=False, campaign_id="campaign-1")
        self.assertEqual(result["status"], "restored")
        state = engine._runs["s1"]
        self.assertEqual(state.capabilities["authenticated_http_version"], 1)
        self.assertEqual(state.capabilities["specialist_http_version"], 1)
        selected = select_candidates(
            campaign_id="campaign-1", scope_digest=state.scope_digest,
            scope={"targets": [TARGET], "web_authenticated_replay": True,
                   "web_specialist_profiles": True},
            advertised=state.capabilities,
            observation_job_ids=state.observation_job_ids)
        self.assertEqual([item.specialty for item in selected],
                         ["exposure", "authentication"])
        await engine.shutdown()

    async def test_restore_rejects_a_different_campaign(self):
        snapshot = make_snapshot(campaign_id="campaign-1")
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})
        engine, result, _ = await self._restore_engine(
            store, knowledge, campaign_id="campaign-2")
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_code"], "checkpoint_access_denied")
        self.assertIn("another campaign", result["reason"])
        await engine.shutdown()

    async def test_malformed_protocol_capability_is_rejected(self):
        checkpoint = build_checkpoint(make_snapshot(capability_versions=True))
        checkpoint["capabilities"]["specialist_http_version"] = True
        checkpoint["digest"] = _payload_digest(checkpoint)
        with self.assertRaises(CheckpointIntegrityError) as error:
            validate_checkpoint(checkpoint, expected_session_id="s1",
                                expected_owner_id="alice")
        self.assertIn("protocol capability", str(error.exception))

    async def test_typed_capabilities_survive_checkpoint_and_reject_boolean_versions(self):
        snapshot = make_snapshot()
        snapshot['capabilities']['typed_adapters'] = {'httpx.http.probe.v1': 1}
        checkpoint = build_checkpoint(snapshot)
        self.assertEqual(checkpoint['capabilities']['typed_adapters'], {'httpx.http.probe.v1': 1})
        validate_checkpoint(checkpoint, expected_session_id='s1', expected_owner_id='alice')
        checkpoint['capabilities']['typed_adapters']['httpx.http.probe.v1'] = True
        checkpoint['digest'] = _payload_digest(checkpoint)
        with self.assertRaisesRegex(CheckpointIntegrityError, 'typed capabilities'):
            validate_checkpoint(checkpoint, expected_session_id='s1', expected_owner_id='alice')

    async def test_pre_spec13_checkpoint_without_optional_fields_is_valid(self):
        snapshot = make_snapshot()
        checkpoint = build_checkpoint(snapshot)
        for field in ("campaign_id", "specialist_phase_done",
                      "specialist_investigation_ids"):
            checkpoint.pop(field)
        checkpoint["digest"] = _payload_digest(checkpoint)
        validate_checkpoint(checkpoint, expected_session_id="s1",
                            expected_owner_id="alice")
        self.assertNotIn("campaign_id", checkpoint)

    async def test_concurrent_recovery_creates_one_active_run(self):
        snapshot = make_snapshot()
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})

        engine = AutonomousEngine()
        loop = AsyncMock()
        with patch("agents.autonomous_engine.run_store", store), \
             patch("agents.autonomous_engine.knowledge_store", knowledge), \
             patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=dict(CONTEXT))), \
             patch.object(engine, "_write_decision_log", AsyncMock()), \
             patch.object(engine, "_run_loop", loop):
            results = await asyncio.gather(
                engine.restore("s1", "alice"),
                engine.restore("s1", "alice"),
            )
        self.assertEqual(sorted(item["status"] for item in results),
                         ["already_running", "restored"])
        self.assertEqual(len([key for key in engine._runs
                              if engine._runs[key].active]), 1)
        await asyncio.sleep(0)
        self.assertEqual(loop.await_count, 1)
        await engine.shutdown()

    async def test_recover_clears_lease_left_by_a_crashed_restore(self):
        snapshot = make_snapshot()
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        claim = await store.claim_restore("s1")
        await store.recover()
        self.assertNotIn("restore_lease", await store.latest("s1"))
        with self.assertRaises(CheckpointConflict):
            await store.commit_restore("s1", claim["run_id"], claim["token"],
                                       copy.deepcopy(snapshot))
        reclaim = await store.claim_restore("s1")
        await store.release_restore("s1", reclaim["run_id"], reclaim["token"])

    async def test_active_checkpoint_cannot_be_restored_by_a_second_engine(self):
        snapshot = make_snapshot()
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        claim = await store.claim_restore("s1")
        active = copy.deepcopy(snapshot)
        active.update(active=True, run_state="planning")
        await store.commit_restore("s1", claim["run_id"], claim["token"], active)
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})

        engine, result, calls = await self._restore_engine(store, knowledge)
        self.assertEqual(result["status"], "already_running")
        self.assertEqual(result["reason_code"], "run_active")
        self.assertNotIn("s1", engine._runs)
        self.assertNotIn("s1", engine._tasks)
        self.assertEqual(knowledge.calls, 0)
        calls["loop"].assert_not_awaited()
        calls["execute"].assert_not_awaited()
        await engine.shutdown()

    async def test_backend_restore_lease_blocks_concurrent_claims(self):
        snapshot = make_snapshot()
        store, backend = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        first = await store.claim_restore("s1")
        self.assertTrue(first["token"])
        with self.assertRaises(CheckpointConflict) as error:
            await store.claim_restore("s1")
        self.assertEqual(error.exception.code, "restore_in_progress")
        await store.release_restore("s1", first["run_id"], first["token"])
        second = await store.claim_restore("s1")
        self.assertNotEqual(first["token"], second["token"])
        await store.release_restore("s1", second["run_id"], second["token"])


class CheckpointAuthorizationRegressionTests(OfflineCase):
    async def test_restored_authorization_material_is_never_reused(self):
        snapshot = make_snapshot()
        store, _ = make_store(snapshot)
        await store.save(snapshot)
        await store.recover()
        knowledge = FakeKnowledge({"job-nmap": ("port_discovery", "run-1")})
        engine = AutonomousEngine()
        with patch("agents.autonomous_engine.run_store", store), \
             patch("agents.autonomous_engine.knowledge_store", knowledge), \
             patch("agents.autonomous_engine.execution_authorization._context",
                   AsyncMock(return_value=dict(CONTEXT))), \
             patch.object(engine, "_write_decision_log", AsyncMock()), \
             patch.object(engine, "_run_loop", AsyncMock()):
            result = await engine.restore("s1", "alice", resume=False)
        self.assertEqual(result["status"], "restored")
        status = engine.get_status("s1")
        self.assertFalse(status["waiting_approval"])
        self.assertIsNone(status["pending_action_id"])
        self.assertIsNone(engine._runs["s1"].pending_approval)
        await engine.shutdown()
