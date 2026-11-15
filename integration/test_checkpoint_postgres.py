"""SPEC-11 PostgreSQL checkpoint integration tests; synthetic data only.

Requires a disposable database ending in *_test:
    ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test \
        python -m unittest integration.test_checkpoint_postgres -v
"""
import asyncio
import hashlib
import os
import subprocess
import sys
import unittest
import uuid

ENABLED = os.environ.get("ARIA_INTEGRATION") == "1"


@unittest.skipUnless(ENABLED, "set ARIA_INTEGRATION=1 with a disposable *_test database")
class CheckpointPostgres(unittest.IsolatedAsyncioTestCase):
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
        owner_id = "spec11-o-" + uuid.uuid4().hex[:12]
        session_id = "spec11-s-" + uuid.uuid4().hex[:12]
        async with async_session() as db:
            db.add(User(id=owner_id, username="u-" + uuid.uuid4().hex[:16],
                        password_hash="unused"))
            await db.flush()
            db.add(PentestSession(id=session_id, user_id=owner_id,
                                  target="192.0.2.1",
                                  scope={"targets": ["192.0.2.1"]}))
            await db.commit()
        return owner_id, session_id

    async def _record(self, owner, session_id, run_id, job_id, stdout):
        from memory.database_models import DecisionLog, async_session
        from memory.knowledge_store import KnowledgeStore
        async with async_session() as db:
            db.add(DecisionLog(
                id=str(uuid.uuid5(uuid.NAMESPACE_URL, "aria-worker:" + job_id)),
                session_id=session_id, user_id=owner,
                decision_type="worker_job",
                metadata_={"job_id": job_id, "session_id": session_id,
                           "user_id": owner, "state": "succeeded",
                           "exit_code": 0,
                           "output_hash": hashlib.sha256(stdout.encode()).hexdigest(),
                           "stderr_hash": hashlib.sha256(b"").hexdigest()},
            ))
            await db.commit()
        return await KnowledgeStore().record_observation(
            session_id=session_id, owner_id=owner, run_id=run_id,
            job_id=job_id, tool="nmap", observation="port_discovery",
            target="192.0.2.1", stdout=stdout, stderr="", exit_code=0,
            hosts_updated=["192.0.2.1"],
            ports_added=[{"ip": "192.0.2.1", "port": 80,
                          "service": "http", "version": "1.0"}],
        )

    async def _snapshot(self, owner, session_id, *, run_id=None, state="planning",
                        jobs=(), executed=(), steps=1, model_calls=1):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from memory.autonomous_runs import command_digest
        from memory.knowledge_store import scope_identity_digest
        engine = AutonomousEngine()
        run_id = run_id or "spec11-run-" + uuid.uuid4().hex[:12]
        scope = {"targets": ["192.0.2.1"]}
        state_obj = SessionRunState(
            session_id=session_id, user_id=owner, owner_id=owner,
            goal="discovery", target="192.0.2.1", skill_level="expert",
            objective="Identify exposed services on the authorized target",
            run_id=run_id, max_steps=12, steps_taken=steps, successful_steps=steps,
            model_calls=model_calls, run_state=state,
            capabilities={"tools": ["curl", "nmap"]},
            scope_digest=scope_identity_digest(scope, "192.0.2.1"),
            active=state not in {"completed", "blocked", "failed"},
        )
        state_obj.completed_observations = ["port_discovery"] if jobs else []
        state_obj.observation_job_ids = ({"port_discovery": [job for job, _ in jobs]}
                                         if jobs else {})
        state_obj.evidence_job_ids = [job for job, _ in jobs]
        state_obj.executed_commands = list(executed)
        state_obj.executed_command_hashes = [command_digest(item)
                                             for item in executed]
        engine._runs[session_id] = state_obj
        return engine.get_status(session_id)

    async def test_save_recover_and_restore_lease_roundtrip(self):
        from memory.autonomous_runs import (
            CheckpointConflict, RunStore, validate_checkpoint,
        )
        owner, session_id = await self._session()
        snapshot = await self._snapshot(owner, session_id)
        store = RunStore()
        await store.save(snapshot)

        stored = await store.latest(session_id)
        validate_checkpoint(stored["checkpoint"],
                            expected_run_id=snapshot["run_id"],
                            expected_session_id=session_id,
                            expected_owner_id=owner,
                            max_steps_limit=12)
        self.assertEqual(stored["checkpoint"]["steps_taken"], 1)

        await store.recover()
        blocked = await store.latest(session_id)
        self.assertEqual(blocked["run_state"], "blocked")
        self.assertEqual(blocked["reason_code"], "restart_reconciliation")
        validate_checkpoint(blocked["checkpoint"],
                            expected_run_id=snapshot["run_id"],
                            expected_session_id=session_id,
                            expected_owner_id=owner,
                            max_steps_limit=12)

        claim = await store.claim_restore(session_id)
        self.assertEqual(claim["run_id"], snapshot["run_id"])
        with self.assertRaises(CheckpointConflict) as error:
            await store.claim_restore(session_id)
        self.assertEqual(error.exception.code, "restore_in_progress")

        resumed = dict(blocked)
        resumed["run_state"] = "planning"
        resumed["active"] = True
        committed = await store.commit_restore(
            session_id, claim["run_id"], claim["token"], resumed)
        self.assertNotIn("restore_lease", committed)
        self.assertEqual(committed["run_state"], "planning")
        self.assertEqual(committed["checkpoint"]["steps_taken"], 1)
        self.assertEqual(committed["checkpoint"]["remaining_steps"], 11)
        self.assertEqual(committed["checkpoint"]["remaining_model_calls"], 19)

    async def test_delayed_snapshot_cannot_reopen_a_terminal_run(self):
        from memory.autonomous_runs import RunStore, CheckpointConflict
        owner, sid = await self._session()
        old = await self._snapshot(owner, sid)
        old['snapshot_revision'] = 1
        store = RunStore()
        await store.save(old)
        terminal = {**old, 'snapshot_revision': 2, 'run_state': 'failed',
                    'active': False, 'reason_code': 'run_error', 'reason': 'Synthetic failure'}
        await store.save(terminal)
        with self.assertRaises(CheckpointConflict):
            await store.save(old)
        final = await store.latest(sid)
        self.assertEqual(final['run_state'], 'failed')
        self.assertEqual(final['reason_code'], 'run_error')
        with self.assertRaises(CheckpointConflict) as invalid:
            await store.save({**old, 'snapshot_revision': 3})
        self.assertEqual(invalid.exception.code, 'checkpoint_state')

    async def test_save_cannot_rebind_a_run_to_another_owned_session(self):
        from memory.autonomous_runs import RunStore, CheckpointAccessError
        owner, sid = await self._session()
        other_owner, other_sid = await self._session()
        store = RunStore()
        original = await self._snapshot(owner, sid)
        await store.save(original)
        forged = await self._snapshot(other_owner, other_sid, run_id=original['run_id'])
        with self.assertRaises(CheckpointAccessError):
            await store.save(forged)
        self.assertEqual((await store.latest(sid))['owner_id'], owner)

    async def test_out_of_order_writes_retain_highest_revision(self):
        from memory.autonomous_runs import RunStore, CheckpointConflict
        owner, sid = await self._session()
        snapshot = await self._snapshot(owner, sid)
        store = RunStore()
        await store.save({**snapshot, 'snapshot_revision': 1})
        results = await asyncio.gather(*[
            store.save({**snapshot, 'snapshot_revision': revision, 'model_calls': revision,
                        'remaining_model_calls': 20 - revision})
            for revision in [5, 3, 4, 2]], return_exceptions=True)
        self.assertTrue(all(not isinstance(item, Exception) or isinstance(item, CheckpointConflict)
                            for item in results))
        saved = await store.latest(sid)
        self.assertEqual(saved['snapshot_revision'], 5)
        self.assertEqual(saved['model_calls'], 5)

    async def test_concurrent_restore_claims_have_exactly_one_winner(self):
        from memory.autonomous_runs import CheckpointConflict, RunStore
        owner, session_id = await self._session()
        snapshot = await self._snapshot(owner, session_id)
        store = RunStore()
        await store.save(snapshot)
        await store.recover()

        first, second = await asyncio.gather(
            store.claim_restore(session_id),
            store.claim_restore(session_id),
            return_exceptions=True,
        )
        results = [item for item in (first, second) if isinstance(item, dict)]
        errors = [item for item in (first, second)
                  if isinstance(item, CheckpointConflict)]
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "restore_in_progress")
        await store.release_restore(session_id, results[0]["run_id"],
                                    results[0]["token"])

    async def test_recover_clears_lease_left_by_a_crashed_restore(self):
        from memory.autonomous_runs import CheckpointConflict, RunStore
        owner, session_id = await self._session()
        snapshot = await self._snapshot(owner, session_id)
        store = RunStore()
        await store.save(snapshot)
        await store.recover()
        claim = await store.claim_restore(session_id, lease_seconds=60)
        await store.recover()
        self.assertNotIn("restore_lease", await store.latest(session_id))
        with self.assertRaises(CheckpointConflict) as error:
            await store.commit_restore(session_id, claim["run_id"],
                                       claim["token"], snapshot)
        self.assertEqual(error.exception.code, "restore_conflict")
        reclaim = await store.claim_restore(session_id)
        await store.release_restore(session_id, reclaim["run_id"],
                                    reclaim["token"])

    async def test_active_checkpoint_rejects_a_second_restore(self):
        from memory.autonomous_runs import CheckpointConflict, RunStore
        owner, session_id = await self._session()
        snapshot = await self._snapshot(owner, session_id)
        store = RunStore()
        await store.save(snapshot)
        await store.recover()
        claim = await store.claim_restore(session_id)
        active = dict(await store.latest(session_id))
        active.update(run_state="planning", active=True)
        await store.commit_restore(session_id, claim["run_id"], claim["token"],
                                   active)
        with self.assertRaises(CheckpointConflict) as error:
            await store.claim_restore(session_id)
        self.assertEqual(error.exception.code, "run_active")

    async def test_engine_restores_real_receipts_without_execution(self):
        from unittest.mock import AsyncMock, patch
        from agents.autonomous_engine import AutonomousEngine
        from memory.autonomous_runs import RunStore
        owner, session_id = await self._session()
        run_id = "spec11-run-" + uuid.uuid4().hex[:12]
        job_id = "spec11-job-" + uuid.uuid4().hex[:12]
        await self._record(owner, session_id, run_id, job_id,
                           "80/tcp open http")
        snapshot = await self._snapshot(
            owner, session_id, run_id=run_id,
            jobs=((job_id, "port_discovery"),),
            executed=("nmap -p 80 192.0.2.1",), steps=2, model_calls=1)
        store = RunStore()
        await store.save(snapshot)
        await store.recover()

        forbidden = AsyncMock(side_effect=AssertionError("restore executed"))
        engine = AutonomousEngine()
        with patch("agents.autonomous_engine.execution_authorization.execute",
                   forbidden), \
             patch("agents.autonomous_engine.execution_authorization.propose",
                   forbidden), \
             patch("agents.autonomous_engine.worker_jobs.execute", forbidden), \
             patch("agents.autonomous_engine.worker_jobs.client.submit", forbidden), \
             patch("agents.autonomous_engine.worker_jobs.client.capabilities",
                   forbidden), \
             patch("llm.pool_manager.pool_manager.planner_preflight", forbidden), \
             patch("agents.orchestrator_agent.orchestrator_agent.process",
                   forbidden), \
             patch.object(engine, "_run_loop", AsyncMock()) as loop:
            result = await engine.restore(session_id, owner, resume=False)
        self.assertEqual(result["status"], "restored")
        self.assertFalse(result["active"])
        self.assertEqual(result["steps_taken"], 2)
        self.assertEqual(result["remaining_steps"], 10)
        self.assertEqual(result["remaining_model_calls"], 19)
        self.assertEqual(result["completed_observations"], ["port_discovery"])
        self.assertEqual(result["evidence_job_ids"], [job_id])
        status = engine.get_status(session_id)
        self.assertEqual(status["scope_digest"], snapshot["scope_digest"])
        self.assertEqual(status["auth_revision"], snapshot["auth_revision"])
        self.assertEqual(status["worker_epoch"], snapshot["worker_epoch"])
        forbidden.assert_not_awaited()
        loop.assert_not_awaited()
        await engine.shutdown()

    async def test_stale_checkpoint_is_rejected_after_a_newer_run(self):
        from memory.autonomous_runs import CheckpointConflict, RunStore
        owner, session_id = await self._session()
        store = RunStore()
        first = await self._snapshot(owner, session_id, run_id="spec11-old-" + self.token)
        await store.save(first)
        # An explicit reconciliation closes the old active record before a
        # later run is created; ordinary saves cannot create two active runs.
        await store.recover()
        await asyncio.sleep(0.02)
        second = await self._snapshot(owner, session_id, run_id="spec11-new-" + self.token)
        await store.save(second)
        await store.recover()

        with self.assertRaises(CheckpointConflict) as error:
            await store.claim_restore(session_id, run_id=first["run_id"])
        self.assertEqual(error.exception.code, "checkpoint_stale")

        claim = await store.claim_restore(session_id)
        self.assertEqual(claim["run_id"], second["run_id"])
        await store.release_restore(session_id, claim["run_id"], claim["token"])

    async def test_duplicate_delivery_is_idempotent_and_restore_fences_old_writer(self):
        from memory.autonomous_runs import RunStore, CheckpointConflict
        owner, sid = await self._session()
        initial = await self._snapshot(owner, sid)
        initial['snapshot_revision'] = 1
        store = RunStore()
        await store.save(initial)
        before = await store.latest(sid)
        await store.save(initial)
        duplicate = await store.latest(sid)
        self.assertEqual(duplicate['checkpointed_at'], before['checkpointed_at'])
        self.assertEqual(duplicate['transitions'], before['transitions'])
        await store.recover()
        reconciled = await store.latest(sid)
        claim = await store.claim_restore(sid)
        restored = await store.commit_restore(sid, claim['run_id'], claim['token'],
            {**reconciled, 'run_state': 'planning', 'active': True})
        self.assertGreater(restored['snapshot_generation'], before['snapshot_generation'])
        with self.assertRaises(CheckpointConflict):
            await store.save({**initial, 'snapshot_revision': 99})
        with self.assertRaises(CheckpointConflict):
            await store.save(await self._snapshot(owner, sid))
        current = {**restored, 'snapshot_revision': restored['snapshot_revision'] + 1,
                   'model_calls': 2, 'remaining_model_calls': 18}
        await store.save(current)
        self.assertEqual((await store.latest(sid))['model_calls'], 2)
