"""Durable knowledge persistence/restoration regressions using synthetic facts only."""
import asyncio
import copy
import hashlib
import json
from unittest.mock import AsyncMock, patch

from agents.autonomous_engine import AutonomousEngine
from memory.attack_knowledge_base import AttackKnowledgeBase
from memory.knowledge_store import (
    KnowledgeAccessError, KnowledgeConflict, KnowledgeIntegrityError,
    KnowledgeStore, SessionIdentity, canonical_digest, observation_key,
    scope_identity_digest,
)
from tests.support import OfflineCase


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _content(metadata):
    return {key: metadata[key] for key in (
        "schema", "session_id", "owner_id", "run_id", "job_id", "tool",
        "observation", "target", "scope_digest", "payload", "evidence",
    )}


class FakeKnowledgeBackend:
    """In-memory backend with the same owner, uniqueness and receipt contracts."""

    def __init__(self):
        self.sessions = {}
        self.rows = {}
        self.receipts_by_job = {}
        self.insert_calls = 0

    def add_session(self, session_id, owner_id="alice", scope=None, target="192.0.2.1"):
        self.sessions[session_id] = {
            "owner_id": owner_id,
            "scope": scope if scope is not None else {"targets": [target]},
            "target": target,
        }

    def add_receipt(self, session_id, job_id, stdout, stderr="", exit_code=0, state="succeeded"):
        self.receipts_by_job[(session_id, job_id)] = {
            "job_id": job_id, "session_id": session_id, "state": state,
            "exit_code": exit_code, "output_hash": _hash(stdout), "stderr_hash": _hash(stderr),
        }

    async def identity(self, session_id, owner_id):
        session = self.sessions.get(session_id)
        if not session or session["owner_id"] != owner_id:
            raise KnowledgeAccessError("Engagement knowledge is unavailable")
        return SessionIdentity(session_id, owner_id,
                               scope_identity_digest(session["scope"], session["target"]))

    async def insert(self, *, row_id, session_id, owner_id, metadata, created_at, scope_digest):
        await asyncio.sleep(0)  # allow concurrent writers to race the deterministic key
        self.insert_calls += 1
        if row_id in self.rows:
            raise KnowledgeConflict()
        self.rows[row_id] = {
            "id": row_id, "session_id": session_id, "owner_id": owner_id,
            "created_at": created_at.isoformat(), "metadata": copy.deepcopy(metadata),
        }

    async def get(self, row_id, session_id, owner_id):
        row = self.rows.get(row_id)
        if not row or row["session_id"] != session_id or row["owner_id"] != owner_id:
            return None
        return copy.deepcopy(row)

    async def list(self, session_id, owner_id):
        return [copy.deepcopy(row) for row in self.rows.values()
                if row["session_id"] == session_id and row["owner_id"] == owner_id]

    async def receipts(self, session_id, job_ids):
        return {job_id: copy.deepcopy(self.receipts_by_job[(session_id, job_id)])
                for job_id in job_ids if (session_id, job_id) in self.receipts_by_job}


class KnowledgeStoreTests(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.backend = FakeKnowledgeBackend()
        self.backend.add_session("s1")
        self.backend.add_session("s2", owner_id="bob", target="198.51.100.2")
        self.store = KnowledgeStore(self.backend)

    async def _record(self, job_id="job-1", *, session_id="s1", owner_id="alice",
                      stdout="80/tcp open http", ports=None, vulns=None, tool="nmap",
                      observation="port_discovery"):
        self.backend.add_receipt(session_id, job_id, stdout)
        return await self.store.record_observation(
            session_id=session_id, owner_id=owner_id, run_id="run-1", job_id=job_id,
            tool=tool, observation=observation, target="192.0.2.1",
            stdout=stdout, stderr="", exit_code=0,
            hosts_updated=["192.0.2.1"],
            ports_added=ports if ports is not None else [
                {"ip": "192.0.2.1", "port": 80, "service": "http", "version": "nginx"}],
            vulns_added=vulns if vulns is not None else [],
        )

    async def test_fresh_knowledge_base_restores_persisted_state(self):
        record = await self._record(vulns=[
            {"ip": "192.0.2.1", "title": "Synthetic exposure", "severity": "high",
             "cve_ids": ["CVE-2024-0001"], "port": 80, "cvss": 7.5},
        ])
        kb = AttackKnowledgeBase()
        result = await self.store.restore("s1", "alice", kb=kb)

        self.assertEqual(result["observations"], 1)
        self.assertEqual(result["restored"], 1)
        host = kb.get_host("s1", "192.0.2.1")
        self.assertIsNotNone(host)
        self.assertEqual(host.ports[80]["service"], "http")
        self.assertEqual(host.ports[80]["scanned_at"], record["observed_at"])
        self.assertEqual(host.vulnerabilities[0]["title"], "Synthetic exposure")
        self.assertEqual(host.vulnerabilities[0]["found_at"], record["observed_at"])
        observations = kb.get_observations("s1")
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["job_id"], "job-1")
        self.assertEqual(observations[0]["observed_at"], record["observed_at"])
        evidence = kb.get_evidence_references("s1")
        self.assertEqual(evidence["job-1"]["output_sha256"], _hash("80/tcp open http"))
        self.assertEqual(evidence["job-1"]["stderr_sha256"], _hash(""))
        timeline = kb.get_timeline("s1")
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["ts"], record["observed_at"])
        self.assertEqual(timeline[0]["event"], "knowledge_restored")

    async def test_repeated_restoration_is_idempotent(self):
        await self._record()
        kb = AttackKnowledgeBase()
        first = await self.store.restore("s1", "alice", kb=kb)
        second = await self.store.restore("s1", "alice", kb=kb)

        self.assertEqual((first["restored"], first["skipped"]), (1, 0))
        self.assertEqual((second["restored"], second["skipped"]), (0, 1))
        host = kb.get_host("s1", "192.0.2.1")
        self.assertEqual(len(host.ports), 1)
        self.assertEqual(len(kb.get_observations("s1")), 1)
        self.assertEqual(len(kb.get_timeline("s1")), 1)

        fresh = AttackKnowledgeBase()
        await self.store.restore("s1", "alice", kb=fresh)
        repeated = await self.store.restore("s1", "alice", kb=fresh)
        self.assertEqual(repeated["restored"], 0)
        self.assertEqual(len(fresh.get_observations("s1")), 1)

    async def test_foreign_owner_and_campaign_cannot_be_loaded(self):
        await self._record()
        self.backend.add_session("s3", owner_id="alice", target="198.51.100.3")
        await self._record("job-3", session_id="s3", owner_id="alice",
                           stdout="22/tcp open ssh", ports=[
                               {"ip": "198.51.100.3", "port": 22, "service": "ssh", "version": ""}])

        with self.assertRaises(KnowledgeAccessError):
            await self.store.restore("s1", "bob")
        with self.assertRaises(KnowledgeAccessError):
            await self.store.restore("s2", "alice")

        other = KnowledgeStore(self.backend)
        fresh = AttackKnowledgeBase()
        result = await other.restore("s2", "bob", kb=fresh)
        self.assertEqual(result["observations"], 0)
        self.assertEqual(fresh.get_all_hosts("s2"), [])

        owner_campaign = AttackKnowledgeBase()
        result = await self.store.restore("s1", "alice", kb=owner_campaign)
        self.assertEqual(result["observations"], 1)
        self.assertIsNotNone(owner_campaign.get_host("s1", "192.0.2.1"))
        self.assertIsNone(owner_campaign.get_host("s1", "198.51.100.3"))

    async def test_metadata_owner_tampering_is_rejected(self):
        await self._record()
        row = next(iter(self.backend.rows.values()))
        row["metadata"]["owner_id"] = "bob"
        with self.assertRaises(KnowledgeIntegrityError):
            await self.store.restore("s1", "alice", kb=AttackKnowledgeBase())

    async def test_missing_or_corrupted_evidence_fails_safely(self):
        await self._record()
        baseline = copy.deepcopy(self.backend.rows)

        def reset_rows():
            self.backend.rows = copy.deepcopy(baseline)

        self.backend.receipts_by_job.clear()
        kb = AttackKnowledgeBase()
        with self.assertRaises(KnowledgeIntegrityError):
            await self.store.restore("s1", "alice", kb=kb)
        self.assertEqual(kb.get_all_hosts("s1"), [])
        self.assertEqual(kb.get_observations("s1"), [])
        self.backend.add_receipt("s1", "job-1", "80/tcp open http")

        reset_rows()
        row = next(iter(self.backend.rows.values()))
        del row["metadata"]["evidence"]
        with self.assertRaises(KnowledgeIntegrityError):
            await self.store.restore("s1", "alice", kb=AttackKnowledgeBase())

        reset_rows()
        row = next(iter(self.backend.rows.values()))
        row["metadata"]["evidence"]["output_sha256"] = "f" * 64
        row["metadata"]["content_digest"] = canonical_digest(_content(row["metadata"]))
        kb = AttackKnowledgeBase()
        with self.assertRaises(KnowledgeIntegrityError):
            await self.store.restore("s1", "alice", kb=kb)
        self.assertEqual(kb.get_all_hosts("s1"), [])
        self.assertEqual(kb.get_observations("s1"), [])

        reset_rows()
        row = next(iter(self.backend.rows.values()))
        row["metadata"]["payload"]["ports_added"][0]["port"] = 99999
        row["metadata"]["content_digest"] = canonical_digest(_content(row["metadata"]))
        with self.assertRaises(KnowledgeIntegrityError):
            await self.store.restore("s1", "alice", kb=AttackKnowledgeBase())

    async def test_scope_change_blocks_restoration(self):
        await self._record()
        self.backend.sessions["s1"]["scope"] = {"targets": ["198.51.100.2"]}
        kb = AttackKnowledgeBase()
        with self.assertRaises(KnowledgeIntegrityError):
            await self.store.restore("s1", "alice", kb=kb)
        self.assertEqual(kb.get_all_hosts("s1"), [])

    async def test_only_bounded_redacted_facts_are_stored(self):
        record = await self._record(
            stdout="80/tcp open http password=hunter2",
            ports=[{"ip": "192.0.2.1", "port": 80, "service": "password=hunter2", "version": "nginx"}],
        )
        serialized = json.dumps(record, sort_keys=True)
        self.assertNotIn("hunter2", serialized)
        self.assertNotIn("80/tcp open http", serialized)
        for forbidden in ("stdout", "stderr", "command", "creds_added", "shells_added"):
            self.assertNotIn('"' + forbidden + '"', serialized)
        self.assertEqual(record["payload"]["ports_added"][0]["service"], 'password="[REDACTED]"')
        self.assertEqual(record["evidence"]["output_sha256"], _hash("80/tcp open http password=hunter2"))

    async def test_concurrent_distinct_writes_are_not_lost(self):
        self.backend.add_receipt("s1", "job-1", "80/tcp open http")
        self.backend.add_receipt("s1", "job-2", "443/tcp open https")
        first, second = await asyncio.gather(
            self.store.record_observation(
                session_id="s1", owner_id="alice", run_id="run-1", job_id="job-1",
                tool="nmap", observation="port_discovery", target="192.0.2.1",
                stdout="80/tcp open http", stderr="", exit_code=0,
                hosts_updated=["192.0.2.1"],
                ports_added=[{"ip": "192.0.2.1", "port": 80, "service": "http", "version": ""}],
            ),
            self.store.record_observation(
                session_id="s1", owner_id="alice", run_id="run-1", job_id="job-2",
                tool="nmap", observation="port_discovery", target="192.0.2.1",
                stdout="443/tcp open https", stderr="", exit_code=0,
                hosts_updated=["192.0.2.1"],
                ports_added=[{"ip": "192.0.2.1", "port": 443, "service": "https", "version": ""}],
            ),
        )
        self.assertNotEqual(first["observation_id"], second["observation_id"])
        self.assertEqual(len(self.backend.rows), 2)
        kb = AttackKnowledgeBase()
        result = await self.store.restore("s1", "alice", kb=kb)
        self.assertEqual(result["observations"], 2)
        self.assertEqual(set(kb.get_host("s1", "192.0.2.1").ports), {80, 443})

    async def test_concurrent_duplicate_write_is_idempotent(self):
        self.backend.add_receipt("s1", "job-1", "80/tcp open http")
        calls = [self.store.record_observation(
            session_id="s1", owner_id="alice", run_id="run-1", job_id="job-1",
            tool="nmap", observation="port_discovery", target="192.0.2.1",
            stdout="80/tcp open http", stderr="", exit_code=0,
            hosts_updated=["192.0.2.1"],
            ports_added=[{"ip": "192.0.2.1", "port": 80, "service": "http", "version": "nginx"}],
        ) for _ in range(2)]
        first, second = await asyncio.gather(*calls)
        self.assertEqual(len(self.backend.rows), 1)
        self.assertEqual(first["observation_id"], observation_key("s1", "job-1"))
        self.assertEqual(first["observation_id"], second["observation_id"])
        self.assertEqual(sorted([first["duplicate"], second["duplicate"]]), [False, True])


class KnowledgeEngineRestartTests(OfflineCase):
    async def test_restart_restores_without_execution_or_worker_submission(self):
        backend = FakeKnowledgeBackend()
        backend.add_session("restart-session")
        store = KnowledgeStore(backend)
        backend.add_receipt("restart-session", "persisted-job", "80/tcp open http")
        await store.record_observation(
            session_id="restart-session", owner_id="alice", run_id="old-run",
            job_id="persisted-job", tool="nmap", observation="port_discovery",
            target="192.0.2.1", stdout="80/tcp open http", stderr="", exit_code=0,
            hosts_updated=["192.0.2.1"],
            ports_added=[{"ip": "192.0.2.1", "port": 80, "service": "http", "version": "nginx"}],
        )
        kb = AttackKnowledgeBase()
        engine = AutonomousEngine()
        context = {"owner_id": "alice", "scope": {"targets": ["192.0.2.1"]}, "auth_revision": 0}
        try:
            with patch("agents.autonomous_engine.knowledge_store", store), \
                 patch("memory.knowledge_store.attack_kb", kb), \
                 patch("agents.autonomous_engine.execution_authorization._context", AsyncMock(return_value=context)), \
                 patch("agents.autonomous_engine.worker_jobs.client.capabilities", AsyncMock(return_value={"tools": ["curl", "nmap"]})), \
                 patch("llm.pool_manager.pool_manager.planner_preflight", AsyncMock(return_value={"ready": True})), \
                 patch.object(engine, "_write_decision_log", AsyncMock()), \
                 patch.object(engine, "_run_loop", AsyncMock()) as loop, \
                 patch("agents.autonomous_engine.execution_authorization.execute", AsyncMock()) as execute, \
                 patch("agents.autonomous_engine.execution_authorization.propose", AsyncMock()) as propose, \
                 patch("agents.autonomous_engine.worker_jobs.execute", AsyncMock()) as worker_execute, \
                 patch("agents.autonomous_engine.worker_jobs.client.submit", AsyncMock()) as submit:
                result = await engine.start("restart-session", "alice", goal="discovery")
                await asyncio.sleep(0)
            self.assertEqual(result["status"], "started")
            loop.assert_awaited_once()
            execute.assert_not_awaited()
            propose.assert_not_awaited()
            worker_execute.assert_not_awaited()
            submit.assert_not_awaited()
            host = kb.get_host("restart-session", "192.0.2.1")
            self.assertIsNotNone(host)
            self.assertEqual(host.ports[80]["service"], "http")
            self.assertEqual(len(kb.get_observations("restart-session")), 1)
        finally:
            from memory.attack_knowledge_base import attack_kb
            attack_kb.unregister_replan_callback("restart-session")
            await engine.shutdown()

    async def test_restore_failure_blocks_start_without_loop(self):
        backend = FakeKnowledgeBackend()
        backend.add_session("restart-session")
        store = KnowledgeStore(backend)
        backend.add_receipt("restart-session", "persisted-job", "80/tcp open http")
        await store.record_observation(
            session_id="restart-session", owner_id="alice", run_id="old-run",
            job_id="persisted-job", tool="nmap", observation="port_discovery",
            target="192.0.2.1", stdout="80/tcp open http", stderr="", exit_code=0,
        )
        backend.receipts_by_job.clear()
        engine = AutonomousEngine()
        context = {"owner_id": "alice", "scope": {"targets": ["192.0.2.1"]}, "auth_revision": 0}
        with patch("agents.autonomous_engine.knowledge_store", store), \
             patch("agents.autonomous_engine.execution_authorization._context", AsyncMock(return_value=context)), \
             patch("agents.autonomous_engine.worker_jobs.client.capabilities", AsyncMock(return_value={"tools": ["curl", "nmap"]})), \
             patch("llm.pool_manager.pool_manager.planner_preflight", AsyncMock(return_value={"ready": True})), \
             patch.object(engine, "_write_decision_log", AsyncMock()), \
             patch.object(engine, "_run_loop", AsyncMock()) as loop:
            result = await engine.start("restart-session", "alice", goal="discovery")
        loop.assert_not_awaited()
        self.assertFalse(result["active"])
        self.assertEqual(result["reason_code"], "knowledge_restore_failed")
        self.assertNotIn("restart-session", engine._tasks)
