"""SPEC-10 real PostgreSQL integration tests; synthetic data only.

Requires a disposable database ending in *_test:
    ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test \
        python -m unittest integration.test_knowledge_store_postgres -v
"""
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

ENABLED = os.environ.get("ARIA_INTEGRATION") == "1"


def _sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


@unittest.skipUnless(ENABLED, "set ARIA_INTEGRATION=1 with a disposable *_test database")
class KnowledgeStorePostgres(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        url = make_url(os.environ["DATABASE_URL"])
        if not (url.database or "").endswith("_test"):
            raise RuntimeError("integration requires a disposable database named *_test")
        subprocess.run([sys.executable, "-B", "-m", "alembic", "upgrade", "head"], check=True)

    async def asyncSetUp(self):
        from memory.database_models import engine
        self.token = uuid.uuid4().hex[:8]
        await engine.dispose()

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    async def _owner_session(self, target="192.0.2.1", scope=None, owner_id=None):
        from memory.database_models import PentestSession, User, async_session
        owner_id = owner_id or "spec10-o-" + uuid.uuid4().hex[:12]
        session_id = "spec10-s-" + uuid.uuid4().hex[:12]
        async with async_session() as db:
            db.add(User(id=owner_id, username="u-" + uuid.uuid4().hex[:16], password_hash="unused"))
            await db.flush()
            db.add(PentestSession(id=session_id, user_id=owner_id, target=target,
                                  scope=scope if scope is not None else {"targets": [target]}))
            await db.commit()
        return owner_id, session_id

    async def _receipt(self, owner_id, session_id, job_id, stdout, stderr="", exit_code=0):
        from memory.database_models import DecisionLog, async_session
        from memory.worker_jobs import SQLJobStore
        async with async_session() as db:
            db.add(DecisionLog(
                id=SQLJobStore.key(job_id), session_id=session_id, user_id=owner_id,
                decision_type="worker_job",
                metadata_={"job_id": job_id, "session_id": session_id, "user_id": owner_id,
                           "state": "succeeded", "exit_code": exit_code,
                           "output_hash": _sha(stdout), "stderr_hash": _sha(stderr)},
            ))
            await db.commit()

    async def _count(self, session_id):
        from sqlalchemy import func, select
        from memory.database_models import DecisionLog, async_session
        async with async_session() as db:
            return await db.scalar(select(func.count()).select_from(DecisionLog).where(
                DecisionLog.session_id == session_id,
                DecisionLog.decision_type == "knowledge_observation"))

    async def _record(self, store, owner_id, session_id, job_id, stdout, port, service="http"):
        await self._receipt(owner_id, session_id, job_id, stdout)
        return await store.record_observation(
            session_id=session_id, owner_id=owner_id, run_id="run-1", job_id=job_id,
            tool="nmap", observation="port_discovery", target="192.0.2.1",
            stdout=stdout, stderr="", exit_code=0, hosts_updated=["192.0.2.1"],
            ports_added=[{"ip": "192.0.2.1", "port": port, "service": service, "version": "1.0"}],
        )

    async def test_roundtrip_idempotency_and_duplicate_conflict(self):
        from memory.attack_knowledge_base import AttackKnowledgeBase
        from memory.knowledge_store import KnowledgeIntegrityError, KnowledgeStore
        owner, sid = await self._owner_session()
        store = KnowledgeStore()
        job = f"job-a-{self.token}"
        record = await self._record(store, owner, sid, job, "80/tcp open http", 80)
        self.assertFalse(record["duplicate"])

        kb = AttackKnowledgeBase()
        first = await store.restore(sid, owner, kb=kb)
        second = await store.restore(sid, owner, kb=kb)
        self.assertEqual((first["restored"], first["skipped"]), (1, 0))
        self.assertEqual((second["restored"], second["skipped"]), (0, 1))
        host = kb.get_host(sid, "192.0.2.1")
        self.assertEqual(host.ports[80]["scanned_at"], record["observed_at"])
        self.assertEqual(len(kb.get_timeline(sid)), 1)

        duplicate = await store.record_observation(
            session_id=sid, owner_id=owner, run_id="run-1", job_id=job,
            tool="nmap", observation="port_discovery", target="192.0.2.1",
            stdout="80/tcp open http", stderr="", exit_code=0,
            hosts_updated=["192.0.2.1"],
            ports_added=[{"ip": "192.0.2.1", "port": 80, "service": "http", "version": "1.0"}],
        )
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(await self._count(sid), 1)
        with self.assertRaises(KnowledgeIntegrityError):
            await store.record_observation(
                session_id=sid, owner_id=owner, run_id="run-1", job_id=job,
                tool="nmap", observation="port_discovery", target="192.0.2.1",
                stdout="80/tcp open http", stderr="", exit_code=0,
                hosts_updated=["192.0.2.1"],
                ports_added=[{"ip": "192.0.2.1", "port": 81, "service": "http", "version": "1.0"}],
            )
        self.assertEqual(await self._count(sid), 1)

    async def test_concurrent_writes_preserve_all_accepted_observations(self):
        from memory.attack_knowledge_base import AttackKnowledgeBase
        from memory.knowledge_store import KnowledgeStore
        owner, sid = await self._owner_session()
        store = KnowledgeStore()
        jobs = [(f"job-{index}-{self.token}", f"{port}/tcp open http", port)
                for index, port in enumerate((80, 81, 82, 83), start=1)]
        for job, stdout, _ in jobs:
            await self._receipt(owner, sid, job, stdout)
        def call(job, port):
            return store.record_observation(
                session_id=sid, owner_id=owner, run_id="run-1", job_id=job,
                tool="nmap", observation="port_discovery", target="192.0.2.1",
                stdout=f"{port}/tcp open http", stderr="", exit_code=0,
                hosts_updated=["192.0.2.1"],
                ports_added=[{"ip": "192.0.2.1", "port": port, "service": "http", "version": ""}],
            )
        results = await asyncio.gather(
            call(jobs[0][0], 80), call(jobs[0][0], 80), call(jobs[1][0], 81),
            call(jobs[2][0], 82), call(jobs[3][0], 83),
        )
        self.assertEqual(len([r for r in results if r["duplicate"]]), 1)
        self.assertEqual(await self._count(sid), 4)
        kb = AttackKnowledgeBase()
        restored = await store.restore(sid, owner, kb=kb)
        self.assertEqual(restored["restored"], 4)
        self.assertEqual(set(kb.get_host(sid, "192.0.2.1").ports), {80, 81, 82, 83})

    async def test_rollback_ownership_scope_and_failed_writes_leave_no_rows(self):
        from memory.attack_knowledge_base import AttackKnowledgeBase
        from memory.database_models import PentestSession, async_session
        from memory.knowledge_store import (
            KnowledgeAccessError, KnowledgeConflict, KnowledgeIntegrityError,
            KnowledgeStore, SQLKnowledgeBackend, scope_identity_digest,
        )
        owner, sid = await self._owner_session()
        other, other_sid = await self._owner_session(owner_id=f"spec10-o-other-{self.token}")
        store = KnowledgeStore()
        record = await self._record(store, owner, sid, f"job-a-{self.token}",
                                    "80/tcp open http", 80)

        with self.assertRaises(KnowledgeAccessError):
            await store.restore(sid, other, kb=AttackKnowledgeBase())
        with self.assertRaises(KnowledgeAccessError):
            await store.restore(other_sid, owner, kb=AttackKnowledgeBase())
        self.assertEqual(await self._count(sid), 1)

        backend = SQLKnowledgeBackend()
        async with async_session() as db:
            session = await db.get(PentestSession, sid)
            stale = scope_identity_digest({"targets": ["192.0.2.1"]}, "192.0.2.1")
            session.scope = {"targets": ["198.51.100.2"]}
            await db.commit()
        with self.assertRaises(KnowledgeIntegrityError):
            await backend.insert(row_id=record["observation_id"], session_id=sid, owner_id=owner,
                                 metadata=record, created_at=datetime.utcnow(),
                                 scope_digest=stale)
        self.assertEqual(await self._count(sid), 1)
        with self.assertRaises(KnowledgeIntegrityError):
            await store.restore(sid, owner, kb=AttackKnowledgeBase())
        self.assertEqual(await self._count(sid), 1)

        owner2, sid2 = await self._owner_session()
        store2 = KnowledgeStore()
        rec2 = await self._record(store2, owner2, sid2, f"job-b-{self.token}",
                                  "443/tcp open https", 443)
        with self.assertRaises(KnowledgeConflict):
            await backend.insert(row_id=rec2["observation_id"], session_id=sid2, owner_id=owner2,
                                 metadata=rec2, created_at=datetime.utcnow(),
                                 scope_digest=scope_identity_digest({"targets": ["192.0.2.1"]}, "192.0.2.1"))
        self.assertEqual(await self._count(sid2), 1)

        with self.assertRaises(Exception):
            await backend.insert(row_id="spec10-nonjson", session_id=sid2, owner_id=owner2,
                                 metadata={"bad": object()}, created_at=datetime.utcnow(),
                                 scope_digest=scope_identity_digest({"targets": ["192.0.2.1"]}, "192.0.2.1"))
        self.assertEqual(await self._count(sid2), 1)

    async def test_process_restart_restores_without_execution_worker_or_external_network(self):
        owner, sid = await self._owner_session()
        job = f"persisted-job-{self.token}"
        await self._receipt(owner, sid, job, "80/tcp open http")

        writer = r'''
import asyncio, json, os
from memory.knowledge_store import KnowledgeStore
async def main():
    record = await KnowledgeStore().record_observation(
        session_id=os.environ["SPEC10_SESSION"], owner_id=os.environ["SPEC10_OWNER"],
        run_id="old-run", job_id=os.environ["SPEC10_JOB"], tool="nmap", observation="port_discovery",
        target="192.0.2.1", stdout="80/tcp open http", stderr="", exit_code=0,
        hosts_updated=["192.0.2.1"],
        ports_added=[{"ip": "192.0.2.1", "port": 80, "service": "http", "version": "nginx"}])
    open(os.environ["SPEC10_RESULT"], "w").write(json.dumps(record))
asyncio.run(main())
'''
        reader = r'''
import asyncio, json, os, socket
from unittest.mock import AsyncMock, patch
from memory.attack_knowledge_base import AttackKnowledgeBase
from memory.execution_authorization import execution_authorization
from memory.knowledge_store import KnowledgeStore
from memory.worker_jobs import worker_jobs

async def forbidden(*args, **kwargs):
    raise AssertionError("restore attempted execution or worker activity")

async def main():
    calls = {}
    original_connect = socket.socket.connect
    def guarded_connect(sock, address):
        host = address[0] if isinstance(address, tuple) else None
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError(f"restore attempted external network: {host}")
        return original_connect(sock, address)
    patches = [
        patch.object(execution_authorization, "_context", AsyncMock(side_effect=forbidden)),
        patch.object(execution_authorization, "execute", AsyncMock(side_effect=forbidden)),
        patch.object(execution_authorization, "propose", AsyncMock(side_effect=forbidden)),
        patch.object(execution_authorization, "decide", AsyncMock(side_effect=forbidden)),
        patch.object(worker_jobs, "execute", AsyncMock(side_effect=forbidden)),
        patch.object(worker_jobs, "verify_receipt", AsyncMock(side_effect=forbidden)),
        patch.object(worker_jobs.client, "submit", AsyncMock(side_effect=forbidden)),
        patch.object(worker_jobs.client, "request", AsyncMock(side_effect=forbidden)),
        patch.object(worker_jobs.client, "capabilities", AsyncMock(side_effect=forbidden)),
        patch.object(socket.socket, "connect", guarded_connect),
    ]
    for item in patches:
        item.start()
    try:
        kb = AttackKnowledgeBase()
        result = await KnowledgeStore().restore(
            os.environ["SPEC10_SESSION"], os.environ["SPEC10_OWNER"], kb=kb)
        host = kb.get_host(os.environ["SPEC10_SESSION"], "192.0.2.1")
        payload = {"restore": result, "port": host.ports[80]["service"] if host else None,
                   "observations": len(kb.get_observations(os.environ["SPEC10_SESSION"]))}
    finally:
        for item in reversed(patches):
            item.stop()
    open(os.environ["SPEC10_RESULT"], "w").write(json.dumps(payload))
asyncio.run(main())
'''
        env = {**os.environ, "SPEC10_OWNER": owner, "SPEC10_SESSION": sid, "SPEC10_JOB": job}
        with tempfile.TemporaryDirectory() as directory:
            writer_result = os.path.join(directory, "writer.json")
            reader_result = os.path.join(directory, "reader.json")
            subprocess.run([sys.executable, "-B", "-c", writer],
                           env={**env, "SPEC10_RESULT": writer_result}, check=True)
            self.assertTrue(json.loads(Path(writer_result).read_text())["observation_id"])
            subprocess.run([sys.executable, "-B", "-c", reader],
                           env={**env, "SPEC10_RESULT": reader_result}, check=True)
            payload = json.loads(Path(reader_result).read_text())
        self.assertEqual(payload["restore"]["restored"], 1)
        self.assertEqual(payload["port"], "http")
        self.assertEqual(payload["observations"], 1)
