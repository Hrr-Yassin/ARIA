"""Real services only. Run separately from tests/ (whose fixtures are offline).

Requires a disposable, empty PostgreSQL database named *_test and Redis DB 15.
The explicit opt-in prevents accidental destructive migration tests.
"""
import asyncio
import os
import subprocess
import sys
import unittest
import uuid

ENABLED = os.environ.get('ARIA_INTEGRATION') == '1'


@unittest.skipUnless(ENABLED, 'set ARIA_INTEGRATION=1 with disposable services')
class Services(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        url = make_url(os.environ['DATABASE_URL'])
        if not url.database.endswith('_test') or not os.environ['REDIS_URL'].endswith('/15'):
            raise RuntimeError('Integration requires database *_test and Redis DB 15')
        # These subprocesses run before any pooled connections are opened.
        cls.migrate('upgrade', 'head')
        cls.migrate('check')
        cls.migrate('downgrade', 'base')
        # Simulate a restored, unversioned legacy v10 schema with retained data.
        subprocess.run([sys.executable, '-c', """
import asyncio
from migrations.schema_v1 import Base, User
from sqlalchemy import text
from memory.database_models import engine, async_session
async def restore():
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE alembic_version"))
        await conn.run_sync(Base.metadata.create_all)
    async with async_session() as db:
        db.add(User(username='legacy-retained', password_hash='unused'))
        await db.commit()
    await engine.dispose()
asyncio.run(restore())
"""], check=True)
        subprocess.run([sys.executable, '-m', 'api.adopt_schema'], check=True)
        cls.migrate('check')
        subprocess.run([sys.executable, '-c', """
import asyncio
from sqlalchemy import text
from memory.database_models import engine
async def verify():
    async with engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM users WHERE username='legacy-retained'")) == 1
    await engine.dispose()
asyncio.run(verify())
"""], check=True)
        cls.migrate('downgrade', 'base')
        cls.migrate('upgrade', 'head')
        cls.migrate('check')

    @staticmethod
    def migrate(*args):
        subprocess.run([sys.executable, '-m', 'alembic', *args], check=True)

    async def asyncSetUp(self):
        from memory.database_models import engine
        # IsolatedAsyncioTestCase creates a fresh event loop for each test.
        await engine.dispose()

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    async def test_lifespan_login_session_and_cache_restart(self):
        import httpx
        from api.main import app
        from api.auth import hash_password
        from memory.database_models import User, async_session
        username = 'integration-' + uuid.uuid4().hex[:12]
        password = uuid.uuid4().hex
        async with async_session() as db:
            db.add(User(username=username, password_hash=hash_password(password)))
            await db.commit()
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver') as client:
                self.assertEqual((await client.get('/api/ready')).status_code, 200)
                login = await client.post('/api/login', json={'username': username, 'password': password})
                self.assertEqual(login.status_code, 200, login.text)
                client.headers['Authorization'] = 'Bearer ' + login.json()['token']
                created = await client.post('/api/session/new', json={'target': '192.0.2.1'})
                self.assertEqual(created.status_code, 200, created.text)
                sid = created.json()['session_id']
                self.assertEqual((await client.get('/api/session/' + sid)).status_code, 200)
                from memory.session_manager import session_manager
                await session_manager._redis.delete(f"session:{sid}")
                self.assertEqual((await client.get('/api/session/' + sid)).json()['target'], '192.0.2.1')
                self.assertEqual((await client.get('/api/session/list')).status_code, 200)
        # Redis socket lifecycle and vector ciphertext round-trip through a real server.
        from redis.asyncio import Redis
        from memory.vector_store import VectorStore
        redis = Redis.from_url(os.environ['REDIS_URL'])
        try:
            before, after = VectorStore(), VectorStore()
            before.add(sid, 'ssh integration evidence')
            await before.persist(redis)
            await after.load(redis)
            self.assertEqual(after.query(sid, 'ssh')[0]['content'], 'ssh integration evidence')
        finally:
            await redis.aclose()

    async def test_playbook_roundtrip_and_concurrent_counters(self):
        from memory.database_models import User, PentestSession, async_session
        from memory.playbook_store import PlaybookStore
        uid, sid = str(uuid.uuid4()), str(uuid.uuid4())
        other_uid, other_sid = str(uuid.uuid4()), str(uuid.uuid4())
        async with async_session() as db:
            db.add(User(id=uid, username=uid, password_hash='unused'))
            db.add(User(id=other_uid, username=other_uid, password_hash='unused'))
            await db.flush()
            db.add(PentestSession(id=sid, user_id=uid, target='192.0.2.1'))
            db.add(PentestSession(id=other_sid, user_id=other_uid, target='192.0.2.2'))
            await db.commit()
        store = PlaybookStore()
        pb = await store.save_successful_path(sid, uid, 'ssh', '1', 'audit', [], 1)
        self.assertIsNotNone(pb)
        await asyncio.gather(*(store.increment_success(pb.id, user_id=uid) for _ in range(5)))
        restored = await PlaybookStore().get_best_playbook('ssh', '1', 'audit', user_id=uid)
        self.assertEqual(restored.success_count, 6)
        self.assertIsNone(await store.get_best_playbook('ssh', '2', user_id=uid))
        self.assertEqual(await store.list_all(user_id=other_uid), [])
