"""Actual isolated dependency failures; the runner owns both disposable containers."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time
import unittest
import uuid

from sqlalchemy import text


@unittest.skipUnless(os.environ.get('ARIA_INFRA_RECOVERY') == '1',
                     'requires the isolated infrastructure recovery runner')
class InfrastructureRecovery(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        from config.settings import settings
        if (not make_url(settings.DATABASE_URL).database.endswith('_test')
                or not settings.REDIS_URL.endswith('/15')):
            raise RuntimeError('Disposable SQL and Redis DB15 required')
        cls.run_id = os.environ['ARIA_INFRA_RUN_ID']
        cls.artifacts = Path(os.environ['ARIA_INFRA_ARTIFACT_DIR'])
        cls.ids = {kind: os.environ['ARIA_INFRA_' + kind.upper() + '_ID'] for kind in ('postgres','redis')}
        for identifier in cls.ids.values():
            row = json.loads(subprocess.check_output(['podman','inspect',identifier],text=True))[0]
            if (row['Config']['Labels'].get('aria.infrastructure.run') != cls.run_id
                    or not row['Name'].lstrip('/').startswith('aria-infra-')):
                raise RuntimeError('Container ownership assertion failed')

    async def asyncSetUp(self):
        from memory.database_models import engine
        await engine.dispose()

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    async def control(self, action, kind):
        args = ['podman', action]
        if action in {'restart','stop'}:
            args += ['--time','2']
        await asyncio.to_thread(subprocess.run,
            [*args,self.ids[kind]],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        if action in {'restart','start'}:
            from redis.asyncio import Redis
            from config.settings import settings
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if kind=='postgres':
                    ready=await asyncio.to_thread(subprocess.run,
                        ['podman','exec',self.ids[kind],'pg_isready','-U','aria_infra','-d','aria_infra_test'],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
                    if ready.returncode==0:return
                else:
                    client=Redis.from_url(settings.REDIS_URL,socket_timeout=1,socket_connect_timeout=1)
                    try:
                        if await client.ping():return
                    except Exception:pass
                    finally:await client.aclose()
                await asyncio.sleep(.1)
            self.fail('Disposable dependency readiness deadline')

    async def test_postgres_restart_validates_idle_pool_before_first_statement(self):
        from memory.database_models import engine
        marker='infra-'+uuid.uuid4().hex
        async with engine.begin() as db:
            await db.execute(text('CREATE TABLE IF NOT EXISTS infrastructure_markers(value TEXT PRIMARY KEY)'))
            await db.execute(text('INSERT INTO infrastructure_markers VALUES (:value)'),{'value':marker})
        await self.control('restart','postgres')
        # No explicit dispose, failed query or application restart before this
        # first checkout. The committed marker must survive exactly once.
        async with engine.connect() as db:
            count=await db.scalar(text('SELECT count(*) FROM infrastructure_markers WHERE value=:value'),{'value':marker})
        self.assertEqual(count,1)
        (self.artifacts/'postgres-recovery.json').write_text(json.dumps({
            'first_checkout_after_restart':'succeeded','committed_marker_count':count,
            'application_restarted':False,'statement_replayed':False})+'\n')

    async def test_redis_loss_preserves_sql_commits_and_recovers_without_api_restart(self):
        import httpx
        from api.main import app
        from memory.session_manager import session_manager
        from memory.database_models import User, async_session
        owner=str(uuid.uuid4())
        async with async_session() as db:
            db.add(User(id=owner,username=owner,password_hash='synthetic-no-login'))
            await db.commit()
        await session_manager.initialize()
        initial=await session_manager.create_session(owner,'192.0.2.1')
        try:
            await self.control('stop','redis')
            created=await session_manager.create_session(owner,'192.0.2.1')
            await session_manager.update_session(initial['session_id'],name='updated-during-cache-outage')
            async with async_session() as db:
                count=await db.scalar(text('SELECT count(*) FROM pentest_sessions WHERE user_id=:owner'),{'owner':owner})
            self.assertEqual(count,2)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://testserver') as client:
                during=await client.get('/api/ready')
                self.assertEqual(during.status_code,200)
                self.assertTrue(during.json()['degraded']);self.assertFalse(during.json()['cache'])
            await self.control('start','redis')
            recovered=await session_manager.get_session(initial['session_id'])
            self.assertEqual(recovered['name'],'updated-during-cache-outage')
            self.assertTrue(await session_manager.cache_available())
            self.assertIsNotNone(await session_manager.get_session(created['session_id'],authoritative=True))
            (self.artifacts/'redis-recovery.json').write_text(json.dumps({
                'sql_session_count':count,'cache_outage_reported':True,
                'recovered_name_matches_committed_update':True,'application_restarted':False,
                'worker_provider_target_operations':0})+'\n')
        finally:
            state=json.loads(subprocess.check_output(['podman','inspect',self.ids['redis']],text=True))[0]['State']
            if not state['Running']:await self.control('start','redis')
            await session_manager.close()
