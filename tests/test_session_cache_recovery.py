"""Optional cache outages must not change durable results or admit stale state."""
import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from redis.exceptions import ConnectionError as RedisConnectionError

from memory.session_manager import SessionManager
from tests.support import OfflineCase


class SessionCacheRecoveryTests(OfflineCase):
    def database(self):
        row = SimpleNamespace(id='session', user_id='owner', target='192.0.2.1',
            name='current', current_phase=None, status=None, tools_run=[],
            open_ports=[], context_type='internal_corporate', scope={},
            created_at=datetime(2026, 11, 17))
        db = AsyncMock()
        db.add = Mock()
        db.execute.return_value.scalar_one_or_none = Mock(return_value=row)
        factory = Mock()
        factory.return_value.__aenter__ = AsyncMock(return_value=db)
        factory.return_value.__aexit__ = AsyncMock(return_value=False)
        return row, db, patch('memory.session_manager.async_session', factory)

    async def test_committed_creation_is_returned_once_when_cache_write_fails(self):
        manager = SessionManager(); manager._redis = AsyncMock()
        manager._redis.setex.side_effect = RedisConnectionError('private credential')
        row, db, database = self.database()
        with database:
            result = await manager.create_session('owner', '192.0.2.1')
        self.assertTrue(result['session_id'])
        db.commit.assert_awaited_once()
        db.add.assert_called_once()

    async def test_unavailable_or_malformed_cache_falls_back_to_database(self):
        for cached in (RedisConnectionError('private credential'), '{bad',
                       '{"session_id":"another","name":"stale"}'):
            manager = SessionManager(); manager._redis = AsyncMock()
            if isinstance(cached, Exception): manager._redis.get.side_effect = cached
            else: manager._redis.get.return_value = cached
            row, db, database = self.database()
            with self.subTest(cached=type(cached).__name__), database:
                result = await manager.get_session('session')
                self.assertEqual(result['name'], 'current')
                self.assertEqual(result['session_id'], 'session')
                db.execute.assert_awaited_once()

    async def test_failed_invalidation_and_process_restart_cannot_reuse_old_cache(self):
        manager = SessionManager(); cache = AsyncMock(); manager._redis = cache
        cache.get.return_value = None
        row, db, database = self.database()
        with database:
            await manager.get_session('session')
            stale = cache.setex.await_args.args[2]
            cache.delete.side_effect = RedisConnectionError('cache offline')
            await manager.update_session('session', name='new')
            row.name = 'new'; cache.get.return_value = stale
            self.assertEqual((await manager.get_session('session'))['name'], 'new')
            # Old Redis contents can outlive the API process. Its new instance
            # must reconstruct from SQL instead of trusting the old cache.
            restarted = SessionManager(); restarted._redis = cache
            cache.get.return_value = stale
            self.assertEqual((await restarted.get_session('session'))['name'], 'new')

    async def test_authoritative_read_never_uses_cache_and_database_errors_propagate(self):
        manager = SessionManager(); manager._redis = AsyncMock()
        row, db, database = self.database()
        with database:
            self.assertEqual((await manager.get_session('session', authoritative=True))['name'], 'current')
            db.commit.side_effect = RuntimeError('durable failure')
            with self.assertRaisesRegex(RuntimeError, 'durable failure'):
                await manager.create_session('owner', '192.0.2.1')
        manager._redis.get.assert_not_awaited()
        manager._redis.setex.assert_not_awaited()

    async def test_cache_cancellation_is_not_success_or_retry(self):
        manager = SessionManager(); manager._redis = AsyncMock()
        manager._redis.get.side_effect = asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await manager.get_session('session')
        manager._redis.get.assert_awaited_once()

    async def test_failed_initial_ping_closes_client_and_never_logs_credentials(self):
        manager = SessionManager(); cache = AsyncMock()
        cache.ping.side_effect = RedisConnectionError('redis://private-credential@host')
        with patch('redis.asyncio.from_url', return_value=cache), \
                patch('memory.session_manager.log') as logger:
            await manager.initialize()
        self.assertIsNone(manager._redis)
        cache.aclose.assert_awaited_once()
        self.assertNotIn('private-credential', str(logger.warning.call_args))

    async def test_optional_cache_operations_have_a_bounded_timeout(self):
        manager = SessionManager(); manager._redis = AsyncMock()
        async def hung(*args): await asyncio.sleep(30)
        manager._redis.get.side_effect = hung
        row, db, database = self.database()
        with patch.object(manager, 'CACHE_TIMEOUT_SECONDS', .01), database:
            self.assertEqual((await asyncio.wait_for(manager.get_session('session'), .5))['name'], 'current')

    async def test_readiness_reports_optional_cache_degradation_without_hiding_database_failure(self):
        connection = AsyncMock()
        context = AsyncMock()
        context.__aenter__.return_value = connection
        for available in (True, False):
            with self.subTest(available=available), \
                    patch('api.main.init_db', AsyncMock()), \
                    patch('memory.database_models.engine', SimpleNamespace(connect=Mock(return_value=context))), \
                    patch('api.main.session_manager.cache_available', AsyncMock(return_value=available)):
                response = await self.client.get('/api/ready')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['cache'], available)
                self.assertEqual(response.json()['degraded'], not available)
                self.assertIs(response.json()['database'], True)
                self.assertIs(response.json()['cache_optional'], True)
        with patch('api.main.init_db', AsyncMock(side_effect=RuntimeError('database offline'))), \
                patch('api.main.session_manager.cache_available', AsyncMock()) as cache:
            self.assertEqual((await self.client.get('/api/ready')).status_code, 503)
            cache.assert_not_awaited()
