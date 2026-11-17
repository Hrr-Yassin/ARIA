"""Dependency loss must not skip process/worker cleanup or claim success."""
import asyncio
from contextlib import ExitStack
from unittest.mock import AsyncMock, patch

from tests.support import OfflineCase
from api.main import lifespan, app


class ShutdownCleanupTests(OfflineCase):
    async def test_shutdown_finishes_local_cleanup_after_reconciliation_failure(self):
        calls = []

        def stage(name, failure=None):
            async def call(*args):
                calls.append(name)
                if failure:
                    raise failure
            return AsyncMock(side_effect=call)

        recover = AsyncMock(side_effect=[None, RuntimeError('private database detail')])
        close = stage('redis_close')
        drain = stage('worker_drain')
        with ExitStack() as stack:
            for path, value in (
                ('api.main.init_db', AsyncMock()),
                ('memory.session_manager.session_manager.initialize', AsyncMock()),
                ('memory.session_manager.session_manager.close', close),
                ('memory.session_manager.session_manager._redis', None),
                ('memory.knowledge_cache.knowledge_cache.initialize_redis', AsyncMock()),
                ('memory.worker_jobs.worker_jobs.recover', recover),
                ('memory.worker_jobs.worker_jobs.drain_cleanup', drain),
                ('memory.autonomous_runs.run_store.recover', AsyncMock()),
                ('memory.team_tasks.team_store.recover', AsyncMock()),
                ('memory.web_actions.web_actions.recover', AsyncMock()),
                ('memory.application_map.application_map.purge_expired', AsyncMock()),
                ('memory.application_map.application_map.retention_loop', AsyncMock()),
                ('orchestrator.campaign_supervisor.campaign_supervisor.start', lambda: None),
                ('orchestrator.campaign_supervisor.campaign_supervisor.stop', stage('supervisor')),
                ('orchestrator.browser_mapping.browser_mapping.close', stage('browser')),
                ('agents.autonomous_engine.autonomous_engine.shutdown', stage('engine')),
            ):
                stack.enter_context(patch(path, value))
            with self.assertRaises(RuntimeError):
                async with lifespan(app):
                    pass
        self.assertEqual(calls, ['supervisor', 'browser', 'engine', 'worker_drain', 'redis_close'])
        self.assertEqual(recover.await_count, 2)

    async def test_cleanup_runs_after_supervisor_stop_failure(self):
        # Reuse the real lifecycle path and verify the first finally cannot
        # suppress the remaining shutdown calls.
        from api.main import _shutdown_resources
        from memory.worker_jobs import worker_jobs
        from memory.session_manager import session_manager
        retention = asyncio.create_task(asyncio.sleep(10))
        with patch('orchestrator.campaign_supervisor.campaign_supervisor.stop',
                AsyncMock(side_effect=RuntimeError('private detail'))), \
             patch('orchestrator.browser_mapping.browser_mapping.close', AsyncMock()) as browser, \
             patch('agents.autonomous_engine.autonomous_engine.shutdown', AsyncMock()) as engine, \
             patch.object(worker_jobs, 'recover', AsyncMock()) as recover, \
             patch.object(worker_jobs, 'drain_cleanup', AsyncMock()) as drain, \
             patch.object(session_manager, '_redis', None), \
             patch.object(session_manager, 'close', AsyncMock()) as close:
            with self.assertRaisesRegex(RuntimeError, '^ARIA shutdown incomplete: campaign_supervisor$'):
                await _shutdown_resources(retention)
            for operation in (browser, engine, recover, drain, close):
                operation.assert_awaited_once()
        self.assertTrue(retention.done())

    async def test_shutdown_preserves_cancellation_after_attempting_each_cleanup(self):
        from api.main import _shutdown_resources
        from memory.worker_jobs import worker_jobs
        from memory.session_manager import session_manager
        retention = asyncio.create_task(asyncio.sleep(10))
        with patch('orchestrator.campaign_supervisor.campaign_supervisor.stop', AsyncMock()), \
             patch('orchestrator.browser_mapping.browser_mapping.close',
                AsyncMock(side_effect=asyncio.CancelledError())), \
             patch('agents.autonomous_engine.autonomous_engine.shutdown', AsyncMock()), \
             patch.object(worker_jobs, 'recover', AsyncMock()) as recover, \
             patch.object(worker_jobs, 'drain_cleanup', AsyncMock()) as drain, \
             patch.object(session_manager, '_redis', None), \
             patch.object(session_manager, 'close', AsyncMock()) as close:
            with self.assertRaises(asyncio.CancelledError):
                await _shutdown_resources(retention)
            for operation in (recover, drain, close):
                operation.assert_awaited_once()
        self.assertTrue(retention.done())
