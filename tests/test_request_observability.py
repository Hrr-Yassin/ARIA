"""HTTP/mission timing boundaries preserve unavailable owner-only work."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from api.auth import TokenData
from api.routers.pentest import autonomous_status
from tests.support import OfflineCase


class RequestObservability(OfflineCase):
    async def test_pool_queue_wait_is_separate_from_context_and_client_invocation(self):
        from llm.pool_manager import LLMPoolManager
        manager = LLMPoolManager()
        await manager._request_slots.acquire()
        queued = asyncio.Event()
        clock = iter((0, 10_000_000, 12_000_000))
        def monotonic_ns():
            value = next(clock)
            queued.set()
            return value
        async def provider(*args):
            return {'success': True, 'content': '{}', 'logical_request_id': 'fixture-request'}
        with patch.object(manager, 'refresh_user_keys', AsyncMock()) as refresh, \
             patch('memory.access_scope.owned_session_ids', AsyncMock(return_value=[])), \
             patch('llm.pool_manager.time', SimpleNamespace(monotonic_ns=monotonic_ns)), \
             patch.object(manager, '_query_for_task', AsyncMock(side_effect=provider)):
            task = asyncio.create_task(manager.query_for_task('owner', 'output_analysis', 'fixture'))
            try:
                await queued.wait()
                refresh.assert_not_awaited()
            finally:
                manager._request_slots.release()
            result = await task
        self.assertEqual(result['request_timings'], {'queue_wait_ms': 10, 'request_context_ms': 2})

    async def test_http_handler_duration_has_server_correlation_without_private_data(self):
        response = await self.client.get('/api/health', headers={'X-Request-ID': 'private-sentinel'})
        self.assertEqual(response.status_code, 200)
        self.assertRegex(response.headers['x-request-id'], r'^[0-9a-f]{32}$')
        self.assertGreaterEqual(float(response.headers['x-aria-handler-ms']), 0)
        self.assertNotIn('private-sentinel', response.headers['x-request-id'])

    async def test_mission_projection_and_ledger_load_are_distinct_and_owned(self):
        async def ledger(*args):
            await asyncio.sleep(.01)
            return {'tasks': []}
        owner = TokenData(user_id='owner', username='fixture', role='pentester', skill_level='expert')
        for actor in (owner, TokenData(user_id='admin', username='admin', role='admin', skill_level='expert')):
            with self.subTest(actor=actor.user_id), \
                 patch('api.routers.pentest.get_accessible_session', AsyncMock(return_value={'user_id': 'owner'})), \
                 patch('api.routers.pentest.autonomous_engine.restored_status', AsyncMock(return_value={'run_state': 'not_started'})), \
                 patch('memory.team_tasks.team_store.view', AsyncMock(side_effect=ledger)) as read:
                result = await autonomous_status('engagement', actor)
                timing = result['timings']
                self.assertGreaterEqual(timing['run_status_load_ms'], 0)
                self.assertGreaterEqual(timing['mission_projection_ms'], 0)
                if actor is owner:
                    self.assertGreaterEqual(timing['task_ledger_load_ms'], 8)
                    read.assert_awaited_once_with('engagement', 'owner')
                else:
                    self.assertIsNone(timing['task_ledger_load_ms'])
                    read.assert_not_awaited()
