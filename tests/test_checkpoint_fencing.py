"""Checkpoint and event delivery consistency; no provider, worker or SQL I/O."""
import asyncio
import copy
from unittest.mock import AsyncMock, patch

from agents.autonomous_engine import AutonomousEngine, SessionRunState
from memory.autonomous_runs import CheckpointConflict, build_checkpoint
from tests.support import OfflineCase


class CheckpointFencingTests(OfflineCase):
    def engine_state(self):
        engine = AutonomousEngine()
        state = SessionRunState('fixture-session', 'owner', 'discovery', '192.0.2.1', 'expert',
            owner_id='owner', objective='Preserve fixture work', scope_digest='a' * 64)
        engine._runs[state.session_id] = state
        return engine, state

    async def test_delayed_first_persistence_cannot_commit_after_a_newer_snapshot(self):
        engine, state = self.engine_state()
        entered, release = asyncio.Event(), asyncio.Event()
        committed = []
        async def save(snapshot):
            snapshot = copy.deepcopy(snapshot)
            if not committed and snapshot['model_calls'] == 0:
                entered.set()
                await release.wait()
            committed.append(snapshot)
        with patch('agents.autonomous_engine.run_store.save', side_effect=save):
            first = asyncio.create_task(engine._persist(state))
            await entered.wait()
            state.model_calls = 1
            second = asyncio.create_task(engine._persist(state))
            await asyncio.sleep(0)
            release.set()
            await asyncio.gather(first, second)
        self.assertEqual([s['model_calls'] for s in committed], [0, 1])
        self.assertEqual([s['snapshot_revision'] for s in committed], [1, 2])

    async def test_old_state_cannot_persist_the_replacement_run(self):
        engine, old = self.engine_state()
        replacement = SessionRunState(old.session_id, 'owner', 'http_check', '192.0.2.1', 'expert')
        engine._runs[old.session_id] = replacement
        with patch('agents.autonomous_engine.run_store.save', AsyncMock()) as save:
            with self.assertRaises(CheckpointConflict):
                await engine._persist(old)
        save.assert_not_awaited()
        self.assertEqual(replacement.snapshot_revision, 0)

    async def test_runtime_capability_serialization_preserves_only_valid_versions(self):
        engine, state = self.engine_state()
        state.capabilities = {'tools': ['nmap', 'curl'], 'typed_adapters': {
            'httpx.http.probe.v1': 1, 'ffuf.http.paths.v1': True, 'unknown-version': 2}}
        checkpoint = build_checkpoint(engine.get_status(state.session_id))
        self.assertEqual(checkpoint['capabilities']['typed_adapters'], {'httpx.http.probe.v1': 1})
        state.capabilities['typed_adapters'] = True
        self.assertEqual(engine.get_status(state.session_id)['capabilities']['typed_adapters'], {})

    async def test_concurrent_events_are_committed_and_delivered_in_sequence(self):
        engine, state = self.engine_state()
        queue = asyncio.Queue(maxsize=40)
        state.subscribers.add(queue)
        with patch('agents.autonomous_engine.run_store.save', AsyncMock()):
            await asyncio.gather(*[engine._emit(state, {'type': 'auto_activity', 'action': f'fixture {n}'})
                                   for n in range(20)])
        delivered = [queue.get_nowait() for _ in range(queue.qsize())]
        self.assertEqual([e['event_sequence'] for e in delivered], list(range(1, 21)))
        self.assertEqual(state.event_sequence, 20)
        self.assertEqual(state.snapshot_revision, 20)

    async def test_slow_subscriber_receives_terminal_event_with_gap_notice(self):
        engine, state = self.engine_state()
        queue = asyncio.Queue(maxsize=1)
        queue.put_nowait({'type': 'auto_activity', 'action': 'old'})
        state.subscribers.add(queue)
        with patch('agents.autonomous_engine.run_store.save', AsyncMock()):
            await engine._emit(state, {'type': 'auto_complete', 'status': 'blocked',
                                       'action': 'Synthetic prerequisite unavailable'})
        last = queue.get_nowait()
        self.assertEqual(last['type'], 'auto_complete')
        self.assertTrue(last['stream_gap'])
        self.assertEqual(last['status'], 'blocked')

    async def test_slow_stop_cannot_cancel_a_replacement_start(self):
        engine, old = self.engine_state()
        entered, release = asyncio.Event(), asyncio.Event()
        async def cancellation(*args):
            entered.set()
            await release.wait()
            return {'pending': 0, 'cancelled': 0, 'jobs': []}
        async def loop(state):
            try:
                await asyncio.Event().wait()
            finally:
                state.active = False
        with patch('agents.autonomous_engine.execution_authorization._context',
                   AsyncMock(return_value={'owner_id': 'owner'})), \
             patch('agents.autonomous_engine.execution_authorization._validate'), \
             patch('agents.autonomous_engine.worker_jobs.cancel_session', side_effect=cancellation), \
             patch('agents.autonomous_engine.worker_jobs.client.capabilities',
                   AsyncMock(return_value={'tools': ['curl', 'nmap']})), \
             patch('llm.pool_manager.pool_manager.planner_preflight', AsyncMock(return_value={'ready': True})), \
             patch('agents.autonomous_engine.knowledge_store.restore', AsyncMock()), \
             patch.object(engine, '_persist', AsyncMock()), \
             patch.object(engine, '_write_decision_log', AsyncMock()), \
             patch.object(engine, '_run_loop', side_effect=loop):
            stop = asyncio.create_task(engine.request_stop(old.session_id, old.user_id))
            await entered.wait()
            start = asyncio.create_task(engine.start(old.session_id, old.user_id))
            await asyncio.sleep(0)
            self.assertFalse(start.done())
            release.set()
            self.assertEqual((await stop)['status'], 'stopped')
            self.assertEqual((await start)['status'], 'started')
            replacement = engine._runs[old.session_id]
            self.assertNotEqual(replacement.run_id, old.run_id)
            self.assertFalse(replacement.stop_requested)
            self.assertFalse(engine._tasks[old.session_id].cancelled())
            await engine.shutdown()
