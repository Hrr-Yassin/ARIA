"""Local transport timing boundaries cannot grant authority or expose content."""
import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import HTTPException, WebSocketDisconnect

from api.auth import TokenData
from api.routers.pentest import autonomous_websocket
from memory.worker_jobs import WorkerClient
from tests.support import OfflineCase


class TransportObservabilityTests(OfflineCase):
    def retain(self, case, clock, record):
        directory = os.environ.get('ARIA_RELIABILITY_ARTIFACT_DIR')
        if directory:
            path = Path(directory) / 'controller-transport-fixtures.jsonl'
            with path.open('a') as file:
                file.write(json.dumps({'case': case, 'clock': clock, **record}) + '\n')

    async def test_worker_exchange_excludes_client_setup_cleanup_and_decode(self):
        clock = {'now': 0}
        def advance(ms):
            clock['now'] += ms * 1_000_000
        class Response:
            status_code = 200
            def raise_for_status(self):
                pass
            async def aiter_bytes(self, **kwargs):
                advance(7)
                yield b'{}'
        class Client:
            async def __aenter__(self):
                advance(3)
                return self
            async def __aexit__(self, *args):
                advance(17)
            @asynccontextmanager
            async def stream(self, *args, **kwargs):
                advance(5)
                try:
                    yield Response()
                finally:
                    advance(11)
        def decode(content):
            advance(13)
            return json.loads(content)
        with patch('memory.worker_jobs.settings.KALI_AGENT_URL', 'http://worker.invalid'), \
             patch('memory.worker_jobs.httpx.AsyncClient', return_value=Client()), \
             patch('memory.worker_jobs.time', SimpleNamespace(monotonic_ns=lambda: clock['now'])), \
             patch('memory.worker_jobs.json', SimpleNamespace(loads=decode)), \
             patch('memory.worker_jobs.log') as log:
            result = await WorkerClient().request('GET', '/capabilities')
        self.assertEqual(result, {})
        record = log.info.call_args.kwargs
        self.assertEqual(record['timings'], {'worker_http_exchange_ms': 23,
            'worker_response_decode_ms': 13, 'worker_client_total_ms': 56})
        self.assertEqual(record['outcome'], 'response_decoded')
        self.retain('setup-body-close-decode-cleanup-boundaries', 'controlled_fixture', record)

    async def test_worker_faults_keep_unexecuted_phases_unavailable_and_never_retry(self):
        for case in ('success', 'invalid_json', 'http_denied', 'timeout', 'oversized', 'cancelled'):
            with self.subTest(case=case):
                calls = []
                async def handler(request):
                    calls.append(request)
                    if case == 'timeout':
                        raise httpx.ReadTimeout('private-timeout-sentinel')
                    if case == 'cancelled':
                        raise asyncio.CancelledError()
                    return httpx.Response(403 if case == 'http_denied' else 200,
                        content=(b'private-sentinel' if case == 'invalid_json' else
                                 b'x' * 1_000_001 if case == 'oversized' else
                                 b'{"private-sentinel":"not-a-log-field","timings":{"forged":999}}'))
                with patch('memory.worker_jobs.settings.KALI_AGENT_URL', 'http://worker.invalid'), \
                     patch('memory.worker_jobs.log') as log:
                    client = WorkerClient(httpx.MockTransport(handler))
                    if case == 'success':
                        await client.request('GET', '/jobs/job', job_id='job', session_id='owned-session')
                    else:
                        error = {'invalid_json': ValueError, 'http_denied': httpx.HTTPStatusError,
                                 'timeout': httpx.ReadTimeout, 'oversized': ValueError,
                                 'cancelled': asyncio.CancelledError}[case]
                        with self.assertRaises(error):
                            await client.request('GET', '/jobs/job', job_id='job', session_id='owned-session')
                self.assertEqual(len(calls), 1)
                self.assertIn('authorization', calls[0].headers)
                record = log.info.call_args.kwargs
                self.assertEqual(record['operation'], 'status')
                self.assertEqual((record['job_id'], record['session_id']), ('job', 'owned-session'))
                self.assertRegex(record['worker_request_id'], '^[0-9a-f]{32}$')
                self.assertNotIn('private-sentinel', str(record))
                self.assertNotIn('private-timeout-sentinel', str(record))
                self.assertNotIn('forged', str(record))
                self.assertNotIn(calls[0].headers['authorization'], str(record))
                self.assertGreaterEqual(record['timings']['worker_http_exchange_ms'], 0)
                self.assertGreaterEqual(record['timings']['worker_client_total_ms'], record['timings']['worker_http_exchange_ms'])
                decode = record['timings']['worker_response_decode_ms']
                if case in ('success', 'invalid_json'):
                    self.assertGreaterEqual(decode, 0)
                else:
                    self.assertIsNone(decode)
                self.assertEqual(record['outcome'], 'response_decoded' if case == 'success' else
                                 'cancelled' if case == 'cancelled' else 'failed')
                self.retain(case, 'local_monotonic_MockTransport', record)

    async def test_worker_zero_timings_are_measured_and_unknown_operation_is_closed(self):
        client = WorkerClient(httpx.MockTransport(lambda req: httpx.Response(200, json={})))
        with patch('memory.worker_jobs.settings.KALI_AGENT_URL', 'http://worker.invalid'), \
             patch('memory.worker_jobs.time', SimpleNamespace(monotonic_ns=lambda: 0)), \
             patch('memory.worker_jobs.log') as log:
            await client.request('GET', '/private-path-sentinel?secret=private-query-sentinel')
        record = log.info.call_args.kwargs
        self.assertEqual(set(record['timings'].values()), {0})
        self.assertEqual(record['operation'], 'other')
        self.assertNotIn('private-', str(record))

    async def test_worker_concurrent_and_lifecycle_requests_keep_identity_separate(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def handler(request):
            job_id = request.url.path.split('/')[2]
            if job_id == 'first':
                entered.set()
                await release.wait()
            else:
                await entered.wait()
                release.set()
            return httpx.Response(200, json={'job_id': job_id, 'session_id': job_id + '-session',
                'state': 'cancelled' if request.method == 'POST' else 'running', 'terminated': True})
        client = WorkerClient(httpx.MockTransport(handler))
        with patch('memory.worker_jobs.settings.KALI_AGENT_URL', 'http://worker.invalid'), \
             patch('memory.worker_jobs.log') as log:
            await asyncio.gather(client.status({'job_id': 'first', 'session_id': 'first-session'}),
                client.cancel({'job_id': 'second', 'session_id': 'second-session'}))
        records = [call.kwargs for call in log.info.call_args_list]
        self.assertEqual(len({record['worker_request_id'] for record in records}), 2)
        self.assertEqual({(r['operation'], r['job_id'], r['session_id']) for r in records},
                         {('status', 'first', 'first-session'), ('cancel', 'second', 'second-session')})

    async def test_websocket_measures_only_authorized_asgi_send_and_preserves_payload(self):
        for error in (None, WebSocketDisconnect(), asyncio.CancelledError()):
            with self.subTest(error=type(error).__name__):
                clock = {'now': 0}
                owner = TokenData(user_id='owner', username='fixture', role='pentester', skill_level='expert')
                ws = AsyncMock(headers={}, query_params={})
                ws.receive_json.return_value = {'token': 'private-token-sentinel'}
                ws.receive.side_effect = asyncio.Event().wait
                event = {'type': 'auto_complete', 'run_id': 'run', 'event_sequence': 3,
                         'session_id': 'engagement', 'private-sentinel': 'not-a-log-field'}
                async def access(*args, **kwargs):
                    clock['now'] += 1_000_000
                async def stream(*args):
                    clock['now'] += 5_000_000
                    yield event
                async def send(*args):
                    clock['now'] += 7_000_000
                    if error is not None:
                        raise error
                ws.send_json.side_effect = send
                with patch('api.routers.pentest.authenticate_socket_token', AsyncMock(return_value=owner)), \
                     patch('api.routers.pentest.get_accessible_session', AsyncMock(side_effect=access)), \
                     patch('api.routers.pentest.autonomous_engine.stream_events', side_effect=stream), \
                     patch('api.routers.pentest.time', SimpleNamespace(monotonic_ns=lambda: clock['now'])), \
                     patch('api.routers.pentest.log') as log:
                    if isinstance(error, asyncio.CancelledError):
                        with self.assertRaises(asyncio.CancelledError):
                            await autonomous_websocket(ws, 'engagement')
                    else:
                        await autonomous_websocket(ws, 'engagement')
                ws.send_json.assert_awaited_once_with(event)
                record = log.info.call_args.kwargs
                self.assertEqual(record['websocket_asgi_send_ms'], 7)
                self.assertEqual((record['session_id'], record['run_id'], record['event_sequence']),
                                 ('engagement', 'run', 3))
                self.assertRegex(record['websocket_stream_id'], '^[0-9a-f]{32}$')
                self.assertNotIn('private-', str(record))
                self.assertEqual(record['outcome'], 'succeeded' if error is None else
                                 'cancelled' if isinstance(error, asyncio.CancelledError) else 'failed')
                self.retain('websocket-' + record['outcome'], 'controlled_fixture', record)

    async def test_websocket_revocation_before_send_exposes_neither_payload_nor_measurement(self):
        owner = TokenData(user_id='owner', username='fixture', role='pentester', skill_level='expert')
        ws = AsyncMock(headers={}, query_params={})
        ws.receive_json.return_value = {'token': 'private-token-sentinel'}
        ws.receive.side_effect = asyncio.Event().wait
        async def stream(*args):
            yield {'run_id': 'private-run-sentinel'}
        with patch('api.routers.pentest.authenticate_socket_token', AsyncMock(return_value=owner)), \
             patch('api.routers.pentest.get_accessible_session', AsyncMock(side_effect=[{}, {}, HTTPException(403, 'revoked')])), \
             patch('api.routers.pentest.autonomous_engine.stream_events', side_effect=stream), \
             patch('api.routers.pentest.log') as log:
            await autonomous_websocket(ws, 'engagement')
        ws.send_json.assert_not_awaited()
        log.info.assert_not_called()
        ws.close.assert_awaited_once_with(code=4401, reason='Access revoked')

    async def test_websocket_disconnect_releases_idle_stream(self):
        owner = TokenData(user_id='owner', username='fixture', role='pentester', skill_level='expert')
        ws = AsyncMock(headers={}, query_params={})
        ws.receive_json.return_value = {'token': 'private-token-sentinel'}
        subscribed, released = asyncio.Event(), asyncio.Event()

        async def receive():
            await subscribed.wait()
            return {'type': 'websocket.disconnect'}

        async def stream(*args):
            try:
                subscribed.set()
                await asyncio.Event().wait()
                yield {}
            finally:
                released.set()

        ws.receive.side_effect = receive
        with patch('api.routers.pentest.authenticate_socket_token', AsyncMock(return_value=owner)), \
             patch('api.routers.pentest.get_accessible_session', AsyncMock(return_value={})), \
             patch('api.routers.pentest.autonomous_engine.stream_events', side_effect=stream):
            await asyncio.wait_for(autonomous_websocket(ws, 'engagement'), timeout=1)
        self.assertTrue(released.is_set())
        ws.send_json.assert_not_awaited()
