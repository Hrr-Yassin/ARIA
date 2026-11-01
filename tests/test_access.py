import time
from unittest.mock import AsyncMock, patch
import jwt
from fastapi import HTTPException
from api.auth import TokenData, get_current_user, create_token, token_identity
from api.main import app
from api.routers.pentest import autonomous_websocket
from api.session_access import get_accessible_session
from config.settings import settings
from tests.support import OfflineCase

OWNER = TokenData(user_id='owner', username='owner', role='pentester', skill_level='expert')
SESSION = {'session_id': 'engagement', 'target': '192.0.2.1', 'user_id': 'owner', 'scope': {'targets': ['192.0.2.1']}}


class AccessTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_missing_owner_is_denied(self):
        with patch('api.session_access.session_manager.get_session', AsyncMock(return_value={'target': '192.0.2.1'})):
            with self.assertRaises(HTTPException) as error:
                await get_accessible_session('engagement', OWNER)
            self.assertEqual(error.exception.status_code, 403)

    async def test_all_eight_v10_routes_reject_non_owner(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        routes = [('POST', 'autonomous/start', {}), ('POST', 'autonomous/stop', {}),
                  ('GET', 'autonomous/status', None), ('GET', 'autonomous/approvals', None),
                  ('POST', 'autonomous/approve', {'action_id': 'x', 'decision': 'approve'}),
                  ('GET', 'decision-log', None), ('GET', 'playbooks', None), ('GET', 'kb-snapshot', None)]
        with patch('api.session_access.session_manager.get_session', AsyncMock(return_value={**SESSION, 'user_id': 'another'})):
            for method, path, body in routes:
                with self.subTest(path=path):
                    response = await self.client.request(method, '/api/pentest/engagement/' + path, json=body)
                    self.assertEqual(response.status_code, 403)

    async def test_owner_status_and_start_contract(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch('api.session_access.session_manager.get_session', AsyncMock(return_value=SESSION)), \
             patch('api.routers.pentest.get_skill_level_from_db', AsyncMock(return_value='expert')), \
             patch('api.routers.pentest.autonomous_engine.start', AsyncMock(return_value={'status': 'started'})) as start:
            self.assertEqual((await self.client.get('/api/pentest/engagement/autonomous/status')).status_code, 200)
            result = await self.client.post('/api/pentest/engagement/autonomous/start', json={'max_steps': 2})
            self.assertEqual(result.status_code, 200)
            self.assertEqual(start.await_args.kwargs['target'], SESSION['target'])
            self.assertEqual(start.await_args.kwargs['max_steps'], 2)
            result = await self.client.post('/api/pentest/engagement/autonomous/start', json={'max_steps': 0})
            self.assertEqual(result.status_code, 422)

    async def test_socket_requires_valid_identity_owner_and_origin(self):
        good = create_token('owner', 'owner', 'pentester', 'expert')
        expired = jwt.encode({'sub': 'owner', 'iat': 1, 'exp': 2}, settings.SECRET_KEY, algorithm='HS256')
        cases = [('', SESSION, {}, False), ('invalid', SESSION, {}, False), (expired, SESSION, {}, False),
                 (good, {**SESSION, 'user_id': 'other'}, {}, False),
                 (good, SESSION, {'origin': 'https://untrusted.invalid'}, False), (good, SESSION, {}, True)]
        for token, session, headers, allowed in cases:
            with self.subTest(allowed=allowed, headers=headers):
                ws = AsyncMock()
                ws.headers, ws.query_params = headers, {}
                ws.receive_json.return_value = {'token': token}
                async def stream(sid):
                    yield {'type': 'test'}
                async def authenticate(token):
                    return token_identity(token)
                with patch('api.routers.pentest.authenticate_socket_token', side_effect=authenticate), \
                     patch('api.session_access.session_manager.get_session', AsyncMock(return_value=session)), \
                     patch('api.routers.pentest.autonomous_engine.stream_events', side_effect=stream) as source:
                    await autonomous_websocket(ws, 'engagement')
                    self.assertEqual(source.called, allowed)
                    self.assertEqual(ws.send_json.await_count, int(allowed))
