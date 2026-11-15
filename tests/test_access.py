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

    async def test_v10_autonomous_routes_reject_non_owner(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        routes = [('POST', 'autonomous/start', {}), ('POST', 'autonomous/stop', {}),
                  ('POST', 'autonomous/restore', {}),
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

    async def test_objectives_reach_distinct_owned_runs_and_oversize_is_rejected(self):
        from agents.autonomous_engine import AutonomousEngine
        engine = AutonomousEngine()
        app.dependency_overrides[get_current_user] = lambda: OWNER
        objectives = {'first': 'Observe HTTP only; retain unresolved hypotheses.',
                      'second': 'Document the separate approved discovery objective.'}

        async def owned_session(sid, **kwargs):
            return {**SESSION, 'session_id': sid}

        with patch('api.session_access.session_manager.get_session',
                   side_effect=owned_session), \
             patch('api.routers.pentest.get_skill_level_from_db',
                   AsyncMock(return_value='expert')), \
             patch('api.routers.pentest.autonomous_engine', engine), \
             patch('agents.autonomous_engine.execution_authorization._context',
                   AsyncMock(return_value={'owner_id': 'owner'})), \
             patch('agents.autonomous_engine.execution_authorization._validate'), \
             patch('agents.autonomous_engine.worker_jobs.client.capabilities',
                   AsyncMock(side_effect=RuntimeError('Synthetic worker unavailable'))), \
             patch('llm.pool_manager.pool_manager.query_for_task', AsyncMock()) as provider:
            for sid, objective in objectives.items():
                response = await self.client.post(
                    f'/api/pentest/{sid}/autonomous/start',
                    json={'objective': objective, 'goal': 'discovery'})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()['original_objective'], objective)
                self.assertFalse(response.json()['objective_truncated'])
            for sid, objective in objectives.items():
                self.assertEqual(engine.get_status(sid)['original_objective'], objective)
            response = await self.client.post('/api/pentest/first/autonomous/start',
                json={'objective': 'x' * (settings.AUTONOMOUS_OBJECTIVE_MAX_CHARS + 1)})
            self.assertEqual(response.status_code, 422)
            self.assertEqual(engine.get_status('first')['original_objective'], objectives['first'])
            provider.assert_not_awaited()

    async def test_completed_run_keeps_pending_mission_tasks_visible(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        run = {'run_id': 'bounded-run', 'run_state': 'completed', 'active': False,
               'original_objective': 'Observe HTTP within approved scope',
               'reason_code': 'required_observations_completed',
               'completion': {'complete': True, 'missing': []}}
        ledger = {'cursor': 4, 'tasks': [{'id': 'review-task', 'state': 'awaiting_review',
                                         'owner_role': 'web_intel'}],
                  'research_hypotheses': [{'id': 'hypothesis', 'state': 'HYPOTHESIZED'}]}
        with patch('api.session_access.session_manager.get_session', AsyncMock(return_value=SESSION)), \
             patch('api.routers.pentest.autonomous_engine.restored_status', AsyncMock(return_value=run)), \
             patch('memory.team_tasks.team_store.view', AsyncMock(return_value=ledger)) as tasks:
            response = await self.client.get('/api/pentest/engagement/autonomous/status')
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['run_state'], 'completed')
        self.assertEqual(data['mission']['state'], 'work_pending')
        self.assertEqual(data['mission']['pending_tasks'][0]['id'], 'review-task')
        self.assertEqual(data['mission']['objective'], run['original_objective'])
        self.assertTrue(data['mission']['observations_completed'])
        self.assertFalse(data['mission']['proposals_require_execution'])
        tasks.assert_awaited_once_with('engagement', 'owner')

    async def test_missing_task_ledger_does_not_become_mission_completion(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        run = {'run_id': 'bounded-run', 'run_state': 'completed', 'active': False,
               'completion': {'complete': True, 'missing': []}}
        with patch('api.session_access.session_manager.get_session', AsyncMock(return_value=SESSION)), \
             patch('api.routers.pentest.autonomous_engine.restored_status', AsyncMock(return_value=run)), \
             patch('memory.team_tasks.team_store.view', AsyncMock(side_effect=RuntimeError('private-storage-error'))):
            response = await self.client.get('/api/pentest/engagement/autonomous/status')
        self.assertEqual(response.json()['mission']['state'], 'blocked')
        self.assertEqual(response.json()['mission']['reason_code'], 'task_ledger_unavailable')
        self.assertIsNone(response.json()['mission']['pending_tasks'])
        self.assertNotIn('private-storage-error', response.text)

    async def test_run_status_admin_access_does_not_expand_team_owner_access(self):
        admin = TokenData(user_id='admin', username='admin', role='admin', skill_level='expert')
        app.dependency_overrides[get_current_user] = lambda: admin
        run = {'run_id': 'bounded-run', 'run_state': 'completed',
               'completion': {'complete': True, 'missing': []}}
        with patch('api.session_access.session_manager.get_session', AsyncMock(return_value=SESSION)), \
             patch('api.routers.pentest.autonomous_engine.restored_status', AsyncMock(return_value=run)), \
             patch('memory.team_tasks.team_store.view', AsyncMock()) as tasks:
            response = await self.client.get('/api/pentest/engagement/autonomous/status')
        self.assertEqual(response.status_code, 200)
        tasks.assert_not_awaited()
        self.assertEqual(response.json()['mission']['reason_code'], 'task_ledger_unavailable')

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
