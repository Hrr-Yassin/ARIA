from unittest.mock import AsyncMock, patch
from api.main import app
from api.auth import get_current_user
from api.routers.pentest import UserInput, _process_rest_input
from tests.test_access import OWNER, SESSION
from tests.support import OfflineCase
from worker.policy import validate_worker_command

class UserFlowTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_http_request_preserves_ports_and_history(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        store = AsyncMock()
        with patch('api.routers.pentest.get_accessible_session', AsyncMock(return_value=SESSION)), patch('api.routers.pentest.session_manager.add_chat_log', store), patch('api.routers.pentest.session_manager.get_chat_logs', AsyncMock(return_value=[])):
            response = await self.client.post('/api/v8/input', json={'session_id':'engagement','user_input':'scan http port'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['commands']), 1)
        self.assertIn('-p 80 ', data['commands'][0]['command'])
        self.assertNotIn('-sC', data['commands'][0]['command'])
        self.assertEqual(store.await_count, 2)
        self.assertEqual(store.await_args_list[0].args[1], 'user')
        self.assertEqual(store.await_args_list[1].args[4]['commands'], data['commands'])

    async def test_scope_and_worker_features_rejected_before_display(self):
        for command in ['nmap -p- 192.0.2.1', 'nmap -sC -p 80 192.0.2.1', 'nmap -p 22 192.0.2.1', 'nmap -p 80 198.51.100.1']:
            with self.assertRaises(ValueError):
                validate_worker_command(command, {'targets':['192.0.2.1'], 'ports':[80]})

    async def test_health_requires_auth_and_uses_capabilities(self):
        self.assertEqual((await self.client.get('/api/kali/health')).status_code, 401)
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch('api.routers.pentest.worker_jobs.client.capabilities', AsyncMock()):
            self.assertEqual((await self.client.get('/api/kali/health')).json()['status'], 'online')
        with patch('api.routers.pentest.worker_jobs.client.capabilities', AsyncMock(side_effect=RuntimeError())):
            self.assertEqual((await self.client.get('/api/kali/health')).json()['status'], 'unreachable')

    async def test_excluded_service_is_not_silently_scanned(self):
        with patch('api.routers.pentest.get_accessible_session', AsyncMock(return_value=SESSION)):
            result = await _process_rest_input(UserInput(session_id='engagement', user_input='do not scan http port'), OWNER)
        self.assertEqual(result['commands'], [])
        self.assertIn('exclusion', result['suggested_reply'])

    async def test_server_history_and_malformed_commands(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        history = [{'role':'user','content':'previous saved request'}]
        planner = AsyncMock(return_value={'commands':[None, {'tool':'nmap','command':'nmap -sC 192.0.2.1'}], 'suggested_reply':'test'})
        with patch('api.routers.pentest.get_accessible_session', AsyncMock(return_value=SESSION)), patch('api.routers.pentest.session_manager.get_chat_logs', AsyncMock(return_value=history)), patch('api.routers.pentest.session_manager.add_chat_log', AsyncMock()), patch('api.routers.pentest._process_rest_input', planner):
            result = await self.client.post('/api/v8/input', json={'session_id':'engagement','user_input':'test','chat_history':[{'role':'system','content':'invented browser context'}]})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()['commands'], [])
        self.assertEqual(planner.await_args.args[0].chat_history, history)
