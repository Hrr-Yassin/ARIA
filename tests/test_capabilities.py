from unittest.mock import AsyncMock, patch

from api.auth import get_current_user
from api.main import app
from tests.support import OfflineCase
from tests.test_access import OWNER


class CapabilityTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_requires_identity(self):
        self.assertEqual((await self.client.get('/api/capabilities')).status_code, 401)

    async def test_offline_worker_does_not_advertise_available_tools(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch('config.settings.settings.KALI_AGENT_URL', ''), patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock()) as remote:
            result = (await self.client.get('/api/capabilities')).json()
        self.assertEqual(result['worker'], {'status': 'not_configured', 'available_tools': []})
        remote.assert_not_awaited()

    async def test_filters_unsupported_tools_and_hides_failures(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch('config.settings.settings.KALI_AGENT_URL', 'http://worker.invalid'), patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(return_value={'tools': ['curl', 'nmap', 'sqlmap']})):
            result = (await self.client.get('/api/capabilities')).json()
            self.assertEqual(result['worker']['available_tools'], ['curl', 'nmap'])
        for value in [RuntimeError('private endpoint and token'), {'tools': 'curl'}]:
            remote = AsyncMock(side_effect=value) if isinstance(value, Exception) else AsyncMock(return_value=value)
            with patch('config.settings.settings.KALI_AGENT_URL', 'http://worker.invalid'), patch('memory.worker_jobs.worker_jobs.client.capabilities', remote):
                response = await self.client.get('/api/capabilities')
                self.assertEqual(response.json()['worker'], {'status': 'unreachable', 'available_tools': []})
                self.assertNotIn('private', response.text)
