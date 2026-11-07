from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from memory.application_map import ApplicationMap
from tests.support import OfflineCase


class ProfileCapabilityTests(OfflineCase):
    async def test_http_proposal_checks_worker_after_ownership_before_proposal(self):
        appmap = ApplicationMap()
        for version, allowed in [(1, True), (0, False), (True, False), (None, False)]:
            with self.subTest(version=version), \
                 patch('worker.http_profile.decode', return_value={'method': 'GET', 'url': 'http://192.0.2.1/'}), \
                 patch.object(appmap, 'replay_material', AsyncMock(return_value=('aria-http 00000000-0000-0000-0000-000000000001 00000000-0000-0000-0000-000000000002 ' + 'a'*64 + ' GET http://192.0.2.1/', 'token'))), \
                 patch('config.settings.settings.KALI_WORKER_PROTOCOL', 'jobs-v1'), \
                 patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock(return_value={'authenticated_http_version': version})), \
                 patch('memory.worker_jobs.worker_jobs.resume_session', AsyncMock()) as resume, \
                 patch('memory.execution_authorization.execution_authorization.propose', AsyncMock(return_value=SimpleNamespace(id='id', status='pending'))) as propose:
                if allowed:
                    self.assertEqual((await appmap.replay_proposal('sid', 'owner', 'identity', 'capture'))['status'], 'pending')
                    resume.assert_awaited_once(); propose.assert_awaited_once()
                else:
                    with self.assertRaises(HTTPException): await appmap.replay_proposal('sid', 'owner', 'identity', 'capture')
                    resume.assert_not_awaited(); propose.assert_not_awaited()

    async def test_foreign_engagement_never_contacts_worker(self):
        appmap = ApplicationMap()
        with patch.object(appmap, 'replay_material', AsyncMock(side_effect=HTTPException(404))), \
             patch('memory.worker_jobs.worker_jobs.client.capabilities', AsyncMock()) as caps:
            with self.assertRaises(HTTPException): await appmap.replay_proposal('foreign', 'owner', 'i', 'c')
            caps.assert_not_awaited()
