import socket
import unittest
from unittest.mock import patch, AsyncMock

import httpx
from api.main import app


class OfflineCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.worker_manifest = patch('agents.report_agent.worker_evidence_manifest', AsyncMock(return_value=[]))
        self.worker_manifest.start()
        # Run persistence is tested separately; these service fixtures remain offline.
        self.connector_owner=patch("config.settings.settings.BURP_CONNECTOR_USER_ID","owner")
        self.connector_owner.start()
        self.web_revoke = patch("memory.web_actions.web_actions.revoke_principal",AsyncMock(return_value={"pending":0}))
        self.web_revoke.start()
        self.run_save = patch("memory.autonomous_runs.run_store.save", new_callable=AsyncMock)
        self.run_save.start()
        self.run_latest = patch("memory.autonomous_runs.run_store.latest", AsyncMock(return_value={"active": False}))
        self.run_latest.start()
        self.network = patch.object(socket.socket, 'connect', side_effect=AssertionError('Network disabled in tests'))
        self.network.start()
        self.dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS disabled in tests"))
        self.dns.start()
        self.admission = patch("memory.worker_jobs.worker_jobs.resume_session", new_callable=AsyncMock)
        self.admission.start()
        self.embedder = patch('memory.vector_store._embedder.available', return_value=False)
        self.embedder.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://testserver')

    async def asyncTearDown(self):
        self.worker_manifest.stop()
        await self.client.aclose()
        self.embedder.stop()
        self.admission.stop()
        self.dns.stop()
        self.network.stop()
        self.connector_owner.stop()
        self.web_revoke.stop()
        self.run_save.stop()
        self.run_latest.stop()
