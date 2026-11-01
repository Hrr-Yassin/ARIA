import socket
import unittest
from unittest.mock import patch, AsyncMock

import httpx
from api.main import app


class OfflineCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
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
        await self.client.aclose()
        self.embedder.stop()
        self.admission.stop()
        self.dns.stop()
        self.network.stop()
