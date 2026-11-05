"""Every declared API route gets a no-identity admission check; no dispatch is allowed.
This is authorization coverage, not a claim of full functional route coverage.
"""
import re
from unittest.mock import AsyncMock,patch
from api.main import app
from tests.support import OfflineCase


class RouteInventory(OfflineCase):
    async def test_every_protected_http_route_denies_missing_identity(self):
        with patch('memory.execution_authorization.execution_authorization.execute',AsyncMock(side_effect=AssertionError('Unauthorized dispatch'))), patch('memory.web_actions.web_actions.execute',AsyncMock(side_effect=AssertionError('Unauthorized replay'))):
            for route in app.routes:
                path=getattr(route,'path','')
                if not path.startswith('/api/') or path in {'/api/login','/api/health','/api/ready'}: continue
                for method in getattr(route,'methods',[]) or []:
                    if method in {'HEAD','OPTIONS'}: continue
                    url=re.sub(r'\{[^}]+\}','00000000-0000-4000-8000-000000000001',path)
                    with self.subTest(route=path,method=method):
                        response=await self.client.request(method,url,json={} if method in {'POST','PATCH','PUT'} else None)
                        self.assertIn(response.status_code,{401,403,503})
