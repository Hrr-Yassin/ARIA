import base64
from unittest.mock import AsyncMock, patch
from api.auth import get_current_user
from api.main import app
from config.settings import settings
from memory.burp_community import inspect_pair, check_command
from tests.support import OfflineCase
from tests.test_access import OWNER


def pair(path='/', auth=''):
    request=f'GET {path} HTTP/1.1\r\nHost: 192.0.2.1\r\n{auth}\r\n'
    return base64.b64encode(request.encode()).decode(), base64.b64encode(b'HTTP/1.1 200 OK\r\n\r\nfixture').decode()


class BurpTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_community_capabilities_and_disabled_gate(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        response = await self.client.get('/api/burp/capabilities')
        self.assertFalse(response.json()['scanner'])
        self.assertEqual(response.json()['authenticated_replay'],'requires_engagement_configuration')
        self.assertEqual(response.json()['mutations'],'requires_engagement_configuration')
        self.assertEqual((await self.client.post('/api/burp/engagement/import',json={'url':'http://192.0.2.1','request_b64':'','response_b64':''})).status_code,503)

    async def test_scope_host_port_and_request_target_rejection(self):
        raw,response=pair()
        scope={'targets':['192.0.2.1'],'ports':[80]}
        for url in ['http://198.51.100.1/','http://192.0.2.1:22/','https://192.0.2.1/','http://192.0.2.1/other']:
            with self.subTest(url=url), self.assertRaises(ValueError): inspect_pair(url,raw,response,scope)

    async def test_credentials_redacted_and_authentication_context_preserved(self):
        raw,response=pair(auth='Authorization: Bearer fixture-secret-value\r\nCookie: session=fixture-cookie\r\n')
        data=inspect_pair('http://192.0.2.1/',raw,response,{'targets':['192.0.2.1']})
        self.assertTrue(data['authenticated'])
        self.assertNotIn('fixture-secret-value',str(data['summary']))
        self.assertNotIn('fixture-cookie',str(data['summary']))
        self.assertNotEqual(data['summary']['authentication_context'],'anonymous')
        self.assertIn('request_b64',data['original'])

    async def test_digest_deduplicates_same_pair_and_retains_context(self):
        raw,response=pair()
        first=inspect_pair('http://192.0.2.1/',raw,response,{'targets':['192.0.2.1']})
        second=inspect_pair('http://192.0.2.1/',raw,response,{'targets':['192.0.2.1']})
        self.assertEqual(first['digest'],second['digest'])

    async def test_approved_check_never_dispatches_rejected_action(self):
        from types import SimpleNamespace
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch.object(settings,'BURP_COMMUNITY_ENABLED',True), patch('api.routers.burp.get_accessible_session',AsyncMock(return_value={'scope':{'targets':['192.0.2.1']}})), patch('api.routers.burp.community.get_evidence',AsyncMock(return_value={})), patch('api.routers.burp.execution_authorization._load',AsyncMock(return_value=(SimpleNamespace(turn_id='evidence',status='rejected'),{}))), patch('api.routers.burp.execution_authorization.execute',AsyncMock()) as execute:
            response=await self.client.post('/api/burp/engagement/evidence/check',json={'action_id':'action'})
        self.assertEqual(response.status_code,403)
        execute.assert_not_awaited()

    async def test_import_ownership_denial_prevents_storage(self):
        from fastapi import HTTPException
        app.dependency_overrides[get_current_user] = lambda: OWNER
        raw,response=pair()
        with patch.object(settings,'BURP_COMMUNITY_ENABLED',True), patch('api.routers.burp.get_accessible_session',AsyncMock(side_effect=HTTPException(403,'Denied'))), patch('api.routers.burp.community.import_pair',AsyncMock()) as save:
            result=await self.client.post('/api/burp/other/import',json={'url':'http://192.0.2.1/','request_b64':raw,'response_b64':response})
        self.assertEqual(result.status_code,403)
        save.assert_not_awaited()

    async def test_budget_and_evidence_binding_prevent_dispatch(self):
        from types import SimpleNamespace
        app.dependency_overrides[get_current_user] = lambda: OWNER
        for turn_id,jobs in [('wrong-evidence',[]),('evidence',[{}]*20)]:
            with patch.object(settings,'BURP_COMMUNITY_ENABLED',True), patch('api.routers.burp.get_accessible_session',AsyncMock(return_value={'scope':{'targets':['192.0.2.1']}})), patch('api.routers.burp.community.get_evidence',AsyncMock(return_value={})), patch('api.routers.burp.execution_authorization._load',AsyncMock(return_value=(SimpleNamespace(turn_id=turn_id,status='approved'),{}))), patch('api.routers.burp.worker_jobs.list_status',AsyncMock(return_value=jobs)), patch('api.routers.burp.execution_authorization.execute',AsyncMock()) as execute:
                response=await self.client.post('/api/burp/engagement/evidence/check',json={'action_id':'action'})
            self.assertIn(response.status_code,[403,409])
            execute.assert_not_awaited()

    async def test_authenticated_capture_never_silently_becomes_anonymous_replay(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as error:
            check_command({'authenticated':True},{'targets':['192.0.2.1']})
        self.assertEqual(error.exception.status_code,409)

    async def test_reflected_json_credentials_are_redacted(self):
        body=b'{"password":"json-fixture-secret"}'
        request=b'POST / HTTP/1.1\r\nHost: 192.0.2.1\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        response=b'HTTP/1.1 200 OK\r\n\r\njson-fixture-secret'
        result=inspect_pair('http://192.0.2.1/',base64.b64encode(request).decode(),base64.b64encode(response).decode(),{'targets':['192.0.2.1']})
        self.assertNotIn('json-fixture-secret',str(result['summary']))

    async def test_desktop_capture_isolation_even_for_same_target_scope(self):
        from api.auth import TokenData
        app.dependency_overrides[get_current_user]=lambda:TokenData(user_id='other',username='other',role='pentester',skill_level='expert')
        with patch.object(settings,'BURP_COMMUNITY_ENABLED',True),patch('memory.web_actions.web_actions.connector',AsyncMock()) as connector:
            response=await self.client.get('/api/burp/other-session/proxy-history')
        self.assertEqual(response.status_code,403)
        connector.assert_not_awaited()
