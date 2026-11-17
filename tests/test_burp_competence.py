"""Synthetic HTTP evidence fidelity and disconnected-connector regressions."""
import base64
import json
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import HTTPException
from api.auth import get_current_user
from api.main import app
from api.routers.burp import CaptureSelection, Pair, import_history_selection, import_selected, repeater
from config.settings import settings
from evaluation.competence import FIXTURES, load_cases, measure
from memory.burp_community import inspect_pair
from security.http_messages import response_metadata
from tests.support import OfflineCase
from tests.test_access import OWNER


def encoded(value: bytes) -> str:
    return base64.b64encode(value).decode()


class BurpCompetenceTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_frozen_integrity_and_response_redaction(self):
        result = measure(load_cases(FIXTURES / 'burp-development-v1.json'))
        self.assertEqual(result['components']['burp_evidence'], {'passed':10,'assessed':10})

    async def test_status_duplicate_headers_and_missing_response_are_distinct(self):
        request = b'GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n'
        response = b'HTTP/1.1 200 OK\r\nX-Trace: first\r\nX-Trace: second\r\n\r\npublic'
        pair = inspect_pair('http://192.0.2.1/',encoded(request),encoded(response),{'targets':['192.0.2.1']})
        self.assertEqual(pair['summary']['response_status'],200)
        self.assertEqual([r['value'] for r in pair['summary']['response_headers'] if r['name']=='x-trace'],['first','second'])
        self.assertEqual(base64.b64decode(pair['original']['response_b64']),response)
        pair = inspect_pair('http://192.0.2.1/',encoded(request),'',{'targets':['192.0.2.1']})
        self.assertIsNone(pair['summary']['response_status'])
        self.assertEqual(pair['summary']['response_framing'],'no_response_observed')

    async def test_import_redacts_known_credentials_from_public_url(self):
        credential = 'synthetic-credential-14'
        url = f'http://192.0.2.1/resource/{credential}?view=summary'
        request = (
            f'GET /resource/{credential}?view=summary HTTP/1.1\r\n'
            f'Host: 192.0.2.1\r\nAuthorization: Bearer {credential}\r\n\r\n'
        ).encode()
        body = Pair(url=url, request_b64=encoded(request), response_b64='')
        session = {'scope': {'targets': ['192.0.2.1']}}
        with patch('api.routers.burp.get_accessible_session', AsyncMock(return_value=session)), \
             patch('api.routers.burp.community.import_pair', AsyncMock()) as store:
            await import_selected('session', body, OWNER)

        _, pair = store.await_args.args
        self.assertEqual(pair['original']['url'], url)
        self.assertEqual(pair['original']['request_b64'], body.request_b64)
        self.assertEqual(pair['summary']['endpoint'], '/resource/[REDACTED]')
        self.assertEqual(pair['summary']['url'], 'http://192.0.2.1/resource/[REDACTED]')
        self.assertNotIn(credential, json.dumps(pair['summary']))

    async def test_head_and_chunked_framing_without_unsafe_decoding(self):
        self.assertEqual(response_metadata(b'HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n','HEAD')['response_body_bytes'],0)
        good=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n'
        self.assertEqual(response_metadata(good,'GET')['response_body_bytes'],4)
        for bad in (good[:-1],good.replace(b'4\r\n',b'9\r\n'),good.replace(b'Transfer-Encoding: chunked',b'Transfer-Encoding: chunked\r\nContent-Length: 14')):
            with self.assertRaises(ValueError): response_metadata(bad,'GET')

    async def test_selection_mismatch_or_invalid_pair_saves_nothing(self):
        first, second = 'a'*64, 'b'*64
        valid={'capture_id':first,'url':'http://192.0.2.1/','request_b64':encoded(b'GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n'),'response_b64':''}
        for captures in ([], [valid], [valid,{**valid,'capture_id':second,'response_b64':encoded(b'bad response')}],
                         [valid,{**valid,'capture_id':first}]):
            with patch('api.routers.burp.get_accessible_session', AsyncMock(return_value={'scope':{'targets':['192.0.2.1']}})), \
                 patch('memory.web_actions.web_actions.connector', AsyncMock(return_value={'captures':captures})), \
                 patch('api.routers.burp.community.import_pair', AsyncMock()) as store:
                with self.assertRaises(HTTPException) as error:
                    await import_history_selection('session',CaptureSelection(capture_ids=[first,second]),OWNER)
                self.assertEqual(error.exception.status_code,422)
                store.assert_not_awaited()

    async def test_staging_requires_capability_and_passive_receipt_then_recovers(self):
        source={'url':'http://192.0.2.1/','request_b64':encoded(b'GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n'),'response_b64':''}
        for metadata, receipt, expected in (({'edition':'COMMUNITY'},{'status':'staged','network_request_sent':False},409),
            ({'edition':'COMMUNITY','repeater_staging':True},{},503),
            ({'edition':'COMMUNITY','repeater_staging':True},{'status':'staged','network_request_sent':False},200)):
            requests=[]
            async def responder(request):
                requests.append(request.url.path)
                return httpx.Response(200,json=metadata if request.url.path.endswith('capabilities') else receipt)
            real_client = httpx.AsyncClient
            def factory(**kwargs):
                return real_client(transport=httpx.MockTransport(responder),**kwargs)
            with patch('api.routers.burp.get_accessible_session', AsyncMock(return_value={'scope':{'targets':['192.0.2.1']}})), \
                 patch('api.routers.burp.community.get_evidence',AsyncMock(return_value={})), \
                 patch('api.routers.burp.community.original',return_value=source), \
                 patch.object(settings,'BURP_CONNECTOR_TOKEN','x'*32), \
                 patch('api.routers.burp.httpx.AsyncClient',side_effect=factory):
                if expected==200:
                    result=await repeater('session','evidence',OWNER)
                    self.assertFalse(result['network_request_sent'])
                else:
                    with self.assertRaises(HTTPException) as error: await repeater('session','evidence',OWNER)
                    self.assertEqual(error.exception.status_code,expected)
        self.assertEqual(requests,['/capabilities','/repeater'])
