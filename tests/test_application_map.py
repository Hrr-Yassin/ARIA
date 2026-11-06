"""Two-account saved-evidence mapping; all network access is blocked."""
import base64
import copy
import json
from contextlib import ExitStack
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException
from api.auth import get_current_user
from api.main import app
from memory.application_map import (
    ApplicationMap, IdentityInput, RequestInput, CaptureInput, ObjectInput, WorkflowInput,
    PermissionInput, DataPolicy, Change, ComparisonInput, compare_responses,
    seal, unseal, now, capture_metadata,
)
from memory.database_models import ChatLog
from security.encryption import evidence_cipher
from tests.support import OfflineCase
from tests.test_access import OWNER


def response(body, status=200):
    return f'HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n'.encode() + body


def source(secret='account-a-secret', body=b'{"owner":"a"}'):
    raw = f'GET /objects?filter=mine HTTP/1.1\r\nHost: 192.0.2.1\r\nAuthorization: Bearer {secret}\r\n\r\n'.encode()
    return {'url': 'http://192.0.2.1/objects?filter=mine',
            'request_b64': base64.b64encode(raw).decode(),
            'response_b64': base64.b64encode(response(body)).decode()}


class ApplicationMapping(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.rows = {}
        self.pending = {}
        self.session = SimpleNamespace(id='engagement', scope={'targets': ['192.0.2.1']})
        async def get(model, key):
            return copy.deepcopy(self.rows.get(key))
        async def commit():
            self.rows.update(copy.deepcopy(self.pending))
            self.pending.clear()
        self.db = SimpleNamespace(get=AsyncMock(side_effect=get), add=lambda row: self.pending.update({row.id: row}),
                                  commit=AsyncMock(side_effect=commit))
        empty = MagicMock(); empty.scalars.return_value.all.return_value = []
        self.db.execute = AsyncMock(return_value=empty)
        self.cm = AsyncMock(); self.cm.__aenter__.return_value = self.db
        self.stack = ExitStack()
        self.stack.enter_context(patch('memory.application_map.async_session', return_value=self.cm))
        async def owned(db, sid, owner):
            if sid != 'engagement' or owner != 'owner':
                raise HTTPException(404, 'Not found')
            return self.session
        self.stack.enter_context(patch('memory.application_map.owned_engagement', side_effect=owned))
        # Track loaded ORM objects as a real SQLAlchemy session does.
        async def tracked_get(model, key):
            row = await get(model, key)
            if row is not None:
                self.pending[key] = row
            return row
        self.db.get.side_effect = tracked_get
        self.stack.enter_context(patch('memory.worker_jobs.worker_jobs.cancel_session', AsyncMock(return_value={'pending': 0})))
        self.store = ApplicationMap()
        self.revision = 0

    async def asyncTearDown(self):
        self.stack.close()
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def change(self, collection, cls, **values):
        result = await self.store.change('engagement', 'owner', collection, cls(expected_revision=self.revision, **values))
        self.revision = result['revision']
        return result['id']

    async def identity(self, secret='account-a-secret'):
        return await self.change('identities', IdentityInput, label='Owned account', role='member',
                                 researcher_controlled=True, credentials={'authorization': 'Bearer ' + secret})

    async def capture(self, identity, eid='capture-a', secret='account-a-secret', body=b'{"owner":"a"}'):
        original = source(secret, body)
        self.rows[eid] = ChatLog(id=eid, session_id='engagement', msg_type='burp_evidence',
            data={'protected_original': evidence_cipher().encrypt(json.dumps(original).encode()).decode()})
        return await self.change('captures', CaptureInput, identity_id=identity, evidence_id=eid)

    async def test_two_accounts_objects_workflow_permissions_and_restart(self):
        first = await self.identity(); second = await self.identity('account-b-secret')
        a = await self.capture(first)
        b = await self.capture(second, 'capture-b', 'account-b-secret', b'{"owner":"b"}')
        obj = await self.change('objects', ObjectInput, label='Owned document', owner_identity_id=first, evidence_ids=['capture-a'])
        await self.change('workflows', WorkflowInput, label='Share document', kind='sharing',
                          evidence_ids=['capture-a', 'capture-b'], before='Private', after='Shared with second account')
        original = await self.change('permissions', PermissionInput, object_id=obj, identity_id=second,
                          operation='read', expected='deny', rationale='Private document', evidence_ids=['capture-a'])
        await self.change('permissions', PermissionInput, object_id=obj, identity_id=second,
                          operation='read', expected='allow', rationale='Owner shared it', evidence_ids=['capture-b'])
        restored = await ApplicationMap().view('engagement', 'owner')
        self.assertEqual(len(restored['identities']), 2)
        self.assertEqual(list(restored['permissions'].values())[-1]['supersedes'], original)
        self.assertEqual(restored['captures'][a]['parameters']['query'], ['filter'])
        self.assertEqual(restored['captures'][b]['identity_id'], second)
        self.assertNotIn('account-a-secret', json.dumps(restored))
        self.assertNotIn('account-b-secret', json.dumps(restored))
        comparison = await self.store.compare('engagement', 'owner', ComparisonInput(left=a, right=b))
        self.assertFalse(comparison['equivalent'])
        self.assertEqual(comparison['verification_status'], 'observation')

    async def test_foreign_owner_references_and_wrong_capture_identity_denied(self):
        identity = await self.identity()
        with self.assertRaises(HTTPException): await self.store.view('engagement', 'other')
        with self.assertRaises(HTTPException): await self.store.view('other', 'owner')
        with self.assertRaises(HTTPException): await self.capture(identity, secret='wrong-account-secret')
        self.rows['foreign'] = ChatLog(id='foreign', session_id='other', msg_type='burp_evidence', data={})
        with self.assertRaises(HTTPException):
            await self.change('captures', CaptureInput, identity_id=identity, evidence_id='foreign')
        with self.assertRaises(HTTPException):
            await self.change('objects', ObjectInput, label='Foreign', owner_identity_id='other', evidence_ids=['foreign'])

    async def test_encryption_stale_revision_and_storage_failure(self):
        await self.identity()
        self.assertNotIn('account-a-secret', repr([row.metadata_ for row in self.rows.values()]))
        with self.assertRaises(HTTPException):
            await self.store.change('engagement', 'owner', 'policy', DataPolicy(expected_revision=0, retention_days=1))
        self.db.commit.side_effect = RuntimeError('storage unavailable')
        with self.assertRaises(RuntimeError): await self.identity('failed-secret')
        self.db.commit.side_effect = None
        state = unseal(next(iter(self.rows.values())).metadata_['sealed'])
        self.assertEqual(len(state['identities']), 1)

    async def test_revoke_erases_map_credentials_and_capture_originals(self):
        identity = await self.identity(); capture = await self.capture(identity)
        await self.store.revoke('engagement', 'owner', identity, Change(expected_revision=self.revision))
        state = unseal(next(row for row in self.rows.values() if hasattr(row, 'metadata_')).metadata_['sealed'])
        self.assertEqual(state['identities'][identity]['credentials'], {})
        self.assertNotIn('original', state['captures'][capture])
        with self.assertRaises(HTTPException) as error:
            await self.store.compare('engagement', 'owner', ComparisonInput(left=capture, right=capture))
        self.assertEqual(error.exception.status_code, 410)

    async def test_expiry_and_sharing_default_deny(self):
        identity = await self.identity(); capture = await self.capture(identity)
        with self.assertRaises(HTTPException): await self.store.view('engagement', 'owner', provider=True)
        await self.change('policy', DataPolicy, retention_days=1, provider_sharing='redacted_metadata')
        self.assertNotIn('original', str(await self.store.view('engagement', 'owner', provider=True)))
        with patch('memory.application_map.now', return_value=now() + timedelta(days=2)):
            view = await self.store.view('engagement', 'owner')
            self.assertFalse(view['identities'][identity]['active'])
            self.assertTrue(view['captures'][capture]['expired'])
        row = next(row for row in self.rows.values() if hasattr(row, 'metadata_'))
        self.assertEqual(unseal(row.metadata_['sealed'])['identities'][identity]['credentials'], {})

    async def test_capture_reattribution_and_unselected_evidence_denied(self):
        first = await self.identity(); await self.capture(first)
        with self.assertRaises(HTTPException): await self.capture(first)
        with self.assertRaises(HTTPException):
            await self.change('workflows', WorkflowInput, label='Unproven', kind='other',
                              evidence_ids=['not-selected'], before='A', after='B')

    async def test_validation_never_reflects_secret_input(self):
        async def current_user():
            return OWNER
        app.dependency_overrides[get_current_user] = current_user
        result = await self.client.post('/api/application-map/engagement/identities', json={
            'expected_revision': 0, 'label': 'A', 'role': 'member', 'researcher_controlled': True,
            'credentials': {'authorization': 'private-invalid\r\nsecret'}})
        self.assertEqual(result.status_code, 422)
        self.assertNotIn('private-invalid', result.text)

    async def test_semantic_normalization_is_explicit_and_preserves_status(self):
        a = response(b'{"a":1,"nonce":"a"}')
        b = response(b'{ "nonce":"b", "a":1 }')
        self.assertFalse(compare_responses(a,b,[])['equivalent'])
        result = compare_responses(a,b,['nonce'])
        self.assertTrue(result['equivalent']); self.assertFalse(result['identical'])
        self.assertFalse(compare_responses(a,response(b'{"a":1}',403),['nonce'])['equivalent'])
        self.assertFalse(compare_responses(response(b'[1,2]'),response(b'[2,1]'),[])['equivalent'])

    async def test_capture_scope_and_host_are_rechecked(self):
        with self.assertRaises(ValueError): capture_metadata(source(), {'targets': ['198.51.100.1']})
        data = source(); data['url'] = 'http://192.0.2.1/elsewhere'
        with self.assertRaises(HTTPException): capture_metadata(data, {'targets': ['192.0.2.1']})

    async def test_provider_consent_and_registered_credential_denial(self):
        from llm.engagement_budget import model_accounting, engagement_context
        await self.identity()
        self.session.metadata_['model_limits']={'tariffs':[{'provider':'groq','model':'fixture','microusd_per_million':100}]}
        token=engagement_context.set({'session_id':'engagement','owner':'owner'})
        try:
            with patch('llm.engagement_budget.async_session',return_value=self.cm), patch('llm.engagement_budget.owned_engagement',AsyncMock(return_value=self.session)):
                with self.assertRaises(HTTPException) as denied:
                    await model_accounting.reserve('owner','groq','fixture','Safe metadata','')
                self.assertEqual(denied.exception.status_code,403)
                await self.change('policy',DataPolicy,retention_days=7,provider_sharing='redacted_metadata')
                with self.assertRaises(HTTPException) as secret:
                    await model_accounting.reserve('owner','groq','fixture','Reflected account-a-secret','')
                self.assertIn('credential',secret.exception.detail)
                attempt=await model_accounting.reserve('owner','groq','fixture','Safe redacted metadata','')
                self.assertEqual(attempt['state'],'reserved')
        finally:
            engagement_context.reset(token)

    async def test_new_request_needs_approval_and_is_not_observation_evidence(self):
        from config.settings import settings
        from cryptography.fernet import Fernet
        from worker.http_profile import decode
        identity=await self.identity()
        self.session.scope['web_authenticated_replay']=True
        draft=await self.change('requests',RequestInput,identity_id=identity,method='GET',url='http://192.0.2.1/objects')
        view=await self.store.view('engagement','owner')
        self.assertEqual(view['requests'][draft]['status'],'planned_request')
        self.assertEqual(view['captures'],{})
        self.assertNotIn('original',view['requests'][draft])
        with self.assertRaises(HTTPException):
            await self.change('objects',ObjectInput,label='Unobserved',owner_identity_id=identity,evidence_ids=[draft])
        key=Fernet.generate_key().decode()
        with patch.object(settings,'HTTP_REPLAY_KEY',key):
            command,token=await self.store.replay_material('engagement','owner',identity,draft)
            self.assertEqual(decode(token,command,key)['method'],'GET')
            self.assertNotIn('account-a-secret',command)

    async def test_existing_private_map_adopts_default_deny_marker(self):
        await self.identity()
        self.session.metadata_={}
        await self.store.view('engagement','owner')
        self.assertTrue(self.session.metadata_['application_mapping'])

    async def test_ambiguous_json_never_silently_normalizes_to_last_value(self):
        result=compare_responses(response(b'{"owner":"a","owner":"b"}'),response(b'{"owner":"b"}'),[])
        self.assertFalse(result['equivalent'])
        self.assertEqual(result['left']['mode'],'bytes')
        result=compare_responses(response(b'{"number":NaN}'),response(b'{ "number":NaN }'),[])
        self.assertFalse(result['equivalent'])
