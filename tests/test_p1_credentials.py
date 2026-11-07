import hashlib
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from cryptography.fernet import Fernet
from fastapi import HTTPException
from api.auth import authenticate_socket_token, authenticate_user, create_token
from llm.pool_manager import LLMPoolManager
from security.credentials import hash_password, verify_password, revoke_credentials
from security.redaction import redact
from tests.support import OfflineCase
from tests import test_authorization_store as store_helpers


class CredentialTests(OfflineCase):
    async def test_password_hashes_upgrade_legacy_with_constant_time_verification(self):
        password='test-only-strong-passphrase'
        hashed=await asyncio.to_thread(hash_password,password)
        self.assertTrue(hashed.startswith('pbkdf2_sha256$'))
        self.assertTrue(await asyncio.to_thread(verify_password,password,hashed));self.assertFalse(await asyncio.to_thread(verify_password,'wrong',hashed))
        legacy='salt$'+hashlib.sha256(('salt:'+password).encode()).hexdigest()
        user=SimpleNamespace(password_hash=legacy,is_active=True,last_login=None)
        db,factory=store_helpers.StoreTests.database(self,[user])
        with patch('api.auth.async_session',factory):
            self.assertIs(await authenticate_user('alice',password),user)
        self.assertTrue(user.password_hash.startswith('pbkdf2_sha256$'));db.commit.assert_awaited_once()

    async def test_revocation_role_change_and_restart_use_database_state(self):
        user=SimpleNamespace(id='alice',username='alice',is_active=True,preferences={},role=SimpleNamespace(value='pentester'),skill_level=SimpleNamespace(value='expert'))
        token=create_token('alice','alice','admin','expert')
        async def identity():
            db,factory=store_helpers.StoreTests.database(self,[user])
            with patch('api.auth.async_session',factory):return await authenticate_socket_token(token)
        self.assertEqual((await identity()).role,'pentester')
        revoke_credentials(user)
        with self.assertRaises(HTTPException):await identity()
        user.is_active=False
        token=create_token('alice','alice','admin','expert',auth_revision=1)
        with self.assertRaises(HTTPException):await identity()
        user.is_active=True
        self.assertEqual((await identity()).auth_revision,1)

    async def test_encryption_rotation_is_restart_safe(self):
        old=Fernet.generate_key().decode();new=Fernet.generate_key().decode()
        with patch('llm.pool_manager.settings.FERNET_KEY',old):
            cipher=LLMPoolManager().encrypt_key('test-only-provider-secret')
        with patch('llm.pool_manager.settings.FERNET_KEY',new),patch('llm.pool_manager.settings.FERNET_PREVIOUS_KEYS',[old]):
            manager=LLMPoolManager();rotated=manager.encrypt_key(manager.decrypt_key(cipher))
        with patch('llm.pool_manager.settings.FERNET_KEY',new):
            self.assertEqual(LLMPoolManager().decrypt_key(rotated),'test-only-provider-secret')
            with self.assertRaises(ValueError):LLMPoolManager().decrypt_key(cipher)

    async def test_structured_and_string_credential_redaction(self):
        value={'password':'never-send','nested':{'Cookie':'session=never-send'},'evidence':'Authorization: Bearer never-send\npassword="never-send"\nhttps://x.test/?key=never-send'}
        sanitized=redact(value)
        self.assertNotIn('never-send',str(sanitized))
        self.assertNotIn('opaque-known',redact('unlabelled opaque-known',known_secrets=['opaque-known']))

    async def test_model_boundary_redacts_and_key_disable_takes_effect(self):
        manager=LLMPoolManager()
        row=SimpleNamespace(id='key',provider='groq',encrypted_key=manager.encrypt_key('test-only-provider-secret'),is_active=True,
          requests_used=0,requests_limit=10,cooldown_until=None,last_error='',label='test')
        async def refresh(uid):manager.load_user_keys(uid,[row])
        client=SimpleNamespace(query=AsyncMock(return_value={'success':True,'content':'{}'}))
        with patch.object(manager,'refresh_user_keys',side_effect=refresh),patch.object(manager,'_reserve_key',AsyncMock(return_value=True)), \
             patch('memory.access_scope.owned_session_ids',AsyncMock(return_value=set())), \
             patch('llm.engagement_budget.model_accounting.reserve', AsyncMock(return_value={'id':'test-attempt'})), patch('llm.engagement_budget.model_accounting.settle', AsyncMock()), patch.dict('llm.pool_manager.PROVIDER_CLIENTS',{'groq':MagicMock(return_value=client)}):
            result=await manager.query_for_task('alice','output_analysis','password="never-send"; test-only-provider-secret')
            self.assertTrue(result['success'])
            prompt=client.query.await_args.args[0]
            self.assertNotIn('never-send',prompt);self.assertNotIn('test-only-provider-secret',prompt)
            self.assertIn('untrusted_engagement_data',prompt)
            self.assertEqual(manager.get_pool('alice').keys[0].decrypted_key,'')
            row.is_active=False;client.query.reset_mock()
            self.assertFalse((await manager.query_for_task('alice','output_analysis','test'))['success'])
            client.query.assert_not_awaited()

    async def test_http_revision_and_active_user_are_checked_without_dependency_override(self):
        user=SimpleNamespace(id='alice',username='alice',is_active=True,preferences={},role=SimpleNamespace(value='pentester'),skill_level=SimpleNamespace(value='expert'))
        token=create_token('alice','alice','admin','expert')
        db,factory=store_helpers.StoreTests.database(self,[])
        response=MagicMock();response.scalar_one_or_none.return_value=user;db.execute.side_effect=None;db.execute.return_value=response
        session={'session_id':'a','user_id':'alice','target':'192.0.2.1','scope':{'targets':['192.0.2.1']}}
        with patch('api.auth.async_session',factory),patch('api.session_access.session_manager.get_session',AsyncMock(return_value=session)):
            url='/api/pentest/a/autonomous/status'
            self.assertEqual((await self.client.get(url,headers={'Authorization':'Bearer '+token})).status_code,200)
            self.assertEqual((await self.client.get(url+'?token='+token)).status_code,401)
            revoke_credentials(user)
            self.assertEqual((await self.client.get(url,headers={'Authorization':'Bearer '+token})).status_code,401)
            user.is_active=False
            current=create_token('alice','alice','admin','expert',auth_revision=1)
            self.assertEqual((await self.client.get(url,headers={'Authorization':'Bearer '+current})).status_code,401)

    async def test_provider_quota_reservation_prevents_concurrent_overuse(self):
        manager=LLMPoolManager()
        row=SimpleNamespace(id='key',provider='groq',encrypted_key=manager.encrypt_key('test-provider-value'),is_active=True,requests_used=0,requests_limit=1,cooldown_until=None,last_error='',label='test')
        async def refresh(uid):manager.load_user_keys(uid,[row])
        remaining=1
        async def reserve(uid,key):
            nonlocal remaining
            if remaining==0:return False
            remaining-=1;return True
        client=SimpleNamespace(query=AsyncMock(return_value={'success':True,'content':'{}'}))
        with patch.object(manager,'refresh_user_keys',side_effect=refresh),patch.object(manager,'_reserve_key',side_effect=reserve),patch('memory.access_scope.owned_session_ids',AsyncMock(return_value=set())),patch('llm.engagement_budget.model_accounting.reserve', AsyncMock(return_value={'id':'test-attempt'})), patch('llm.engagement_budget.model_accounting.settle', AsyncMock()), patch.dict('llm.pool_manager.PROVIDER_CLIENTS',{'groq':MagicMock(return_value=client)}):
            results=await asyncio.gather(*(manager.query_for_task('alice','output_analysis','test') for _ in range(2)))
        self.assertEqual(sum(r['success'] for r in results),1);client.query.assert_awaited_once()

    async def test_gemini_credentials_are_not_in_urls(self):
        import httpx
        from llm.gemini_client import GeminiClient
        real_client=httpx.AsyncClient;seen=[]
        def handler(request):
            seen.append(request)
            return httpx.Response(200,json={'candidates':[{'content':{'parts':[{'text':'{}'}]}}]})
        def factory(**kwargs):return real_client(transport=httpx.MockTransport(handler),**kwargs)
        with patch('llm.gemini_client.httpx.AsyncClient',side_effect=factory):
            self.assertTrue((await GeminiClient(api_key='test-provider-value').query('test'))['success'])
        self.assertNotIn('test-provider-value',str(seen[0].url))
        self.assertEqual(seen[0].headers['x-goog-api-key'],'test-provider-value')

    async def test_logout_persists_revocation_before_worker_cleanup(self):
        from api.auth import get_current_user, TokenData
        from api.main import app
        user=SimpleNamespace(id='alice',preferences={})
        db,factory=store_helpers.StoreTests.database(self,[user])
        identity=TokenData(user_id='alice',username='alice',role='pentester',skill_level='expert')
        app.dependency_overrides[get_current_user]=lambda:identity
        async def cleanup(uid):
            self.assertEqual(uid,'alice');self.assertEqual(user.preferences['auth_revision'],1)
            db.commit.assert_awaited_once()
            return {'cancelled':0,'pending':1}
        try:
            with patch('memory.database_models.async_session',factory), \
                 patch('agents.autonomous_engine.autonomous_engine.revoke_principal',AsyncMock()), \
                 patch('memory.worker_jobs.worker_jobs.revoke_principal',side_effect=cleanup):
                response=await self.client.post('/api/logout')
                self.assertEqual(response.status_code,200)
                self.assertEqual(response.json()['cancellation']['pending'],1)
        finally:app.dependency_overrides.clear()

    async def test_login_admission_is_atomic_and_storage_failure_denies(self):
        from security.login_throttle import LoginThrottle
        limiter=LoginThrottle(account_limit=2,peer_limit=5)
        results=await asyncio.gather(*(limiter.reserve('alice','test-peer') for _ in range(3)),return_exceptions=True)
        self.assertEqual(sum(isinstance(r,HTTPException) for r in results),1)
        redis=SimpleNamespace(eval=AsyncMock(side_effect=RuntimeError('unavailable')))
        with self.assertRaises(HTTPException) as error:await LoginThrottle().reserve('bob','peer',redis)
        self.assertEqual(error.exception.status_code,503)
