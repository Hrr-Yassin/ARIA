import asyncio
import fnmatch
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from api.auth import get_current_user, TokenData
from api.main import app
from memory.vector_store import VectorStore
from memory.playbook_store import PlaybookStore
from tests.support import OfflineCase
from tests.test_access import OWNER, SESSION


class RedisMemory:
    def __init__(self): self.data={}
    async def set(self,key,value,**kwargs): self.data[key]=value
    async def get(self,key): return self.data.get(key)
    async def scan(self,cursor=0,match='*',**kwargs):
        return 0,[k for k in self.data if fnmatch.fnmatch(k,match)]


class IsolationTests(OfflineCase):
    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_two_users_retrieval_before_ranking_and_after_restart(self):
        store=VectorStore(); store.add('a','private alice ssh evidence'); store.add('b','private bob ssh evidence')
        redis=RedisMemory(); await store.persist(redis)
        restored=VectorStore(); await restored.load(redis); await restored.load(redis)
        async def visible(uid): return {'alice':{'a'},'bob':{'b'}}.get(uid,set())
        with patch('memory.vector_store.owned_session_ids',side_effect=visible):
            for instance in (store,restored):
                a,b=await asyncio.gather(instance.search_similar('private ssh evidence',user_id='alice'),instance.search_similar('private ssh evidence',user_id='bob'))
                self.assertEqual({r.session_id for r in a},{'a'})
                self.assertEqual({r.session_id for r in b},{'b'})
                self.assertEqual(await instance.search_similar('private ssh evidence'),[])
        self.assertEqual(len(restored.get_all('a')),1)

    async def test_semantic_search_filters_other_user_before_scoring(self):
        class Vector:
            def __mul__(self,other): return self
            def sum(self): return 1.0
        store=VectorStore(); store.add('a','alice private');store.add('b','bob private')
        for entries in store._store.values():
            for e in entries: e['embedding']=Vector()
        with patch('memory.vector_store.owned_session_ids',AsyncMock(return_value={'a'})), \
             patch('memory.vector_store._embedder.available',return_value=True), \
             patch('memory.vector_store._embedder.encode',return_value=Vector()):
            self.assertEqual([r.session_id for r in await store.search_similar('private',user_id='alice')],['a'])

    async def test_pickle_namespace_and_invalid_vectors_are_never_loaded(self):
        redis=RedisMemory(); redis.data['embeddings:a:legacy']=b'cos\nsystem\n'
        redis.data['aria:vectors:v2:a:invalid']=json.dumps({'version':2,'session_id':'a','id':'invalid','content':'bad','metadata':{},'agent':'test','type':'test','ts':0,'embedding':[float('nan')]})
        store=VectorStore(); await store.load(redis)
        self.assertEqual(store.get_all('a'),[])
        with self.assertRaises(ValueError): store._safe_embedding([[1.0]])

    async def test_playbooks_are_private_under_concurrency_and_revocation(self):
        rows=[SimpleNamespace(id=uid,user_id=uid,session_id=sid,target_profile='ssh',created_at=None,
              phases={'service':'ssh','goal_type':'initial_access','success_count':1,'success_rate':1,'steps':[{'command':uid}]}) for uid,sid in [('alice','a'),('bob','b')]]
        db=AsyncMock()
        async def execute(query):
            params=query.compile().params
            uid=params['user_id_1']
            result=MagicMock();result.scalars.return_value.all.return_value=[r for r in rows if r.user_id==uid]
            return result
        db.execute.side_effect=execute
        factory=MagicMock();factory.return_value.__aenter__=AsyncMock(return_value=db)
        factory.return_value.__aexit__=AsyncMock(return_value=False)
        async def visible(uid):return {'alice':{'a'},'bob':{'b'}}.get(uid,set())
        store=PlaybookStore()
        with patch('memory.playbook_store.owned_session_ids',side_effect=visible),patch('memory.database_models.async_session',factory):
            a,b=await asyncio.gather(store.list_all('alice'),store.list_all('bob'))
            self.assertEqual([p.id for p in a],['alice']);self.assertEqual([p.id for p in b],['bob'])
            self.assertEqual(await store.list_all(),[])
        with patch('memory.playbook_store.owned_session_ids',AsyncMock(return_value=set())):
            self.assertEqual(await store.list_all('alice'),[])
            with self.assertRaises(PermissionError): await store.increment_success('bob',user_id='alice')

    async def test_report_download_requires_owner_and_registered_intact_file(self):
        name='pentest_report_'+'a'*32+'.md'
        with TemporaryDirectory() as directory:
            path=Path(directory)/name;path.write_bytes(b'private report')
            metadata={'session_id':'engagement','sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
            with patch('api.routers.reports.settings.REPORT_OUTPUT_DIR',directory), \
                 patch('api.routers.reports.find_report',AsyncMock(return_value=metadata)), \
                 patch('api.session_access.session_manager.get_session',AsyncMock(return_value=SESSION)):
                self.assertEqual((await self.client.get('/api/report/download/'+name)).status_code,401)
                app.dependency_overrides[get_current_user]=lambda:OWNER
                response=await self.client.get('/api/report/download/'+name)
                self.assertEqual(response.content,b'private report')
                other=TokenData(user_id='other',username='other',role='pentester',skill_level='expert')
                app.dependency_overrides[get_current_user]=lambda:other
                self.assertEqual((await self.client.get('/api/report/download/'+name)).status_code,403)
                app.dependency_overrides[get_current_user]=lambda:OWNER
                path.write_bytes(b'changed')
                self.assertEqual((await self.client.get('/api/report/download/'+name)).status_code,404)
                path.unlink();path.symlink_to(Path('config/settings.py').resolve())
                self.assertEqual((await self.client.get('/api/report/download/'+name)).status_code,404)

    async def test_cache_and_status_deny_second_user_before_reading(self):
        app.dependency_overrides[get_current_user]=lambda:OWNER
        with patch('api.session_access.session_manager.get_session',AsyncMock(return_value={**SESSION,'user_id':'other'})), \
             patch('api.routers.pentest.knowledge_cache.get_all_for_session') as read:
            for path in ('cache','status'):
                self.assertEqual((await self.client.get('/api/v8/'+path+'/engagement')).status_code,403)
            read.assert_not_called()

    async def test_concurrent_report_exports_do_not_overwrite_same_target(self):
        from agents.report_agent import ReportAgent
        from security.encryption import evidence_cipher
        with TemporaryDirectory() as directory,patch('config.settings.settings.REPORT_OUTPUT_DIR',directory), \
             patch('api.auth.current_identity',AsyncMock(return_value=OWNER)), \
             patch('api.session_access.get_accessible_session',AsyncMock(return_value=SESSION)), \
             patch('memory.session_manager.session_manager.get_findings_summary',AsyncMock(return_value={'findings':[],'counts':{},'total':0})), \
             patch('memory.session_manager.session_manager.get_chat_logs',AsyncMock(return_value=[])), \
             patch('agents.report_agent.register_report',AsyncMock()) as register:
            first,second=await asyncio.gather(*(ReportAgent().generate_report('engagement','owner','markdown') for _ in range(2)))
            self.assertNotEqual(first['filename'],second['filename'])
            self.assertEqual(register.await_count,2)
            self.assertEqual(Path(first['filepath']).stat().st_mode & 0o777,0o600)
        cache=RedisMemory();store=VectorStore();store.add('a','password="test-credential"')
        await store.persist(cache)
        self.assertNotIn('test-credential',str(cache.data))

    async def test_socket_revocation_stops_before_next_event(self):
        from api.routers.pentest import autonomous_websocket
        from fastapi import HTTPException
        ws=AsyncMock();ws.headers={};ws.query_params={};ws.receive_json.return_value={'token':'test-token'}
        async def events(sid):
            yield {'type':'first'}
            yield {'type':'second'}
        with patch('api.routers.pentest.authenticate_socket_token',AsyncMock(side_effect=[OWNER,OWNER,OWNER,HTTPException(401,'revoked')])), \
             patch('api.session_access.session_manager.get_session',AsyncMock(return_value=SESSION)), \
             patch('api.routers.pentest.autonomous_engine.stream_events',side_effect=events):
            await autonomous_websocket(ws,'engagement')
        ws.send_json.assert_awaited_once_with({'type':'first'})
        self.assertEqual(ws.close.await_args.kwargs['code'],4401)

    async def test_unconfirmed_cancellation_prevents_archiving_session(self):
        app.dependency_overrides[get_current_user]=lambda:OWNER
        with patch('api.session_access.session_manager.get_session',AsyncMock(return_value=SESSION)), \
             patch('memory.worker_jobs.worker_jobs.cancel_session',AsyncMock(return_value={'cancelled':0,'pending':1,'jobs':[]})), \
             patch('api.routers.sessions.session_manager.delete_session',AsyncMock()) as archive:
            response=await self.client.delete('/api/session/engagement')
            self.assertEqual(response.status_code,409);archive.assert_not_awaited()

    async def test_forged_worker_result_is_denied_before_analysis_or_mutation(self):
        from fastapi import HTTPException
        app.dependency_overrides[get_current_user]=lambda:OWNER
        with patch('api.session_access.session_manager.get_session',AsyncMock(return_value=SESSION)), \
             patch('api.routers.pentest.worker_jobs.verify_receipt',AsyncMock(side_effect=HTTPException(403,'mismatch'))), \
             patch('api.routers.pentest.session_manager.add_tools_run',AsyncMock()) as mutate:
            response=await self.client.post('/api/tool-results',json={'job_id':'job','session_id':'engagement','command':'nmap 192.0.2.1','stdout':'fabricated'})
            self.assertEqual(response.status_code,403);mutate.assert_not_awaited()

    async def test_trusted_operator_can_migrate_legacy_reports_without_inferred_owner(self):
        from api.import_report import import_report
        from tests import test_authorization_store as helpers
        db,factory=helpers.StoreTests.database(self,[SimpleNamespace(user_id='owner')])
        with TemporaryDirectory() as directory:
            source=Path(directory)/'old.md';source.write_text('private old report')
            destination=Path(directory)/'reports'
            with patch('api.import_report.async_session',factory),patch('api.import_report.settings.REPORT_OUTPUT_DIR',str(destination)), \
                 patch('api.import_report.register_report',AsyncMock()) as register:
                filename=await import_report(source,'engagement')
            self.assertEqual(register.await_args.args[1],'owner')
            self.assertEqual((destination/filename).read_text(),source.read_text())
            self.assertEqual((destination/filename).stat().st_mode & 0o777,0o600)

    async def test_legacy_report_migration_cannot_delete_a_colliding_export(self):
        from api.import_report import import_report
        from tests import test_authorization_store as helpers
        db,factory=helpers.StoreTests.database(self,[SimpleNamespace(user_id='owner')])
        with TemporaryDirectory() as directory:
            source=Path(directory)/'old.md';source.write_text('old')
            destination=Path(directory)/('pentest_report_'+'c'*32+'.md');destination.write_text('existing')
            with patch('api.import_report.async_session',factory),patch('api.import_report.settings.REPORT_OUTPUT_DIR',directory), \
                 patch('api.import_report.uuid.uuid4',return_value=SimpleNamespace(hex='c'*32)):
                with self.assertRaises(FileExistsError):await import_report(source,'engagement')
            self.assertEqual(destination.read_text(),'existing')
