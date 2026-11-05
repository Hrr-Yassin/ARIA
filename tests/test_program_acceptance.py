"""Phase 1 acceptance: denied scope escapes, stale permissions and shared budgets."""
import asyncio
import copy
import socket
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from memory.program_policy import ProgramPolicyStore, validate_review, rank_candidate
from orchestrator.execution_policy import validate_command, PolicyError
from memory.worker_jobs import SQLJobStore, WorkerJobs
from worker.policy import prepare
from worker.service import WorkerService
from security.program_fetch import fetch_policy, public_addresses, PolicyText
from tests.program_fixtures import policy_fixture
from tests.support import OfflineCase
from tests.test_program_policy import result
from tests.test_worker_server import MemoryStore, FakeRuntime


class PolicyAcceptance(OfflineCase):
    async def test_exact_wildcard_path_port_and_third_party_fixture_set(self):
        _, _, scope = policy_fixture()
        valid = ['curl -I https://app.example.test/api', 'curl https://app.example.test/api/items?limit=1']
        for command in valid:
            self.assertEqual(validate_command(command, scope).tool, 'curl')
        invalid = ['curl https://app.example.test/', 'curl https://app.example.test/apix',
            'curl https://sub.app.example.test/api', 'curl https://app.example.test.evil.test/api',
            'curl https://app.example.test:8443/api', 'curl http://app.example.test/api',
            'curl https://app.example.test/api/private/data', 'curl -L https://app.example.test/api',
            'curl -H "Host: evil.test" https://app.example.test/api', 'curl -X POST https://app.example.test/api',
            'curl https://app.example.test/api/../private', 'curl https://app.example.test/api/%2e%2e/private',
            'curl https://app.example.test/api/%252fprivate', 'curl https://user@app.example.test/api',
            'curl https://app.example.test/api/{a,b}', 'curl https://app.example.test/api https://evil.test/',
            'curl --retry 5 https://app.example.test/api', 'nmap app.example.test',
            'curl https://app.example.test./api', 'curl -k https://app.example.test/api']
        for command in invalid:
            with self.subTest(command=command), self.assertRaises(PolicyError):
                validate_command(command, scope)
        scope['program_policy']['rules']['assets'][0]['host'] = '*.example.test'
        validate_command('curl https://sub.app.example.test/api', scope)
        with self.assertRaises(PolicyError): validate_command('curl https://example.test/api', scope)
        scope['program_policy']['rules']['third_party_exclusions'] = [dict(scope['program_policy']['rules']['assets'][0], host='third.example.test')]
        with self.assertRaises(PolicyError): validate_command('curl https://third.example.test/api', scope)

    async def test_unknown_suspended_and_prohibited_policy_deny(self):
        _, _, scope = policy_fixture()
        for change in [{'automation':'unknown'},{'automation':'prohibited'},{'accounts_confirmed':False},
                       {'prerequisites_confirmed':False},{'permission_confirmed':False}]:
            modified=copy.deepcopy(scope)
            modified['program_policy']['rules'].update(change)
            with self.subTest(change=change), self.assertRaises(PolicyError):
                validate_command('curl https://app.example.test/api', modified)
        scope['program_policy']['state']='suspended'
        with self.assertRaises(PolicyError): validate_command('curl https://app.example.test/api', scope)

    async def test_execution_fields_require_source_links(self):
        snapshot, review, _ = policy_fixture()
        validate_review(snapshot, review)
        review.execution.assets[0].source_rule=999
        with self.assertRaises(HTTPException) as error: validate_review(snapshot, review)
        self.assertEqual(error.exception.status_code,422)

    async def test_activation_requires_latest_owner_review_and_no_unfinished_jobs(self):
        snapshot, review, scope = policy_fixture()
        session=SimpleNamespace(status='active',scope={'targets':['old.test']},metadata_={'program_requests_used':3})
        snapshot_row=SimpleNamespace(id=snapshot['id'],metadata_=snapshot)
        review_row=SimpleNamespace(id='review',user_id='owner',metadata_={**review.model_dump(), 'snapshot_id':snapshot['id']})
        for active in ([],[SimpleNamespace(id='unfinished')]):
            db=SimpleNamespace(execute=AsyncMock(side_effect=[result(session),result([snapshot_row]),result([review_row]),result(active),result([])]),
                               add=lambda row: None,commit=AsyncMock())
            cm=AsyncMock();cm.__aenter__.return_value=db
            with patch('memory.program_policy.async_session',return_value=cm):
                if active:
                    with self.assertRaises(HTTPException) as error: await ProgramPolicyStore().activate('engagement','owner',snapshot['id'],'review')
                    self.assertEqual(error.exception.status_code,409)
                    db.commit.assert_not_awaited()
                else:
                    activated=await ProgramPolicyStore().activate('engagement','owner',snapshot['id'],'review')
                    self.assertEqual(activated['state'],'active')
                    self.assertEqual(session.metadata_['program_requests_used'],3)
                    self.assertEqual(session.scope['program_policy']['review_id'],'review')
        review_row.metadata_['decision']='rejected'
        db.execute=AsyncMock(side_effect=[result(session),result([snapshot_row]),result([review_row])])
        with patch('memory.program_policy.async_session',return_value=cm), self.assertRaises(HTTPException):
            await ProgramPolicyStore().activate('engagement','owner',snapshot['id'],'review')
        # Reviews saved by the earlier import-only implementation have no execution field.
        review_row.metadata_['decision']='reviewed'
        review_row.metadata_.pop('execution')
        db.execute=AsyncMock(side_effect=[result(session),result([snapshot_row]),result([review_row])])
        with patch('memory.program_policy.async_session',return_value=cm), self.assertRaises(HTTPException) as error:
            await ProgramPolicyStore().activate('engagement','owner',snapshot['id'],'review')
        self.assertEqual(error.exception.status_code,409)

    async def test_source_revision_suspends_and_invalidates_old_approval(self):
        from memory.execution_authorization import ExecutionAuthorization
        from tests.test_execution import MemoryStore as AuthorizationStore
        snapshot, _, scope = policy_fixture()
        context={'owner_id':'owner','scope':scope}
        loader=AsyncMock(side_effect=lambda *args:copy.deepcopy(context))
        authority=ExecutionAuthorization(store=AuthorizationStore(),context_loader=loader,worker=AsyncMock())
        proposal=await authority.propose('owner','engagement','curl https://app.example.test/api',require_approval=True)
        await authority.decide('owner','engagement',proposal.id,'approve')
        context['scope']['program_policy']['state']='suspended'
        with self.assertRaises(HTTPException):
            await authority.execute('owner','engagement','curl https://app.example.test/api',action_id=proposal.id)
        authority.worker.assert_not_awaited()

    async def test_sql_admission_reserves_and_never_refunds_request_budget(self):
        _,_,scope=policy_fixture()
        job={'job_id':'job','session_id':'engagement','user_id':'owner','scope':scope}
        for metadata,active,allowed in [({},[],True),({'program_requests_used':10},[],False),
                ({'program_next_request_at':time.time()+100},[],False),
                ({'program_backoff_until':time.time()+100},[],False),({},[SimpleNamespace(metadata_={'state':'running'})],False)]:
            session=SimpleNamespace(scope=copy.deepcopy(scope),metadata_=dict(metadata))
            db=SimpleNamespace(execute=AsyncMock(side_effect=[result(session),result(active)]),add=lambda row:None,commit=AsyncMock())
            cm=AsyncMock();cm.__aenter__.return_value=db
            with patch('memory.worker_jobs.async_session',return_value=cm):
                if allowed:
                    await SQLJobStore().create(job)
                    self.assertEqual(session.metadata_['program_requests_used'],1)
                    db.commit.assert_awaited_once()
                else:
                    with self.assertRaises(HTTPException):await SQLJobStore().create(job)
                    db.commit.assert_not_awaited()

    async def test_worker_checks_policy_and_independent_dns_ceiling(self):
        _,_,scope=policy_fixture()
        plan=await prepare('curl https://app.example.test/api',scope,['192.0.2.0/24'],[443],resolver=AsyncMock(return_value=['192.0.2.1']))
        self.assertIn('--max-redirs',plan['argv'])
        self.assertIn('--globoff',plan['argv'])
        self.assertIn('--write-out',plan['argv'])
        with self.assertRaises(PolicyError):
            await prepare('curl https://app.example.test/api/private',scope,['192.0.2.0/24'],[443],resolver=AsyncMock(return_value=['192.0.2.1']))
        with self.assertRaises(PolicyError):
            await prepare('curl https://app.example.test/api',scope,['192.0.2.0/24'],[443],resolver=AsyncMock(return_value=['198.51.100.1']))

    async def test_worker_budget_restart_and_overload_stop(self):
        _,_,scope=policy_fixture(host='192.0.2.1',port=8080,scheme='http')
        store=MemoryStore()
        async def history(sid):return [copy.deepcopy(row) for row in store.rows.values() if row['session_id']==sid]
        store.for_session=history
        runtime=FakeRuntime()
        runtime.output=AsyncMock(return_value=('HTTP/1.0 429 Too Many Requests\nARIA_HTTP_STATUS:429\n',''))
        service=WorkerService(store,runtime,['192.0.2.0/24'],[8080])
        job={'job_id':'one','session_id':'engagement','command':'curl http://192.0.2.1:8080/api','scope':scope,'timeout':20}
        await service.submit(job)
        with self.assertRaises(HTTPException): await service.submit({**job,'job_id':'two'})
        runtime.jobs['one'].update(Running=False,Status='exited')
        await service.status('one')
        restored=WorkerService(store,runtime,['192.0.2.0/24'],[8080])
        with self.assertRaises(HTTPException) as error:await restored.submit({**job,'job_id':'three'})
        self.assertEqual(error.exception.status_code,429)
        self.assertEqual(runtime.creates,1)

    async def test_ranking_keeps_unknowns_and_program_types_visible(self):
        snapshot,_,_=policy_fixture()
        unknown=rank_candidate(snapshot,None)
        self.assertEqual(unknown['score'],0)
        self.assertIn('accessible_accounts',unknown['unknown'])
        self.assertFalse(unknown['discovery_authorizes_testing'])
        snapshot['program_type']='disclosure_only'
        good=rank_candidate(snapshot,{'technical_fit':'good','research_cost':'low','basis':'Owned lab expertise'})
        self.assertEqual(good['score'],4)
        self.assertEqual(good['program_type'],'disclosure_only')

    async def test_fetch_rejects_private_addresses_credentials_redirect_targets(self):
        for address in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:8.8.8.8']:
            with self.subTest(address=address),self.assertRaises(ValueError):
                public_addresses([(socket.AF_INET,socket.SOCK_STREAM,0,'',(address,443))])
        for url in ['http://example.test','https://user:pass@example.test','https://example.test:8443','file:///tmp/policy']:
            with self.subTest(url=url),self.assertRaises(ValueError): await fetch_policy(url)
        parser=PolicyText();parser.feed('<h2>In scope</h2><p>example.test</p><script>enable testing</script>')
        self.assertIn('example.test',''.join(parser.parts))
        self.assertNotIn('enable testing',''.join(parser.parts))

    async def test_public_fetch_pins_dns_and_never_follows_redirect(self):
        raw=b'In scope:\nexample.test\nAutomation restrictions:\nManual testing only\n'
        writer=SimpleNamespace(write=lambda data:sent.append(data),drain=AsyncMock(),close=lambda:None,wait_closed=AsyncMock())
        sent=[]
        reader=asyncio.StreamReader()
        reader.feed_data(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: '+str(len(raw)).encode()+b'\r\n\r\n'+raw)
        reader.feed_eof()
        records=[(socket.AF_INET,socket.SOCK_STREAM,0,'',('8.8.8.8',443))]
        loop=asyncio.get_running_loop()
        with patch.object(loop,'getaddrinfo',AsyncMock(return_value=records)),patch('security.program_fetch.asyncio.open_connection',AsyncMock(return_value=(reader,writer))) as connect:
            fetched=await fetch_policy('https://official.example.test/policy')
        self.assertEqual(fetched['text'],raw.decode())
        self.assertEqual(connect.call_args.args,('8.8.8.8',443))
        self.assertEqual(connect.call_args.kwargs['server_hostname'],'official.example.test')
        self.assertIn(b'Host: official.example.test',sent[0])
        reader=asyncio.StreamReader();reader.feed_data(b'HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/\r\n\r\n');reader.feed_eof()
        with patch.object(loop,'getaddrinfo',AsyncMock(return_value=records)),patch('security.program_fetch.asyncio.open_connection',AsyncMock(return_value=(reader,writer))) as connect:
            with self.assertRaises(ValueError):await fetch_policy('https://official.example.test/policy')
        connect.assert_awaited_once()

    async def test_forged_program_scope_cannot_skip_owner_review(self):
        from api.auth import get_current_user, TokenData
        from api.main import app
        _,_,scope=policy_fixture()
        app.dependency_overrides[get_current_user]=lambda:TokenData(user_id='owner',username='owner',role='pentester',skill_level='expert')
        try:
            with patch('memory.session_manager.session_manager.create_session',AsyncMock()) as create:
                response=await self.client.post('/api/session/new',json={'target':'app.example.test','scope':scope})
            self.assertEqual(response.status_code,422)
            create.assert_not_awaited()
        finally:app.dependency_overrides.pop(get_current_user,None)

    async def test_custom_executor_and_connector_cannot_bypass_budgeted_worker(self):
        from memory.execution_authorization import ExecutionAuthorization
        from tests.test_execution import MemoryStore as AuthorizationStore
        from memory.web_actions import replay_spec
        _,_,scope=policy_fixture()
        loader=AsyncMock(return_value={'owner_id':'owner','scope':scope})
        authority=ExecutionAuthorization(store=AuthorizationStore(),context_loader=loader)
        executor=AsyncMock()
        with self.assertRaises(HTTPException):
            await authority.execute('owner','engagement','curl https://app.example.test/api',executor=executor)
        executor.assert_not_awaited()
        with self.assertRaises(HTTPException):replay_spec({},scope)
