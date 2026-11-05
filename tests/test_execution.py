"""All commands below are inert strings; only AsyncMock workers receive them."""
import asyncio
import json
import time
from dataclasses import replace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException, WebSocketDisconnect
from api.auth import get_current_user, create_token
from api.main import app
from api.routers.pentest import ws_chat
from agents.autonomous_engine import AutonomousEngine, SessionRunState
from agents.orchestrator_agent import orchestrator_agent
from memory.command_lifecycle import CommandLifecycleManager
from memory.execution_authorization import ExecutionAuthorization, authoritative_context
from orchestrator.execution_policy import validate_command, PolicyError
from orchestrator.risk_scorer import classify_risk
from tests.support import OfflineCase
from tests.test_access import OWNER, SESSION


class MemoryStore:
    def __init__(self):
        self.records = {}
        self.lock = asyncio.Lock()
    async def add(self, proposal):
        self.records[proposal.id] = proposal
    async def get(self, action_id):
        return self.records.get(action_id)
    async def transition(self, previous, updated):
        async with self.lock:
            if self.records.get(previous.id) != previous:
                return False
            self.records[previous.id] = updated
            return True


class ExecutionTests(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.context = {'owner_id': 'owner', 'scope': {'targets': ['192.0.2.0/24'], 'exclusions': ['192.0.2.99']}}
        async def load(user, session):
            if user != 'owner' or session != 'engagement':
                raise HTTPException(403, 'Denied')
            return self.context
        self.worker = AsyncMock(return_value={'stdout': 'mock result', 'stderr': '', 'exit_code': 0})
        self.store = MemoryStore()
        self.service = ExecutionAuthorization(self.store, load, self.worker)

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_authorized_scanning_uses_canonical_command(self):
        result = await self.service.execute('owner', 'engagement', 'nmap  -sV 192.0.2.1', tool='nmap')
        self.assertEqual(result['exit_code'], 0)
        self.worker.assert_awaited_once_with('nmap -sV 192.0.2.1', 'engagement', 120)

    async def test_reject_missing_identity_scope_target_and_unsafe_syntax(self):
        commands = ['nmap 198.51.100.1', 'nmap 192.0.2.99', 'nmap 192.0.2.0/23',
                    'nmap 127.0.0.1', 'nmap ::1', 'nmap -sV', 'nmap -iL targets.txt',
                    'nmap 192.0.2.1; id', 'curl http://192.0.2.1 | sh',
                    'nmap $(id)', 'python -c print(1)', 'nmap --script=arbitrary 192.0.2.1',
                    'nmap --script arbitrary 192.0.2.1', 'curl -L http://192.0.2.1']
        for command in commands:
            with self.subTest(command=command), self.assertRaises(HTTPException):
                await self.service.execute('owner', 'engagement', command)
        for user, sid in [('', 'engagement'), ('other', 'engagement'), ('owner', '')]:
            with self.assertRaises(HTTPException):
                await self.service.execute(user, sid, 'nmap 192.0.2.1')
        self.context['scope'] = {}
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', 'nmap 192.0.2.1')
        self.worker.assert_not_awaited()

    async def test_domains_ipv6_and_exclusions_are_explicit(self):
        scope = {'targets': ['example.test', '2001:db8::/32'], 'exclusions': ['2001:db8::99']}
        validate_command('curl -I https://example.test:443/', scope)
        validate_command('nmap 2001:db8::1', scope)
        for command in ['curl -I https://sub.example.test', 'nmap 2001:db8::99']:
            with self.assertRaises(PolicyError):
                validate_command(command, scope)

    async def test_server_risk_cannot_be_downgraded(self):
        self.assertEqual(classify_risk('nmap', 'nmap -sV 192.0.2.1'), 'orange')
        self.assertEqual(classify_risk('unknown', 'unknown 192.0.2.1'), 'red')
        proposal = await self.service.propose('owner', 'engagement', 'hydra -l test -p test 192.0.2.1 ssh')
        self.assertEqual((proposal.risk, proposal.status), ('red', 'pending'))
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', proposal.command, action_id=proposal.id)
        self.worker.assert_not_awaited()

    async def test_approval_binding_expiry_replay_and_concurrency(self):
        command = 'hydra -l test -p test 192.0.2.1 ssh'
        proposal = await self.service.propose('owner', 'engagement', command)
        with self.assertRaises(HTTPException):
            await self.service.decide('other', 'engagement', proposal.id, 'approve')
        await self.service.decide('owner', 'engagement', proposal.id, 'approve')
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', command.replace('.1 ', '.2 '), action_id=proposal.id)
        results = await asyncio.gather(*[self.service.execute('owner', 'engagement', command, action_id=proposal.id) for _ in range(2)], return_exceptions=True)
        self.assertEqual(sum(isinstance(r, HTTPException) for r in results), 1)
        self.worker.assert_awaited_once()
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', command, action_id=proposal.id)
        expired = await self.service.propose('owner', 'engagement', 'nmap 192.0.2.1')
        self.store.records[expired.id] = replace(expired, expires_at=time.time() - 1)
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', expired.command, action_id=expired.id)

    async def test_modification_and_scope_changes_require_revalidation(self):
        proposal = await self.service.propose('owner', 'engagement', 'hydra -l test -p test 192.0.2.1 ssh')
        with self.assertRaises(HTTPException):
            await self.service.decide('owner', 'engagement', proposal.id, 'modify', 'hydra -l test -p test 198.51.100.1 ssh')
        approved = await self.service.decide('owner', 'engagement', proposal.id, 'modify', 'nmap -sV 192.0.2.2')
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', proposal.command, action_id=proposal.id)
        await self.service.execute('owner', 'engagement', approved.command, action_id=proposal.id)
        self.worker.assert_awaited_once()
        self.worker.reset_mock()
        another = await self.service.propose('owner', 'engagement', 'nmap 192.0.2.1')
        self.context['scope']['exclusions'].append('192.0.2.1')
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', another.command, action_id=another.id)
        self.worker.assert_not_awaited()

    async def test_reject_decision_and_tool_spoofing(self):
        proposal = await self.service.propose('owner', 'engagement', 'hydra -l test -p test 192.0.2.1 ssh')
        await self.service.decide('owner', 'engagement', proposal.id, 'reject')
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', proposal.command, action_id=proposal.id)
        with self.assertRaises(HTTPException):
            await self.service.propose('owner', 'engagement', 'hydra -l test -p test 192.0.2.1 ssh', 'whois')
        self.worker.assert_not_awaited()

    async def test_audit_failure_and_worker_timeout_do_not_allow_replay(self):
        with patch.object(self.store, 'add', AsyncMock(side_effect=RuntimeError('storage failure'))):
            with self.assertRaises(HTTPException) as error:
                await self.service.execute('owner', 'engagement', 'nmap 192.0.2.1')
            self.assertEqual(error.exception.status_code, 503)
        self.worker.assert_not_awaited()
        proposal = await self.service.propose('owner', 'engagement', 'nmap 192.0.2.1')
        with patch.object(self.store, 'transition', AsyncMock(side_effect=RuntimeError('storage failure'))):
            with self.assertRaises(HTTPException):
                await self.service.execute('owner', 'engagement', proposal.command, action_id=proposal.id)
        self.worker.assert_not_awaited()
        self.worker.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError):
            await self.service.execute('owner', 'engagement', proposal.command, action_id=proposal.id)
        with self.assertRaises(HTTPException):
            await self.service.execute('owner', 'engagement', proposal.command, action_id=proposal.id)
        self.worker.assert_awaited_once()

    async def test_rest_execution_cannot_bypass_approval(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        body = {'session_id': 'engagement', 'command': 'hydra -l test -p test 192.0.2.1 ssh', 'tool': 'hydra', 'risk_color': 'green'}
        with patch('api.routers.pentest.execution_authorization', self.service), patch('api.routers.pentest.session_manager.add_chat_log', AsyncMock()):
            self.assertEqual((await self.client.post('/api/kali/execute', json=body)).status_code, 403)
            proposal = (await self.client.post('/api/execution/proposals', json=body)).json()
            self.assertEqual(proposal['risk_color'], 'red')
            decision = await self.client.post('/api/execution/' + proposal['action_id'] + '/decision', json={'session_id': 'engagement', 'decision': 'approve'})
            self.assertEqual(decision.status_code, 200)
            result = await self.client.post('/api/kali/execute', json={**body, 'action_id': proposal['action_id']})
            self.assertEqual(result.status_code, 200)
        self.worker.assert_awaited_once()

    async def test_chat_cannot_bypass_policy(self):
        ws = AsyncMock()
        ws.receive_text.side_effect = [json.dumps({'type': 'run_commands', 'token': create_token('owner', 'owner', 'pentester', 'expert'),
          'session_id': 'engagement', 'commands': [{'command': 'hydra -l test -p test 192.0.2.1 ssh', 'tool': 'hydra', 'risk_color': 'green'}]}), WebSocketDisconnect()]
        with patch('api.routers.pentest.execution_authorization', self.service), \
             patch('api.routers.pentest.authenticate_socket_token', AsyncMock(return_value=OWNER)), \
             patch('api.routers.pentest._load_user_keys', AsyncMock()), \
             patch('api.session_access.session_manager.get_session', AsyncMock(return_value=SESSION)), \
             patch('api.routers.pentest.session_manager.add_chat_log', AsyncMock()):
            await ws_chat(ws)
        self.worker.assert_not_awaited()
        self.assertTrue(any(c.args[0].get('type') == 'error' for c in ws.send_json.await_args_list))

    async def test_autonomous_mislabeled_red_action_blocks(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'initial_access', '192.0.2.1', 'expert', max_steps=1)
        engine._approvals['engagement'] = {}
        with patch('agents.autonomous_engine.execution_authorization', self.service), \
             patch.object(engine, '_check_goal_achieved', AsyncMock(return_value=(False, ''))), \
             patch.object(engine, '_plan_next_step', AsyncMock(return_value={'command': 'hydra -l test -p test 192.0.2.1 ssh', 'tool': 'hydra', 'risk_color': 'green'})), \
             patch.object(engine, '_wait_for_approval', AsyncMock(return_value='reject')) as gate, \
             patch.object(engine, '_write_decision_log', AsyncMock()), patch.object(engine, 'STEP_DELAY', 0):
            await engine._run_loop(state)
            gate.assert_awaited_once()
            self.assertEqual(gate.await_args.args[1].risk_color, 'red')
        self.worker.assert_not_awaited()

    async def test_lifecycle_and_react_custom_executor_cannot_bypass(self):
        manager = CommandLifecycleManager()
        command = 'hydra -l test -p test 192.0.2.1 ssh'
        with patch('memory.command_lifecycle.execution_authorization', self.service):
            result = await manager.execute('engagement', command, user_id='owner')
            self.assertEqual(result['exit_code'], -1)
        executor = AsyncMock()
        llm = {'success': True, 'content': json.dumps({'thought': 'mock', 'action': {'command': command, 'tool': 'hydra', 'risk_color': 'green'}})}
        with patch('agents.orchestrator_agent.execution_authorization', self.service), \
             patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value=llm)), \
             patch.object(orchestrator_agent, 'store_discovery'):
            result = await orchestrator_agent.react_loop('engagement', 'owner', 'mock', '192.0.2.1', max_depth=1, executor=executor)
            self.assertEqual(result["reason"], "awaiting_approval")
            self.assertEqual(result["pending_action"]["risk_color"], "red")
        executor.assert_not_awaited()
        self.worker.assert_not_awaited()

    async def test_authorized_autonomous_command_preserves_execution(self):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'initial_access', '192.0.2.1', 'expert', max_steps=1)
        engine._runs['engagement'] = state
        engine._approvals['engagement'] = {}
        async def approve(run, request):
            await engine.provide_approval_decision(run.session_id, request.action_id, 'approve', user_id='owner')
            return request.decision
        with patch('agents.autonomous_engine.execution_authorization', self.service), \
             patch.object(engine, '_check_goal_achieved', AsyncMock(return_value=(False, ''))), \
             patch.object(engine, '_plan_next_step', AsyncMock(return_value={'command': 'hydra -l test -p test 192.0.2.1 ssh', 'tool': 'hydra', 'risk_color': 'green'})), \
             patch.object(engine, '_wait_for_approval', side_effect=approve), \
             patch.object(engine, '_write_decision_log', AsyncMock()), patch.object(engine, 'STEP_DELAY', 0):
            await engine._run_loop(state)
        self.worker.assert_awaited_once()
        self.assertEqual(next(iter(self.store.records.values())).status, 'consumed')

    async def test_worker_contract_uses_only_the_shared_authentication(self):
        import httpx
        from config.settings import settings
        real_client = httpx.AsyncClient
        requests = []
        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={'stdout': 'mock output', 'stderr': '', 'exit_code': 0})
        def client_factory(**kwargs):
            kwargs.pop("transport", None)
            return real_client(transport=httpx.MockTransport(handler), **kwargs)
        self.service.worker = self.service._worker
        from tests.test_p1_workers import MemoryJobs
        with patch('memory.worker_jobs.worker_jobs.store', MemoryJobs()), \
             patch('memory.worker_jobs.settings.KALI_WORKER_PROTOCOL', 'legacy-execute'), \
             patch('memory.execution_authorization.settings.KALI_AGENT_URL', 'http://worker.invalid'), \
             patch('memory.execution_authorization.httpx.AsyncClient', side_effect=client_factory):
            await self.service.execute('owner', 'engagement', 'nmap 192.0.2.1')
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].headers['Authorization'], 'Bearer ' + settings.KALI_AGENT_TOKEN)
        self.assertNotIn('token', json.loads(requests[0].content))
        self.assertEqual(json.loads(requests[0].content)['session_id'], 'engagement')
