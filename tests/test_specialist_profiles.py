"""Offline controls for the finite Phase 4 HTTP profiles; never sends traffic."""
import copy
import json
import os
import uuid
from unittest.mock import patch, MagicMock

from fastapi import HTTPException
from pydantic import ValidationError
from worker.http_profile import command_for, decode, cipher, prepare_http
from memory.application_map import RequestInput, request_specialty
from orchestrator.specialist_investigations import investigation_capabilities
from memory.team_tasks import TaskSpec
from tests import test_http_profile as http_profile_tests
from tests.test_http_profile import Store
from tests.test_worker_server import FakeRuntime, request
from worker.service import WorkerService
from tests.test_authorization_review import fixture


class SpecialistProfiles(http_profile_tests.HttpProfile):
    """Reuse lifecycle, isolation and retention controls for both new profiles."""
    def setUp(self):
        super().setUp()
        enabled = patch.dict(os.environ, {'HTTP_SPECIALIST_PROFILES_ENABLED': 'true'})
        enabled.start()
        self.addCleanup(enabled.stop)
        self.scope['web_specialist_profiles'] = True
        self.spec.update(method='PUT', body='{"count":1}', specialty={
            'profile': 'controlled_json_put', 'object_id': str(uuid.uuid4()),
            'authorized': True, 'invariant': 'Only the controlled count changes'})
        self.bind()

    def bind(self):
        self.command = command_for(self.identity, self.capture, self.spec)
        self.token = cipher().encrypt(json.dumps(self.spec).encode()).decode()

    async def test_integer_query_profile_and_method_bounds(self):
        self.spec.update(method='GET', url='http://192.0.2.1:8080/objects?count=-1', body='')
        self.spec['specialty']['profile'] = 'integer_query'
        self.bind()
        self.assertEqual(decode(self.token, self.command), self.spec)
        plan = await prepare_http(self.command, self.scope, ['192.0.2.0/24'], [8080], self.token)
        self.assertEqual(plan['ports'], [8080])
        for suffix in ['count=x', 'count=1000000', 'count=1&other=2', 'count=%31', 'count=1&count=2']:
            self.spec['url'] = 'http://192.0.2.1:8080/objects?' + suffix
            self.bind()
            with self.subTest(suffix=suffix), self.assertRaises(ValueError): decode(self.token, self.command)

    async def test_put_shape_and_attestations_are_independently_rechecked(self):
        for change in [dict(body='{"count":1,"other":2}'), dict(body='{"count":{}}'),
                       dict(body='{"count":"<script>"}'), dict(body='{"count": 1}'),
                       dict(body='{"count":1000000}'), dict(method='DELETE')]:
            spec = {**self.spec, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                decode(cipher().encrypt(json.dumps(spec).encode()).decode(), command_for(self.identity, self.capture, spec))
        for change in [{'authorized': False}, {'object_id': 'foreign'}, {'invariant': ' '}, {'profile': 'shell'}]:
            spec = {**self.spec, 'specialty': {**self.spec['specialty'], **change}}
            with self.subTest(change=change), self.assertRaises(ValueError):
                decode(cipher().encrypt(json.dumps(spec).encode()).decode(), command_for(self.identity, self.capture, spec))

    async def test_missing_lab_opt_in_denies_before_container_creation(self):
        runtime = FakeRuntime()
        service = WorkerService(Store(), runtime, ['192.0.2.0/24'], [8080])
        for scope in [{**self.scope, 'web_specialist_profiles': False},
                      {**self.scope, 'program_policy': {'state': 'draft'}}]:
            with self.assertRaises(HTTPException):
                await service.submit(request(command=self.command, scope=scope, timeout=10, protected_http=self.token))
        self.assertEqual(runtime.creates, 0)

    async def test_runner_sends_exact_approved_body_once_and_preserves_private_evidence(self):
        import base64
        from worker.http_runner import run
        response = MagicMock(status=200, reason='OK')
        response.read.return_value = b'{"count":1}'
        response.getheaders.return_value = [('Content-Type', 'application/json')]
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch('worker.http_runner.Path.read_text', return_value=self.key), \
             patch('worker.http_runner.http.client.HTTPConnection', return_value=connection) as connect, \
             patch('builtins.print') as output:
            self.assertEqual(run({'protected_http': self.token, 'http_command': self.command}), 0)
        connect.assert_called_once_with('192.0.2.1', 8080, timeout=10)
        connection.putrequest.assert_called_once_with('PUT', '/objects', skip_host=True, skip_accept_encoding=True)
        connection.endheaders.assert_called_once_with(b'{"count":1}')
        connection.getresponse.assert_called_once()
        connection.close.assert_called_once()
        receipt = json.loads(output.call_args.args[0])
        private = json.loads(cipher().decrypt(receipt['protected_response'].encode()))
        self.assertTrue(base64.b64decode(private['request_b64']).endswith(b'\r\n\r\n{"count":1}'))
        self.assertNotIn('owned-account-secret', output.call_args.args[0])

    async def test_controlled_object_evidence_and_owner_are_required(self):
        state = fixture()
        args = (state, 'a', 'o', 'https://lab.test/item', self.spec['specialty'])
        self.assertEqual(request_specialty(*args), self.spec['specialty'])
        for mutate in [lambda s: s['objects']['o'].update(owner_identity_id='b'),
                       lambda s: s['captures']['c1'].update(expired=True),
                       lambda s: s['identities']['a'].update(researcher_controlled=False),
                       lambda s: s['captures']['c1']['original'].update(url='https://lab.test/other')]:
            changed = copy.deepcopy(state); mutate(changed)
            with self.assertRaises(HTTPException): request_specialty(changed, *args[1:])

    async def test_capability_versions_and_scope_both_required(self):
        caps = {'authenticated_http_version': 1, 'specialist_http_version': 1}
        self.assertTrue(investigation_capabilities(caps, self.scope)['reviewed_input_profile'])
        for version in [True, '1', 0, None]:
            self.assertFalse(investigation_capabilities({**caps, 'specialist_http_version': version}, self.scope)['reviewed_state_change'])
        self.assertFalse(investigation_capabilities(caps, {})['reviewed_input_profile'])

    async def test_specialist_tasks_cannot_omit_question_completion(self):
        spec = dict(owner_role='vuln', objective='Review boundary', expected_output='Observation',
                    completion_criteria=['Review controlled evidence'], specialty='input_validation')
        with self.assertRaises(ValidationError): TaskSpec(**spec)
        self.assertEqual(TaskSpec(**spec, phase='vulnerability_analysis', security_questions=['boundary']).specialty, 'input_validation')

    async def test_request_contract_rejects_unreviewed_mutation(self):
        with self.assertRaises(ValidationError):
            RequestInput(expected_revision=0, identity_id='a', method='PUT', url='https://lab.test/item')
        with self.assertRaises(ValidationError):
            RequestInput(expected_revision=0, identity_id='a', method='PUT', url='https://lab.test/item',
                         profile='controlled_json_put', object_id='o', action_authorized=False, invariant='Owned field')

    async def test_controller_requires_exact_specialty_capability_before_dispatch(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from memory.worker_jobs import WorkerJobs
        from tests.test_p1_workers import MemoryJobs
        from config.settings import settings
        for version, allowed in [(1, True), (0, False), (True, False), ('1', False), (None, False)]:
            worker = SimpleNamespace(capabilities=AsyncMock(return_value={
                'authenticated_http_version': 1, 'specialist_http_version': version}),
                submit=AsyncMock(return_value={'state': 'cancelled', 'terminated': True, 'exit_code': -1, 'stdout': ''}))
            authorize = AsyncMock(return_value={'scope': self.scope})
            jobs = WorkerJobs(MemoryJobs(), worker)
            with self.subTest(version=version), \
                 patch.object(settings, 'KALI_WORKER_PROTOCOL', 'jobs-v1'), \
                 patch.object(settings, 'HTTP_REPLAY_KEY', self.key), \
                 patch('memory.application_map.application_map.replay_material', AsyncMock(return_value=(self.command, self.token))):
                if allowed:
                    await jobs.execute('job', 'owner', 'session', self.command, 10, authorization_check=authorize)
                    worker.submit.assert_awaited_once()
                    self.assertEqual(authorize.await_count, 2)
                else:
                    with self.assertRaises(HTTPException):
                        await jobs.execute('job', 'owner', 'session', self.command, 10, authorization_check=authorize)
                    worker.submit.assert_not_awaited()


    async def test_integer_query_runner_does_not_follow_redirect_and_overload_stops_engagement(self):
        from unittest.mock import AsyncMock
        from worker.http_runner import run
        self.spec.update(method='GET', url='http://192.0.2.1:8080/objects?count=-1', body='')
        self.spec['specialty']['profile'] = 'integer_query'
        self.bind()
        response = MagicMock(status=302, reason='Found')
        response.read.return_value = b''
        response.getheaders.return_value = [('Location', 'https://outside.test/')]
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch('worker.http_runner.Path.read_text', return_value=self.key), \
             patch('worker.http_runner.http.client.HTTPConnection', return_value=connection) as connect, \
             patch('builtins.print'):
            self.assertEqual(run({'protected_http': self.token, 'http_command': self.command}), 0)
        connect.assert_called_once()
        connection.putrequest.assert_called_once_with('GET', '/objects?count=-1', skip_host=True, skip_accept_encoding=True)
        connection.getresponse.assert_called_once()
        runtime, store = FakeRuntime(), Store()
        service = WorkerService(store, runtime, ['192.0.2.0/24'], [8080])
        req = request(command=self.command, scope=self.scope, timeout=10, protected_http=self.token)
        await service.submit(req)
        runtime.inspect = AsyncMock(return_value={'Running': False, 'Status': 'exited', 'ExitCode': 0})
        runtime.output = AsyncMock(return_value=(json.dumps({'status': 429}), ''))
        await service.status(req['job_id'])
        self.assertTrue(store.rows[req['job_id']]['overloaded'])
        with self.assertRaises(HTTPException): await service.submit({**req, 'job_id': str(uuid.uuid4())})
        self.assertEqual(runtime.creates, 1)

    async def test_worker_opt_in_is_required_even_with_valid_approval_and_scope(self):
        from worker.http_profile import specialties_available
        with patch.dict(os.environ, {'HTTP_SPECIALIST_PROFILES_ENABLED': 'false'}):
            self.assertFalse(specialties_available())
            with self.assertRaises(ValueError):
                await prepare_http(self.command, self.scope, ['192.0.2.0/24'], [8080], self.token)

    async def test_body_object_and_invariant_changes_invalidate_existing_approval_digest(self):
        for change in [{'body': '{"count":2}'}, {'specialty': {**self.spec['specialty'], 'invariant': 'A different invariant'}},
                       {'specialty': {**self.spec['specialty'], 'object_id': str(uuid.uuid4())}}]:
            changed = {**self.spec, **change}
            token = cipher().encrypt(json.dumps(changed).encode()).decode()
            with self.subTest(change=change), self.assertRaises(ValueError): decode(token, self.command)
