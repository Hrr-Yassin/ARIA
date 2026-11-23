"""P4 operational authorization profiles: validation, central enforcement and audit."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pydantic import ValidationError

from memory.engagement_profiles import (AuthorizedPentestProfile, BugBountyProfile, CTFProfile, PrivateLabProfile,
                                        ProfileDenied, apply_profile, check_operation, requires_approval)
from memory.execution_authorization import ExecutionAuthorization
from tests.support import OfflineCase
from tests.test_execution import MemoryStore

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
STATEMENT = 'The owner operates this isolated lab and authorizes testing of the listed assets.'


def lab(**changes):
    return PrivateLabProfile(**{'targets': ['192.168.77.20'], 'ports': [80], 'inventory': ['192.168.77.20'],
                                'permitted_capabilities': ['curl', 'httpx.http.probe.v1'],
                                'prohibited_capabilities': ['nmap'], 'ownership_statement': STATEMENT,
                                'isolation': {'network_isolated': True, 'description': 'Libvirt isolated network'},
                                **changes})


def pentest(**changes):
    return AuthorizedPentestProfile(**{'targets': ['10.20.0.0/24'], 'exclusions': ['10.20.0.1'],
                                       'permitted_capabilities': ['curl'], 'authorization_reference': 'SOW-2026-17',
                                       'authorized_by': 'Client CISO', 'authorization_document_sha256': 'a' * 64,
                                       'rules_of_engagement': 'Business hours only; no denial of service; notify on findings.',
                                       'valid_from': NOW - timedelta(days=1), 'valid_until': NOW + timedelta(days=5),
                                       'exclusions_reviewed': True, **changes})


def scope_for(profile, revision=1, **extra):
    return apply_profile({'blocked_typed_capabilities': [], **extra}, profile, revision, 'owner', 'Configured for test')


class ProfileValidation(OfflineCase):
    def test_each_profile_requires_its_documentation(self):
        with self.assertRaises(ValidationError):
            PrivateLabProfile.model_validate({'targets': ['192.168.77.20'], 'permitted_capabilities': ['curl']})
        with self.assertRaises(ValidationError):               # valid_until missing
            CTFProfile(targets=['ctf.example.test'], permitted_capabilities=['curl'], challenge_name='c',
                       challenge_scope=STATEMENT, rules_text=STATEMENT, rules_source='event page')
        with self.assertRaises(ValidationError):               # exclusions not explicitly reviewed
            pentest(exclusions_reviewed=False)
        with self.assertRaises(ValidationError):
            pentest(authorization_document_sha256='not-a-digest')
        with self.assertRaises(ValidationError):               # no program snapshot
            BugBountyProfile.model_validate({'targets': ['app.example.test'], 'permitted_capabilities': ['curl'],
                                             'testing_restrictions': STATEMENT, 'exclusions_reviewed': True})

    def test_authorization_is_never_inferred_from_reachability(self):
        for bad in (['*'], ['0.0.0.0/0'], ['10.0.0.0/8'], ['any']):
            with self.subTest(targets=bad), self.assertRaises(ValidationError):
                lab(targets=bad, inventory=['192.168.77.20'])
        with self.assertRaises(ValidationError):              # public address is not a private lab asset
            lab(targets=['8.8.8.8'], inventory=['8.8.8.8'])
        with self.assertRaises(ValidationError):              # target must be in the declared inventory
            lab(targets=['192.168.77.21'])

    def test_sensitive_profiles_cannot_lower_approval(self):
        with self.assertRaises(ValidationError):
            pentest(approval='red_only')
        with self.assertRaises(ValidationError):
            lab(permitted_capabilities=['nmap'], prohibited_capabilities=['nmap'])
        self.assertEqual(lab(approval='red_only').approval, 'red_only')

    def test_apply_profile_preserves_owner_blocks_and_program_policy(self):
        scope = apply_profile({'blocked_typed_capabilities': ['ffuf.http.paths.v1'], 'program_policy': {'state': 'active'},
                               'targets': ['old.example.test']}, lab(), 3, 'owner', 'reason')
        self.assertEqual(scope['targets'], ['192.168.77.20'])
        self.assertEqual(scope['blocked_typed_capabilities'], ['ffuf.http.paths.v1'])
        self.assertEqual(scope['program_policy'], {'state': 'active'})
        self.assertEqual(scope['engagement_profile']['revision'], 3)


class ProfileEvaluation(OfflineCase):
    def test_capability_validity_schedule_and_program_checks(self):
        scope = scope_for(lab())
        self.assertIsNotNone(check_operation(scope, 'curl http://192.168.77.20/', 'curl', 'green', NOW))
        for command, tool, code in (('nmap -p 80 192.168.77.20', 'nmap', 'capability_prohibited'),
                                    ('searchsploit apache', 'searchsploit', 'capability_not_permitted')):
            with self.subTest(code=code), self.assertRaises(ProfileDenied) as denied:
                check_operation(scope, command, tool, 'orange', NOW)
            self.assertEqual(denied.exception.code, code)
        expired = scope_for(pentest(valid_from=NOW - timedelta(days=9), valid_until=NOW - timedelta(days=1)))
        with self.assertRaises(ProfileDenied) as denied:
            check_operation(expired, 'curl http://10.20.0.5/', 'curl', 'green', NOW)
        self.assertEqual(denied.exception.code, 'outside_validity')
        weekend_only = scope_for(lab(schedule=[{'days': [5, 6]}]))     # NOW is a Monday
        with self.assertRaises(ProfileDenied) as denied:
            check_operation(weekend_only, 'curl http://192.168.77.20/', 'curl', 'green', NOW)
        self.assertEqual(denied.exception.code, 'outside_schedule')
        bounty = BugBountyProfile(targets=['app.example.test'], permitted_capabilities=['curl'], exclusions_reviewed=True,
                                  program_snapshot_id='snap-1', testing_restrictions=STATEMENT)
        with self.assertRaises(ProfileDenied) as denied:
            check_operation(scope_for(bounty, program_policy={'state': 'suspended', 'snapshot_id': 'snap-1'}),
                            'curl https://app.example.test/', 'curl', 'green', NOW)
        self.assertEqual(denied.exception.code, 'program_policy_mismatch')

    def test_approval_levels(self):
        sensitive = scope_for(pentest())['engagement_profile']
        self.assertTrue(requires_approval(sensitive, 'orange'))
        self.assertFalse(requires_approval(sensitive, 'green'))
        self.assertTrue(requires_approval({**sensitive, 'approval': 'all'}, 'green'))
        self.assertFalse(requires_approval(None, 'orange'))          # legacy unprofiled behavior unchanged


class CentralEnforcement(OfflineCase):
    def service(self, scope, *, dispatched=0):
        self.contexts = {'scope': scope, 'owner_id': 'owner'}
        self.worker = AsyncMock(return_value={'stdout': 'ok', 'stderr': '', 'exit_code': 0, 'job_id': 'job'})
        self.audit = AsyncMock()
        return ExecutionAuthorization(MemoryStore(), AsyncMock(side_effect=lambda *a, **k: self.contexts),
                                      self.worker, rate_counter=AsyncMock(return_value=dispatched), audit=self.audit)

    async def test_sensitive_operation_needs_human_approval_then_dispatches(self):
        service = self.service(scope_for(pentest(limits={'max_timeout_seconds': 30})))
        command = 'curl http://10.20.0.5/'
        with patch('memory.engagement_profiles.datetime') as clock:
            clock.now.return_value = NOW
            clock.fromisoformat = datetime.fromisoformat
            proposal = await service.propose('owner', 'engagement', command, 'curl')
            self.assertEqual(proposal.risk, 'orange')
            self.assertEqual(proposal.status, 'pending')
            with self.assertRaises(HTTPException):
                await service.execute('owner', 'engagement', command, 'curl', action_id=proposal.id)
            self.worker.assert_not_awaited()
            await service.decide('owner', 'engagement', proposal.id, 'approve')
            await service.execute('owner', 'engagement', command, 'curl', action_id=proposal.id, timeout=60)
        self.worker.assert_awaited_once()
        assert self.worker.await_args is not None
        self.assertEqual(self.worker.await_args.args[2], 30)          # profile timeout cap

    async def test_denials_reject_before_dispatch_and_are_audited(self):
        service = self.service(scope_for(lab()))
        for command, tool in (('nmap -p 80 192.168.77.20', 'nmap'),          # prohibited capability
                              ('curl http://192.168.77.99/', 'curl'),          # outside declared assets
                              ('curl http://evil.example.com/', 'curl')):     # discovered/redirected host
            with self.subTest(command=command), self.assertRaises(HTTPException) as denied:
                await service.propose('owner', 'engagement', command, tool)
            self.assertEqual(denied.exception.status_code, 403)
        self.worker.assert_not_awaited()
        audited = [call.args[3] for call in self.audit.await_args_list]
        self.assertEqual(audited[0]['reason'], 'capability_prohibited')
        self.assertEqual(audited[0]['stage'], 'propose')

    async def test_profile_change_invalidates_prior_approvals(self):
        service = self.service(scope_for(lab(approval='red_only')))
        command = 'curl http://192.168.77.20/'
        proposal = await service.propose('owner', 'engagement', command, 'curl')
        self.contexts = {'scope': scope_for(lab(approval='red_only', ports=[80, 443]), revision=2), 'owner_id': 'owner'}
        with self.assertRaises(HTTPException) as denied:
            await service.execute('owner', 'engagement', command, 'curl', action_id=proposal.id)
        self.assertIn('no longer valid', str(denied.exception.detail))
        self.worker.assert_not_awaited()

    async def test_denied_capability_stays_denied_on_retry(self):
        service = self.service(scope_for(lab()))
        for _ in range(3):
            with self.assertRaises(HTTPException):
                await service.execute('owner', 'engagement', 'nmap -p 80 192.168.77.20', 'nmap')
        self.worker.assert_not_awaited()
        self.assertEqual(self.audit.await_count, 3)

    async def test_hourly_limit(self):
        service = self.service(scope_for(lab(approval='red_only', limits={'max_operations_per_hour': 5})), dispatched=5)
        command = 'curl http://192.168.77.20/'
        proposal = await service.propose('owner', 'engagement', command, 'curl')
        with self.assertRaises(HTTPException) as denied:
            await service.execute('owner', 'engagement', command, 'curl', action_id=proposal.id)
        self.assertEqual(denied.exception.status_code, 429)
        self.worker.assert_not_awaited()

    async def test_policy_change_between_approval_and_dispatch_blocks_the_worker(self):
        service = ExecutionAuthorization(MemoryStore(), AsyncMock(side_effect=lambda *a, **k: self.contexts),
                                         rate_counter=AsyncMock(return_value=0), audit=AsyncMock())
        self.contexts = {'scope': scope_for(lab(approval='red_only')), 'owner_id': 'owner'}
        command = 'curl http://192.168.77.20/'
        proposal = await service.propose('owner', 'engagement', command, 'curl')
        submitted = AsyncMock()

        async def dispatch(job_id, user_id, session_id, cmd, timeout, authorization_check):
            # The profile is tightened while the job waits for the worker; same scope digest
            # semantics apply, and the dispatch-time recheck must refuse the job.
            self.contexts = {'scope': {**self.contexts['scope'], 'engagement_profile': {
                **self.contexts['scope']['engagement_profile'], 'prohibited_capabilities': ['curl'],
                'permitted_capabilities': ['httpx.http.probe.v1']}}, 'owner_id': 'owner'}
            await authorization_check()
            await submitted()
        with patch('memory.execution_authorization.worker_jobs.execute', side_effect=dispatch):
            with self.assertRaises(HTTPException) as denied:
                await service.execute('owner', 'engagement', command, 'curl', action_id=proposal.id)
        self.assertEqual(denied.exception.status_code, 403)
        submitted.assert_not_awaited()

    async def test_unprofiled_engagement_keeps_legacy_behavior(self):
        service = self.service({'targets': ['192.168.77.20'], 'exclusions': []})
        proposal = await service.propose('owner', 'engagement', 'curl http://192.168.77.20/', 'curl')
        self.assertEqual(proposal.status, 'authorized')


class NoModelControlOfPermissions(OfflineCase):
    async def test_chat_cannot_change_the_authorization_mode(self):
        from api.auth import get_current_user
        from api.main import app
        from orchestrator.intent_engine import Intent, IntentResult
        owner = SimpleNamespace(user_id='owner', username='owner', role='admin', skill_level='expert')
        app.dependency_overrides[get_current_user] = lambda: owner
        update = AsyncMock()
        result = IntentResult(intent=Intent.SET_MODE, confidence=0.99, target=None, raw_input='switch to lab mode',
                              entities={'attack_mode': 'lab'}, suggested_reply='', needs_confirmation=False)
        try:
            with patch('api.routers.pentest.intent_engine.parse', return_value=result), \
                 patch('api.routers.pentest.session_manager.update_session', update), \
                 patch('api.routers.pentest.get_accessible_session', AsyncMock(return_value={'target': '192.0.2.1'})), \
                 patch('api.routers.pentest.session_manager.get_chat_logs', AsyncMock(return_value=[])), \
                 patch('api.routers.pentest.session_manager.add_chat_log', AsyncMock()):
                response = await self.client.post('/api/v8/input', json={'session_id': 'engagement',
                                                                     'user_input': 'switch to lab mode'})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        self.assertEqual(response.status_code, 200, response.text)
        update.assert_not_awaited()
        self.assertIn('not accepted from chat', response.json()['suggested_reply'])

    async def test_session_creation_cannot_inject_a_profile(self):
        from api.auth import get_current_user
        from api.main import app
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(user_id='owner', role='admin')
        try:
            response = await self.client.post('/api/session/new', json={
                'target': '192.168.77.20', 'scope': {'targets': ['192.168.77.20'],
                                                     'engagement_profile': {'kind': 'private_lab'}}})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        self.assertEqual(response.status_code, 422)



class ProfileRequirement(OfflineCase):
    def service(self, scope):
        self.worker = AsyncMock()
        return ExecutionAuthorization(MemoryStore(), AsyncMock(return_value={'scope': scope, 'owner_id': 'owner'}),
                                      self.worker, rate_counter=AsyncMock(return_value=0), audit=AsyncMock())

    async def test_new_engagement_denies_all_execution_until_profiled(self):
        service = self.service({'targets': ['192.168.77.20'], 'exclusions': [], 'profile_required': True})
        with self.assertRaises(HTTPException) as denied:
            await service.propose('owner', 'engagement', 'curl http://192.168.77.20/', 'curl')
        detail = denied.exception.detail
        self.assertEqual(detail.get('reason') if isinstance(detail, dict) else None, 'profile_required')
        self.worker.assert_not_awaited()

    async def test_profiled_engagement_stays_profile_required(self):
        scope = apply_profile({'targets': ['192.168.77.20']}, lab(), 1, 'owner', 'migrate legacy engagement')
        self.assertTrue(scope['profile_required'])
        from memory.engagement_profiles import describe
        self.assertEqual(describe(None, True)['state'], 'profile_required')
        self.assertEqual(describe(None)['state'], 'legacy')

    async def test_legacy_engagement_rules_are_unchanged_not_widened(self):
        legacy = {'targets': ['192.168.77.20'], 'exclusions': []}
        service = self.service(legacy)
        self.assertEqual((await service.propose('owner', 'engagement', 'curl http://192.168.77.20/', 'curl')).status,
                         'authorized')
        with self.assertRaises(HTTPException):          # omission of a profile grants nothing beyond the legacy scope
            await service.propose('owner', 'engagement', 'curl http://192.168.77.21/', 'curl')

    async def test_session_creation_sets_requirement_and_rejects_client_flags(self):
        from api.auth import get_current_user
        from api.main import app
        app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(user_id='owner', role='admin')
        create = AsyncMock(return_value={'session_id': 'new'})
        try:
            with patch('api.routers.sessions.session_manager.create_session', create):
                ok = await self.client.post('/api/session/new', json={'target': '192.168.77.20'})
                forged = await self.client.post('/api/session/new', json={
                    'target': '192.168.77.20', 'scope': {'targets': ['192.168.77.20'], 'profile_required': False}})
        finally:
            app.dependency_overrides.pop(get_current_user, None)
        self.assertEqual(ok.status_code, 200, ok.text)
        assert create.await_args is not None
        self.assertTrue(create.await_args.args[4]['profile_required'])
        self.assertEqual(forged.status_code, 422)
