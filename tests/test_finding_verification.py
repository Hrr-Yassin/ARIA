"""Independent saved-evidence controls, durable review and isolation; no traffic."""
import copy
from contextlib import ExitStack
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pydantic import ValidationError
from memory.finding_verification import (
    Candidate, ContentControl, Review, Validation, VerificationStore, advance, current, duplicate_key, verify_content,
)
from memory.team_tasks import digest, materialize
from tests.support import OfflineCase
from memory.team_tasks import TeamStore


def review(state, revision, **kwargs):
    return Review(request_id=uuid.uuid4(), expected_revision=revision, state=state,
                  reason='Independent inspection of saved lab observations', **kwargs)


def validation(positive='p1', negative='n1', **kwargs):
    values = dict(steps=['Reset the synthetic fixture', 'Read the controlled private object as the other account'],
        evidence_references=[positive], negative_control_references=[negative],
        ownership_references=['owner'], permission_references=['permission'],
        account_and_object='Researcher accounts A and B; object owned by A',
        expected_permission='B must be denied access to the private object',
        meaningful_content='Private synthetic marker in original JSON; generic HTTP 200 excluded',
        demonstrated_impact='B reads the private synthetic object',
        clean_state_procedure='Reset lab fixture and use fresh isolated sessions',
        clean_state=True, negative_control_passed=True, controlled_accounts_and_objects=True,
        meaningful_content_confirmed=True, observed_behavior='violation')
    return Validation(**{**values, **kwargs})


class FindingVerification(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.events = []
        self.pending = []
        self.session = SimpleNamespace(id='engagement', user_id='owner', scope={'targets':['app.example.test']}, metadata_={})
        async def commit():
            self.events.extend(copy.deepcopy(row.metadata_) for row in self.pending)
            self.pending.clear()
        self.db = SimpleNamespace(add=self.pending.append, commit=AsyncMock(side_effect=commit))
        cm = AsyncMock(); cm.__aenter__.return_value = self.db
        self.stack = ExitStack()
        self.stack.enter_context(patch('memory.team_tasks.async_session', return_value=cm))
        self.stack.enter_context(patch('memory.team_tasks.owned_engagement', AsyncMock(return_value=self.session)))
        self.stack.enter_context(patch.object(TeamStore, '_events', AsyncMock(side_effect=lambda *args: copy.deepcopy(self.events))))
        self.store = TeamStore()

    async def asyncTearDown(self):
        self.stack.close()
        await super().asyncTearDown()


    async def seed(self):
        for ref in ['initial', 'owner', 'permission', 'p1', 'n1', 'p2', 'n2']:
            self.events.append({'collection': 'evidence', 'entity_id': ref,
                'sequence': len(self.events) + 1, 'id': str(uuid.uuid4()),
                'data': {'id': ref, 'hashes': {'content_sha256': digest({'ref': ref})},
                         'source_kind': 'chat', 'source_id': ref}})
        self.events.append({'collection': 'tasks', 'entity_id': 'specialist',
            'sequence': len(self.events) + 1, 'id': str(uuid.uuid4()),
            'data': {'id': 'specialist', 'specialty': 'authorization',
                     'result': {'evidence_references': ['initial']}}})
        from tests.test_authorization_review import fixture, encoded
        self.session.scope = {'targets': ['lab.test']}
        self.mapped = fixture()
        for identity in self.mapped['identities'].values():
            identity['credentials'] = {}
        template = self.mapped['captures']['c2']
        for cid, source_id, private in [('c1', 'owner', True), ('c2', 'p1', True),
                ('n1', 'n1', False), ('p2', 'p2', True), ('n2', 'n2', False)]:
            capture = copy.deepcopy(template)
            capture['identity_id'] = 'a' if cid == 'c1' else 'b'
            capture['evidence_id'] = source_id
            payload = b'{"secret":"synthetic-private-marker"}' if private else b'{"error":"denied"}'
            capture['original']['response_b64'] = encoded(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n' + payload)
            self.mapped['captures'][cid] = capture
        self.mapped['objects']['o']['evidence_ids'] = ['owner']
        self.stack.enter_context(patch('memory.application_map.application_map._load',
            AsyncMock(side_effect=lambda *args: (self.session, None, self.mapped))))
        self.verification = VerificationStore()
        self.body = Candidate(request_id=uuid.uuid4(), title='Private object exposed',
            underlying_cause='Missing object authorization', affected_workflow='Read private object',
            hypothesis='Other account can read object', expected_behavior='Deny other account',
            evidence_references=['initial'], specialist_task_id='specialist',
            potential_escalation='Other object classes are untested')
        event = await self.verification.create('engagement', 'owner', self.body)
        return event['data']

    async def step(self, finding, target, **kwargs):
        event = await self.verification.review('engagement', 'owner', finding['id'],
            review(target, finding['revision'], **kwargs))
        return event['data']

    async def test_independent_lab_path_persists_signoff_and_stops(self):
        finding = await self.seed()
        finding = await self.step(finding, 'hypothesis')
        control = ContentControl(object_id='o', owner_capture_id='c1', outsider_capture_id='c2',
                                 negative_capture_id='n1', private_json_key='secret')
        finding = await self.step(finding, 'tested', validation=validation(content_control=control))
        finding = await self.step(finding, 'reproduced', validation=validation('p2', 'n2',
            content_control=control.model_copy(update={'outsider_capture_id': 'p2', 'negative_capture_id': 'n2'})))
        with self.assertRaises(HTTPException):
            await self.step(finding, 'reviewed')
        finding = await self.step(finding, 'reviewed', human_signoff=True)
        finding = await self.step(finding, 'reportable', human_signoff=True)
        self.assertTrue(finding['stop_testing'])
        self.assertEqual(finding['human_signoff']['actor'], 'owner')
        self.assertEqual(finding['test']['demonstrated_impact'], 'B reads the private synthetic object')
        # Re-materializing persisted events is the restart path; no worker is invoked.
        restored = materialize(copy.deepcopy(self.events))['verification_findings'][finding['id']]
        self.assertEqual(restored, finding)
        view = await VerificationStore().view('engagement', 'owner')
        self.assertTrue(view['findings'][0]['ready_for_external_submission'])
        self.assertEqual(view['private_program_duplicates'], 'unknown')
        self.mapped['captures']['p2']['expired'] = True
        view = await self.verification.view('engagement', 'owner')
        self.assertFalse(view['findings'][0]['ready_for_external_submission'])

    async def test_no_skips_reuse_stale_revision_or_model_agreement(self):
        finding = await self.seed()
        for target in ['tested', 'reproduced', 'reviewed', 'reportable']:
            with self.assertRaises(HTTPException):
                await self.step(finding, target, human_signoff=True)
        finding = await self.step(finding, 'hypothesis')
        with self.assertRaises(HTTPException):
            await self.step(finding, 'tested')
        with self.assertRaises(HTTPException):
            await self.verification.review('engagement', 'owner', finding['id'], review('tested', 1, validation=validation()))
        finding = await self.step(finding, 'tested', validation=validation())
        with self.assertRaises(HTTPException):
            await self.step(finding, 'reproduced', validation=validation())
        finding = await self.step(finding, 'reproduced', validation=validation('p2', 'n2'))
        with self.assertRaises(HTTPException):
            await self.step(finding, 'reviewed', human_signoff=True)
        with self.assertRaises(ValidationError):
            Review(request_id=uuid.uuid4(), expected_revision=3, state='reportable', reason='Models agree', confidence=1)

    async def test_secure_misleading_missing_and_alias_controls(self):
        finding = await self.seed()
        finding = await self.step(finding, 'hypothesis')
        for behavior in ['expected', 'ambiguous']:
            with self.assertRaises(HTTPException):
                await self.step(finding, 'tested', validation=validation(observed_behavior=behavior))
        for changes in [{'evidence_references': ['foreign']}, {'negative_control_references': ['p1']}]:
            with self.assertRaises(HTTPException):
                await self.step(finding, 'tested', validation=validation(**changes))
        state = materialize(self.events)
        state['evidence']['n1']['source_id'] = 'p1'
        with self.assertRaises(HTTPException):
            advance(finding, review('tested', finding['revision'], validation=validation()), state, self.session.scope, 'owner')
        with self.assertRaises(ValidationError):
            validation(meaningful_content='   ')
        for field in ['clean_state', 'negative_control_passed', 'controlled_accounts_and_objects', 'meaningful_content_confirmed']:
            with self.assertRaises(ValidationError):
                validation(**{field: False})
        blocked = await self.step(finding, 'inconclusive', smallest_missing_validation='Inspect private JSON marker against a public-page control')
        self.assertEqual(blocked['state'], 'inconclusive')
        rejected = await self.step(await self.step(blocked, 'hypothesis'), 'rejected')
        self.assertEqual(rejected['state'], 'rejected')

    async def test_scope_evidence_revocation_and_revalidation(self):
        finding = await self.seed()
        finding = await self.step(finding, 'hypothesis')
        self.session.scope = {'targets': ['changed.example.test']}
        with self.assertRaises(HTTPException):
            await self.step(finding, 'tested', validation=validation())
        blocked = await self.step(finding, 'blocked', smallest_missing_validation='Recheck authorization under changed scope')
        finding = await self.step(blocked, 'hypothesis')
        finding = await self.step(finding, 'tested', validation=validation())
        state = materialize(self.events)
        del state['evidence']['p1']
        self.assertFalse(current(finding, state, self.session.scope))
        with self.assertRaises(HTTPException):
            advance(finding, review('reproduced', finding['revision'], validation=validation('p2', 'n2')),
                    state, self.session.scope, 'owner')

    async def test_duplicate_retry_conflict_and_attribution(self):
        finding = await self.seed()
        retried = await self.verification.create('engagement', 'owner', self.body)
        self.assertTrue(retried['duplicate'])
        with self.assertRaises(HTTPException):
            await self.verification.create('engagement', 'owner', self.body.model_copy(update={'title': 'Changed'}))
        duplicate = await self.verification.create('engagement', 'owner', self.body.model_copy(update={'request_id': uuid.uuid4()}))
        self.assertEqual(duplicate['data']['local_duplicate_candidates'], [finding['id']])
        self.assertEqual(duplicate_key(' MISSING  authorization ', 'READ'), duplicate_key('missing authorization', 'read'))
        with self.assertRaises(HTTPException):
            await self.verification.create('engagement', 'owner', self.body.model_copy(update={'request_id': uuid.uuid4(), 'evidence_references': ['owner']}))

    async def test_owner_denial_storage_failure_and_review_retry(self):
        finding = await self.seed()
        with patch('memory.team_tasks.owned_engagement', AsyncMock(side_effect=HTTPException(404))):
            with self.assertRaises(HTTPException):
                await self.verification.view('engagement', 'outsider')
            with self.assertRaises(HTTPException):
                await self.step(finding, 'hypothesis')
        body = review('hypothesis', 1)
        first = await self.verification.review('engagement', 'owner', finding['id'], body)
        retry = await self.verification.review('engagement', 'owner', finding['id'], body)
        self.assertEqual(first['id'], retry['id'])
        self.assertTrue(retry['duplicate'])
        before = copy.deepcopy(self.events)
        self.db.commit.side_effect = RuntimeError('Storage unavailable')
        with self.assertRaises(RuntimeError):
            await self.step(first['data'], 'tested', validation=validation())
        self.assertEqual(self.events, before)

    async def test_original_content_controls_reject_generic_success_and_public_access(self):
        await self.seed()
        control = ContentControl(object_id='o', owner_capture_id='c1', outsider_capture_id='c2',
                                 negative_capture_id='n1', private_json_key='secret')
        state = materialize(self.events)
        run = validation(content_control=control).model_dump()
        self.assertTrue(verify_content(self.mapped, control, run, state)['private_content_match'])
        from tests.test_authorization_review import encoded
        original = self.mapped['captures']['c2']['original']['response_b64']
        self.mapped['captures']['c2']['original']['response_b64'] = encoded(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nPublic login page')
        with self.assertRaises(HTTPException):
            verify_content(self.mapped, control, run, state)
        self.mapped['captures']['c2']['original']['response_b64'] = original
        self.mapped['permissions']['p']['expected'] = 'allow'
        with self.assertRaises(HTTPException):
            verify_content(self.mapped, control, run, state)
