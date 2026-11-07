"""Evidence-to-report acceptance and denied export; all storage/transports are doubles."""
import copy
import io
import json
import uuid
import zipfile
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pydantic import ValidationError
from api.auth import get_current_user
from api.main import app
from memory.database_models import ChatLog, DecisionLog
from memory.finding_verification import ContentControl
from memory.professional_reports import (
    DraftInput, OutcomeInput, ReportSignoff, RetestInput, TriageInput,
    ProfessionalReportStore, sha, render_report, export_secrets,
)
from memory.team_tasks import TeamStore, digest, materialize
from tests import test_finding_verification as verification_fixtures
from tests.support import OfflineCase
from tests.test_access import OWNER


class ProfessionalReports(OfflineCase):
    seed = verification_fixtures.FindingVerification.seed
    step = verification_fixtures.FindingVerification.step

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.events, self.pending, self.bundles, self.sources = [], [], {}, {}
        self.session = SimpleNamespace(id='engagement', user_id='owner', scope={}, metadata_={})
        async def commit():
            for row in self.pending:
                if row.decision_type == 'team_event':
                    self.events.append(copy.deepcopy(row.metadata_))
                else:
                    self.bundles[row.id] = copy.deepcopy(row)
            self.pending.clear()
        async def get(model, key):
            if model is DecisionLog:
                return self.bundles.get(key)
            if model is ChatLog:
                content = self.sources.get(key, json.dumps({'ref': key}, sort_keys=True, separators=(',', ':')))
                return SimpleNamespace(session_id='engagement', role='tool_output', content=content)
            raise AssertionError('Unexpected model')
        self.db = SimpleNamespace(add=self.pending.append, commit=AsyncMock(side_effect=commit), get=AsyncMock(side_effect=get))
        cm = AsyncMock(); cm.__aenter__.return_value = self.db
        self.stack = ExitStack()
        self.stack.enter_context(patch('memory.team_tasks.async_session', return_value=cm))
        self.stack.enter_context(patch('memory.team_tasks.owned_engagement', AsyncMock(return_value=self.session)))
        self.stack.enter_context(patch.object(TeamStore, '_events', AsyncMock(side_effect=lambda *args: copy.deepcopy(self.events))))
        self.store = TeamStore()
        self.reports = ProfessionalReportStore()

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        self.stack.close()
        await super().asyncTearDown()

    async def ready(self, large_source=False):
        finding = await self.seed()
        if large_source:
            self.sources['initial'] = 'Synthetic lab supporting evidence. ' * 200 + 'END-OF-COMPLETE-EVIDENCE'
            entry = next(event['data'] for event in self.events if event['collection'] == 'evidence' and event['entity_id'] == 'initial')
            entry['hashes'] = {'content_sha256': sha(self.sources['initial'].encode())}
        finding = await self.step(finding, 'hypothesis')
        control = ContentControl(object_id='o', owner_capture_id='c1', outsider_capture_id='c2',
                                 negative_capture_id='n1', private_json_key='secret')
        finding = await self.step(finding, 'tested', validation=verification_fixtures.validation(content_control=control))
        finding = await self.step(finding, 'reproduced', validation=verification_fixtures.validation('p2', 'n2',
            content_control=control.model_copy(update={'outsider_capture_id': 'p2', 'negative_capture_id': 'n2'})))
        finding = await self.step(finding, 'reviewed', human_signoff=True)
        return await self.step(finding, 'reportable', human_signoff=True)

    async def create_report(self, finding, template='bug_bounty', **changes):
        body = DraftInput(request_id=uuid.uuid4(), template=template, finding_ids=[finding['id']], **changes)
        return (await self.reports.create('engagement', 'owner', body))['data']

    async def sign(self, report):
        return await self.reports.signoff('engagement', 'owner', report['id'], ReportSignoff(
            request_id=uuid.uuid4(), package_sha256=report['package_sha256'], human_review=True,
            reproduced_from_report=True, redactions_reviewed=True, reason='Reproduced from exact draft and inspected attachments'))

    async def test_complete_reproduction_report_preview_signoff_and_export(self):
        finding = await self.ready(large_source=True)
        report = await self.create_report(finding)
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', report['id'])
        preview = await self.reports.preview('engagement', 'owner', report['id'])
        for label in ['Asset', 'Prerequisites', 'Expected behavior', 'Actual behavior', 'Demonstrated impact',
                      'Remediation', 'Independent reproduction', 'Negative control']:
            self.assertIn(label, preview['files']['report.md'])
        self.assertTrue(any('END-OF-COMPLETE-EVIDENCE' in value for value in preview['files'].values()))
        self.assertEqual(len([name for name in preview['files'] if name.endswith('.http')]), 10)
        manifest = json.loads(preview['files']['manifest.json'])
        self.assertEqual(len(manifest['evidence']), 7)
        await self.sign(report)
        bundle, fingerprint = await self.reports.export('engagement', 'owner', report['id'])
        self.assertEqual(sha(bundle), fingerprint)
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            self.assertEqual(archive.read('report.md').decode(), preview['files']['report.md'])
            for item in manifest['evidence']:
                for attached in item['files']:
                    self.assertEqual(sha(archive.read(attached['path'])), attached['export_sha256'])
        restored = materialize(copy.deepcopy(self.events))
        self.assertEqual(restored['report_drafts'][report['id']], report)
        self.assertEqual(restored['report_signoffs'][report['id']]['package_sha256'], fingerprint)
        # Full evidence is encrypted separately from public ledger/events.
        self.assertTrue(all('sealed' not in event['data'] for event in self.events))
        self.assertTrue(all('END-OF-COMPLETE-EVIDENCE' not in row.metadata_['sealed'] for row in self.bundles.values()))

    async def test_only_current_verified_claims_and_distinct_observations(self):
        finding = await self.seed()
        with self.assertRaises(HTTPException):
            await self.create_report(finding)
        report = (await self.reports.create('engagement', 'owner', DraftInput(
            request_id=uuid.uuid4(), template='pentest', observation_ids=[finding['id']])) )['data']
        self.assertEqual(report['document']['findings'], [])
        self.assertEqual(report['document']['observations'][0]['state'], 'observation')
        self.assertIn('No verified findings', report['markdown'])
        self.assertIn('unverified', report['markdown'])
        await self.sign(report)
        with self.assertRaises(HTTPException):
            await self.reports.create('engagement', 'owner', DraftInput(request_id=uuid.uuid4(),
                template='pentest', finding_ids=['foreign-finding']))
        with self.assertRaises(ValidationError):
            DraftInput(request_id=uuid.uuid4(), template='bug_bounty', finding_ids=[])
        with self.assertRaises(ValidationError):
            DraftInput(request_id=uuid.uuid4(), template='pentest', finding_ids=['x'], observation_ids=['x'])

    async def test_revoked_scope_evidence_permissions_and_finding_block_exports(self):
        finding = await self.ready()
        report = await self.create_report(finding)
        await self.sign(report)
        original_scope = self.session.scope
        self.session.scope = {'targets': ['changed.test']}
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', report['id'])
        self.session.scope = original_scope
        self.mapped['permissions']['p']['expected'] = 'allow'
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', report['id'])
        self.mapped['permissions']['p']['expected'] = 'deny'
        self.mapped['captures']['p2']['expired'] = True
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', report['id'])
        self.mapped['captures']['p2']['expired'] = False
        self.sources['initial'] = 'Modified original supporting source'
        with self.assertRaises(HTTPException):
            await self.reports.preview('engagement', 'owner', report['id'])
        self.sources.clear()
        await self.step(finding, 'rejected')
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', report['id'])

    async def test_immutable_revisions_exact_hash_retry_and_storage_failure(self):
        finding = await self.ready()
        body = DraftInput(request_id=uuid.uuid4(), template='pentest', finding_ids=[finding['id']])
        first = await self.reports.create('engagement', 'owner', body)
        self.assertTrue((await self.reports.create('engagement', 'owner', body))['duplicate'])
        with self.assertRaises(HTTPException):
            await self.reports.create('engagement', 'owner', body.model_copy(update={'template': 'bug_bounty'}))
        report = first['data']
        with self.assertRaises(HTTPException):
            await self.reports.signoff('engagement', 'owner', report['id'], ReportSignoff(request_id=uuid.uuid4(),
                package_sha256='0' * 64, human_review=True, reproduced_from_report=True, redactions_reviewed=True, reason='Wrong revision'))
        signed = await self.sign(report)
        next_report = await self.create_report(finding, 'pentest', previous_report_id=report['id'])
        self.assertEqual(next_report['revision'], 2)
        self.assertEqual(next_report['root_id'], report['id'])
        self.assertEqual(materialize(self.events)['report_signoffs'][report['id']], signed['data'])
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', next_report['id'])
        with self.assertRaises(HTTPException):
            await self.create_report(finding, 'pentest', previous_report_id=report['id'])
        before = copy.deepcopy(self.events)
        self.db.commit.side_effect = RuntimeError('Storage unavailable')
        with self.assertRaises(RuntimeError):
            await self.create_report(finding, 'pentest', previous_report_id=next_report['id'])
        self.assertEqual(self.events, before)

    async def test_complete_bundle_redaction_and_no_markdown_execution(self):
        finding = await self.ready()
        # A known credential outside the selected identities must also be removed.
        self.mapped['identities']['unused'] = {'credentials': {'authorization': 'Bearer report-credential-canary'},
            'active': True, 'researcher_controlled': True}
        for ref in ('initial', 'permission'):
            self.sources[ref] = 'Authorization: Bearer report-credential-canary\n<script>alert(1)</script> [click](https://bad.test)'
            entry = next(event['data'] for event in self.events if event['collection'] == 'evidence' and event['entity_id'] == ref)
            entry['hashes'] = {'content_sha256': sha(self.sources[ref].encode())}
        # New private map metadata invalidates the old Phase 5 control fingerprint.
        with self.assertRaises(HTTPException):
            await self.create_report(finding)
        # Preserve the gate: create a new finding from the changed saved evidence and review it.
        finding = await self.step(finding, 'blocked', smallest_missing_validation='Recheck after evidence change')
        finding = await self.step(finding, 'hypothesis')
        control = ContentControl(object_id='o', owner_capture_id='c1', outsider_capture_id='c2', negative_capture_id='n1', private_json_key='secret')
        finding = await self.step(finding, 'tested', validation=verification_fixtures.validation(content_control=control))
        finding = await self.step(finding, 'reproduced', validation=verification_fixtures.validation('p2', 'n2', content_control=control.model_copy(update={'outsider_capture_id': 'p2', 'negative_capture_id': 'n2'})))
        finding = await self.step(finding, 'reviewed', human_signoff=True)
        finding = await self.step(finding, 'reportable', human_signoff=True)
        report = await self.create_report(finding)
        preview = await self.reports.preview('engagement', 'owner', report['id'])
        self.assertNotIn('report-credential-canary', json.dumps(preview))
        document = copy.deepcopy(report['document'])
        document['findings'][0]['title'] = '<script>alert(1)</script> [click](https://bad.test)'
        markdown = render_report(document)
        self.assertNotIn('<script>', markdown)
        self.assertIn('\\[click\\]', markdown)
        self.assertIn('Potential escalation (unverified)', markdown)
        from memory.application_map import sanitize
        from urllib.parse import quote
        secret = 'tést-token-check'
        mapped = copy.deepcopy(self.mapped)
        mapped['identities']['unused']['credentials'] = {'authorization': 'Bearer ' + secret}
        encoded = json.dumps(secret, ensure_ascii=True)[1:-1]
        redacted = sanitize(secret + ' ' + encoded + ' ' + quote(secret, safe=''), export_secrets(mapped))
        self.assertNotIn(secret, redacted)
        self.assertNotIn(encoded, redacted)
        self.assertNotIn(quote(secret, safe=''), redacted)

    async def test_outcome_history_payment_separation_and_revision_isolation(self):
        finding = await self.ready()
        report = await self.create_report(finding)
        await self.sign(report)
        def outcome(status, revision, **changes):
            return OutcomeInput(request_id=uuid.uuid4(), expected_revision=revision, status=status,
                external_action_recorded=True, platform_reference='Synthetic triage ID 123', note='Human-recorded platform response', **changes)
        with self.assertRaises(HTTPException):
            await self.reports.outcome('engagement', 'owner', report['id'], outcome('accepted', 0))
        for index, status in enumerate(['submitted', 'triaged', 'duplicate', 'informative', 'rejected', 'accepted', 'resolved', 'paid']):
            body = outcome(status, index, **({'amount': '125.50', 'currency': 'USD'} if status == 'paid' else {}))
            event = await self.reports.outcome('engagement', 'owner', report['id'], body)
            self.assertTrue((await self.reports.outcome('engagement', 'owner', report['id'], body))['duplicate'])
        history = event['data']['history']
        self.assertEqual(len(history), 8)
        self.assertEqual(history[-1]['amount'], '125.50')
        self.assertTrue(all(item['amount'] is None for item in history[:-1]))
        with self.assertRaises(HTTPException):
            await self.reports.outcome('engagement', 'owner', report['id'], outcome('triaged', 0))
        with self.assertRaises(ValidationError):
            outcome('accepted', 8, amount='100', currency='USD')
        with self.assertRaises(ValidationError):
            outcome('paid', 8)

    async def test_saved_triage_and_retest_never_execute_or_rewrite_findings(self):
        finding = await self.ready()
        report = await self.create_report(finding)
        await self.sign(report)
        ref = 'fresh-retest'
        content = json.dumps({'ref': ref}, sort_keys=True, separators=(',', ':'))
        self.events.append({'collection': 'evidence', 'entity_id': ref, 'sequence': len(self.events) + 1,
            'id': str(uuid.uuid4()), 'data': {'id': ref, 'hashes': {'content_sha256': sha(content.encode())},
                                           'source_kind': 'chat', 'source_id': ref}})
        body = RetestInput(request_id=uuid.uuid4(), finding_id=finding['id'], expected_scope_digest=report['scope_digest'],
            result='fixed', evidence_references=[ref], human_review=True, rationale='Saved fresh lab observation denies the outsider')
        event = await self.reports.retest('engagement', 'owner', report['id'], body)
        self.assertFalse(event['data']['execution_performed'])
        self.assertEqual(materialize(self.events)['verification_findings'][finding['id']], finding)
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', report['id'])
        next_report = await self.create_report(finding, previous_report_id=report['id'])
        self.assertIn('fixed', next_report['markdown'])
        self.session.scope = {'targets': ['new-scope.test']}
        with self.assertRaises(HTTPException):
            await self.reports.retest('engagement', 'owner', report['id'], body.model_copy(update={'request_id': uuid.uuid4()}))
        triage = await self.reports.triage('engagement', 'owner', report['id'], TriageInput(
            request_id=uuid.uuid4(), finding_id=finding['id'], topic='impact'))
        self.assertTrue(triage['data']['scope_changed'])
        self.assertFalse(triage['data']['sent'])
        self.assertIn('Historical observations', triage['data']['text'])
        self.assertIn('Unverified potential escalation', triage['data']['text'])

    async def test_owner_only_routes_and_signed_export_headers(self):
        finding = await self.ready()
        report = await self.create_report(finding)
        app.dependency_overrides[get_current_user] = lambda: OWNER
        response = await self.client.get(f"/api/report/engagement/drafts/{report['id']}/preview")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['signed'])
        await self.sign(report)
        response = await self.client.get(f"/api/report/engagement/drafts/{report['id']}/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['x-report-sha256'], sha(response.content))
        self.assertEqual(response.headers['cache-control'], 'no-store')
        with patch('memory.team_tasks.owned_engagement', AsyncMock(side_effect=HTTPException(404))):
            response = await self.client.get(f"/api/report/foreign/drafts/{report['id']}/export")
            self.assertEqual(response.status_code, 404)
            response = await self.client.post('/api/report/foreign/drafts', json={'request_id': str(uuid.uuid4()),
                'template': 'pentest', 'finding_ids': [finding['id']]})
            self.assertEqual(response.status_code, 404)

    async def test_bundle_integrity_and_missing_complete_sources_fail_closed(self):
        finding = await self.ready()
        report = await self.create_report(finding)
        await self.sign(report)
        row = self.bundles[report['bundle_id']]
        original = row.metadata_['sealed']
        row.metadata_['sealed'] = 'invalid-ciphertext'
        with self.assertRaises(HTTPException):
            await self.reports.export('engagement', 'owner', report['id'])
        row.metadata_['sealed'] = original
        original_get = self.db.get.side_effect
        async def missing(model, key):
            if model is ChatLog and key == 'initial':
                return None
            return await original_get(model, key)
        self.db.get.side_effect = missing
        with self.assertRaises(HTTPException):
            await self.reports.preview('engagement', 'owner', report['id'])

    async def test_report_claims_are_bounded_by_the_content_verifier(self):
        finding = await self.ready()
        report = await self.create_report(finding)
        exported = report['document']['findings'][0]
        self.assertTrue(exported['title'].startswith('Private JSON disclosure on '))
        self.assertIn('selected private JSON value', exported['impact'])
        self.assertIn('have not been demonstrated', exported['impact'])
        self.assertEqual(exported['priority'], 'unrated')
        with self.assertRaises(ValidationError):
            DraftInput(request_id=uuid.uuid4(), template='bug_bounty', finding_ids=[finding['id']],
                impact='Unproven code execution supplied by a model')
