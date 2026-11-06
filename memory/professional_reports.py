"""Immutable, evidence-bound report drafts and human-recorded outcomes. No target I/O."""
import base64
import hashlib
import html
import io
import json
import re
import uuid
import zipfile
from decimal import Decimal
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import quote, quote_plus

from fastapi import HTTPException
from pydantic import Field, model_validator
from memory import team_tasks
from memory.application_map import application_map, known_secrets, sanitize, capture_metadata
from memory.database_models import ChatLog, DecisionLog
from memory.finding_verification import ContentControl, current, verify_content, evidence_snapshot
from memory.team_tasks import Strict, Reference, Criterion, digest, materialize, team_store
from orchestrator.execution_policy import PolicyError
from security.encryption import evidence_cipher

MAX_BUNDLE_BYTES = 16 * 1024 * 1024
LIMITATIONS = [
    'Verified findings are limited to the supervised private-JSON disclosure controls supported by Phase 5.',
    'Ownership, permission intent and clean-state execution are human-reviewed assertions supported by saved evidence.',
    'Potential escalation is unverified; model confidence, labels and HTTP success alone are not proof.',
    'Attachments contain complete saved bounded observations with credential redaction; redaction can change byte lengths.',
    'No request, retest, platform submission or provider call is performed by this report workflow.',
    'Private program duplicate status is unknown. Coverage and retest conclusions are human assertions.',
]


class Recommendation(Strict):
    finding_id: Reference
    priority: Literal['critical', 'high', 'medium', 'low', 'info', 'unrated'] = 'unrated'
    remediation: Criterion


class DraftInput(Strict):
    request_id: uuid.UUID
    template: Literal['bug_bounty', 'pentest']
    finding_ids: list[Reference] = Field(default_factory=list, max_length=20)
    observation_ids: list[Reference] = Field(default_factory=list, max_length=50)
    recommendations: list[Recommendation] = Field(default_factory=list, max_length=20)
    previous_report_id: Reference | None = None

    @model_validator(mode='after')
    def selection(self):
        selected = self.finding_ids + self.observation_ids
        if len(set(selected)) != len(selected):
            raise ValueError('Select distinct findings and observations')
        if self.template == 'bug_bounty' and (len(self.finding_ids) != 1 or self.observation_ids):
            raise ValueError('Bug bounty drafts require exactly one reportable finding')
        ids = [item.finding_id for item in self.recommendations]
        if len(set(ids)) != len(ids) or not set(ids).issubset(self.finding_ids):
            raise ValueError('Recommendations must refer to distinct selected verified findings')
        if any(not item.remediation.strip() for item in self.recommendations):
            raise ValueError('A substantive remediation recommendation is required')
        return self


class ReportSignoff(Strict):
    request_id: uuid.UUID
    package_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    human_review: Literal[True]
    reproduced_from_report: Literal[True]
    redactions_reviewed: Literal[True]
    reason: Criterion


class OutcomeInput(Strict):
    request_id: uuid.UUID
    expected_revision: int = Field(ge=0)
    status: Literal['submitted', 'triaged', 'duplicate', 'informative', 'rejected', 'accepted', 'resolved', 'paid']
    external_action_recorded: Literal[True]
    platform_reference: Criterion
    note: Criterion
    amount: Decimal | None = Field(default=None, gt=0, max_digits=12, decimal_places=2)
    currency: str | None = Field(default=None, pattern=r'^[A-Z]{3}$')

    @model_validator(mode='after')
    def payment(self):
        if self.status == 'paid':
            if self.amount is None or self.currency is None:
                raise ValueError('Paid outcomes require actual amount and currency')
        elif self.amount is not None or self.currency is not None:
            raise ValueError('Record payment only with a paid outcome')
        return self


class RetestInput(Strict):
    request_id: uuid.UUID
    finding_id: Reference
    expected_scope_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    result: Literal['fixed', 'still_vulnerable', 'inconclusive']
    evidence_references: list[Reference] = Field(min_length=1, max_length=30)
    human_review: Literal[True]
    rationale: Criterion


class TriageInput(Strict):
    request_id: uuid.UUID
    finding_id: Reference
    topic: Literal['reproduction', 'impact', 'scope', 'retest']


def export_secrets(mapped: dict) -> list[str]:
    values = set(known_secrets(mapped))
    # Captures may represent credentials as JSON escapes, UTF-8 octets or URL text.
    for value in list(values):
        values.update((json.dumps(value, ensure_ascii=True)[1:-1], quote(value, safe=''),
                       quote_plus(value, safe=''), value.encode('utf-8').decode('iso-8859-1')))
    return sorted(values, key=len, reverse=True)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded_json(value) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True)


def markdown_text(value) -> str:
    # Render untrusted text as literal text, including target HTML and Markdown links.
    text = html.escape(str(value), quote=True)
    return re.sub(r'([\\`*_{}\[\]()#+.!|>~-])', r'\\\1', text)


def render_report(document: dict) -> str:
    lines = ['# ' + ('Bug bounty draft' if document['template'] == 'bug_bounty' else 'Pentest report draft'),
             '', 'Human-reviewed draft. External submission is a separate human action.', '',
             '## Scope', '', markdown_text(encoded_json(document['scope'])), '', '## Limitations', '']
    lines.extend('- ' + markdown_text(item) for item in document['limitations'])
    lines += ['', '## Coverage (recorded assertions)', '']
    for item in document['coverage']:
        lines.append('- ' + markdown_text(f"{item['question']} — {item['status']}; gap: {item.get('gap_reason', '')}"))
    if not document['coverage']:
        lines.append('No coverage assertions recorded; untested areas remain unknown.')
    lines += ['', '## Verified findings', '']
    if not document['findings']:
        lines.append('No verified findings selected. This is not assurance that the application is secure.')
    for finding in document['findings']:
        lines += ['### ' + markdown_text(finding['title']), '', 'Finding ID: ' + markdown_text(finding['id']), '']
        for label, key in [('Asset', 'asset'), ('Prerequisites', 'prerequisites'),
                           ('Expected behavior', 'expected'), ('Actual behavior', 'actual'),
                           ('Demonstrated impact', 'impact'), ('Potential escalation (unverified)', 'potential_escalation'),
                           ('Priority (human recommendation)', 'priority'), ('Remediation recommendation', 'remediation')]:
            lines += ['**' + label + '**', '', markdown_text(finding[key]), '']
        for label, key in [('Initial test', 'test'), ('Independent reproduction', 'reproduction')]:
            run = finding[key]
            lines += ['**' + label + '**', '', 'Clean state: ' + markdown_text(run['clean_state_procedure']), '']
            lines += [f'{index}. {markdown_text(step)}' for index, step in enumerate(run['steps'], 1)]
            lines += ['', 'Expected permission: ' + markdown_text(run['expected_permission']), '',
                      'Negative control: ' + markdown_text(', '.join(run['negative_control_references'])), '']
        lines += ['**Evidence attachments**', '']
        lines.extend('- ' + markdown_text(path) for path in finding['attachments'])
        lines += ['', '**Retest status (human-recorded)**', '']
        retests = [item for item in document['retests'] if item['finding_id'] == finding['id']]
        lines.extend(markdown_text(item['result'] + ': ' + item['rationale']) for item in retests)
        if not retests:
            lines.append('Not retested.')
        lines.append('')
    lines += ['## Observations and unresolved questions (unverified)', '']
    for observation in document['observations']:
        lines += ['- ' + markdown_text(f"{observation['title']} [{observation['state']}]: {observation['hypothesis']}"),
                  '  Evidence: ' + markdown_text(', '.join(observation['evidence_references']))]
    if not document['observations']:
        lines.append('No additional observations selected.')
    lines += ['', 'Full redacted attachments, source hashes, and finding/evidence bindings are in manifest.json.', '']
    return '\n'.join(lines)


def zip_bundle(files: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, content in sorted(files.items()):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content.encode('utf-8'))
    return output.getvalue()


def assert_verified(finding: dict, state: dict, scope: dict, mapped: dict) -> None:
    if finding['state'] != 'reportable' or not finding.get('human_signoff') or not current(finding, state, scope):
        raise HTTPException(409, 'Selected finding is not currently reportable')
    try:
        for key in ('test', 'reproduction'):
            run = finding[key]
            control = ContentControl(**run['content_control'])
            if verify_content(mapped, control, run, state) != run['content_verification']:
                raise HTTPException(409, 'Finding control evidence changed; revalidate before reporting')
            for cid in (control.owner_capture_id, control.outsider_capture_id, control.negative_capture_id):
                capture_metadata(mapped['captures'][cid]['original'], scope)
    except (KeyError, ValueError, TypeError, PolicyError):
        raise HTTPException(409, 'Finding original content or scope is unavailable') from None


def draft_id(sid: str, rid: uuid.UUID) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-report:{sid}:{rid}'))


async def source_files(db, sid: str, references: list[str], state: dict, mapped: dict) -> tuple[dict, list]:
    """Export complete retained sources or fail; catalog summaries are never substitutes."""
    files, manifest = {}, []
    secrets = export_secrets(mapped)
    for index, ref in enumerate(sorted(set(references))):
        evidence = state['evidence'][ref]
        entry = {'reference': ref, 'catalog': sanitize(evidence, secrets), 'files': [],
                 'redaction': 'Credentials removed; no excerpt truncation. Original hashes retained.',
                 'trust': 'Untrusted saved observation; only verified content controls establish report claims.'}
        captures = [item for item in mapped['captures'].values()
                    if evidence['source_kind'] == 'chat' and item['evidence_id'] == evidence['source_id']]
        if captures:
            capture = next((item for item in captures if not item.get('expired') and item.get('original')), None)
            if capture is None:
                raise HTTPException(410, 'Original report evidence expired or was revoked')
            for label in ('request', 'response'):
                raw = base64.b64decode(capture['original'][label + '_b64'], validate=True)
                path = f'evidence/{index:03d}-{label}.http'
                try:
                    decoded, encoding = raw.decode('utf-8'), 'UTF-8'
                except UnicodeDecodeError:
                    decoded, encoding = raw.decode('iso-8859-1'), 'ISO-8859-1'
                text = sanitize(decoded, secrets)
                files[path] = text
                entry['files'].append({'path': path, 'original_sha256': sha(raw),
                    'export_sha256': sha(text.encode()), 'original_bytes': len(raw), 'export_bytes': len(text.encode()),
                    'encoding': f'HTTP octets decoded as {encoding}, redacted, then encoded as UTF-8'})
        else:
            if evidence['source_kind'] != 'chat':
                raise HTTPException(409, 'Complete source evidence must be retained as a selected capture or tool-output chat record')
            source = await db.get(ChatLog, evidence['source_id'])
            if source is None or source.session_id != sid or source.role != 'tool_output':
                raise HTTPException(410, 'Complete supporting evidence unavailable')
            content = source.content or ''
            if sha(content.encode()) != evidence['hashes'].get('content_sha256'):
                raise HTTPException(409, 'Supporting source changed after cataloging')
            path = f'evidence/{index:03d}-source.txt'
            text = sanitize(content, secrets)
            files[path] = text
            entry['files'].append({'path': path, 'original_sha256': sha(content.encode()),
                'export_sha256': sha(text.encode()), 'original_bytes': len(content.encode()),
                'export_bytes': len(text.encode()), 'encoding': 'UTF-8 text'})
        manifest.append(entry)
        if sum(len(text.encode()) for text in files.values()) > MAX_BUNDLE_BYTES:
            raise HTTPException(413, 'Report evidence exceeds bundle limit; select fewer findings')
    return files, manifest


class ProfessionalReportStore:
    async def _read(self, sid: str, owner: str, operation):
        async with team_tasks.async_session() as db:
            session = await team_tasks.owned_engagement(db, sid, owner)
            state = materialize(await team_store._events(db, sid))
            return await operation(db, session, state)

    async def _mapped(self, db, sid: str, owner: str) -> dict:
        _, _, mapped = await application_map._load(db, sid, owner)
        return mapped

    async def create(self, sid: str, owner: str, body: DraftInput) -> dict:
        async def build(db, session, state):
            if len(state['report_drafts']) >= 100:
                raise HTTPException(409, 'Report draft limit reached')
            mapped = await self._mapped(db, sid, owner)
            secrets = export_secrets(mapped)
            selected = {}
            for fid in body.finding_ids + body.observation_ids:
                finding = state['verification_findings'].get(fid)
                if finding is None:
                    raise HTTPException(422, 'Finding is outside this engagement')
                if fid in body.finding_ids:
                    assert_verified(finding, state, session.scope or {}, mapped)
                selected[fid] = finding
            parent = state['report_drafts'].get(body.previous_report_id) if body.previous_report_id else None
            if body.previous_report_id:
                if not parent or parent['template'] != body.template:
                    raise HTTPException(422, 'Previous report must be an owned revision of the same template')
                if any(item.get('previous_report_id') == parent['id'] for item in state['report_drafts'].values()):
                    raise HTTPException(409, 'This report already has a newer revision')
            rid = draft_id(sid, body.request_id)
            retests = [item for item in state['report_retests'].values() if item['finding_id'] in body.finding_ids]
            refs = set(ref for item in selected.values() for ref in item['evidence_snapshot'])
            refs.update(ref for item in retests for ref in item['evidence_references'])
            evidence_snapshot(state, list(refs))
            files, manifest = await source_files(db, sid, sorted(refs), state, mapped)
            findings = []
            recommendations = {item.finding_id: item for item in body.recommendations}
            for fid in body.finding_ids:
                finding = selected[fid]
                run = finding['reproduction']
                control = run['content_control']
                recommendation = recommendations.get(fid)
                attachments = [file['path'] for entry in manifest if entry['reference'] in finding['evidence_snapshot'] for file in entry['files']]
                owner_id = mapped['objects'][control['object_id']]['owner_identity_id']
                outsider_id = mapped['captures'][control['outsider_capture_id']]['identity_id']
                asset = mapped['captures'][control['owner_capture_id']]['original']['url']
                prerequisites = f"Researcher-controlled owner identity {owner_id}, outsider identity {outsider_id}, controlled object {control['object_id']}. Supply fresh private credentials locally; attachments redact credentials."
                expected = 'The recorded, human-reviewed permission denies the outsider read access to this controlled private object.'
                actual = 'The saved outsider response contained the selected private JSON value matching the owner response; the separate negative-control response lacked that value.'
                impact = 'In the saved test and independent reproduction, the researcher-controlled outsider read the selected private JSON value from the controlled object. Further access and escalation have not been demonstrated.'
                # Generate only the claim proven by the supported verifier. Arbitrary specialist
                # titles and human impact prose cannot expand the demonstrated impact.
                def report_run(key):
                    return {**finding[key], 'account_and_object': prerequisites, 'expected_permission': expected,
                            'meaningful_content': actual, 'demonstrated_impact': impact}
                findings.append({'id': fid, 'title': 'Private JSON disclosure on ' + asset,
                    'asset': asset, 'prerequisites': prerequisites, 'expected': expected,
                    'actual': actual, 'impact': impact,
                    'potential_escalation': finding['potential_escalation'] or 'Not established.',
                    'priority': recommendation.priority if recommendation else 'unrated',
                    'remediation': recommendation.remediation if recommendation else 'Enforce server-side object authorization on every read; verify owner and outsider controls.',
                    'test': report_run('test'), 'reproduction': report_run('reproduction'), 'attachments': attachments,
                    'finding_revision': finding['revision']})
            document = sanitize({'template': body.template, 'scope': session.scope or {},
                'limitations': LIMITATIONS, 'coverage': list(state['coverage'].values()), 'findings': findings,
                'retests': retests, 'observations': [{key: selected[fid][key] for key in
                    ('id', 'title', 'state', 'hypothesis', 'evidence_references')} for fid in body.observation_ids]}, secrets)
            files['report.md'] = render_report(document)
            bindings = {fid: digest(item) for fid, item in selected.items()}
            files['manifest.json'] = encoded_json({'schema': 'aria-report-v1', 'report_id': rid,
                'scope_digest': digest(session.scope or {}), 'finding_bindings': bindings,
                'evidence': manifest, 'document_sha256': digest(document), 'limitations': LIMITATIONS})
            files['report.json'] = encoded_json(document)
            raw = encoded_json(files).encode()
            if len(raw) > MAX_BUNDLE_BYTES:
                raise HTTPException(413, 'Report bundle exceeds storage limit; select fewer findings')
            package_hash = sha(zip_bundle(files))
            bundle_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-report-bundle:' + rid))
            db.add(DecisionLog(id=bundle_id, session_id=sid, user_id=owner,
                decision_type='report_bundle_private', metadata_={'sealed': evidence_cipher().encrypt(raw).decode()}))
            return 'report_drafts', rid, {'id': rid, 'session_id': sid, 'template': body.template,
                'revision': parent['revision'] + 1 if parent else 1,
                'root_id': parent['root_id'] if parent else rid, 'previous_report_id': body.previous_report_id,
                'document': document, 'markdown': files['report.md'], 'bundle_id': bundle_id,
                'package_sha256': package_hash, 'scope_digest': digest(session.scope or {}),
                'finding_bindings': bindings, 'evidence_snapshot': evidence_snapshot(state, sorted(refs)),
                'source_manifest_digest': digest(manifest),
                'coverage_digest': digest(state['coverage']), 'retest_bindings': {item['id']: digest(item) for item in retests}}
        return await team_store.mutate(sid, owner, str(body.request_id), {'report_draft': body.model_dump(mode='json')}, build)

    async def _validate(self, db, session, state: dict, report: dict, owner: str) -> dict:
        if report['scope_digest'] != digest(session.scope or {}) or report['coverage_digest'] != digest(state['coverage']):
            raise HTTPException(409, 'Report scope or coverage changed; create a new revision')
        mapped = await self._mapped(db, session.id, owner)
        for fid, fingerprint in report['finding_bindings'].items():
            finding = state['verification_findings'].get(fid)
            if finding is None or digest(finding) != fingerprint:
                raise HTTPException(409, 'Report finding changed; create a new revision')
            if fid in {item['id'] for item in report['document']['findings']}:
                assert_verified(finding, state, session.scope or {}, mapped)
        if evidence_snapshot(state, list(report['evidence_snapshot'])) != report['evidence_snapshot']:
            raise HTTPException(409, 'Report catalog evidence changed')
        retests = {item['id']: digest(item) for item in state['report_retests'].values()
                   if item['finding_id'] in {item['id'] for item in report['document']['findings']}}
        if retests != report['retest_bindings']:
            raise HTTPException(409, 'Retest status changed; create a new report revision')
        # Check complete supporting source availability and content, not just the catalog.
        _, manifest = await source_files(db, session.id, list(report['evidence_snapshot']), state, mapped)
        if digest(manifest) != report['source_manifest_digest']:
            raise HTTPException(409, 'Source evidence or redaction changed; create a new revision')
        return mapped

    @staticmethod
    def _report(state: dict, rid: str) -> dict:
        report = state['report_drafts'].get(rid)
        if not report:
            raise HTTPException(404, 'Report draft not found')
        return report

    async def _files(self, db, sid: str, report: dict, mapped: dict) -> dict:
        row = await db.get(DecisionLog, report['bundle_id'])
        if not row or row.session_id != sid or row.decision_type != 'report_bundle_private':
            raise HTTPException(410, 'Report evidence bundle unavailable')
        try:
            raw = evidence_cipher().decrypt(row.metadata_['sealed'].encode())
            files = json.loads(raw)
            if sha(zip_bundle(files)) != report['package_sha256']:
                raise ValueError('Bundle changed')
        except Exception:
            raise HTTPException(409, 'Report bundle integrity check failed') from None
        # Newly registered credentials must not leak through an older signed bundle.
        if sanitize(files, export_secrets(mapped)) != files:
            raise HTTPException(409, 'New redaction required; create and review a new revision')
        return files

    async def list(self, sid: str, owner: str) -> dict:
        async def read(db, session, state):
            mapped = await self._mapped(db, sid, owner)
            return sanitize({key: list(state[key].values()) for key in
                    ('report_drafts', 'report_signoffs', 'report_outcomes', 'report_retests', 'report_correspondence')}, export_secrets(mapped))
        return await self._read(sid, owner, read)

    async def preview(self, sid: str, owner: str, rid: str) -> dict:
        async def read(db, session, state):
            report = self._report(state, rid)
            mapped = await self._validate(db, session, state, report, owner)
            files = await self._files(db, sid, report, mapped)
            return {'report': report, 'files': files, 'signed': rid in state['report_signoffs'],
                    'signoff': sanitize(state['report_signoffs'].get(rid), export_secrets(mapped)),
                    'external_submission': 'human_action_required'}
        return await self._read(sid, owner, read)

    async def signoff(self, sid: str, owner: str, rid: str, body: ReportSignoff) -> dict:
        async def build(db, session, state):
            report = self._report(state, rid)
            if rid in state['report_signoffs']:
                raise HTTPException(409, 'Immutable report already signed')
            if body.package_sha256 != report['package_sha256']:
                raise HTTPException(409, 'Review and sign the exact previewed package hash')
            mapped = await self._validate(db, session, state, report, owner)
            await self._files(db, sid, report, mapped)
            return 'report_signoffs', rid, {'id': rid, 'report_id': rid, 'revision': report['revision'],
                'package_sha256': report['package_sha256'], 'actor': owner,
                'review': sanitize(body.model_dump(mode='json', exclude={'request_id'}), export_secrets(mapped))}
        return await team_store.mutate(sid, owner, str(body.request_id), {'report': rid, 'signoff': body.model_dump(mode='json')}, build)

    async def export(self, sid: str, owner: str, rid: str) -> tuple[bytes, str]:
        async def read(db, session, state):
            report = self._report(state, rid)
            signoff = state['report_signoffs'].get(rid)
            if not signoff or signoff['package_sha256'] != report['package_sha256']:
                raise HTTPException(409, 'Human report sign-off is required before export')
            mapped = await self._validate(db, session, state, report, owner)
            files = await self._files(db, sid, report, mapped)
            return zip_bundle(files), report['package_sha256']
        return await self._read(sid, owner, read)

    async def outcome(self, sid: str, owner: str, rid: str, body: OutcomeInput) -> dict:
        async def build(db, session, state):
            self._report(state, rid)
            if rid not in state['report_signoffs']:
                raise HTTPException(409, 'Record outcomes against a signed report revision')
            previous = state['report_outcomes'].get(rid, {'revision': 0, 'history': [], 'status': None})
            if body.expected_revision != previous['revision']:
                raise HTTPException(409, 'Stale outcome revision')
            if previous['revision'] == 0 and body.status != 'submitted':
                raise HTTPException(409, 'Record the actual submission before triage or payment')
            mapped = await self._mapped(db, sid, owner)
            entry = sanitize(body.model_dump(mode='json', exclude={'request_id', 'expected_revision'}), export_secrets(mapped))
            if len(previous['history']) >= 500:
                raise HTTPException(409, 'Outcome history limit reached')
            entry['recorded_by'] = owner
            entry['recorded_at'] = datetime.now(timezone.utc).isoformat()
            return 'report_outcomes', rid, {'id': rid, 'report_id': rid, 'revision': previous['revision'] + 1,
                'status': body.status, 'history': [*previous['history'], entry],
                'limitation': 'Human-recorded platform outcome; not independently fetched or verified.'}
        return await team_store.mutate(sid, owner, str(body.request_id), {'report': rid, 'outcome': body.model_dump(mode='json')}, build)

    async def retest(self, sid: str, owner: str, rid: str, body: RetestInput) -> dict:
        async def build(db, session, state):
            report = self._report(state, rid)
            if rid not in state['report_signoffs'] or body.finding_id not in {item['id'] for item in report['document']['findings']}:
                raise HTTPException(422, 'Retest must refer to a finding in a signed report')
            if body.expected_scope_digest != digest(session.scope or {}) or body.expected_scope_digest != report['scope_digest']:
                raise HTTPException(409, 'Scope changed; reauthorize and verify in a new report workflow')
            refs = evidence_snapshot(state, body.evidence_references)
            finding = state['verification_findings'][body.finding_id]
            if set(refs).intersection(finding['evidence_snapshot']):
                raise HTTPException(422, 'Retest requires fresh evidence, not the original reproduction')
            original_sources = {(state['evidence'][ref]['source_kind'], state['evidence'][ref]['source_id']) for ref in finding['evidence_snapshot']}
            if any((state['evidence'][ref]['source_kind'], state['evidence'][ref]['source_id']) in original_sources for ref in refs):
                raise HTTPException(422, 'Retest source aliases are not fresh evidence')
            mapped = await self._mapped(db, sid, owner)
            await source_files(db, sid, body.evidence_references, state, mapped)
            key = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-retest:{sid}:{body.request_id}'))
            return 'report_retests', key, {'id': key, 'report_id': rid, 'recorded_by': owner,
                **sanitize(body.model_dump(mode='json', exclude={'request_id'}), export_secrets(mapped)),
                'evidence_snapshot': refs, 'verification': 'human_recorded_saved_evidence', 'execution_performed': False}
        return await team_store.mutate(sid, owner, str(body.request_id), {'report': rid, 'retest': body.model_dump(mode='json')}, build)

    async def triage(self, sid: str, owner: str, rid: str, body: TriageInput) -> dict:
        async def build(db, session, state):
            report = self._report(state, rid)
            if rid not in state['report_signoffs']:
                raise HTTPException(409, 'Triage answers require a signed report revision')
            finding = next((item for item in report['document']['findings'] if item['id'] == body.finding_id), None)
            if finding is None:
                raise HTTPException(422, 'Finding is outside this signed report')
            mapped = await self._mapped(db, sid, owner)
            if body.topic == 'reproduction':
                answer = encoded_json({'prerequisites': finding['prerequisites'], 'reproduction': finding['reproduction'], 'attachments': finding['attachments']})
            elif body.topic == 'impact':
                answer = 'Demonstrated: ' + finding['impact'] + '\nUnverified potential escalation: ' + finding['potential_escalation']
            elif body.topic == 'scope':
                answer = encoded_json({'asset': finding['asset'], 'historical_report_scope': report['document']['scope']})
            else:
                answer = encoded_json([item for item in state['report_retests'].values() if item['finding_id'] == body.finding_id])
                if answer == '[]':
                    answer = 'No retest has been recorded.'
            answer = 'DRAFT — human review required. Based on saved evidence for report ' + rid + '.\nHistorical observations do not establish current behavior. No new testing performed.\n\n' + answer
            key = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-triage:{sid}:{body.request_id}'))
            return 'report_correspondence', key, {'id': key, 'report_id': rid, 'finding_id': body.finding_id,
                'topic': body.topic, 'text': sanitize(answer, export_secrets(mapped)),
                'report_package_sha256': report['package_sha256'],
                'evidence_references': sorted(set(report['evidence_snapshot']) |
                    {ref for item in state['report_retests'].values() if body.topic == 'retest' and item['finding_id'] == body.finding_id
                     for ref in item['evidence_references']}), 'sent': False, 'scope_changed': report['scope_digest'] != digest(session.scope or {})}
        return await team_store.mutate(sid, owner, str(body.request_id), {'report': rid, 'triage': body.model_dump(mode='json')}, build)


professional_reports = ProfessionalReportStore()
