"""Saved-evidence verification ledger. No model output grants verification or execution."""
import re
import uuid
from typing import Literal

from fastapi import HTTPException
from pydantic import AwareDatetime, Field, ValidationError, model_validator
from memory.team_tasks import Strict, Reference, Criterion, digest, public, team_store

FindingState = Literal['observation', 'hypothesis', 'tested', 'reproduced', 'reviewed',
                       'reportable', 'rejected', 'inconclusive', 'blocked']
TRANSITIONS = {
    'observation': {'hypothesis', 'rejected', 'inconclusive', 'blocked'},
    'hypothesis': {'tested', 'rejected', 'inconclusive', 'blocked'},
    'tested': {'reproduced', 'rejected', 'inconclusive', 'blocked'},
    'reproduced': {'reviewed', 'rejected', 'inconclusive', 'blocked'},
    'reviewed': {'reportable', 'rejected', 'inconclusive', 'blocked'},
    'reportable': {'rejected', 'inconclusive', 'blocked'},
    'rejected': set(), 'inconclusive': {'hypothesis'}, 'blocked': {'hypothesis'},
}


class Candidate(Strict):
    request_id: uuid.UUID
    title: Criterion
    underlying_cause: Criterion
    affected_workflow: Criterion
    hypothesis: Criterion
    expected_behavior: Criterion
    evidence_references: list[Reference] = Field(min_length=1, max_length=30)
    specialist_task_id: Reference
    potential_escalation: str = Field(default='', max_length=2000)


class ContentControl(Strict):
    object_id: Reference
    owner_capture_id: Reference
    outsider_capture_id: Reference
    negative_capture_id: Reference
    private_json_key: Reference


def verify_content(mapped: dict, control: ContentControl, validation: dict, ledger: dict) -> dict:
    """Recheck original private content and a denied/missing-content control."""
    from memory.application_map import ExposureReview, exposure_review
    def inspect(capture_id):
        return exposure_review(mapped, ExposureReview(capture_id=capture_id,
            object_id=control.object_id, owner_capture_id=control.owner_capture_id,
            private_json_key=control.private_json_key, inspection_authorized=True,
            intended_visibility='restricted', observed_audience='outside',
            meaningful_private_content='present', rationale='Independent private-content control'))
    positive, negative = inspect(control.outsider_capture_id), inspect(control.negative_capture_id)
    if (positive['assessment'] != 'candidate_unauthorized_disclosure' or
            negative.get('private_content_match') is not False):
        raise HTTPException(409, 'Private content must match only in the positive observation')
    captures = mapped['captures']
    outsider, denied = captures[control.outsider_capture_id], captures[control.negative_capture_id]
    if outsider['identity_id'] != denied['identity_id']:
        raise HTTPException(409, 'Negative control must use the same outsider identity')
    for capture_id, refs in ((control.owner_capture_id, validation['ownership_references']),
            (control.outsider_capture_id, validation['evidence_references']),
            (control.negative_capture_id, validation['negative_control_references'])):
        capture = captures[capture_id]
        if not any(ledger['evidence'][ref]['source_kind'] == 'chat' and
                   ledger['evidence'][ref]['source_id'] == capture['evidence_id'] for ref in refs):
            raise HTTPException(422, 'Selected capture must match its cataloged control evidence')
    # Hash private input; retain no original response, credential or marker in the ledger.
    selected = {'captures': {key: captures[key] for key in
                (control.owner_capture_id, control.outsider_capture_id, control.negative_capture_id)},
                'objects': mapped['objects'], 'permissions': mapped['permissions'],
                'identities': {key: {field: value.get(field) for field in
                    ('active', 'researcher_controlled', 'expires_at')} for key, value in mapped['identities'].items()}}
    return {'input_digest': digest(selected), 'private_content_match': True,
            'negative_content_match': False, 'owner_content_sha256': positive['owner_content_sha256']}


class Validation(Strict):
    """Human-recorded lab procedure and controls, never an instruction to execute."""
    content_control: ContentControl | None = None
    steps: list[Criterion] = Field(min_length=1, max_length=20)
    evidence_references: list[Reference] = Field(min_length=1, max_length=30)
    negative_control_references: list[Reference] = Field(min_length=1, max_length=30)
    ownership_references: list[Reference] = Field(min_length=1, max_length=30)
    permission_references: list[Reference] = Field(min_length=1, max_length=30)
    account_and_object: Criterion
    expected_permission: Criterion
    meaningful_content: Criterion
    demonstrated_impact: Criterion
    clean_state_procedure: Criterion
    clean_state: Literal[True]
    negative_control_passed: Literal[True]
    controlled_accounts_and_objects: Literal[True]
    meaningful_content_confirmed: Literal[True]
    observed_behavior: Literal['expected', 'violation', 'ambiguous']

    @model_validator(mode='after')
    def substantive_review(self):
        if any(not text.strip() for text in [*self.steps, self.account_and_object,
                self.expected_permission, self.meaningful_content, self.demonstrated_impact,
                self.clean_state_procedure]):
            raise ValueError('Validation requires substantive procedure and review text')
        return self


class Review(Strict):
    request_id: uuid.UUID
    expected_revision: int = Field(ge=1)
    state: FindingState
    reason: Criterion
    validation: Validation | None = None
    smallest_missing_validation: str = Field(default='', max_length=2000)
    human_signoff: bool = False


def duplicate_key(cause: str, workflow: str) -> str:
    return digest({'cause': ' '.join(cause.casefold().split()),
                   'workflow': ' '.join(workflow.casefold().split())})


def evidence_snapshot(state: dict, references: list[str]) -> dict:
    result = {}
    for ref in references:
        evidence = state['evidence'].get(ref)
        if not evidence or not evidence.get('hashes'):
            raise HTTPException(422, 'Verification requires cataloged evidence with hashes')
        result[ref] = digest(evidence)
    return result


def validation_refs(validation: dict) -> list[str]:
    return list(dict.fromkeys(ref for key in ('evidence_references', 'negative_control_references',
        'ownership_references', 'permission_references') for ref in validation[key]))


def evidence_lineage(state: dict, references: list[str]) -> set[tuple[str, str]]:
    """Match aliases by source ID, verified job lineage or full capture digest."""
    identities = set()
    for ref in references:
        evidence = state['evidence'][ref]
        identities.add((evidence['source_kind'], evidence['source_id']))
        if evidence.get('job_id'):
            identities.add(('job', evidence['job_id']))
        if capture := evidence.get('hashes', {}).get('capture_sha256'):
            identities.add(('capture_sha256', capture))
    return identities


def check_validation_lineage(state: dict, finding: dict, validation: dict, prior: dict | None = None) -> None:
    positive = evidence_lineage(state, validation['evidence_references'])
    negative = evidence_lineage(state, validation['negative_control_references'])
    if positive & negative:
        raise HTTPException(422, 'Negative controls must use separate source observations')
    if prior is not None:
        earlier = evidence_lineage(state, prior['evidence_references'] +
            prior['negative_control_references'] + finding['evidence_references'])
        if (positive | negative) & earlier:
            raise HTTPException(409, 'Reproduction needs fresh positive and negative observations')


def current(finding: dict, state: dict, scope: dict) -> bool:
    if finding['scope_digest'] != digest(scope):
        return False
    return all(ref in state['evidence'] and digest(state['evidence'][ref]) == value
               for ref, value in finding['evidence_snapshot'].items())


def advance(finding: dict, body: Review, state: dict, scope: dict, actor: str) -> dict:
    if finding['revision'] != body.expected_revision:
        raise HTTPException(409, 'Stale finding revision')
    if body.state not in TRANSITIONS[finding['state']]:
        raise HTTPException(409, 'Invalid finding transition')
    if body.state not in {'blocked', 'rejected', 'inconclusive', 'hypothesis'} and not current(finding, state, scope):
        raise HTTPException(409, 'Scope or evidence changed; block and revalidate the candidate')
    updated = {**finding, 'state': body.state, 'revision': finding['revision'] + 1,
               'reason': body.reason, 'reviewer_role': 'human_reviewer', 'reviewer_id': actor,
               'smallest_missing_validation': body.smallest_missing_validation}
    if body.state in {'blocked', 'inconclusive'} and not body.smallest_missing_validation.strip():
        raise HTTPException(422, 'Record the smallest missing validation')
    if body.state == 'hypothesis':
        updated.update(scope_digest=digest(scope), test=None, reproduction=None, human_review=None,
                       human_signoff=None, stop_testing=False, evidence_snapshot=evidence_snapshot(state, finding['evidence_references']))
    if body.state in {'tested', 'reproduced'}:
        if body.validation is None:
            raise HTTPException(422, 'A recorded validation and negative control are required')
        validation = body.validation.model_dump()
        refs = validation_refs(validation)
        snapshot = evidence_snapshot(state, refs)
        check_validation_lineage(state, finding, validation, finding['test'] if body.state == 'reproduced' else None)
        if validation['observed_behavior'] != 'violation':
            raise HTTPException(409, 'Expected or ambiguous behavior cannot establish a finding')
        updated['stop_testing'] = body.state == 'reproduced'
        updated['test' if body.state == 'tested' else 'reproduction'] = {
            **validation, 'recorded_by': actor, 'method': 'human_saved_evidence_review'}
        updated['evidence_snapshot'] = {**finding['evidence_snapshot'], **snapshot}
    elif body.validation is not None:
        raise HTTPException(422, 'Validation is only accepted at tested or reproduced transitions')
    if body.state in {'reviewed', 'reportable'}:
        if not all((finding.get(key) or {}).get('content_verification') for key in ('test', 'reproduction')):
            raise HTTPException(409, 'Reviewed/reportable findings require supported original-content controls for both runs')
        if not body.human_signoff or not finding.get('test') or not finding.get('reproduction'):
            raise HTTPException(422, 'Recorded human review of independent reproduction is required')
        updated['human_review' if body.state == 'reviewed' else 'human_signoff'] = {
            'actor': actor, 'reason': body.reason, 'revision': finding['revision'],
            'evidence_snapshot': finding['evidence_snapshot'], 'scope_digest': finding['scope_digest']}
        updated['stop_testing'] = True
    return updated


class FindingRevision(Strict):
    event_id: Reference
    sequence: int = Field(strict=True, ge=1)
    timestamp: AwareDatetime
    revision: int = Field(strict=True, ge=1)
    state: FindingState
    actor: Literal['human_reviewer', 'engagement_owner'] | None
    reason: str | None
    smallest_missing_validation: str | None
    specialist_task_id: Reference | None
    evidence_snapshot: dict[str, str]
    references: dict[str, list[str]]


class FindingHistory(Strict):
    schema_version: Literal['aria.mission.finding-history.v1'] = 'aria.mission.finding-history.v1'
    session_id: str
    finding_id: str
    revisions: list[FindingRevision]
    next_before_sequence: int | None
    rejected_records: int


def recorded_revision(event: dict, owner: str) -> FindingRevision:
    data = event['data']

    def reference(value: object) -> str | None:
        return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,100}', value) else None

    def refs(key: str, row: dict) -> list[str]:
        values = row.get(key)
        if not isinstance(values, list):
            return []
        return list(dict.fromkeys(value for item in values[:100] if (value := reference(item))))

    def note(key: str) -> str | None:
        value = data.get(key)
        return public(value)[:2000] if isinstance(value, str) and value.strip() else None

    references = {'candidate_evidence': refs('evidence_references', data)}
    for phase in ('test', 'reproduction'):
        proof = data.get(phase)
        if isinstance(proof, dict):
            for field in ('evidence', 'negative_control', 'ownership', 'permission'):
                links = refs(field + '_references', proof)
                if links:
                    references[f'{phase}_{field}'] = links
    snapshot = data.get('evidence_snapshot')
    actor = 'engagement_owner' if event.get('actor') == owner else None
    if data.get('reviewer_role') == 'human_reviewer':
        actor = 'human_reviewer'
    return FindingRevision(event_id=event['id'], sequence=event['sequence'], timestamp=event['timestamp'],
        revision=data['revision'], state=data['state'], actor=actor,
        reason=note('reason'), smallest_missing_validation=note('smallest_missing_validation'),
        specialist_task_id=reference(data.get('specialist_task_id')), references=references,
        evidence_snapshot={key: value for key, value in snapshot.items()
            if reference(key) and isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value)}
            if isinstance(snapshot, dict) else {})


class VerificationStore:
    async def history(self, sid: str, owner: str, finding_id: str, before: int | None, limit: int) -> FindingHistory:
        events, older = await team_store.event_page(sid, owner, None, limit, before=before,
            entity=('verification_findings', finding_id))
        if not events:
            raise HTTPException(404, 'Finding history unavailable')
        revisions = []
        rejected = 0
        for event in reversed(events):
            try:
                revisions.append(recorded_revision(event, owner))
            except (AttributeError, KeyError, TypeError, ValidationError):
                rejected += 1
        first = events[0].get('sequence') if isinstance(events[0], dict) else None
        return FindingHistory(session_id=sid, finding_id=finding_id, revisions=revisions,
            next_before_sequence=first if older and type(first) is int and first > 0 else None,
            rejected_records=rejected)

    async def view(self, sid: str, owner: str) -> dict:
        ledger = await team_store.view(sid, owner)
        state = {'evidence': {item['id']: item for item in ledger['evidence']}}
        findings = [{**item, 'verification_current': current(item, state, ledger['scope']),
                     'ready_for_external_submission': False}
                    for item in ledger['verification_findings']]
        if any(item['state'] == 'reportable' for item in findings):
            from memory import team_tasks
            from memory.application_map import application_map
            async with team_tasks.async_session() as db:
                _, _, mapped = await application_map._load(db, sid, owner)
                for item in findings:
                    if item['state'] != 'reportable':
                        continue
                    try:
                        check_validation_lineage(state, item, item['test'])
                        check_validation_lineage(state, item, item['reproduction'], item['test'])
                        valid = all(verify_content(mapped, ContentControl(**item[key]['content_control']),
                            item[key], state) == item[key]['content_verification'] for key in ('test', 'reproduction'))
                    except (HTTPException, KeyError, TypeError, ValueError):
                        valid = False
                    item['verification_current'] = item['verification_current'] and valid
                    item['ready_for_external_submission'] = bool(
                        item['verification_current'] and item.get('human_review') and item.get('human_signoff'))
        return {'findings': findings, 'private_program_duplicates': 'unknown',
                'limitation': 'Human-reviewed saved evidence; no autonomous reproduction or external submission.'}

    async def create(self, sid: str, owner: str, body: Candidate) -> dict:
        async def build(db, session, state):
            task = state['tasks'].get(body.specialist_task_id)
            if not task or not task.get('specialty') or not task.get('result'):
                raise HTTPException(422, 'A collected specialist task is required')
            if not set(body.evidence_references).issubset(task['result'].get('evidence_references', [])):
                raise HTTPException(422, 'Candidate evidence must be attributable to its specialist result')
            if len(state['verification_findings']) >= 500:
                raise HTTPException(409, 'Finding limit reached')
            key = duplicate_key(body.underlying_cause, body.affected_workflow)
            duplicates = [item['id'] for item in state['verification_findings'].values() if item['duplicate_key'] == key]
            fid = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-verification:{sid}:{body.request_id}'))
            return 'verification_findings', fid, {**body.model_dump(mode='json', exclude={'request_id'}),
                'id': fid, 'session_id': sid, 'state': 'observation', 'revision': 1,
                'duplicate_key': key, 'local_duplicate_candidates': duplicates,
                'private_program_duplicates': 'unknown', 'scope_digest': digest(session.scope or {}),
                'evidence_snapshot': evidence_snapshot(state, body.evidence_references),
                'test': None, 'reproduction': None, 'human_review': None, 'human_signoff': None}
        return await team_store.mutate(sid, owner, str(body.request_id), {'candidate': body.model_dump(mode='json')}, build)

    async def review(self, sid: str, owner: str, fid: str, body: Review) -> dict:
        async def build(db, session, state):
            finding = state['verification_findings'].get(fid)
            if finding is None:
                raise HTTPException(404, 'Finding not found')
            updated = advance(finding, body, state, session.scope or {}, owner)
            if body.state in {'tested', 'reproduced', 'reviewed', 'reportable'}:
                if body.state in {'reviewed', 'reportable'}:
                    check_validation_lineage(state, updated, updated['test'])
                    check_validation_lineage(state, updated, updated['reproduction'], updated['test'])
                from memory.application_map import application_map, capture_metadata
                runs = [key for key in ('test', 'reproduction') if updated.get(key)]
                if any(updated[key].get('content_control') for key in runs):
                    _, _, mapped = await application_map._load(db, sid, owner)
                    for key in runs:
                        run = updated[key]
                        if not run.get('content_control'):
                            continue
                        control = ContentControl(**run['content_control'])
                        for cid in (control.owner_capture_id, control.outsider_capture_id, control.negative_capture_id):
                            capture = mapped['captures'].get(cid, {})
                            if not capture.get('original'):
                                raise HTTPException(410, 'Original control evidence unavailable')
                            from orchestrator.execution_policy import PolicyError
                            try:
                                capture_metadata(capture['original'], session.scope or {})
                            except (PolicyError, ValueError, KeyError, TypeError):
                                raise HTTPException(409, 'Original control is invalid or outside current scope') from None
                        verification = verify_content(mapped, control, run, state)
                        if run.get('content_verification') and run['content_verification'] != verification:
                            raise HTTPException(409, 'Control evidence or permissions changed; revalidate')
                        updated[key] = {**run, 'content_verification': verification}
            return 'verification_findings', fid, updated
        return await team_store.mutate(sid, owner, str(body.request_id),
                                       {'finding': fid, 'review': body.model_dump(mode='json')}, build)


verification_store = VerificationStore()
