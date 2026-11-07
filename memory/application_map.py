"""Private, owner-bound application mapping. Saved evidence never grants execution.

The encrypted snapshot is separate from chat/model context. Engagement row locks
serialize updates; a revision prevents lost human corrections. No target I/O.
"""
import asyncio
import base64
import copy
import hashlib
import json
import re
import shlex
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal
from urllib.parse import parse_qs, urlsplit

from fastapi import HTTPException
from pydantic import Field, SecretStr, model_validator

from sqlalchemy import select
from memory.database_models import ChatLog, DecisionLog, PentestSession, WebAction, async_session
from memory.program_policy import owned_engagement
from memory.team_tasks import Strict
from orchestrator.execution_policy import validate_command
from security.encryption import evidence_cipher
from security.redaction import redact, deployment_secrets

Text = Annotated[str, Field(min_length=1, max_length=500)]
Ref = Annotated[str, Field(min_length=1, max_length=100)]


def now() -> datetime:
    return datetime.now(timezone.utc)


class Change(Strict):
    expected_revision: int = Field(ge=0)


class IdentityInput(Change):
    label: Text
    role: Text
    researcher_controlled: Literal[True]
    # Credentials are write-only, never accepted in labels or URLs by design.
    credentials: dict[Literal['authorization', 'cookie', 'x-api-key'], SecretStr] = Field(default_factory=dict)

    @model_validator(mode='after')
    def bounded_credentials(self):
        for value in self.credentials.values():
            raw = value.get_secret_value()
            if not 1 <= len(raw) <= 8192 or any(ord(c) < 32 or ord(c) > 126 for c in raw):
                raise ValueError('Credentials must be bounded printable HTTP header values')
        return self


class RequestInput(Change):
    identity_id: Ref
    method: Literal['GET', 'HEAD', 'PUT'] = 'GET'
    url: str = Field(min_length=1, max_length=3000)
    profile: Literal['integer_query', 'controlled_json_put'] | None = None
    object_id: Ref | None = None
    action_authorized: Literal[True] | None = None
    invariant: Text | None = None
    json_body: dict[str, str | int | bool] | None = Field(default=None, min_length=1, max_length=1)

    @model_validator(mode='after')
    def reviewed_shape(self):
        if self.profile is None:
            if self.method == 'PUT' or any(v is not None for v in
                    (self.object_id, self.action_authorized, self.invariant, self.json_body)):
                raise ValueError('Specialty method or metadata requires a reviewed profile')
        elif not self.object_id or self.action_authorized is not True or not self.invariant or not self.invariant.strip():
            raise ValueError('Controlled object, authorization and invariant required')
        return self



def request_specialty(state, identity_id, object_id, url, review):
    """Bind a reviewed action to this owner's recorded, unexpired object resource."""
    require(state, 'objects', [object_id])
    obj = state['objects'][object_id]
    identity = state['identities'].get(identity_id, {})
    if (obj['owner_identity_id'] != identity_id or identity.get('researcher_controlled') is not True
            or not identity.get('active')):
        raise HTTPException(409, 'An active controlled object owner is required')
    resource = urlsplit(url)._replace(query='').geturl()
    supporting = [c for c in state['captures'].values() if c['evidence_id'] in obj['evidence_ids']
                  and c['identity_id'] == identity_id and not c.get('expired')
                  and c.get('original', {}).get('url') == resource]
    if not supporting:
        raise HTTPException(409, 'The exact controlled object resource needs unexpired owner evidence')
    return review

class CaptureInput(Change):
    identity_id: Ref
    evidence_id: Ref


class ObjectInput(Change):
    label: Text
    owner_identity_id: Ref
    evidence_ids: list[Ref] = Field(min_length=1, max_length=30)


class WorkflowInput(Change):
    label: Text
    kind: Literal['sharing', 'invitation', 'export', 'account_settings', 'other']
    # Ordered captures describe observations, not instructions to execute.
    evidence_ids: list[Ref] = Field(min_length=1, max_length=30)
    before: Text
    after: Text


class PermissionInput(Change):
    object_id: Ref
    identity_id: Ref
    operation: Text
    expected: Literal['allow', 'deny', 'unknown']
    rationale: Text
    evidence_ids: list[Ref] = Field(default_factory=list, max_length=30)


class DataPolicy(Change):
    retention_days: int = Field(ge=1, le=90)
    provider_sharing: Literal['deny', 'redacted_metadata'] = 'deny'


class ComparisonInput(Strict):
    left: Ref
    right: Ref
    # Explicit opt-in removal only; ignored fields remain visible in the result.
    ignore_json_keys: list[Text] = Field(default_factory=list, max_length=20)



class AuthorizationReview(Strict):
    object_id: Ref
    owner_capture_id: Ref
    other_capture_id: Ref
    operation: Text


def authorization_review(state: dict, body: AuthorizationReview) -> dict:
    """Compare selected observations; recorded ownership and permissions are assertions."""
    require(state, 'objects', [body.object_id])
    require(state, 'captures', [body.owner_capture_id, body.other_capture_id])
    obj = state['objects'][body.object_id]
    left, right = (state['captures'][body.owner_capture_id], state['captures'][body.other_capture_id])
    identities = state['identities']
    owner_id, other_id = obj['owner_identity_id'], right['identity_id']
    if (left['identity_id'] != owner_id or owner_id == other_id or
            not identities.get(owner_id, {}).get('active') or not identities.get(other_id, {}).get('active') or
            identities.get(owner_id, {}).get('researcher_controlled') is not True or
            identities.get(other_id, {}).get('researcher_controlled') is not True):
        raise HTTPException(409, 'Two active, distinct controlled identities including the recorded owner are required')
    if left['evidence_id'] not in obj['evidence_ids']:
        raise HTTPException(409, 'Owner observation must support the recorded object')
    if left.get('expired') or right.get('expired'):
        raise HTTPException(410, 'Original capture expired or was revoked')
    if any(left.get(k) != right.get(k) for k in ('method', 'origin', 'route')):
        raise HTTPException(409, 'Observations must use the same method and resource')
    permissions = [p for p in state['permissions'].values() if
                   p['object_id'] == body.object_id and p['identity_id'] == other_id and p['operation'] == body.operation]
    if not permissions or permissions[-1]['expected'] == 'unknown':
        raise HTTPException(409, 'A current expected permission is required')
    try:
        urls = [c['original']['url'] for c in (left, right)]
        if urls[0] != urls[1] or urlsplit(urls[0]).query or left['method'] not in {'GET', 'HEAD'}:
            raise HTTPException(409, 'Only the same bodyless GET or HEAD resource without a query is supported')
        for capture in (left, right):
            request = base64.b64decode(capture['original']['request_b64'], validate=True)
            if not request.partition(b'\r\n\r\n')[1] or request.partition(b'\r\n\r\n')[2]:
                raise HTTPException(409, 'Request bodies are unsupported')
        raw = [base64.b64decode(c['original']['response_b64'], validate=True) for c in (left, right)]
        comparison = compare_responses(*raw, [])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, 'Original responses are unavailable') from None
    return {'object_id': body.object_id, 'capture_ids': [body.owner_capture_id, body.other_capture_id],
            'evidence_ids': [left['evidence_id'], right['evidence_id']],
            'expected_permission': permissions[-1]['expected'], 'permission_id': permissions[-1]['id'],
            'comparison': comparison, 'status': 'observation',
            'limitations': ['Ownership and permission are human assertions; inspect meaningful content and public or shared access before drawing a conclusion.',
                            'Response equality and HTTP status do not establish authorization or confirm a finding.']}



class AuthenticationReview(Strict):
    authenticated_capture_id: Ref
    unauthenticated_capture_id: Ref
    expected_authentication_required: Literal[True]
    action_authorized: Literal[True]
    session_state: Literal['absent', 'logged_out', 'expired'] = 'absent'


def authentication_review(state: dict, body: AuthenticationReview) -> dict:
    """Review saved resource observations; this does not exercise session actions."""
    require(state, 'captures', [body.authenticated_capture_id, body.unauthenticated_capture_id])
    left, right = (state['captures'][body.authenticated_capture_id], state['captures'][body.unauthenticated_capture_id])
    identities = state['identities']
    a, b = identities.get(left['identity_id'], {}), identities.get(right['identity_id'], {})
    if (left['identity_id'] == right['identity_id'] or
            any(not i.get('active') or i.get('researcher_controlled') is not True for i in (a, b)) or
            not a.get('credentials') or (body.session_state == 'absent' and b.get('credentials')) or
            (body.session_state != 'absent' and not b.get('credentials'))):
        raise HTTPException(409, 'Active controlled identities with the selected session credentials are required')
    if left.get('expired') or right.get('expired'):
        raise HTTPException(410, 'Original capture expired or was revoked')
    try:
        urls = [c['original']['url'] for c in (left, right)]
        if (urls[0] != urls[1] or urlsplit(urls[0]).query or
                left['method'] not in {'GET', 'HEAD'} or left['method'] != right['method']):
            raise HTTPException(409, 'The same bodyless GET or HEAD resource without a query is required')
        requests = [base64.b64decode(c['original']['request_b64'], validate=True) for c in (left, right)]
        if any(not request.partition(b'\r\n\r\n')[1] or request.partition(b'\r\n\r\n')[2] for request in requests):
            raise HTTPException(409, 'Request bodies are unsupported')
        # Captures are bound to identity credentials on import; check again here.
        def auth_headers(request):
            result = {}
            for line in request.partition(b'\r\n\r\n')[0].decode('iso-8859-1').split('\r\n')[1:]:
                name, separator, value = line.partition(':')
                if separator and name.lower() in {'authorization', 'cookie', 'x-api-key'}:
                    if name.lower() in result:
                        raise ValueError('duplicate header')
                    result[name.lower()] = value.strip()
            return result
        if auth_headers(requests[0]) != a['credentials'] or auth_headers(requests[1]) != b.get('credentials', {}):
            raise HTTPException(409, 'Capture authentication does not match the selected identities')
        raw = [base64.b64decode(c['original']['response_b64'], validate=True) for c in (left, right)]
        comparison = compare_responses(*raw, [])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, 'Original observations are unavailable or invalid') from None
    return {'capture_ids': [body.authenticated_capture_id, body.unauthenticated_capture_id],
            'evidence_ids': [left['evidence_id'], right['evidence_id']], 'comparison': comparison,
            'status': 'observation', 'session_state': body.session_state, 'limitations': [
                'Logout/expiry and the intended authentication requirement are researcher assertions; no lifecycle action is executed.',
                'The permission and expected authentication requirement are researcher assertions.',
                'The credential-free request can still carry other authentication mechanisms; review the original request.',
                'Status and response equality do not establish access to meaningful protected content.']}



class ExposureReview(Strict):
    capture_id: Ref
    inspection_authorized: Literal[True]
    intended_visibility: Literal['public', 'recipient', 'restricted', 'unknown']
    observed_audience: Literal['intended', 'outside', 'unknown']
    meaningful_private_content: Literal['present', 'absent', 'unknown']
    rationale: Text
    object_id: Ref | None = None
    owner_capture_id: Ref | None = None
    private_json_key: Text | None = None

    @model_validator(mode='after')
    def content_control(self):
        selected = (self.object_id, self.owner_capture_id, self.private_json_key)
        if any(value is not None for value in selected) and not all(selected):
            raise ValueError('Private-content comparison requires object, owner capture and JSON key')
        return self


def exposure_review(state: dict, body: ExposureReview) -> dict:
    """Structure human review of saved evidence without classifying a vulnerability."""
    require(state, 'captures', [body.capture_id])
    capture = state['captures'][body.capture_id]
    identity = state['identities'].get(capture['identity_id'], {})
    if not identity.get('active') or identity.get('researcher_controlled') is not True:
        raise HTTPException(409, 'An active controlled observation identity is required')
    if capture.get('expired') or not capture.get('original', {}).get('response_b64'):
        raise HTTPException(410, 'Original capture expired or unavailable')
    try:
        raw = base64.b64decode(capture['original']['response_b64'], validate=True)
        compare_responses(raw, raw, [])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, 'Original observation is unavailable or invalid') from None
    if not body.rationale.strip():
        raise HTTPException(422, 'A review rationale is required')
    if body.observed_audience == 'intended' or (body.intended_visibility == 'public' and body.meaningful_private_content != 'present'):
        assessment = 'expected_or_public'
    elif (body.intended_visibility in {'restricted', 'recipient'} and body.observed_audience == 'outside' and
          body.meaningful_private_content == 'present'):
        assessment = 'possible_unauthorized_disclosure'
    elif body.meaningful_private_content == 'absent':
        assessment = 'no_private_content_identified'
    else:
        assessment = 'inconclusive'
    control = {}
    status = 'human_assertion'
    if body.object_id:
        comparison = authorization_review(state, AuthorizationReview(object_id=body.object_id,
            owner_capture_id=body.owner_capture_id, other_capture_id=body.capture_id, operation='read'))
        try:
            def selected_value(item):
                raw = base64.b64decode(item['original']['response_b64'], validate=True)
                metadata = compare_responses(raw, raw, [])['left']
                if metadata['mode'] != 'json':
                    return None
                payload = json.loads(raw.partition(b'\r\n\r\n')[2])
                value = payload.get(body.private_json_key) if isinstance(payload, dict) else None
                return value if isinstance(value, str) and 8 <= len(value) <= 2048 else None
            expected = selected_value(state['captures'][body.owner_capture_id])
            observed = selected_value(capture)
        except (ValueError, KeyError, TypeError):
            raise HTTPException(409, 'Private JSON content control is unavailable') from None
        if expected is None:
            raise HTTPException(409, 'Owner evidence needs a meaningful selected private JSON string')
        matched = expected == observed
        control = {'evidence_ids': comparison['evidence_ids'], 'private_content_match': matched,
                   'owner_content_sha256': hashlib.sha256(expected.encode()).hexdigest()}
        if comparison['expected_permission'] == 'allow' or body.intended_visibility == 'public' or body.observed_audience == 'intended':
            assessment = 'expected_or_public'
        elif body.intended_visibility in {'restricted', 'recipient'} and body.observed_audience == 'outside' and body.meaningful_private_content == 'present' and matched:
            assessment = 'candidate_unauthorized_disclosure'
        else:
            assessment = 'inconclusive'
        status = 'observation'
    return {'capture_id': body.capture_id, 'evidence_id': capture['evidence_id'], **control,
            'assessment': assessment, 'status': status,
            'rationale': sanitize(body.rationale, known_secrets(state)),
            'limitations': ['Visibility, audience and content are researcher assertions, not independently verified facts.',
                            'A status code, scanner label, or response similarity does not establish disclosure.']}



class BusinessLogicReview(Strict):
    workflow_id: Ref
    object_id: Ref
    invariant: Text
    expected_after: Text
    action_authorized: Literal[True]
    controlled_state_change: Literal[True]
    invariant_result: Literal['satisfied', 'violated', 'unknown']
    rationale: Text


def business_logic_review(state: dict, body: BusinessLogicReview) -> dict:
    """Review recorded before/after evidence, without dispatching a state change."""
    require(state, 'workflows', [body.workflow_id])
    require(state, 'objects', [body.object_id])
    workflow, obj = state['workflows'][body.workflow_id], state['objects'][body.object_id]
    identity = state['identities'].get(obj['owner_identity_id'], {})
    if not identity.get('active') or identity.get('researcher_controlled') is not True:
        raise HTTPException(409, 'Active researcher-controlled object owner required')
    if not all(value.strip() for value in (body.invariant, body.expected_after, body.rationale)):
        raise HTTPException(422, 'Invariant, expected state and rationale are required')
    captures = {capture['evidence_id']: capture for capture in state['captures'].values()}
    evidence = workflow['evidence_ids']
    if len(set(evidence)) < 2 or any(ref not in captures or captures[ref].get('expired') for ref in evidence):
        raise HTTPException(409, 'At least two unexpired before/after observations are required')
    if not set(obj['evidence_ids']).intersection(evidence):
        raise HTTPException(409, 'Workflow evidence must include supporting evidence for the controlled object')
    if any(captures[ref]['identity_id'] != obj['owner_identity_id'] for ref in evidence):
        raise HTTPException(409, 'Workflow observations must be attributed to the controlled object owner')
    try:
        selected = [captures[ref] for ref in evidence]
        if len({c['original']['url'] for c in selected}) != 1:
            raise HTTPException(409, 'Workflow controls must observe the same controlled resource')
        comparisons = [compare_responses(base64.b64decode(selected[0]['original']['response_b64'], validate=True),
                                        base64.b64decode(c['original']['response_b64'], validate=True), [])
                       for c in selected[1:]]
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, 'Original workflow observations are unavailable or invalid') from None
    secrets = known_secrets(state)
    return {'workflow_id': body.workflow_id, 'object_id': body.object_id, 'evidence_ids': evidence,
            'invariant': sanitize(body.invariant, secrets), 'expected_after': sanitize(body.expected_after, secrets),
            'recorded_before': workflow['before'], 'recorded_after': workflow['after'],
            'invariant_result': body.invariant_result, 'comparisons': comparisons, 'rationale': sanitize(body.rationale, secrets),
            'status': 'human_assertion', 'limitations': [
                'The authorization, controlled state change, invariant and result are human assertions.',
                'Saved observations do not prove causation or independently verify a business invariant.']}


class InputValidationReview(Strict):
    object_id: Ref
    baseline_capture_id: Ref
    test_capture_id: Ref
    invariant: Text
    action_authorized: Literal[True]
    boundary_result: Literal['satisfied', 'violated', 'unknown']
    rationale: Text


def input_validation_review(state: dict, body: InputValidationReview) -> dict:
    """Review one saved integer-query control; execution uses a separate approval."""
    require(state, 'captures', [body.baseline_capture_id, body.test_capture_id])
    baseline, tested = (state['captures'][body.baseline_capture_id], state['captures'][body.test_capture_id])
    if body.baseline_capture_id == body.test_capture_id:
        raise HTTPException(409, 'Distinct baseline and test observations required')
    for capture in (baseline, tested):
        if capture.get('expired'):
            raise HTTPException(410, 'Original capture expired')
    if baseline['identity_id'] != tested['identity_id']:
        raise HTTPException(409, 'Input controls require the same controlled object owner')
    from worker.http_profile import specialty_shape
    review = {'profile': 'integer_query', 'object_id': body.object_id,
              'authorized': body.action_authorized, 'invariant': body.invariant}
    try:
        url = tested['original']['url']
        request_specialty(state, baseline['identity_id'], body.object_id, url, review)
        if baseline['evidence_id'] not in state['objects'][body.object_id]['evidence_ids']:
            raise HTTPException(409, 'Baseline must support the recorded controlled object')
        if baseline['original']['url'] != urlsplit(url)._replace(query='').geturl():
            raise HTTPException(409, 'Baseline must be the same resource without query')
        specialty_shape({'method': tested['method'], 'url': url, 'body': '', 'specialty': review})
        for capture in (baseline, tested):
            raw = base64.b64decode(capture['original']['request_b64'], validate=True)
            parsed = capture_metadata(capture['original'], {'targets': [urlsplit(url).hostname],
                'ports': [urlsplit(url).port or (443 if urlsplit(url).scheme == 'https' else 80)]})
            if parsed['method'] != 'GET' or not raw.partition(b'\r\n\r\n')[1] or raw.partition(b'\r\n\r\n')[2]:
                raise HTTPException(409, 'Only bodyless GET controls are supported')
        comparison = compare_responses(*[base64.b64decode(c['original']['response_b64'], validate=True)
                                         for c in (baseline, tested)], [])
    except (KeyError, TypeError, ValueError, AttributeError):
        raise HTTPException(409, 'Invalid bounded input observations') from None
    if not body.rationale.strip():
        raise HTTPException(422, 'Review rationale required')
    return {'object_id': body.object_id, 'capture_ids': [body.baseline_capture_id, body.test_capture_id],
            'evidence_ids': [baseline['evidence_id'], tested['evidence_id']], 'comparison': comparison,
            'boundary_result': body.boundary_result, 'status': 'human_assertion',
            'invariant': sanitize(body.invariant, known_secrets(state)),
            'rationale': sanitize(body.rationale, known_secrets(state)),
            'limitations': ['The invariant and observed boundary result are human assertions.',
                            'Error codes, reflected input and scanner labels do not confirm a finding.']}


def fresh() -> dict:
    return {'revision': 0, 'policy': {'retention_days': 7, 'provider_sharing': 'deny'},
            'identities': {}, 'captures': {}, 'requests': {}, 'objects': {}, 'workflows': {}, 'permissions': {}}


def seal(state: dict) -> str:
    payload = json.dumps(state, separators=(',', ':')).encode()
    if len(payload) > 16 * 1024 * 1024:
        raise HTTPException(409, 'Engagement map exceeds the 16 MiB storage limit')
    return evidence_cipher().encrypt(payload).decode()


def unseal(value: str) -> dict:
    state = json.loads(evidence_cipher().decrypt(value.encode()))
    state.setdefault('requests', {})
    return state


def known_secrets(state: dict) -> list[str]:
    values = list(deployment_secrets())
    for identity in state['identities'].values():
        for key, value in identity['credentials'].items():
            values.append(value)
            if key == 'authorization':
                values.append(value.split(' ', 1)[-1])
            if key == 'cookie':
                values.extend(part.partition('=')[2].strip() for part in value.split(';'))
    return values


def sanitize(value, secrets):
    # Unlike general-purpose redaction, redact even short known credential values.
    if isinstance(value, dict):
        return {sanitize(k, secrets): sanitize(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
            value = value.replace(secret, '[REDACTED]')
    return redact(value)


def expire(state: dict) -> None:
    timestamp = now().isoformat()
    # Keep non-secret attribution but destroy expired credentials and raw bodies.
    for identity in state['identities'].values():
        if identity['expires_at'] <= timestamp:
            identity['credentials'] = {}
            identity['active'] = False
    for capture in [*state['captures'].values(), *state['requests'].values()]:
        if capture['expires_at'] <= timestamp:
            capture.pop('original', None)
            capture['expired'] = True


def public(state: dict) -> dict:
    result = copy.deepcopy(state)
    for identity in result['identities'].values():
        identity.pop('credentials')
    for capture in [*result['captures'].values(), *result['requests'].values()]:
        capture.pop('original', None)
    return result


def require(state: dict, collection: str, references: list[str]) -> None:
    if any(ref not in state[collection] for ref in references):
        raise HTTPException(422, 'Reference does not belong to this engagement map')


def capture_metadata(source: dict, scope: dict) -> dict:
    """Parse selected, previously saved captures without sending a request."""
    parts = urlsplit(source['url'])
    if parts.scheme not in {'http', 'https'} or parts.username or parts.password or parts.fragment:
        raise HTTPException(422, 'Expected an HTTP(S) evidence URL without userinfo or fragment')
    validate_command(shlex.join(['curl', '-I', source['url']]), scope)
    raw = base64.b64decode(source['request_b64'], validate=True)
    response = base64.b64decode(source['response_b64'], validate=True)
    if len(raw) > 65536 or len(response) > 1048576:
        raise HTTPException(422, 'Evidence exceeds bounded capture limits')
    head, sep, body = raw.partition(b'\r\n\r\n')
    lines = head.decode('iso-8859-1').split('\r\n')
    method, target, version = lines[0].split(' ')
    expected = (parts.path or '/') + ('?' + parts.query if parts.query else '')
    if not sep or target != expected or version not in {'HTTP/1.0', 'HTTP/1.1'} or method not in {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}:
        raise HTTPException(422, 'Invalid captured request line')
    parameters = {'query': sorted(parse_qs(parts.query, keep_blank_values=True)), 'body': []}
    headers = {}
    for line in lines[1:]:
        key, separator, value = line.partition(':')
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise HTTPException(422, 'Invalid captured header')
        if key.lower() in headers:
            raise HTTPException(422, 'Duplicate captured headers are unsupported')
        headers[key.lower()] = value.strip()
    if headers.get('host', '').lower() != parts.netloc.lower():
        raise HTTPException(422, 'Capture Host differs from evidence URL')
    if 'transfer-encoding' in headers or 'proxy-authorization' in headers:
        raise HTTPException(422, 'Unsupported captured framing')
    if (body and 'content-length' not in headers) or int(headers.get('content-length', '0')) != len(body):
        raise HTTPException(422, 'Captured body length mismatch')
    content_type = headers.get('content-type', '').split(';')[0].strip().lower()
    if content_type == 'application/json' and body:
        payload = json.loads(body)
        if isinstance(payload, dict):
            parameters['body'] = sorted(payload)
    elif content_type == 'application/x-www-form-urlencoded':
        parameters['body'] = sorted(parse_qs(body.decode(), keep_blank_values=True))
    return {'method': method, 'route': parts.path or '/', 'origin': f'{parts.scheme}://{parts.netloc}',
            'parameters': parameters, 'request_sha256': hashlib.sha256(raw).hexdigest(),
            'response_sha256': hashlib.sha256(response).hexdigest()}


def compare_responses(left: bytes, right: bytes, ignore: list[str]) -> dict:
    def normalized(raw):
        if len(raw) > 1048576:
            raise HTTPException(422, 'Response exceeds comparison limit')
        head, sep, body = raw.partition(b'\r\n\r\n')
        if not sep:
            raise HTTPException(422, 'Expected bounded HTTP response evidence')
        lines = head.decode('iso-8859-1').split('\r\n')
        match = re.fullmatch(r'HTTP/1\.[01] ([1-5][0-9]{2})(?: .*)?', lines[0])
        if not match:
            raise HTTPException(422, 'Invalid response status')
        headers = {}
        for line in lines[1:]:
            key, separator, value = line.partition(':')
            if not separator:
                raise HTTPException(422, 'Invalid response header')
            headers[key.lower()] = value.strip()
        content_type = headers.get('content-type', '').split(';')[0].strip().lower()
        mode = 'bytes'
        value = body
        if content_type == 'application/json' or content_type.endswith('+json'):
            try:
                def unique_object(pairs):
                    result = {}
                    for key, item in pairs:
                        if key in result:
                            raise ValueError('Ambiguous duplicate JSON key')
                        result[key] = item
                    return result
                def invalid_constant(value):
                    raise ValueError('Non-finite JSON number')
                value = json.loads(body, object_pairs_hook=unique_object, parse_constant=invalid_constant)
                def strip(item):
                    if isinstance(item, dict):
                        return {k: strip(v) for k, v in item.items() if k not in ignore}
                    if isinstance(item, list):
                        return [strip(v) for v in item]
                    return item
                value = json.dumps(strip(value), sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
                mode = 'json'
            except (ValueError, UnicodeError, RecursionError):
                value = body
        return {'status': int(match[1]), 'content_type': content_type, 'mode': mode,
                'body_digest': hashlib.sha256(value).hexdigest(), 'raw_sha256': hashlib.sha256(raw).hexdigest(),
                'bytes': len(raw)}
    a, b = normalized(left), normalized(right)
    return {'left': a, 'right': b, 'identical': left == right,
            'equivalent': all(a[key] == b[key] for key in ('status', 'content_type', 'mode', 'body_digest')),
            'ignored_json_keys': ignore, 'verification_status': 'observation',
            'limitation': 'Comparison does not establish authorization or vulnerability; headers other than content type are not compared.'}


class ApplicationMap:
    async def _load(self, db, sid: str, owner: str):
        session = await owned_engagement(db, sid, owner)
        key = str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-application-map:' + sid))
        row = await db.get(DecisionLog, key)
        if row is None:
            row = DecisionLog(id=key, session_id=sid, user_id=owner,
                              decision_type='application_map_private', metadata_={})
            state = fresh()
            db.add(row)
        else:
            state = unseal(row.metadata_['sealed'])
        session.metadata_ = {**(getattr(session, 'metadata_', None) or {}), 'application_mapping': True}
        expire(state)
        return session, row, state

    async def _save(self, db, row, state):
        # The source capture follows the selected map's earliest retention bound.
        for capture in state['captures'].values():
            source = await db.get(ChatLog, capture['evidence_id'])
            if source is None or source.session_id != row.session_id:
                continue
            data = dict(source.data or {})
            data['retention_expires_at'] = min(data.get('retention_expires_at', capture['expires_at']),
                                                capture['expires_at'])
            if capture['expired']:
                data.pop('protected_original', None)
                data['retention_expired'] = True
                summary = data.get('summary', {})
                data['summary'] = {key: summary[key] for key in ('method', 'endpoint', 'parameters') if key in summary}
                source.content = json.dumps(data['summary'])
            source.data = data
        expired_evidence = [capture['evidence_id'] for capture in state['captures'].values() if capture['expired']]
        if expired_evidence:
            legacy = (await db.execute(select(WebAction).where(
                WebAction.session_id == row.session_id, WebAction.evidence_id.in_(expired_evidence)
            ).with_for_update())).scalars().all()
            for action in legacy:
                action.protected_spec = seal({'retention_expired': True})
                action.protected_response = None
                action.result = {'retention_expired': True, 'reason_code': 'source_retention_expired'}
                if action.state in {'pending', 'approved'}:
                    action.state = 'cancelled'
                elif action.state in {'claimed', 'unknown', 'cancel_requested'}:
                    action.state = 'cancel_requested'
        jobs = (await db.execute(select(DecisionLog).where(
            DecisionLog.session_id == row.session_id, DecisionLog.decision_type == 'worker_job',
            DecisionLog.metadata_['http_identity'].as_string().is_not(None)).with_for_update())).scalars().all()
        for job in jobs:
            data = dict(job.metadata_)
            identity = state['identities'].get(data.get('http_identity'))
            capture = state['captures'].get(data.get('http_capture')) or state['requests'].get(data.get('http_capture'))
            if identity and capture:
                cutoff = min(identity['expires_at'], capture['expires_at'])
                if not identity['active'] or capture['expired']:
                    cutoff = min(cutoff, now().isoformat())
                data['private_expires_at'] = min(data.get('private_expires_at', cutoff), cutoff)
                if data['private_expires_at'] <= now().isoformat() and data['state'] in {'succeeded', 'failed', 'cancelled'}:
                    data.pop('protected_http', None)
                    data.pop('protected_response', None)
                    data['private_evidence_expired'] = True
                job.metadata_ = data
        # No plaintext credentials or source bodies in audit/chat/session JSON.
        row.metadata_ = {'schema_version': 1, 'sealed': seal(state)}
        await db.commit()

    async def purge_expired(self) -> None:
        # Scan only private map rows; each engagement is serialized separately,
        # including archived engagements whose API is no longer writable.
        offset = 0
        while True:
            async with async_session() as db:
                ids = list((await db.execute(select(DecisionLog.session_id).where(
                    DecisionLog.decision_type == 'application_map_private').order_by(DecisionLog.id)
                    .offset(offset).limit(100))).scalars().all())
            if not ids:
                break
            for sid in ids:
                async with async_session() as db:
                    session = (await db.execute(select(PentestSession).where(PentestSession.id == sid).with_for_update())).scalar_one_or_none()
                    if session is None:
                        continue
                    session.metadata_ = {**(session.metadata_ or {}), 'application_mapping': True}
                    key = str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-application-map:' + sid))
                    row = await db.get(DecisionLog, key)
                    if row:
                        state = unseal(row.metadata_['sealed'])
                        expire(state)
                        await self._save(db, row, state)
            offset += len(ids)

    async def retention_loop(self) -> None:
        while True:
            try:
                await self.purge_expired()
                from memory.worker_jobs import worker_jobs
                await worker_jobs.enforce_retention()
                await worker_jobs.store.expire_http()
                from memory.web_actions import web_actions
                await web_actions.retention_cleanup()
            except asyncio.CancelledError:
                raise
            except Exception:
                import structlog
                structlog.get_logger(__name__).warning('application_retention_cleanup_failed')
            await asyncio.sleep(60)

    async def view(self, sid: str, owner: str, provider: bool = False) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)  # Persist lazy expiry on every access.
            if provider and state['policy']['provider_sharing'] != 'redacted_metadata':
                raise HTTPException(403, 'Provider sharing is disabled for this application map')
            return public(state)

    async def change(self, sid: str, owner: str, kind: str, body: Change) -> dict:
        async with async_session() as db:
            session, row, state = await self._load(db, sid, owner)
            if state['revision'] != body.expected_revision:
                raise HTTPException(409, 'Application map changed; reload before editing')
            data = body.model_dump(exclude={'expected_revision'})
            key = str(uuid.uuid4())
            timestamp = now()
            expires = (timestamp + timedelta(days=state['policy']['retention_days'])).isoformat()
            if kind == 'identities':
                data['credentials'] = {k: v.get_secret_value() for k, v in body.credentials.items()}
                data.update(active=True, expires_at=expires)
                # Sanitize annotations before retention can erase known secrets.
                temporary = {**state, 'identities': {**state['identities'], key: data}}
                data['label'] = sanitize(data['label'], known_secrets(temporary))
                data['role'] = sanitize(data['role'], known_secrets(temporary))
            elif kind == 'requests':
                require(state, 'identities', [body.identity_id])
                identity = state['identities'][body.identity_id]
                if not identity['active']:
                    raise HTTPException(409, 'Identity expired or revoked')
                from worker.http_profile import command_for, validate
                spec = {'method': body.method, 'url': body.url, 'headers': identity['credentials'],
                        'expires_at': min(expires, identity['expires_at'])}
                if body.profile:
                    spec['specialty'] = request_specialty(state, body.identity_id, body.object_id, body.url, {
                        'profile': body.profile, 'object_id': body.object_id,
                        'authorized': body.action_authorized, 'invariant': body.invariant})
                    spec['body'] = json.dumps(body.json_body, sort_keys=True, separators=(',', ':')) if body.json_body is not None else ''
                    from worker.http_profile import specialty_shape
                    try:
                        specialty_shape(spec)
                    except (ValueError, TypeError, AttributeError):
                        raise HTTPException(422, 'Request exceeds the bounded specialty profile') from None
                    if (session.scope or {}).get('web_specialist_profiles') is not True:
                        raise HTTPException(409, 'Specialty profiles require explicit lab scope opt-in')
                try:
                    validate(command_for(body.identity_id, key, spec), session.scope or {})
                    if any(secret and secret in body.url for secret in known_secrets(state)):
                        raise ValueError('Credential in URL')
                    parts = urlsplit(body.url)
                    raw = (body.method + ' ' + (parts.path or '/') + ('?' + parts.query if parts.query else '') + ' HTTP/1.1\r\nHost: ' + parts.netloc + '\r\n' +
                           ''.join(name + ': ' + value + '\r\n' for name, value in identity['credentials'].items()) +
                           ('Content-Type: application/json\r\nContent-Length: ' + str(len(spec['body'])) + '\r\n' if body.method == 'PUT' else '') +
                           '\r\n' + spec.get('body', '')).encode('ascii')
                except (ValueError, TypeError, UnicodeError):
                    raise HTTPException(422, 'Request URL or method is outside the reviewed HTTP profile') from None
                data = {'identity_id': body.identity_id, 'method': body.method, 'route': parts.path or '/',
                        'origin': parts.scheme + '://' + parts.netloc, 'status': 'planned_request',
                        'original': {'url': body.url, 'request_b64': base64.b64encode(raw).decode(), 'response_b64': '',
                                     **({'specialty': spec['specialty'], 'body': spec['body']} if body.profile else {})},
                        'expired': False, 'expires_at': min(expires, identity['expires_at'])}
            elif kind == 'captures':
                require(state, 'identities', [body.identity_id])
                if not state['identities'][body.identity_id]['active']:
                    raise HTTPException(409, 'Identity expired or revoked')
                source_row = await db.get(ChatLog, body.evidence_id)
                if not source_row or source_row.session_id != sid or source_row.msg_type != 'burp_evidence':
                    raise HTTPException(404, 'Selected capture not found in this engagement')
                from memory.burp_community import original, credential_values
                source = original(source_row.data)
                try:
                    metadata = capture_metadata(source, session.scope or {})
                    captured_headers = {}
                    for line in base64.b64decode(source['request_b64']).partition(b'\r\n\r\n')[0].decode('iso-8859-1').split('\r\n')[1:]:
                        name, _, value = line.partition(':')
                        if name.lower() in {'authorization', 'cookie', 'x-api-key'}:
                            captured_headers[name.lower()] = value.strip()
                    if captured_headers != state['identities'][body.identity_id]['credentials']:
                        raise HTTPException(409, 'Capture credentials do not match the selected identity')
                    secrets = known_secrets(state) + credential_values(base64.b64decode(source['request_b64']))
                except (ValueError, TypeError, KeyError, RecursionError):
                    raise HTTPException(422, 'Invalid or out-of-scope saved capture') from None
                for field in ('route', 'origin', 'parameters'):
                    metadata[field] = sanitize(metadata[field], secrets)
                data = {**metadata, **data, 'original': source,
                        'role': state['identities'][body.identity_id]['role'],
                        'attribution': 'human_selected', 'expired': False, 'expires_at': expires}
                # Bind a saved capture once; an identity swap is not new evidence.
                if any(c['evidence_id'] == body.evidence_id for c in state['captures'].values()):
                    raise HTTPException(409, 'Capture already mapped; preserve its original attribution')
            elif kind == 'objects':
                require(state, 'identities', [body.owner_identity_id])
                self._evidence(state, body.evidence_ids)
            elif kind == 'workflows':
                self._evidence(state, body.evidence_ids)
            elif kind == 'permissions':
                require(state, 'objects', [body.object_id])
                require(state, 'identities', [body.identity_id])
                self._evidence(state, body.evidence_ids)
                # Append corrections, preserving prior human expectations.
                data['supersedes'] = next((p['id'] for p in reversed(list(state['permissions'].values()))
                    if (p['object_id'], p['identity_id'], p['operation']) ==
                       (body.object_id, body.identity_id, body.operation)), None)
            elif kind == 'policy':
                state['policy'] = data
                for collection in ('identities', 'captures', 'requests'):
                    for item in state[collection].values():
                        ceiling = (datetime.fromisoformat(item['created_at']) +
                                   timedelta(days=body.retention_days)).isoformat()
                        item['expires_at'] = min(item['expires_at'], ceiling)
                expire(state)
            else:
                raise HTTPException(422, 'Unknown mapping operation')
            if kind != 'policy':
                if len(state[kind]) >= (20 if kind == 'identities' else 500):
                    raise HTTPException(409, 'Engagement map capacity reached')
                if kind not in {'identities', 'captures', 'requests'}:
                    for field in ('label', 'before', 'after', 'operation', 'rationale'):
                        if field in data:
                            data[field] = sanitize(data[field], known_secrets(state))
                data.update(id=key, recorded_by=owner, created_at=timestamp.isoformat())
                state[kind][key] = data
            state['revision'] += 1
            await self._save(db, row, state)
            return {'id': key if kind != 'policy' else None, 'revision': state['revision']}

    @staticmethod
    def _evidence(state, references):
        valid = {item['evidence_id'] for item in state['captures'].values()}
        if any(ref not in valid for ref in references):
            raise HTTPException(422, 'Evidence must be selected into this engagement map')

    async def revoke(self, sid: str, owner: str, identity_id: str, body: Change) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            if state['revision'] != body.expected_revision:
                raise HTTPException(409, 'Application map changed; reload before editing')
            require(state, 'identities', [identity_id])
            state['identities'][identity_id].update(credentials={}, active=False)
            # Captured requests may contain the same credential: erase those too.
            for capture in [*state['captures'].values(), *state['requests'].values()]:
                if capture['identity_id'] == identity_id:
                    capture.pop('original', None)
                    capture['expired'] = True
            state['revision'] += 1
            await self._save(db, row, state)
            revision = state['revision']
        from memory.worker_jobs import worker_jobs
        cancellation = await worker_jobs.cancel_session(owner, sid)
        from orchestrator.browser_mapping import browser_mapping
        await browser_mapping.revoke(owner, sid, identity_id)
        return {'revision': revision, 'worker_cancellation': cancellation}

    async def replay_material(self, sid: str, owner: str, identity_id: str, capture_id: str) -> tuple[str, str]:
        from config.settings import settings
        from worker.http_profile import command_for, cipher, decode, validate
        async with async_session() as db:
            session, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            require(state, 'identities', [identity_id])
            capture = state['captures'].get(capture_id) or state['requests'].get(capture_id)
            if capture is None:
                raise HTTPException(404, 'Saved capture or planned request not found')
            identity = state['identities'][identity_id]
            if not identity['active'] or capture['expired'] or capture['identity_id'] != identity_id:
                raise HTTPException(409, 'Replay identity or capture is expired, revoked or mismatched')
            original = capture['original']
            raw = base64.b64decode(original['request_b64'])
            head, _, body = raw.partition(b'\r\n\r\n')
            method = head.split(b' ', 1)[0].decode('ascii')
            if 'specialty' not in original and (method not in {'GET', 'HEAD'} or body):
                raise HTTPException(409, 'Authenticated worker supports bodyless GET/HEAD only')
            spec = {'method': method, 'url': original['url'], 'headers': identity['credentials'],
                    'expires_at': min(identity['expires_at'], capture['expires_at'])}
            if 'specialty' in original:
                review = original['specialty']
                request_specialty(state, identity_id, review['object_id'], spec['url'], review)
                if (session.scope or {}).get('web_specialist_profiles') is not True:
                    raise HTTPException(409, 'Specialty profile lab permission was revoked')
                spec.update(specialty=review, body=original['body'])
            command = command_for(identity_id, capture_id, spec)
            try:
                validate(command, session.scope or {})
                token = cipher(settings.HTTP_REPLAY_KEY).encrypt(json.dumps(spec).encode()).decode()
                decode(token, command, settings.HTTP_REPLAY_KEY)
                if len(token) > 12000:
                    raise ValueError('Encrypted HTTP request exceeds transport limit')
            except (ValueError, TypeError):
                raise HTTPException(409, 'Replay key, credential size, URL or scope does not support this profile') from None
            return command, token

    async def replay_proposal(self, sid: str, owner: str, identity_id: str, capture_id: str) -> dict:
        from memory.execution_authorization import execution_authorization
        command, token = await self.replay_material(sid, owner, identity_id, capture_id)
        from config.settings import settings
        from worker.http_profile import decode
        approved_spec = decode(token, command, settings.HTTP_REPLAY_KEY)
        from memory.worker_jobs import worker_jobs
        if settings.KALI_WORKER_PROTOCOL != 'jobs-v1':
            raise HTTPException(409, 'Authenticated HTTP requires the jobs-v1 worker profile')
        try:
            async with asyncio.timeout(3):
                caps = await worker_jobs.client.capabilities()
            from worker.http_profile import parse
            args = parse(command)
            capability = 'specialist_http_version' if args[4] == 'PUT' or urlsplit(args[5]).query else 'authenticated_http_version'
            version = caps.get(capability) if isinstance(caps, dict) else None
            if type(version) is not int or version != 1:
                raise ValueError('Unsupported profile')
        except Exception:
            raise HTTPException(409, 'Worker authenticated HTTP capability is unavailable') from None
        await worker_jobs.resume_session(owner, sid)
        proposal = await execution_authorization.propose(owner, sid, command, 'aria-http',
            require_approval=True, turn_id=capture_id)
        return {'action_id': proposal.id, 'command': command, 'status': proposal.status,
                'identity_id': identity_id, 'capture_id': capture_id,
                'reviewed_request': {'method': approved_spec['method'], 'url': approved_spec['url'],
                    **({'specialty': redact(approved_spec['specialty']), 'body': redact(approved_spec['body'])}
                       if 'specialty' in approved_spec else {})},
                'limitation': 'Executes only the approval-bound reviewed method, URL and bounded body with identity authentication. No redirects or retries; specialty actions require controlled-object lab opt-in.'}

    async def catalog_replay(self, sid: str, owner: str, job_id: str) -> dict:
        from config.settings import settings
        from memory.worker_jobs import worker_jobs
        from security.encryption import evidence_cipher
        from worker.http_profile import cipher
        async with async_session() as db:
            session, row, state = await self._load(db, sid, owner)
            job = await worker_jobs.store.get(job_id)
            if (not job or job['session_id'] != sid or job['user_id'] != owner
                    or job['state'] != 'succeeded' or not job.get('protected_response')):
                raise HTTPException(404, 'Completed private replay not found')
            identity = state['identities'].get(job.get('http_identity'))
            if not identity or not identity['active'] or job['private_expires_at'] <= now().isoformat():
                raise HTTPException(410, 'Replay identity or evidence expired')
            capture_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-replay-capture:' + job_id))
            if capture_id in state['captures']:
                return {'id': capture_id, 'revision': state['revision'], 'duplicate': True}
            if len(state['captures']) >= 500:
                raise HTTPException(409, 'Engagement capture capacity reached')
            private = json.loads(cipher(settings.HTTP_REPLAY_KEY).decrypt(job['protected_response'].encode()))
            spec = json.loads(cipher(settings.HTTP_REPLAY_KEY).decrypt(job['protected_http'].encode()))
            original = {'url': spec['url'], 'request_b64': private['request_b64'], 'response_b64': private['response_b64']}
            metadata = capture_metadata(original, session.scope or {})
            for field in ('route', 'origin', 'parameters'):
                metadata[field] = sanitize(metadata[field], known_secrets(state))
            evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-replay-source:' + job_id))
            timestamp = now().isoformat()
            state['captures'][capture_id] = {**metadata, 'id': capture_id, 'identity_id': job['http_identity'],
                'evidence_id': evidence_id, 'job_id': job_id, 'role': identity['role'], 'original': original,
                'attribution': 'authenticated_worker_receipt', 'expired': False,
                'expires_at': min(job['private_expires_at'], identity['expires_at']),
                'recorded_by': owner, 'created_at': timestamp}
            if await db.get(ChatLog, evidence_id) is None:
                db.add(ChatLog(id=evidence_id, session_id=sid, role='tool_output', msg_type='application_capture',
                    content=json.dumps(metadata), data={'source': 'authenticated_worker_receipt', 'job_id': job_id,
                    'summary': metadata, 'protected_original': evidence_cipher().encrypt(json.dumps(original).encode()).decode()}))
            state['revision'] += 1
            await self._save(db, row, state)
            return {'id': capture_id, 'evidence_id': evidence_id, 'revision': state['revision'], 'duplicate': False}

    async def replay_comparison(self, sid: str, owner: str, job_id: str) -> dict:
        from config.settings import settings
        from memory.worker_jobs import worker_jobs
        from worker.http_profile import cipher
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            job = await worker_jobs.store.get(job_id)
            if not job or job['session_id'] != sid or job['user_id'] != owner or not job.get('protected_response'):
                raise HTTPException(404, 'Authenticated replay evidence not found')
            identity = state['identities'].get(job.get('http_identity'))
            if not identity or not identity['active']:
                raise HTTPException(410, 'Replay identity expired or revoked')
            # Resolve the exact baseline from the server-bound encrypted spec.
            spec = json.loads(cipher(settings.HTTP_REPLAY_KEY).decrypt(job['protected_http'].encode()))
            candidates = [capture for capture in state['captures'].values()
                          if capture['identity_id'] == job['http_identity'] and not capture['expired']
                          and capture['original']['url'] == spec['url']
                          and capture['method'] == spec['method']]
            capture_id = job.get('http_capture')
            baseline = next((capture for capture in candidates if capture['id'] == capture_id), None)
            if baseline is None:
                if capture_id in state['requests'] and not state['requests'][capture_id]['expired']:
                    raise HTTPException(409, 'Planned request has no observed baseline; catalog the receipt first')
                raise HTTPException(410, 'Replay baseline expired or was revoked')
            raw = json.loads(cipher(settings.HTTP_REPLAY_KEY).decrypt(job['protected_response'].encode()))
            return {**compare_responses(base64.b64decode(baseline['original']['response_b64']),
                                       base64.b64decode(raw['response_b64']), []),
                    'job_id': job_id, 'identity_id': job['http_identity'], 'capture_id': capture_id}

    async def review_authorization(self, sid: str, owner: str, body: AuthorizationReview) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            return authorization_review(state, body)

    async def review_authentication(self, sid: str, owner: str, body: AuthenticationReview) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            return authentication_review(state, body)

    async def review_exposure(self, sid: str, owner: str, body: ExposureReview) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            return exposure_review(state, body)

    async def review_input_validation(self, sid: str, owner: str, body: InputValidationReview) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            return input_validation_review(state, body)

    async def review_business_logic(self, sid: str, owner: str, body: BusinessLogicReview) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            return business_logic_review(state, body)

    async def compare(self, sid: str, owner: str, body: ComparisonInput) -> dict:
        async with async_session() as db:
            _, row, state = await self._load(db, sid, owner)
            await self._save(db, row, state)
            require(state, 'captures', [body.left, body.right])
            captures = [state['captures'][ref] for ref in (body.left, body.right)]
            if any(capture['expired'] for capture in captures):
                raise HTTPException(410, 'Original capture expired or was revoked')
            raw = [base64.b64decode(capture['original']['response_b64'], validate=True) for capture in captures]
            result = compare_responses(*raw, body.ignore_json_keys)
            result['ignored_json_keys'] = sanitize(body.ignore_json_keys, known_secrets(state))
            return {**result, 'capture_ids': [body.left, body.right]}


application_map = ApplicationMap()
