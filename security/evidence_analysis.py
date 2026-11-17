"""Reference-grounded deterministic review aids, without inference or execution.

These rules explain evidence limitations. They never promote a candidate to a
verified finding; the human finding-verification state machine remains authority.
"""
from __future__ import annotations

from security.redaction import redact

AUTHZ = 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
WSTG = 'https://owasp.org/www-project-web-security-testing-guide/v42/'


def review(record: dict) -> dict:
    """Interpret a bounded structured observation as an attributed review aid."""
    kind, data = record.get('kind'), record.get('data') or {}
    ref = record.get('evidence_id')
    if not isinstance(ref, str) or not ref or len(ref) > 100 or not isinstance(data, dict):
        raise ValueError('An attributed structured observation is required')
    rule, fact, missing, alternative, remediation, source = (
        'unsupported_observation', 'No applicable deterministic interpretation.',
        'A supported structured observation with source provenance.',
        'The supplied material may be incomplete or outside this profile.',
        'Obtain an authorized independently reviewed evidence record before drawing conclusions.', WSTG)
    if kind == 'authentication':
        rule = 'bearer_not_authentication_proof'
        fact = 'A Bearer header indicates a presented credential scheme; token format, validity and authenticated success are unknown.'
        missing = 'Server-side credential validation, identity attribution and controlled valid/invalid comparisons.'
        alternative = 'The token may be opaque, expired, invalid, or irrelevant to a public response.'
        remediation = 'Validate credentials on the server and protect token transport/storage; do not assume JWT from Bearer.'
        source = 'https://www.rfc-editor.org/rfc/rfc6750'
    elif kind == 'authorization':
        rule = 'status_not_authorization_proof'
        fact = 'A successful status alone does not establish access to a private object or an authorization bypass.'
        missing = 'Controlled identities/roles, object ownership, actual sensitive content, negative controls and independent reproduction.'
        alternative = 'The resource may be public, a generic success/error page, or cached shared content.'
        remediation = 'Enforce server-side object/action authorization on every request and deny by default.'
        source = AUTHZ
    elif kind == 'session':
        rule = 'cookie_flags_need_context'
        fact = 'Observed cookie attributes do not establish session purpose, entropy, rotation, expiry or fixation resistance.'
        missing = 'Session-cookie purpose, HTTPS context, attribute scope, lifecycle and login/logout rotation controls.'
        alternative = 'The cookie may be an unrelated preference or deliberately readable application value.'
        remediation = 'For sensitive session cookies use Secure, HttpOnly and appropriate SameSite; validate lifecycle and CSRF defenses separately.'
        source = 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'
    elif kind == 'input_validation':
        rule = 'reflection_not_execution'
        fact = 'Reflection of input does not establish browser execution, SQL interpretation or a confirmed injection vulnerability.'
        missing = 'Output context, encoding/escaping, parser behavior, positive/negative controls and independently reproduced effect.'
        alternative = 'The application may safely encode text or return it in a non-executable context.'
        remediation = 'Use context-appropriate output encoding, parameterized queries and server-side input validation.'
    elif kind == 'cryptography':
        rule = 'decoded_jwt_not_verified'
        fact = 'Decoding a JWT or reading an algorithm claim does not validate its signature or prove server acceptance.'
        missing = 'Allowed algorithms, key selection, signature validation, issuer/audience/expiry enforcement and controlled server behavior.'
        alternative = 'The token may be a fabricated or rejected input; an untrusted header is not verifier configuration.'
        remediation = 'Pin accepted algorithms and trusted keys; validate signatures and required claims with a reviewed library.'
        source = 'https://www.rfc-editor.org/rfc/rfc8725'
    elif kind == 'access_control':
        rule = 'client_ui_not_access_control'
        fact = 'A hidden client-side action is not evidence that the server authorizes or rejects that action.'
        missing = 'Server policy, object/action ownership checks and tests across roles and direct API requests.'
        alternative = 'A server check may exist independently of the interface; UI evidence cannot prove its absence.'
        remediation = 'Enforce least privilege and deny-by-default authorization in the server trust boundary.'
        source = AUTHZ
    elif kind == 'api_security':
        wildcard = data.get('allow_origin') == '*' and data.get('allow_credentials') is True
        rule = 'wildcard_not_credentialed_cors' if wildcard else 'cors_requires_browser_context'
        fact = ('A wildcard allow-origin does not permit credentialed CORS response sharing in conforming browsers.' if wildcard
                else 'CORS headers alone do not prove that an untrusted origin can read sensitive authenticated content.')
        missing = 'Browser credentials mode, requesting origin, actual sensitive content and reproducible browser controls.'
        alternative = 'The browser may reject the response or the resource may intentionally be public; CORS is not CSRF protection.'
        remediation = 'Use explicit trusted origins where credentialed sharing is required; retain server authorization and separate CSRF defenses.'
        source = 'https://fetch.spec.whatwg.org/#cors-protocol-and-credentials'
    elif kind == 'network_security':
        state = data.get('state')
        rule = 'filtered_not_open' if state in {'filtered','open|filtered','closed|filtered'} else 'open_not_vulnerability_proof'
        fact = ('A filtered or ambiguous scan state does not establish an open service.' if rule == 'filtered_not_open'
                else 'An open port indicates a reachable listener from the observed vantage, not a vulnerability or exact service version.')
        missing = 'Exact protocol, vantage, timestamps, reachability controls and application/service evidence.'
        alternative = 'Filtering, routing, probe loss, a middlebox or a different vantage may explain the observation.'
        remediation = 'Restrict unnecessary network exposure and validate required services against an explicit network policy.'
        source = 'https://nmap.org/book/man-port-scanning-basics.html'
    elif kind == 'business_logic':
        rule = 'http_success_not_business_invariant_proof'
        fact = 'Repeated HTTP success responses do not establish a repeated persisted effect, race condition or violated business invariant.'
        missing = 'A defined invariant, controlled pre/post state, idempotency behavior, ownership and independently reproduced effects.'
        alternative = 'Requests may be idempotent, rejected semantically, or return cached/generic acknowledgements.'
        remediation = 'Enforce business invariants and idempotency atomically on the server; validate authorized state-transition controls.'
    elif kind == 'architecture':
        rule = 'tls_not_secure_architecture_proof'
        fact = 'TLS addresses transport protection; it does not establish correct authorization, key management or a secure software architecture.'
        missing = 'Trust boundaries, data flows, privilege separation, key lifecycle, dependency provenance and reviewed threat assumptions.'
        alternative = 'The connection may be encrypted while application or backend boundaries remain vulnerable.'
        remediation = 'Review the threat model and enforce least privilege, authenticated boundaries and secure key/secret lifecycle.'
    return {'kind':'deterministic_evidence_review', 'topic':kind, 'rule_ids':[rule],
            'observations':[{'text':fact, 'evidence_references':[ref], 'verified':False}],
            'hypotheses':[], 'confirmed_vulnerabilities':[], 'missing_information':[missing],
            'alternative_explanations':[alternative], 'remediation':[remediation],
            'evidence_references':[ref], 'references':[source], 'commands':[],
            'limitations':['Structured rule aid, not model reasoning, independent verification or a confirmed finding.'],
            'independent_human_review':False}


def review_http(summary: dict, evidence_id: str) -> dict:
    """Explain recorded HTTP status/auth/cookie/banner/CORS observations."""
    reviews = [review({'kind':'authorization','data':summary,'evidence_id':evidence_id})]
    if summary.get('authentication_scheme') == 'bearer':
        reviews.append(review({'kind':'authentication','data':{},'evidence_id':evidence_id}))
    headers = {h['name']:h['value'] for h in summary.get('response_headers', [])}
    if 'set-cookie' in headers:
        reviews.append(review({'kind':'session','data':{},'evidence_id':evidence_id}))
    if 'access-control-allow-origin' in headers:
        reviews.append(review({'kind':'api_security','data':{
            'allow_origin':headers['access-control-allow-origin'],
            'allow_credentials':headers.get('access-control-allow-credentials')=='true'},
            'evidence_id':evidence_id}))
    status = summary.get('response_status')
    result = {'evidence_id':evidence_id, 'response_status':status,
              'status_meaning':'No response was observed' if status is None else 'Recorded HTTP response only; authorization and vulnerability status unverified',
              'reviews':reviews, 'commands':[], 'confirmed_vulnerabilities':[],
              'limitations':['Missing headers, body/context, server configuration and independent controls remain unknown.']}
    if 'server' in headers:
        result['banner_interpretation'] = 'Server is an advertised product hint; absent versions/configuration and CVE applicability remain unknown.'
    return redact(result)
