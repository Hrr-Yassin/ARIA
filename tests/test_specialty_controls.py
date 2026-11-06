"""Known secure/vulnerable/misleading/missing controls for each Phase 4 specialty.

Ground truth belongs to synthetic fixtures. Reviews remain observations/assertions;
these controls never promote a candidate to an independently verified finding.
"""
import hashlib
import unittest
from fastapi import HTTPException
from memory.application_map import (
    AuthorizationReview, authorization_review, AuthenticationReview, authentication_review,
    ExposureReview, exposure_review, BusinessLogicReview, business_logic_review,
    InputValidationReview, input_validation_review,
)
from tests.test_authorization_review import fixture, encoded


def response(content, status=200):
    return (f'HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\n\r\n'.encode() + content)


def controlled_fixture():
    state = fixture()
    for identity in state['identities'].values(): identity['credentials'] = {}
    state['identities']['a']['credentials'] = {'authorization': 'Bearer synthetic-account'}
    state['captures']['c1']['original']['request_b64'] = encoded(
        b'GET /item HTTP/1.1\r\nHost: lab.test\r\nAuthorization: Bearer synthetic-account\r\n\r\n')
    return state


class SpecialtyControls(unittest.TestCase):
    def test_authorization_four_controls(self):
        state = controlled_fixture()
        body = AuthorizationReview(object_id='o', owner_capture_id='c1', other_capture_id='c2', operation='read')
        private = b'controlled-private-record-48'
        state['captures']['c1']['original']['response_b64'] = encoded(response(private))
        for label, content, status in [('secure', b'access denied', 403), ('vulnerable', private, 200),
                                       ('misleading', b'public login page', 200)]:
            with self.subTest(control=label):
                state['captures']['c2']['original']['response_b64'] = encoded(response(content, status))
                result = authorization_review(state, body)
                self.assertEqual(result['status'], 'observation')
                self.assertEqual(result['comparison']['equivalent'], label == 'vulnerable')
                self.assertEqual(result['comparison']['right']['body_digest'], hashlib.sha256(content).hexdigest())
                self.assertEqual(result['evidence_ids'], ['e1', 'e2'])
        state['permissions'].clear()
        with self.assertRaises(HTTPException) as error: authorization_review(state, body)
        self.assertEqual(error.exception.status_code, 409)

    def test_authentication_four_controls(self):
        state = controlled_fixture()
        body = AuthenticationReview(authenticated_capture_id='c1', unauthenticated_capture_id='c2',
                                    expected_authentication_required=True, action_authorized=True)
        private = b'controlled-private-session-record'
        state['captures']['c1']['original']['response_b64'] = encoded(response(private))
        for label, content, status in [('secure', b'login required', 401), ('vulnerable', private, 200),
                                       ('misleading', b'public error', 200)]:
            with self.subTest(control=label):
                state['captures']['c2']['original']['response_b64'] = encoded(response(content, status))
                result = authentication_review(state, body)
                self.assertEqual(result['status'], 'observation')
                self.assertEqual(result['comparison']['equivalent'], label == 'vulnerable')
                self.assertEqual(result['evidence_ids'], ['e1', 'e2'])
                self.assertNotIn('synthetic-account', str(result))
        state['identities']['b']['credentials'] = {'cookie': 'still-authenticated'}
        with self.assertRaises(HTTPException): authentication_review(state, body)

    def test_exposure_four_controls(self):
        state = controlled_fixture()
        fields = dict(capture_id='c2', inspection_authorized=True, intended_visibility='restricted',
                      observed_audience='outside', meaningful_private_content='present', rationale='Synthetic fixture ground truth')
        cases = [('secure', dict(observed_audience='intended'), 'expected_or_public'),
                 ('vulnerable', {}, 'possible_unauthorized_disclosure'),
                 ('misleading', dict(intended_visibility='public', meaningful_private_content='absent'), 'expected_or_public')]
        for label, changes, expected in cases:
            with self.subTest(control=label):
                result = exposure_review(state, ExposureReview(**{**fields, **changes}))
                self.assertEqual(result['assessment'], expected)
                self.assertEqual(result['status'], 'human_assertion')
                self.assertEqual(result['evidence_id'], 'e2')
        state['captures']['c2']['expired'] = True
        with self.assertRaises(HTTPException) as error: exposure_review(state, ExposureReview(**fields))
        self.assertEqual(error.exception.status_code, 410)

    def test_business_logic_four_controls(self):
        state = controlled_fixture()
        state['captures']['c2']['identity_id'] = 'a'
        state['workflows'] = {'w': {'evidence_ids': ['e1', 'e2'], 'before': 'count=1', 'after': 'human inspected'}}
        fields = dict(workflow_id='w', object_id='o', invariant='Count stays one', expected_after='count=1',
                      action_authorized=True, controlled_state_change=True, rationale='Controlled fixture')
        for label, content, outcome in [('secure', b'count=1', 'satisfied'), ('vulnerable', b'count=2', 'violated'),
                                         ('misleading', b'HTTP success with no meaningful state', 'unknown')]:
            with self.subTest(control=label):
                state['captures']['c2']['original']['response_b64'] = encoded(response(content))
                result = business_logic_review(state, BusinessLogicReview(**fields, invariant_result=outcome))
                self.assertEqual(result['invariant_result'], outcome)
                self.assertEqual(result['status'], 'human_assertion')
                self.assertEqual(result['comparisons'][0]['right']['body_digest'], hashlib.sha256(content).hexdigest())
                self.assertEqual(result['evidence_ids'], ['e1', 'e2'])
        state['captures']['c2']['original']['response_b64'] = encoded(b'not a response')
        with self.assertRaises(HTTPException):
            business_logic_review(state, BusinessLogicReview(**fields, invariant_result='unknown'))
        state['workflows']['w']['evidence_ids'] = ['e1']
        with self.assertRaises(HTTPException):
            business_logic_review(state, BusinessLogicReview(**fields, invariant_result='unknown'))

    def test_input_validation_four_controls(self):
        state = controlled_fixture()
        # Canonical UUID object binding is repeated by the worker.
        object_id = '00000000-0000-0000-0000-000000000001'
        state['objects'][object_id] = state['objects'].pop('o')
        state['captures']['c2']['identity_id'] = 'a'
        state['captures']['c2']['original'].update(url='https://lab.test/item?count=-1',
            request_b64=encoded(b'GET /item?count=-1 HTTP/1.1\r\nHost: lab.test\r\n\r\n'))
        body = dict(object_id=object_id, baseline_capture_id='c1', test_capture_id='c2',
                    invariant='Negative counts are rejected', action_authorized=True, rationale='Controlled fixture')
        for label, content, status, outcome in [('secure', b'negative rejected', 400, 'satisfied'),
                ('vulnerable', b'count=-1 accepted', 200, 'violated'),
                ('misleading', b'generic error', 500, 'unknown')]:
            with self.subTest(control=label):
                state['captures']['c2']['original']['response_b64'] = encoded(response(content, status))
                result = input_validation_review(state, InputValidationReview(**body, boundary_result=outcome))
                self.assertEqual(result['boundary_result'], outcome)
                self.assertEqual(result['status'], 'human_assertion')
                self.assertEqual(result['evidence_ids'], ['e1', 'e2'])
                self.assertEqual(result['comparison']['right']['body_digest'], hashlib.sha256(content).hexdigest())
        state['objects'][object_id]['evidence_ids'] = []
        with self.assertRaises(HTTPException):
            input_validation_review(state, InputValidationReview(**body, boundary_result='unknown'))

    def test_exposure_content_control_distinguishes_actual_private_content_from_http_success(self):
        state = controlled_fixture()
        fields = dict(capture_id='c2', object_id='o', owner_capture_id='c1', private_json_key='controlled_record',
                      inspection_authorized=True, intended_visibility='restricted', observed_audience='outside',
                      meaningful_private_content='present', rationale='Private controlled JSON record')
        private = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"controlled_record":"synthetic-private-marker-48"}'
        state['captures']['c1']['original']['response_b64'] = encoded(private)
        for label, raw, expected, matched in [
            ('secure', response(b'denied', 403), 'inconclusive', False),
            ('vulnerable', private, 'candidate_unauthorized_disclosure', True),
            ('misleading', response(b'public login page'), 'inconclusive', False),
            ('duplicate-json', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
                b'{"controlled_record":"synthetic-private-marker-48","controlled_record":"public"}', 'inconclusive', False)]:
            with self.subTest(control=label):
                state['captures']['c2']['original']['response_b64'] = encoded(raw)
                result = exposure_review(state, ExposureReview(**fields))
                self.assertEqual(result['assessment'], expected)
                self.assertEqual(result['private_content_match'], matched)
                self.assertEqual(result['status'], 'observation')
                self.assertNotIn('synthetic-private-marker-48', str(result))
                self.assertEqual(result['evidence_ids'], ['e1', 'e2'])
        state['captures']['c2']['original']['response_b64'] = encoded(private)
        state['permissions']['p']['expected'] = 'allow'
        self.assertEqual(exposure_review(state, ExposureReview(**fields))['assessment'], 'expected_or_public')
        state['permissions'].clear()
        with self.assertRaises(HTTPException): exposure_review(state, ExposureReview(**fields))

    def test_saved_logout_and_expiry_controls_validate_credential_attribution(self):
        state = controlled_fixture()
        state['identities']['b']['credentials'] = {'cookie': 'revoked-controlled-session'}
        state['captures']['c2']['original']['request_b64'] = encoded(
            b'GET /item HTTP/1.1\r\nHost: lab.test\r\nCookie: revoked-controlled-session\r\n\r\n')
        for lifecycle in ('logged_out', 'expired'):
            body = AuthenticationReview(authenticated_capture_id='c1', unauthenticated_capture_id='c2',
                expected_authentication_required=True, action_authorized=True, session_state=lifecycle)
            for raw in (response(b'denied', 401), response(b'private'), response(b'generic login')):
                state['captures']['c2']['original']['response_b64'] = encoded(raw)
                result = authentication_review(state, body)
                self.assertEqual(result['status'], 'observation')
                self.assertEqual(result['session_state'], lifecycle)
                self.assertNotIn('revoked-controlled-session', str(result))
            state['identities']['b']['credentials'] = {}
            with self.assertRaises(HTTPException): authentication_review(state, body)
            state['identities']['b']['credentials'] = {'cookie': 'revoked-controlled-session'}
