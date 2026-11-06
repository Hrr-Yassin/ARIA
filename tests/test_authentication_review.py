import copy
import unittest
from fastapi import HTTPException
from pydantic import ValidationError
from memory.application_map import AuthenticationReview, authentication_review
from tests.test_authorization_review import fixture, encoded


class AuthenticationReviewTests(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        self.state['identities']['a']['credentials'] = {'authorization': 'Bearer synthetic'}
        self.state['identities']['b']['credentials'] = {}
        self.state['captures']['c1']['original']['request_b64'] = encoded(
            b'GET /item HTTP/1.1\r\nHost: lab.test\r\nAuthorization: Bearer synthetic\r\n\r\n')
        self.body = AuthenticationReview(authenticated_capture_id='c1', unauthenticated_capture_id='c2',
                                         expected_authentication_required=True, action_authorized=True)

    def test_secure_and_misleading_equal_responses_are_only_observations(self):
        for response in (b'HTTP/1.1 403 Forbidden\r\n\r\n',
                         b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nprivate'):
            self.state['captures']['c2']['original']['response_b64'] = encoded(response)
            result = authentication_review(self.state, self.body)
            self.assertEqual(result['status'], 'observation')
            self.assertNotIn('synthetic', str(result))

    def test_missing_prerequisites_and_mismatched_credentials_block(self):
        states = []
        state = copy.deepcopy(self.state); state['identities']['a']['active'] = False; states.append(state)
        state = copy.deepcopy(self.state); state['identities']['b']['credentials'] = {'cookie': 'x'}; states.append(state)
        state = copy.deepcopy(self.state); state['captures']['c1']['original']['request_b64'] = state['captures']['c2']['original']['request_b64']; states.append(state)
        state = copy.deepcopy(self.state); state['captures']['c2']['expired'] = True; states.append(state)
        state = copy.deepcopy(self.state); state['captures']['c2']['original']['url'] += '?q=1'; states.append(state)
        for state in states:
            with self.subTest(state=state), self.assertRaises(HTTPException):
                authentication_review(state, self.body)
        with self.assertRaises(ValidationError):
            AuthenticationReview(authenticated_capture_id='c1', unauthenticated_capture_id='c2',
                                 expected_authentication_required=True, action_authorized=False)
