import base64
import copy
import unittest
from fastapi import HTTPException
from memory.application_map import AuthorizationReview, authorization_review


def encoded(value):
    return base64.b64encode(value).decode()


def fixture():
    def capture(identity, evidence, body):
        return {'identity_id': identity, 'evidence_id': evidence, 'method': 'GET',
                'origin': 'https://lab.test', 'route': '/item', 'expired': False,
                'original': {'url': 'https://lab.test/item',
                    'request_b64': encoded(b'GET /item HTTP/1.1\r\nHost: lab.test\r\n\r\n'),
                    'response_b64': encoded(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' + body)}}
    return {'identities': {'a': {'active': True, 'researcher_controlled': True}, 'b': {'active': True, 'researcher_controlled': True}},
            'objects': {'o': {'owner_identity_id': 'a', 'evidence_ids': ['e1']}},
            'captures': {'c1': capture('a', 'e1', b'private'), 'c2': capture('b', 'e2', b'private')},
            'permissions': {'p': {'id': 'p', 'object_id': 'o', 'identity_id': 'b',
                                   'operation': 'read', 'expected': 'deny'}}}


class AuthorizationReviewTests(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        self.body = AuthorizationReview(object_id='o', owner_capture_id='c1', other_capture_id='c2', operation='read')

    def test_equal_response_is_only_observation(self):
        result = authorization_review(self.state, self.body)
        self.assertEqual(result['status'], 'observation')
        self.assertEqual(result['expected_permission'], 'deny')
        self.assertIn('do not establish', result['limitations'][1])

    def test_missing_or_revoked_prerequisites_block(self):
        variants = []
        state = copy.deepcopy(self.state); state['identities']['b']['active'] = False; variants.append(state)
        state = copy.deepcopy(self.state); state['objects']['o']['evidence_ids'] = []; variants.append(state)
        state = copy.deepcopy(self.state); state['permissions']['p']['expected'] = 'unknown'; variants.append(state)
        state = copy.deepcopy(self.state); state['captures']['c2']['expired'] = True; variants.append(state)
        state = copy.deepcopy(self.state); state['captures']['c2']['original']['url'] += '?id=2'; variants.append(state)
        for state in variants:
            with self.subTest(state=state), self.assertRaises(HTTPException):
                authorization_review(state, self.body)

    def test_latest_permission_and_different_responses(self):
        self.state['permissions']['corrected'] = {**self.state['permissions']['p'], 'id': 'corrected', 'expected': 'allow'}
        self.state['captures']['c2']['original']['response_b64'] = encoded(b'HTTP/1.1 403 Forbidden\r\n\r\n')
        result = authorization_review(self.state, self.body)
        self.assertEqual(result['permission_id'], 'corrected')
        self.assertEqual(result['status'], 'observation')
