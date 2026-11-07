import unittest
from fastapi import HTTPException
from pydantic import ValidationError
from memory.application_map import BusinessLogicReview, business_logic_review
from tests.test_authorization_review import fixture


class BusinessLogicReviewTests(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        for identity in self.state['identities'].values(): identity['credentials'] = {}
        self.state['captures']['c2']['identity_id'] = 'a'
        self.state['workflows'] = {'w': {'evidence_ids': ['e1', 'e2'], 'before': 'one', 'after': 'one'}}
        self.body = BusinessLogicReview(workflow_id='w', object_id='o', invariant='Count stays one',
            expected_after='one', action_authorized=True, controlled_state_change=True,
            invariant_result='satisfied', rationale='Human reviewed observations')

    def test_review_is_human_assertion_for_both_outcomes(self):
        for outcome in ('satisfied', 'violated', 'unknown'):
            result = business_logic_review(self.state, self.body.model_copy(update={'invariant_result': outcome}))
            self.assertEqual(result['invariant_result'], outcome)
            self.assertEqual(result['status'], 'human_assertion')

    def test_prerequisites_block(self):
        self.state['captures']['c2']['identity_id'] = 'b'
        with self.assertRaises(HTTPException): business_logic_review(self.state, self.body)
        with self.assertRaises(ValidationError):
            BusinessLogicReview(**{**self.body.model_dump(), 'action_authorized': False})
        self.state['captures']['c2']['identity_id'] = 'a'
        self.state['captures']['c2']['expired'] = True
        with self.assertRaises(HTTPException): business_logic_review(self.state, self.body)
