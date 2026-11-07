import unittest
from fastapi import HTTPException
from pydantic import ValidationError
from memory.application_map import ExposureReview, exposure_review
from tests.test_authorization_review import fixture


class ExposureReviewTests(unittest.TestCase):
    def setUp(self):
        self.state = fixture()
        for identity in self.state['identities'].values():
            identity['credentials'] = {}

    def review(self, **changes):
        fields = dict(capture_id='c1', inspection_authorized=True, intended_visibility='restricted',
                      observed_audience='outside', meaningful_private_content='present', rationale='Reviewed controlled content')
        fields.update(changes)
        return exposure_review(self.state, ExposureReview(**fields))

    def test_controls_are_assertions_not_findings(self):
        self.assertEqual(self.review()['assessment'], 'possible_unauthorized_disclosure')
        self.assertEqual(self.review()['status'], 'human_assertion')
        self.assertEqual(self.review(intended_visibility='public', meaningful_private_content='absent')['assessment'], 'expected_or_public')
        self.assertEqual(self.review(meaningful_private_content='absent')['assessment'], 'no_private_content_identified')
        self.assertEqual(self.review(observed_audience='unknown')['assessment'], 'inconclusive')
        self.assertEqual(self.review(intended_visibility='public')['assessment'], 'inconclusive')
        self.assertEqual(self.review(intended_visibility='recipient')['assessment'], 'possible_unauthorized_disclosure')

    def test_missing_prerequisites_block(self):
        with self.assertRaises(ValidationError): self.review(inspection_authorized=False)
        with self.assertRaises(HTTPException): self.review(capture_id='foreign')
        self.state['captures']['c1']['expired'] = True
        with self.assertRaises(HTTPException): self.review()
