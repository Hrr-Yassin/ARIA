"""Permission records cannot bypass the exact native command/proposal binding."""
from datetime import datetime,timedelta,timezone
import unittest

from integration.supervised_lab_validation import COMMAND,validate_owner_approval


class SupervisedLabValidationTests(unittest.TestCase):
    def approval(self):
        return {'source':'explicit_project_owner_reply_in_conversation','proposal_id':'proposal',
            'command':COMMAND,'approved':True,'maximum_submissions':1,
            'owner_reply':'Approve the exact single bounded HEAD observation.',
            'received_at':datetime.now(timezone.utc).isoformat()}

    def test_exact_fresh_owner_decision_is_required(self):
        validate_owner_approval(self.approval(),'proposal',COMMAND)
        for key,value in (('source','model_generated'),('approved',1),('approved',False),
                          ('maximum_submissions',2),('maximum_submissions',True),
                          ('proposal_id','old'),('command','curl http://other-host'),('owner_reply','')):
            with self.subTest(key=key),self.assertRaises(PermissionError):
                validate_owner_approval({**self.approval(),key:value},'proposal',COMMAND)

    def test_expired_and_naive_records_never_grant_approval(self):
        for value in ((datetime.now(timezone.utc)-timedelta(minutes=11)).isoformat(),
                      datetime.now().isoformat()):
            with self.subTest(value=value),self.assertRaises(PermissionError):
                validate_owner_approval({**self.approval(),'received_at':value},'proposal',COMMAND)
