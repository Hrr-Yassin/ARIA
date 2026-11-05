import unittest
from llm.validation_budget import ValidationBudget


class BudgetTests(unittest.TestCase):
    def test_failed_calls_still_consume_reserved_budget(self):
        budget=ValidationBudget(max_calls=2,max_tokens=100)
        self.assertTrue(budget.reserve('abc','',40))
        self.assertTrue(budget.reserve('abc','',40))
        self.assertFalse(budget.reserve('','',1))
        self.assertEqual(budget.calls,2)

    def test_token_ceiling_blocks_before_dispatch(self):
        budget=ValidationBudget(max_tokens=10)
        self.assertFalse(budget.reserve('12345','',6))
        self.assertEqual(budget.calls,0)
