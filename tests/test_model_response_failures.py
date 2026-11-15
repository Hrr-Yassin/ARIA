"""Strict model failure categories preserve evidence and do not dispatch work."""
import json
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from agents.base_agent import _agent_context
from agents.orchestrator_agent import orchestrator_agent
from agents.autonomous_engine import AutonomousEngine, InvestigationReviewError, SessionRunState
from llm.base_llm import response_schema
from tests.support import OfflineCase


class ModelResponseFailureTests(OfflineCase):
    def test_generic_parser_rejects_non_string_outputs_and_retains_blocker(self):
        for content in (None, 1, True, {}, [], b'{}'):
            context = {}
            token = _agent_context.set(context)
            try:
                with self.subTest(content=content):
                    self.assertIsNone(orchestrator_agent.parse_json(content))
                    self.assertEqual(context['provider_error'], 'malformed_model_output')
            finally:
                _agent_context.reset(token)

    async def reject_review(self, result, *, budget_exhausted=False):
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert',
                                successful_steps=2, steps_taken=2)
        if budget_exhausted:
            state.model_calls = engine.MAX_MODEL_CALLS
        with patch.object(engine, '_persist', AsyncMock()), \
             patch.object(engine, '_emit', AsyncMock()) as emit, \
             patch('agents.orchestrator_agent.record_planner_diagnostic', AsyncMock()), \
             patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value=result)) as query, \
             patch('memory.research.research_store.ingest_review', AsyncMock()) as ingest:
            with self.assertRaises(InvestigationReviewError) as rejected:
                await engine._review_investigation(state)
            emit.assert_not_awaited()
            ingest.assert_not_awaited()
            if budget_exhausted:
                query.assert_not_awaited()
            else:
                query.assert_awaited_once()
            self.assertEqual(state.successful_steps, 2)
            self.assertEqual(state.steps_taken, 2)
            self.assertIsNone(response_schema.get())
            self.assertNotIn('private-sentinel', str(rejected.exception))
            return rejected.exception.code

    async def test_invalid_review_matrix_remains_strict_and_private(self):
        cases = ['', '{', '{}', '[]', '{"observations":[],"hypotheses":[]}',
                 '{"observations":{},"hypotheses":[],"limitations":[]}',
                 '{"observations":[],"hypotheses":[],"limitations":[],"extra":"private-sentinel"}',
                 None, 12]
        for content in cases:
            with self.subTest(content=content):
                self.assertEqual(await self.reject_review({'success': True, 'content': content}),
                                 'invalid_review_output')

    async def test_review_failure_categories_are_explicit_without_extra_calls(self):
        for error, code in [('provider_timeout', 'review_provider_timeout'),
                            ('provider_request_failed', 'review_transport_failed'),
                            ('local_model_request_failed', 'review_transport_failed'),
                            ('model_output_truncated', 'review_output_truncated'),
                            ('private-sentinel', 'review_provider_unavailable')]:
            with self.subTest(error=error):
                self.assertEqual(await self.reject_review({'success': False, 'error': error}), code)
        self.assertEqual(await self.reject_review({}, budget_exhausted=True), 'model_call_budget')

    async def test_review_retains_safe_budget_and_accounting_denials(self):
        for code in ('model_tariff_missing', 'model_budget_exhausted',
                     'model_accounting_inconsistent', 'campaign_budget_exhausted',
                     'campaign_budget_unavailable', 'campaign_not_running'):
            with self.subTest(code=code):
                self.assertEqual(await self.reject_review({'success': False, 'error': code}), code)

    def test_budget_error_rejects_untrusted_codes_without_crashing(self):
        from llm.planner_errors import budget_error
        for code in ([], {}, None, 5, 'private-sentinel'):
            with self.subTest(code=code):
                self.assertEqual(budget_error(HTTPException(409, {'code': code})),
                                 'model_budget_denied')
        self.assertEqual(budget_error(HTTPException(409, {'code': 'model_accounting_inconsistent'})),
                         'model_accounting_inconsistent')
