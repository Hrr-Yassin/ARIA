"""Owner isolation, public event projections and read-only admission accounting."""
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch

from api.auth import TokenData, create_token
from api.routers.mission import team_event
from llm.engagement_budget import ModelLimits, admission_snapshot
from memory.campaign_observability import append_operation
from memory.command_registry import CommandEntry
from tests.support import OfflineCase

TS = '2026-11-17T12:00:00Z'
OWNER = 'owner'
SID = 'fixture-session'


class MissionControlTests(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.headers = {'Authorization': 'Bearer ' + create_token(OWNER, 'owner', 'admin', 'expert')}
        self.identity = self.enterContext(patch('api.auth.current_identity', AsyncMock(return_value=
            TokenData(user_id=OWNER, username='owner', role='admin', skill_level='expert'))))
        self.session = self.enterContext(patch('api.session_access.session_manager.get_session',
            AsyncMock(return_value={'session_id': SID, 'user_id': OWNER})))
        self.model = {'provider': 'local', 'model': 'configured-review-model'}
        self.replay_summary = self.enterContext(patch('api.routers.mission.web_replay_summary',
            AsyncMock(return_value={'records': 0, 'pending_cancellations': 0, 'unknown_outcomes': 0}), create=True))

    async def test_operations_retains_unconfirmed_web_cancellations_independently(self):
        self.replay_summary.return_value = {'records': 4, 'pending_cancellations': 1, 'unknown_outcomes': 2}
        with patch('api.routers.mission.recent_worker_receipts', AsyncMock(return_value=[])), \
             patch('api.routers.mission.recent_authorizations', AsyncMock(side_effect=RuntimeError('private-error'))):
            response = await self.client.get(f'/api/mission/{SID}/operations', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get('web_replays'), self.replay_summary.return_value)
        self.assertIsNone(response.json()['authorizations'])
        self.replay_summary.assert_awaited_once_with(SID, OWNER)
        self.assertNotIn('private-error', response.text)

    async def test_stop_response_keeps_pending_web_replays_unconfirmed(self):
        for worker_pending, web_pending in ((0, 1), (1, 0), (0, 0)):
            with self.subTest(worker=worker_pending, web=web_pending), \
                 patch('api.routers.pentest._reject_if_campaign_active', AsyncMock()), \
                 patch('api.routers.pentest.autonomous_engine.request_stop', AsyncMock(return_value={
                     'status': 'cancellation_pending' if worker_pending else 'stopped',
                     'pending': worker_pending, 'cancelled': 0})), \
                 patch('memory.web_actions.web_actions.cancel_all', AsyncMock(return_value={
                     'pending': web_pending, 'cancelled': 0})):
                response = await self.client.post(f'/api/pentest/{SID}/autonomous/stop', headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['pending'], worker_pending + web_pending)
            self.assertEqual(response.json()['status'],
                             'cancellation_pending' if worker_pending + web_pending else 'stopped')

    async def test_positive_call_headroom_does_not_override_minimum_token_reservation(self):
        limits = ModelLimits(max_calls=20, max_tokens=200000)
        metadata = {'model_usage': {'calls': 15, 'reserved_tokens': 196074}}
        result = admission_snapshot(metadata, limits, self.model)
        self.assertEqual(result['state'], 'blocked')
        self.assertEqual(result['reasons'], ['token_reservation_floor'])
        self.assertEqual(result['remaining']['calls'], 5)
        self.assertEqual(result['remaining']['tokens'], 3926)
        self.assertEqual(result['minimum_tokens'], 8192)
        self.assertEqual(metadata, {'model_usage': {'calls': 15, 'reserved_tokens': 196074}})

    async def test_available_floor_is_not_full_admission_and_malformed_accounting_is_unknown(self):
        model = {'provider': 'groq', 'model': 'fixture'}
        limits = ModelLimits(max_cost_microusd=1, tariffs=[{'provider': 'groq', 'model': 'fixture', 'microusd_per_million': 1000000}])
        cost_blocked = admission_snapshot({}, limits, model)
        self.assertEqual(cost_blocked['reasons'], ['cost_reservation_floor'])
        self.assertEqual(cost_blocked['minimum_cost_microusd'], 8192)
        okay = admission_snapshot({}, ModelLimits(), self.model)
        self.assertEqual(okay['state'], 'undetermined')
        for usage in ({'calls': True}, {'stop_reason': ['bad retained state']}):
            invalid = admission_snapshot({'model_usage': usage}, limits, self.model)
            self.assertEqual(invalid['state'], 'blocked')
            self.assertEqual(invalid['remaining'], {'calls': None, 'tokens': None, 'cost_microusd': None})

    async def test_accounting_view_projects_retained_metrics_with_an_explicit_allowlist(self):
        from llm.engagement_budget import model_accounting

        private = 'fixture-private-accounting-data'
        usage = {'calls': 15, 'reserved_tokens': 196074, 'tasks': {'private': private},
                 'reported_tokens': 'invalid', 'stop_reason': [private]}
        # The public read must survive malformed retained diagnostic fields.
        admission = admission_snapshot({}, ModelLimits(), self.model)
        admission.update(state='blocked', reasons=['model_provider_sharing_denied'])
        budget = {'limits': {**ModelLimits().model_dump(), 'private': private}, 'configured_selection': self.model,
                  'admission': admission,
                  'tariff_quotes': {'internal': private}, 'usage': usage, 'attempts_limit': 100,
                  'attempts': [{'id': 'own-attempt', 'session_id': SID, 'owner': private, 'timestamp': TS,
                                'provider': 'openrouter', 'model': 'vendor/requested-model', 'state': 'failed',
                                'error_code': private, 'provider_usage': {'cost': '0.000021', 'model': 'vendor/review-model', 'raw': private},
                                'timings': {'pool_attempt_ms': 32.5, 'provider_attempt_ms': 10**400, 'response_debug': private},
                                'input_tokens': None, 'output_tokens': 4, 'content': private},
                               {'id': 'foreign-attempt', 'session_id': 'other-session', 'timestamp': TS},
                               []]}
        with patch.object(model_accounting, 'status', AsyncMock(return_value=budget)) as source:
            response = await self.client.get(f'/api/mission/{SID}/accounting', headers=self.headers)
        source.assert_awaited_once_with(SID, OWNER)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertNotIn(private, response.text)
        data = response.json()
        self.assertEqual(data['session_id'], SID)
        self.assertEqual(data['admission']['reasons'], ['model_provider_sharing_denied'])
        self.assertEqual(data['usage']['calls'], 15)
        self.assertIsNone(data['usage']['reported_tokens'])
        self.assertEqual(data['omitted_attempts'], 2)
        self.assertEqual([item['id'] for item in data['attempts']], ['own-attempt'])
        attempt = data['attempts'][0]
        self.assertIsNone(attempt['error_code'])
        self.assertEqual(attempt['model'], 'vendor/requested-model')
        self.assertEqual(attempt['provider_reported_model'], 'vendor/review-model')
        self.assertEqual(attempt['output_tokens'], 4)
        self.assertEqual(attempt['provider_usage'], {'cost': '0.000021'})
        self.assertEqual(attempt['timings']['pool_attempt_ms'], 32.5)
        self.assertIsNone(attempt['timings']['provider_attempt_ms'])

    async def test_event_endpoints_require_owner_even_for_admin(self):
        with patch('api.routers.mission.team_store.event_page', AsyncMock()) as ledger:
            self.session.return_value = {'session_id': SID, 'user_id': 'another-owner'}
            for projection in ('events', 'operations'):
                response = await self.client.get(f'/api/mission/{SID}/{projection}', headers=self.headers)
                self.assertEqual(response.status_code, 403)
            response = await self.client.get(f'/api/mission/{SID}/events')
            self.assertEqual(response.status_code, 401)
        ledger.assert_not_awaited()

    async def test_event_response_is_independently_available_and_has_strict_allowlist(self):
        private = 'fixture-private-field'
        record = {'id': 'ledger-1', 'sequence': 7, 'collection': 'tasks', 'entity_id': 'task-1',
            'timestamp': TS, 'actor': private, 'data': {'owner_role': 'web_intel', 'state': 'awaiting_review',
                'reasoning': private, 'evidence_inputs': ['evidence-2'], 'dependencies': ['task-0']}}
        with patch('api.routers.mission.team_store.event_page', AsyncMock(return_value=([record], False))) as loader, \
             patch('api.routers.mission.campaign_store.latest_for_session', AsyncMock(side_effect=RuntimeError(private))):
            response = await self.client.get(f'/api/mission/{SID}/events?team_after=5', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        data = response.json()
        self.assertEqual(data['campaign']['state'], 'unavailable')
        self.assertTrue(data['team']['gap'])
        self.assertEqual(data['team']['cursor'], 7)
        self.assertEqual(data['team']['events'][0]['evidence_ids'], ['evidence-2'])
        self.assertEqual(data['team']['events'][0]['task_id'], 'task-1')
        self.assertNotIn(private, response.text)
        loader.assert_awaited_once_with(SID, OWNER, 5, 50)

    async def test_campaign_rollover_advances_the_source_cursor_without_joining_ids(self):
        now = datetime.now(timezone.utc)
        operation = {}
        for index in range(54):
            operation = append_operation(operation, event='campaign_heartbeat', to_state='running',
                now=now + timedelta(seconds=index), correlation='fixture-correlation')
        row = {'id': 'campaign-new', 'owner_id': OWNER, 'operations': operation}
        with patch('api.routers.mission.team_store.event_page', AsyncMock(return_value=([], False))), \
             patch('api.routers.mission.campaign_store.latest_for_session', AsyncMock(return_value=row)):
            response = await self.client.get(f'/api/mission/{SID}/events?campaign_id=campaign-old&campaign_after=70',
                headers=self.headers)
        data = response.json()['campaign']
        self.assertEqual(data['campaign_id'], 'campaign-new')
        self.assertTrue(data['gap'])
        self.assertEqual(len(data['events']), 50)
        self.assertGreater(data['oldest'], 1)
        self.assertEqual(data['events'][0]['campaign_id'], 'campaign-new')

    async def test_archive_lists_retained_campaigns_with_an_owner_scoped_cursor(self):
        now = datetime.fromisoformat(TS).replace(tzinfo=None)
        database = AsyncMock()
        database.execute.return_value = Mock()
        database.execute.return_value.all.return_value = [
            ('newer', 'cancelled', now, now), ('older', 'completed', now, now),
        ]
        connection = AsyncMock()
        connection.__aenter__.return_value = database
        with patch('api.routers.mission.async_session', return_value=connection):
            response = await self.client.get(f'/api/mission/{SID}/campaigns?limit=1', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(response.json()['campaigns'], [{'id': 'newer', 'state': 'cancelled',
            'created_at': TS, 'updated_at': TS}])
        self.assertEqual(response.json()['next_before'], 'newer')
        query = database.execute.call_args.args[0]
        self.assertEqual(list(query.selected_columns.keys()), ['id', 'state', 'created_at', 'updated_at'])
        self.assertEqual(set(query.compile().params.values()), {SID, OWNER, 2})

    async def test_archive_does_not_look_up_records_for_a_foreign_session(self):
        self.session.return_value = {'session_id': SID, 'user_id': 'someone-else'}
        with patch('api.routers.mission.async_session') as database:
            for endpoint in ('campaigns', 'campaigns/older/events'):
                response = await self.client.get(f'/api/mission/{SID}/{endpoint}', headers=self.headers)
                self.assertEqual(response.status_code, 403)
        database.assert_not_called()

    async def test_receipt_dependency_failure_preserves_sanitized_command_projection(self):
        entry = CommandEntry('curl fixture-secret-argument', 'fixture-entry', '',
            'HTTP/2 503\r\nSet-Cookie: fixture-secret-cookie', 'failed', execution_time_ms=0)
        with patch('api.routers.mission.recent_worker_receipts', AsyncMock(side_effect=RuntimeError('fixture-secret-storage'))), \
             patch('api.routers.mission.command_registry.get_history', Mock(return_value=[entry])):
            response = await self.client.get(f'/api/mission/{SID}/operations', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsNone(data['receipts'])
        self.assertEqual(data['commands'][0]['http_status'], 503)
        self.assertIsNone(data['commands'][0]['duration_ms'])
        self.assertNotIn('fixture-secret-', response.text)

    async def test_worker_receipt_exposes_only_bound_typed_version(self):
        from api.routers.mission import recent_worker_receipts
        created = datetime.fromisoformat(TS)
        capability = 'semgrep.source.scan.v1'
        attestation = {'capability': capability, 'request_sha256': 'a' * 64, 'registry_sha256': 'b' * 64,
                       'image_id': 'sha256:' + 'c' * 64, 'binary_sha256': 'd' * 64,
                       'declared_tool_version': '1.99.0'}
        job = {'job_id': 'job-valid', 'state': 'succeeded', 'adapter_capability': capability,
               'adapter_request_sha256': 'a' * 64, 'adapter_registry_sha256': 'b' * 64,
               'adapter_attestation': attestation, 'stdout': 'private-output', 'exit_code': 0, 'output_hash': 'e' * 64,
               'saved_source_review': {'output_sha256': 'e' * 64, 'parser_status': 'none',
                                       'observation_count': 1, 'truncated': False,
                                       'dynamic_python_evaluation_matches': 1}}
        database = AsyncMock()
        database.execute.return_value = Mock()
        database.execute.return_value.all.return_value = [
            (created, job), (created, {**job, 'job_id': 'job-invalid', 'adapter_request_sha256': '0' * 64, 'exit_code': 2}),
            (created, {'job_id': 'legacy', 'state': 'succeeded'})]
        context = AsyncMock()
        context.__aenter__.return_value = database
        with patch('api.routers.mission.async_session', return_value=context):
            receipts = await recent_worker_receipts(SID, OWNER, 100)
        self.assertEqual([item.attested_declared_version for item in receipts], ['1.99.0', None, None])
        self.assertEqual([item.capability for item in receipts], [capability, capability, None])
        self.assertEqual([item.catalog_eligible for item in receipts], [True, False, False])
        self.assertEqual(receipts[0].source_review.model_dump(), {
            'parser_status': 'parsed', 'unverified_observations': 1, 'truncated': False,
            'dynamic_python_evaluation_matches': 1})
        self.assertIsNone(receipts[1].source_review)
        self.assertEqual(receipts[1].catalog_issue, 'Worker receipt state and exit status disagree')
        self.assertNotIn('private-output', str(receipts))
        self.assertNotIn('binary_sha256', str(receipts))

    async def test_operations_projects_durable_authorization_history_without_receipts(self):
        created = datetime.fromisoformat(TS)
        database = AsyncMock()
        database.execute.return_value = Mock()
        database.execute.return_value.all.return_value = [
            ('audit-reject', created, 'execution_rejected', 'action-one', 'reject'),
            ('action-one', created - timedelta(seconds=1), 'execution_authorization', None, 'rejected'),
            ('audit-malformed', created - timedelta(seconds=2), 'execution_approved', 'private non-identifier', 'approve'),
        ]
        context = AsyncMock()
        context.__aenter__.return_value = database
        with patch('api.routers.mission.async_session', return_value=context), \
             patch('api.routers.mission.recent_worker_receipts', AsyncMock(side_effect=RuntimeError('fixture-private'))):
            response = await self.client.get(f'/api/mission/{SID}/operations', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.json()['receipts'])
        history = response.json()['authorizations']
        self.assertEqual(history['omitted'], 1)
        self.assertFalse(history['truncated'])
        self.assertEqual([(r['event'], r['action_id'], r['decision']) for r in history['records']], [
            ('rejection_recorded', 'action-one', 'reject'), ('proposal_registered', 'action-one', None)])
        self.assertNotIn('private', response.text)
        # The projection queries the action reference but omits full metadata and command text.
        selected = list(database.execute.call_args.args[0].selected_columns.keys())
        self.assertEqual(selected, ['id', 'created_at', 'decision_type', 'action_id', 'human_decision'])

    async def test_evidence_projection_uses_worker_source_identity_only_when_recorded(self):
        event = team_event(SID, {'id': 'fixture-event', 'collection': 'evidence', 'sequence': 1, 'timestamp': TS,
            'entity_id': 'evidence-current', 'data': {'source_kind': 'worker', 'source_id': 'worker-record'}})
        self.assertEqual(event.job_id, 'worker-record')
        self.assertEqual(event.evidence_ids, ['evidence-current'])
        self.assertIsNone(event.correlation_id)
