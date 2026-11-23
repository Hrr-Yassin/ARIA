import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from api.auth import TokenData, create_token
from memory.traffic_observations import HAR_SOURCE, canonical, har_records, project_capture, retained_capture
from security.encryption import evidence_cipher
from security.har import MAX_HAR_BYTES, MAX_HAR_ENTRIES, MAX_PREVIEW_CHARS, MAX_PREVIEW_INPUT
from tests.support import OfflineCase


HAR_FIXTURE = Path(__file__).with_name('fixtures') / 'mission-synthetic.har'


class TrafficObservations(OfflineCase):
    def test_metadata_projection_excludes_private_capture_material(self):
        private = 'fixture-sensitive-value'
        projected = project_capture('capture-a', datetime(2026, 11, 19, tzinfo=timezone.utc), {
            'url': f'https://records.example.test/{private}?token={private}',
            'method': 'GET',
            'request_headers': {'authorization': private, 'content-type': 'application/json; token=' + private},
            'response_headers': [{'name': 'set-cookie', 'value': private},
                                 {'name': 'content-type', 'value': 'text/plain; charset=utf-8'}],
            'response_preview': private,
            'response_status': 403,
            'response_body_bytes': 0,
            'authentication_context': private,
        })
        self.assertNotIn(private, str(projected))
        self.assertEqual(projected['destination'], 'https://records.example.test')
        self.assertEqual(projected['response_status'], 403)
        self.assertEqual(projected['response_body_bytes'], 0)
        self.assertEqual(projected['request_content_type'], 'application/json')
        self.assertEqual(projected['response_content_type'], 'text/plain')
        self.assertIsNone(projected['captured_at'])
        self.assertIsNone(projected['latency_ms'])

    def test_invalid_legacy_fields_stay_unknown(self):
        capture = project_capture('malformed', None, {
            'url': 'https://secret@records.example.test:invalid/',
            'method': [],
            'response_status': True,
            'response_body_bytes': 1048577,
            'response_protocol': {},
            'response_framing': {},
            'response_headers': {'content-type': ['private']},
        })
        for key in ('imported_at', 'destination', 'method', 'response_status', 'response_body_bytes',
                    'protocol', 'framing', 'response_content_type'):
            self.assertIsNone(capture[key], key)

    async def test_route_validates_pagination_and_requires_owner(self):
        token = create_token('admin', 'admin', 'admin', 'expert')
        headers = {'Authorization': 'Bearer ' + token}
        with patch('api.auth.current_identity', AsyncMock(return_value=TokenData(
                user_id='admin', username='admin', role='admin', skill_level='expert'))),              patch('api.session_access.session_manager.get_session', AsyncMock(return_value={'user_id': 'other'})),              patch('memory.traffic_observations.retained_traffic', AsyncMock()) as read:
            path = '/api/mission/fixture-session/traffic'
            self.assertEqual((await self.client.get(path)).status_code, 401)
            self.assertEqual((await self.client.get(path + '?limit=101', headers=headers)).status_code, 422)
            self.assertEqual((await self.client.get(path, headers=headers)).status_code, 403)
            read.assert_not_awaited()

    def test_har_preserves_archive_timing_and_discards_bodies_by_default(self):
        records, skipped = har_records(json.loads(HAR_FIXTURE.read_bytes()), False)
        self.assertEqual((len(records), skipped), (2, 0))
        capture = project_capture('fixture', None, records[0]['summary'], HAR_SOURCE)
        self.assertEqual(capture['captured_at'], '2026-11-19T09:00:00.250000+00:00')
        self.assertEqual(capture['latency_ms'], 42.5)
        self.assertEqual(capture['destination'], 'https://records.example.test')
        self.assertEqual((capture['method'], capture['response_status'], capture['protocol']), ('POST', 202, 'HTTP/2'))
        self.assertGreater(capture['request_body_bytes'], 0)
        self.assertEqual(capture['response_body_bytes'], capture['response_content_bytes'])
        self.assertEqual(records[0]['inspection']['request']['preview']['state'], 'not_selected')
        self.assertIsNone(records[0]['inspection']['response']['preview']['text'])
        self.assertNotIn('Quarterly inventory sample', str(records))
        self.assertNotIn('fixture-har-private-', str(records))

    def test_reviewed_har_redacts_credentials_and_reflections_before_preview(self):
        records, _ = har_records(json.loads(HAR_FIXTURE.read_bytes()), True)
        self.assertNotIn('fixture-har-private-', str(records))
        self.assertNotIn('synthetic-path', str(records))
        request = records[0]['inspection']['request']
        response = records[0]['inspection']['response']
        self.assertIn({'name': 'authorization', 'value': '[REDACTED]'}, request['headers'])
        self.assertIn({'name': 'set-cookie', 'value': '[REDACTED]'}, response['headers'])
        self.assertEqual(request['omitted_headers'], 1)
        self.assertEqual(json.loads(request['preview']['text'])['password'], '[REDACTED]')
        self.assertIn('\n  ', response['preview']['text'])
        body = json.loads(response['preview']['text'])
        self.assertEqual(body['echo'], ['[REDACTED]'] * 6)
        self.assertEqual(body['label'], 'Quarterly inventory sample')
        note = records[1]['inspection']['response']['preview']
        self.assertIn('Archived inventory note', note['text'])
        self.assertIn('[REDACTED]', note['text'])

    def test_har_limits_and_unsupported_previews_remain_explicit(self):
        archive = json.loads(HAR_FIXTURE.read_bytes())
        entries = archive['log']['entries']
        text_body = entries[1]['response']['content']
        text_body['text'] = 'x' * (MAX_PREVIEW_CHARS + 8)
        snippet = har_records(archive, True)[0][1]['inspection']['response']['preview']
        self.assertEqual((len(snippet['text']), snippet['truncated']), (MAX_PREVIEW_CHARS, True))
        text_body['encoding'] = 'base64'
        self.assertEqual(har_records(archive, True)[0][1]['inspection']['response']['preview']['state'], 'encoded')
        del text_body['encoding']
        text_body['text'] = 'x' * (MAX_PREVIEW_INPUT + 1)
        self.assertEqual(har_records(archive, True)[0][1]['inspection']['response']['preview']['state'], 'oversized')
        entries[0]['response']['content']['text'] = '{not valid JSON'
        self.assertEqual(har_records(archive, True)[0][0]['inspection']['response']['preview']['state'], 'invalid_json')
        entries.append({'request': {'method': 'GET', 'url': 'file:///not-http'}, 'response': {'status': 0}})
        self.assertEqual(har_records(archive, False)[1], 1)
        archive['log']['entries'] = entries * MAX_HAR_ENTRIES
        with self.assertRaises(HTTPException) as error:
            har_records(archive, False)
        self.assertEqual(error.exception.status_code, 413)

    async def test_inspection_seal_binds_capture_and_saved_metadata(self):
        [record, _], _ = har_records(json.loads(HAR_FIXTURE.read_bytes()), True)
        seal = evidence_cipher().encrypt(canonical({'session_id': 'engagement', 'capture_id': 'capture-a', **record})).decode()
        summary = record['summary']
        db = AsyncMock()
        manager = AsyncMock()
        manager.__aenter__.return_value = db
        with patch('memory.traffic_observations.async_session', return_value=manager):
            for sid, capture_id, data in [('engagement', 'capture-a', summary), ('other-session', 'capture-a', summary),
                    ('engagement', 'capture-b', summary), ('engagement', 'capture-a', {**summary, 'method': 'GET'})]:
                with self.subTest(sid=sid, capture_id=capture_id, same_metadata=data == summary):
                    db.execute.return_value.one_or_none = lambda: (capture_id, None, data, HAR_SOURCE, seal)
                    result = await retained_capture(sid, 'owner', capture_id)
                    valid = sid == 'engagement' and capture_id == 'capture-a' and data == summary
                    self.assertEqual(result['response']['preview']['state'], 'available' if valid else 'inspection_unavailable')
                    self.assertEqual('Quarterly inventory sample' in str(result), valid)

    async def test_import_bounds_body_and_enforces_owner_and_bearer_before_storage(self):
        owner = TokenData(user_id='owner', username='owner', role='admin', skill_level='expert')
        token = create_token(owner.user_id, owner.username, owner.role, owner.skill_level)
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/har+json'}
        path = '/api/mission/engagement/traffic/import-har'
        archive = HAR_FIXTURE.read_bytes()

        async def large_stream():
            for _ in range(3):
                yield b' ' * (MAX_HAR_BYTES // 2)

        with patch('api.auth.current_identity', AsyncMock(return_value=owner)), \
             patch('api.session_access.session_manager.get_session', AsyncMock(return_value={'user_id': 'owner'})) as session, \
             patch('memory.traffic_observations.retain_har', AsyncMock(return_value={'imported': 2})) as retain:
            self.client.cookies.set('pentestai_token', token)
            self.assertEqual((await self.client.post(path, content=archive)).status_code, 401)
            self.client.cookies.clear()
            self.assertEqual((await self.client.post(path, headers=headers, content=b'{unparseable')).status_code, 422)
            self.assertEqual((await self.client.post(path, headers=headers, content=large_stream())).status_code, 413)
            self.assertEqual((await self.client.post(path, headers=headers, content=b' ' * (MAX_HAR_BYTES + 1))).status_code, 413)
            session.return_value = {'user_id': 'foreign'}
            self.assertEqual((await self.client.post(path, headers=headers, content=archive)).status_code, 403)
            retain.assert_not_awaited()
            session.return_value = {'user_id': 'owner'}
            accepted = await self.client.post(path + '?include_bodies=true', headers=headers, content=archive)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(accepted.headers['Cache-Control'], 'no-store')
        retain.assert_awaited_once_with('engagement', 'owner', json.loads(archive), True)
