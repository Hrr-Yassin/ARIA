"""P2 tool readiness, outcome classification, selection and reasoning integration."""
import copy
import uuid
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from orchestrator.reasoning import CycleInput, ProposedHypothesis, run_cycle
from security_tools.adapters import contract_digest, encode, sha256
from security_tools.intelligence import (VALIDATION_BASELINE, classify_outcome, readiness, select_tools,
                                         tool_cycle_input)
from tests.support import OfflineCase

SCOPE = {'targets': ['192.0.2.1'], 'ports': [8080]}
READY = {'nmap.tcp.connect.v1', 'httpx.http.probe.v1', 'nuclei.http.observe.v1', 'ffuf.http.paths.v1',
         'semgrep.source.scan.v1', 'subfinder.domain.passive.v1'}


def advertisement(**changes):
    pins = {cap: {'declared_version': VALIDATION_BASELINE[cap]['version'],
                  'image_id': VALIDATION_BASELINE[cap]['image_id']} for cap in READY}
    data = {'typed_adapters': {cap: 1 for cap in READY}, 'typed_profile_pins': pins,
            'typed_registry_sha256': contract_digest()}
    data.update(changes)
    return data


def by_cap(report):
    return {e['capability']: e for e in report['capabilities']}


def state_with(*claims, refs=('ev-http',)):
    state, _ = run_cycle(None, CycleInput(
        evidence=[{'job_id': ref, 'output': [{'kind': 'http', 'locator': 'http://192.0.2.1:8080/',
                                              'summary': 'HTTP 200'}]} for ref in refs],
        interpretations=[], available_follow_ups={},
        hypotheses=[ProposedHypothesis(description=c, evidence_job_ids=list(refs),
                                       alternative_explanations=['Generic page']) for c in claims]))
    return state


class Readiness(OfflineCase):
    def test_validated_pins_and_matching_contract_are_ready(self):
        report = by_cap(readiness(advertisement(), local_digest=contract_digest()))
        self.assertTrue(all(report[c]['ready'] for c in READY))
        self.assertEqual(report['katana.http.crawl.v1']['status'], 'unavailable')

    def test_drift_unpinned_unvalidated_blocked_and_mismatch(self):
        drift = advertisement()
        drift['typed_profile_pins']['httpx.http.probe.v1']['declared_version'] = '1.8.0'
        self.assertEqual(by_cap(readiness(drift, local_digest=contract_digest()))['httpx.http.probe.v1']['reasons'][-1],
                         'version_drift')
        unpinned = by_cap(readiness(advertisement(typed_profile_pins={}), local_digest=contract_digest()))
        self.assertEqual(unpinned['nmap.tcp.connect.v1']['status'], 'unconfirmed')
        self.assertTrue(unpinned['nmap.tcp.connect.v1']['selectable'])
        katana = advertisement()
        katana['typed_adapters']['katana.http.crawl.v1'] = 1
        self.assertEqual(by_cap(readiness(katana, local_digest=contract_digest()))['katana.http.crawl.v1']['status'],
                         'unvalidated')
        blocked = by_cap(readiness(advertisement(), local_digest=contract_digest(), blocked=['ffuf.http.paths.v1']))
        self.assertEqual(blocked['ffuf.http.paths.v1']['status'], 'blocked')
        mismatch = readiness(advertisement(typed_registry_sha256='0' * 64), local_digest=contract_digest())
        self.assertEqual(mismatch['contract'], 'mismatch')
        self.assertEqual(mismatch['summary']['incompatible'], 6)
        offline = readiness(None, local_digest=contract_digest(), worker_status='unreachable')
        self.assertEqual(offline['summary']['unavailable'], 10)

    def test_live_advertisement_without_pins_is_unconfirmed_not_ready(self):
        # Shape observed from the running lab worker on 2026-11-22 (no version pins, no contract digest).
        report = readiness({'typed_adapters': {c: 1 for c in READY}}, local_digest=contract_digest())
        self.assertEqual(report['contract'], 'not_reported')
        self.assertEqual(report['summary']['unconfirmed'], 6)
        self.assertEqual(report['summary']['ready'], 0)


class Classification(OfflineCase):
    def test_categories(self):
        cases = [('succeeded', {'error': 'none', 'observations': [{}]}, 'observed', False),
                 ('succeeded', {'error': 'none', 'observations': []}, 'no_observations', False),
                 ('failed', {'error': 'tool_failed'}, 'tool_failure', True),
                 ('failed', {'error': 'timeout'}, 'timeout', True),
                 ('failed', {'error': 'resource_exhausted'}, 'resource_exhausted', False),
                 ('cancelled', {'error': 'cancelled'}, 'cancelled', False),
                 ('succeeded', {'error': 'invalid_output'}, 'malformed_output', False),
                 ('succeeded', {'error': 'invalid_output', 'truncated': True}, 'truncated', False),
                 ('unknown', {'error': 'unknown'}, 'unknown', False)]
        for state, output, category, retryable in cases:
            with self.subTest(category=category):
                outcome = classify_outcome(state, output)
                self.assertEqual((outcome['category'], outcome['retryable']), (category, retryable))
                self.assertEqual(outcome['evidence_usable'], category in {'observed', 'no_observations'})


class Selection(OfflineCase):
    def setUp(self):
        self.report = readiness(advertisement(), local_digest=contract_digest())

    def test_path_hypothesis_selects_bounded_path_comparison_first(self):
        state = state_with('The application may expose an /admin path.')
        picks = select_tools(state, self.report, target='192.0.2.1', scope=SCOPE)
        self.assertEqual(picks[0]['capability'], 'ffuf.http.paths.v1')
        self.assertEqual(picks[0]['operation']['parameters']['url'], 'http://192.0.2.1:8080')
        self.assertTrue(all(p['requires_approval'] and not p['executed'] for p in picks))

    def test_executed_unready_and_out_of_scope_operations_are_excluded(self):
        state = state_with('The application may expose an /admin path.')
        first = select_tools(state, self.report, target='192.0.2.1', scope=SCOPE)[0]
        again = select_tools(state, self.report, target='192.0.2.1', scope=SCOPE,
                             executed_requests=[sha256(first['request'])])
        self.assertNotIn('ffuf.http.paths.v1', [p['capability'] for p in again])
        blocked = readiness(advertisement(), local_digest=contract_digest(), blocked=['ffuf.http.paths.v1'])
        self.assertNotIn('ffuf.http.paths.v1', [p['capability'] for p in select_tools(
            state, blocked, target='192.0.2.1', scope=SCOPE)])
        self.assertEqual(select_tools(state, self.report, target='198.51.100.7', scope=SCOPE), [])

    def test_no_live_need_no_recommendation(self):
        self.assertEqual(select_tools(None, self.report, target='192.0.2.1', scope=SCOPE), [])

    def test_prior_tool_outcome_counts_as_executed(self):
        state = state_with('The application may expose an /admin path.')
        request = select_tools(state, self.report, target='192.0.2.1', scope=SCOPE)[0]['request']
        state, _ = run_cycle(state, tool_cycle_input('ev-ffuf', {
            'state': 'succeeded', 'capability': 'ffuf.http.paths.v1', 'output': {'error': 'none', 'observations': []},
            'provenance': {'job_id': 'job-ffuf', 'request_sha256': sha256(request)}}))
        self.assertNotIn('ffuf.http.paths.v1', [p['capability'] for p in select_tools(
            state, self.report, target='192.0.2.1', scope=SCOPE)])
        self.assertEqual(state['verification_results']['ev-ffuf']['category'], 'no_observations')


class ReasoningAndOrchestration(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.events, self.pending = [], []
        session = SimpleNamespace(id='engagement', scope=SCOPE, metadata_={})

        async def commit():
            self.events.extend(copy.deepcopy(row.metadata_) for row in self.pending)
            self.pending.clear()
        db = SimpleNamespace(add=self.pending.append, commit=AsyncMock(side_effect=commit))
        cm = AsyncMock()
        cm.__aenter__.return_value = db
        from memory.team_tasks import TeamStore, digest
        self.stack = ExitStack()
        self.stack.enter_context(patch('memory.team_tasks.async_session', return_value=cm))
        self.stack.enter_context(patch('memory.team_tasks.owned_engagement', AsyncMock(return_value=session)))
        self.stack.enter_context(patch.object(TeamStore, '_events', AsyncMock(
            side_effect=lambda *args: copy.deepcopy(self.events))))
        for index, ref in enumerate(('ev-http', 'ev-tool'), 1):
            self.events.append({'collection': 'evidence', 'entity_id': ref, 'sequence': index, 'id': str(uuid.uuid4()),
                                'data': {'id': ref, 'source_kind': 'worker', 'source_id': f'job-{ref}',
                                         'summary': 'receipt', 'owner_id': 'owner', 'session_id': 'engagement',
                                         'hashes': {'content_sha256': digest({'s': ref})}}})
        # Real reasoning store over the in-memory ledger; canonical IDs follow the catalog.
        from memory.investigation_state import InvestigationStateStore
        self.store = InvestigationStateStore()
        self.stack.enter_context(patch('memory.investigation_state.investigation_state', self.store))
        self.evidence_canonical.update({'job-ev-http': 'ev-http', 'job-ev-tool': 'ev-tool'})

    async def asyncTearDown(self):
        self.stack.close()
        await super().asyncTearDown()

    async def test_changed_tool_observation_contests_hypothesis_and_replans_challenge(self):
        from orchestrator.collaboration import CollaborationCoordinator, Delegation, DelegationPlan
        from orchestrator.team_coordinator import TeamCoordinator
        from security_tools.intelligence import ingest_tool_result
        from agents.result_contract import AgentResult
        await self.store.advance('engagement', 'owner', 'seed', CycleInput(
            evidence=[{'job_id': 'ev-http', 'output': [{'kind': 'http', 'locator': 'http://192.0.2.1:8080/',
                                                       'summary': 'HTTP 200 title Synthetic fixture'}]}],
            interpretations=[], available_follow_ups={}, hypotheses=[]))
        calls = []

        class Specialist:
            def __init__(self, role):
                self.role = role

            async def process(self, sid, owner, data, skill):
                calls.append((self.role, sorted(data['team_evidence'][i]['id'] for i in range(len(data['team_evidence'])))))
                hyps = [{'description': 'The web root may serve a maintenance page soon.', 'evidence_references': ['ev-http'],
                         'alternative_explanations': ['Normal application']}] if self.role == 'web_intel' else []
                return {'agent_result': AgentResult(interpreted_request='x', evidence_references=['ev-http'],
                                                    hypotheses=hyps, uncertainty=['Unverified']).model_dump()}
        with patch.object(TeamCoordinator, 'specialists', lambda _s: {r: Specialist(r) for r in
                                                                       ('recon', 'scan', 'vuln', 'web_intel', 'correlation', 'report')}):
            coordinator = CollaborationCoordinator(TeamCoordinator(), self.store)
            plan = await coordinator.create_plan('engagement', 'owner', DelegationPlan(
                request_id=uuid.uuid4(), objective='Interpret HTTP.', delegations=[Delegation(
                    key='analysis-web', role='web_intel', objective='Interpret HTTP.', evidence_inputs=['ev-http'],
                    completion_criteria=['Cite evidence'])]))
            await coordinator.advance('engagement', 'owner', plan['id'])
            # A typed httpx result now shows a different response at the same locator.
            ingested = await ingest_tool_result('engagement', 'owner', {
                'state': 'succeeded', 'capability': 'httpx.http.probe.v1', 'exit_code': 0,
                'output': {'error': 'none', 'observations': [{'kind': 'http', 'locator': 'http://192.0.2.1:8080/',
                                                               'summary': 'HTTP 503 title Maintenance'}]},
                'provenance': {'job_id': 'job-ev-tool', 'request_sha256': 'a' * 64}})
            self.assertEqual(ingested['evidence_id'], 'ev-tool')
            self.assertEqual(ingested['changed_evidence'], ['ev-http'])
            self.assertTrue(ingested['requires_revalidation'])
            outcome = await coordinator.advance('engagement', 'owner', plan['id'])
        challenge = next(r for r in outcome['plan']['replans'] if r['event'] == 'contradiction_challenge')
        self.assertEqual(calls[-1][0], 'correlation')
        # The challenger examines both the original and the superseding tool evidence.
        self.assertEqual(calls[-1][1], ['ev-http', 'ev-tool'])
        self.assertTrue(challenge['delegation'].startswith('challenge-'))

    async def test_unusable_outcome_is_recorded_not_observed(self):
        from security_tools.intelligence import ingest_tool_result
        result = await ingest_tool_result('engagement', 'owner', {
            'state': 'failed', 'capability': 'httpx.http.probe.v1', 'exit_code': 124,
            'output': {'error': 'timeout', 'observations': []}, 'provenance': {'job_id': 'job-ev-tool'}})
        self.assertEqual(result['outcome']['category'], 'timeout')
        record = await self.store.current('engagement', 'owner')
        self.assertEqual(record['state']['observations'], {})
        self.assertEqual(record['state']['verification_results']['ev-tool']['category'], 'timeout')
        missing = await ingest_tool_result('engagement', 'owner', {'state': 'cancelled', 'output': {'error': 'cancelled'}})
        self.assertEqual(missing['status'], 'not_ingested')

    async def test_encoded_request_is_canonical(self):
        operation = {'tool': 'httpx', 'parameters': {'url': 'http://192.0.2.1:8080'}}
        self.assertEqual(encode(operation), encode(copy.deepcopy(operation)))
