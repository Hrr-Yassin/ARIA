"""Investigation reasoning kernel, persistent state and supervised review regressions."""
import copy
import json
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from memory.team_tasks import TeamStore, digest, materialize
from orchestrator.reasoning import (CycleInput, ProposedHypothesis, Retraction, claim_key,
                                    planner_summary, run_cycle, supervise, empty_state)
from tests.support import OfflineCase

HTTP = {'job_id': 'job-http', 'output': [{'kind': 'http', 'locator': 'http://192.0.2.1:8080/',
                                          'summary': 'HTTP 200 title Synthetic fixture'}]}
PORT = {'job_id': 'job-port', 'output': [{'kind': 'port', 'locator': '192.0.2.1:8080',
                                          'summary': 'tcp/8080 open'}]}
FOLLOW = {'bounded_http_paths': {'operation': {'tool': 'ffuf', 'parameters': {'url': 'http://192.0.2.1:8080/'}},
                                 'evidence_job_id': 'job-http', 'requires_approval': True,
                                 'validation_criterion': 'Compare /admin and /test statuses.'}}


def proposal(description, refs=('job-http',), **changes):
    return ProposedHypothesis(**{'description': description, 'evidence_job_ids': list(refs),
                                 'alternative_explanations': ['Generic default page'], **changes})


def cycle(hypotheses, evidence=(HTTP,), follow=FOLLOW, **changes):
    return CycleInput(evidence=list(evidence), interpretations=['Server returned a page'],
                      hypotheses=hypotheses, available_follow_ups=follow, **changes)


class ReasoningKernel(OfflineCase):
    def test_facts_are_receipts_and_interpretations_are_assumptions(self):
        state, report = run_cycle(None, cycle([]))
        self.assertTrue(all(o['fact'] for o in state['observations'].values()))
        self.assertEqual(state['interpretations'][0]['kind'], 'assumption')
        self.assertEqual(report['analyze']['facts'], 1)

    def test_supervisor_rejects_unsupported_and_fabricated_conclusions(self):
        state, report = run_cycle(None, cycle([
            proposal('The web server is vulnerable to remote code execution.'),
            proposal('Port evidence may indicate an admin panel', refs=('job-fabricated',)),
            proposal('The site may expose an administrative path', follow_up='bounded_http_paths'),
        ]))
        rejected = {item['index']: item['challenges'] for item in report['hypothesize']['rejected']}
        self.assertIn('unsupported_conclusion', rejected[0])
        self.assertIn('unknown_evidence_cited', rejected[1])
        self.assertEqual(len(report['accepted_for_research']), 1)
        self.assertNotIn(None, [report['hypothesize']['proposal_ids'][2]])

    def test_hedged_claim_is_not_an_overclaim_and_confidence_is_capped(self):
        accepted, challenges, confidence = supervise(
            proposal('The service may be vulnerable if the default page is reachable', confidence=.95),
            {'job-http'}, {'job-http'}, empty_state())
        self.assertTrue(accepted)
        self.assertIn('confidence_capped', challenges)
        self.assertLessEqual(confidence, .4)

    def test_competing_hypotheses_on_shared_evidence_are_linked(self):
        state, _ = run_cycle(None, cycle([
            proposal('An administrative interface may be reachable', follow_up='bounded_http_paths'),
            proposal('The page may be a generic placeholder with no application behind it'),
        ]))
        live = list(state['hypotheses'].values())
        self.assertEqual(live[0]['competes_with'], [live[1]['id']])
        self.assertEqual(live[1]['competes_with'], [live[0]['id']])

    def test_duplicate_proposals_merge_instead_of_creating_redundant_work(self):
        state, _ = run_cycle(None, cycle([proposal('The site may expose an administrative path')]))
        state, report = run_cycle(state, cycle([proposal('An administrative path the site may expose')],
                                               evidence=(HTTP, PORT)))
        self.assertEqual(len(state['hypotheses']), 1)
        self.assertEqual(len(report['hypothesize']['merged']), 1)

    def test_contradiction_contests_then_rejects_and_blocks_repetition(self):
        claim = 'The site may expose an administrative path'
        state, _ = run_cycle(None, cycle([proposal(claim, follow_up='bounded_http_paths')]))
        hid = next(iter(state['hypotheses']))
        state, report = run_cycle(state, cycle([], evidence=(HTTP, PORT), retractions=[
            Retraction(prior_hypothesis_id=hid, reason='Paths returned 404', evidence_job_ids=['job-port'])]))
        self.assertEqual(state['hypotheses'][hid]['status'], 'contested')
        self.assertLessEqual(state['hypotheses'][hid]['confidence'], .4)
        state, report = run_cycle(state, cycle([], retractions=[
            Retraction(prior_hypothesis_id=hid, reason='Same page', evidence_job_ids=['job-http'])]))
        self.assertEqual(state['hypotheses'][hid]['status'], 'rejected')
        self.assertIn(hid, report['contradictions']['rejected'])
        state, report = run_cycle(state, cycle([proposal(claim)]))
        self.assertIn('previously_rejected_without_new_evidence', report['hypothesize']['rejected'][0]['challenges'])

    def test_retraction_without_evidence_changes_nothing(self):
        state, _ = run_cycle(None, cycle([proposal('The site may expose an administrative path')]))
        hid = next(iter(state['hypotheses']))
        state, report = run_cycle(state, cycle([], retractions=[
            Retraction(prior_hypothesis_id=hid, reason='Seems unlikely', evidence_job_ids=['job-unknown'])]))
        self.assertEqual(state['hypotheses'][hid]['status'], 'active')

    def test_decision_is_consistent_until_evidence_changes(self):
        hyp = proposal('The site may expose an administrative path', follow_up='bounded_http_paths')
        state, first = run_cycle(None, cycle([hyp]))
        self.assertEqual(first['decision']['action'], 'bounded_http_paths')
        state, second = run_cycle(state, cycle([hyp]))
        self.assertFalse(second['decision']['changed'])
        self.assertEqual(second['decision']['decision'], first['decision']['decision'])
        changed = {'job_id': 'job-http-2', 'output': [{'kind': 'http', 'locator': 'http://192.0.2.1:8080/',
                                                       'summary': 'HTTP 503 maintenance'}]}
        state, third = run_cycle(state, cycle([], evidence=(changed,)))
        self.assertTrue(third['decision']['changed'])
        self.assertEqual(third['decision']['revised'][0]['reason'], 'supporting evidence changed')
        self.assertTrue(next(iter(state['hypotheses'].values()))['requires_revalidation'])

    def test_completed_analysis_is_not_replanned(self):
        hyp = proposal('The site may expose an administrative path', follow_up='bounded_http_paths')
        state, _ = run_cycle(None, cycle([hyp]))
        state, report = run_cycle(state, cycle([hyp], completed_follow_ups=['bounded_http_paths']))
        self.assertNotEqual(report['decision']['action'], 'bounded_http_paths')
        self.assertTrue(next(p for p in report['priorities'] if p['action'] == 'bounded_http_paths')['redundant'])

    def test_missing_information_and_planner_summary_are_bounded(self):
        state, report = run_cycle(None, cycle([proposal('The site may expose an administrative path',
                                                        missing_information=['Expected 404 baseline'])]))
        texts = [item['requires'] for item in report['missing_information']]
        self.assertIn('Expected 404 baseline', texts)
        self.assertTrue(any('Negative control' in text for text in texts))
        summary = planner_summary(state)
        self.assertIn('unverified', summary['verification'])
        self.assertLessEqual(len(summary['live_hypotheses']), 4)

    def test_kernel_never_confirms(self):
        state, _ = run_cycle(None, cycle([proposal('The site may expose an administrative path', confidence=1.0)],
                                         evidence=(HTTP, PORT)))
        self.assertTrue(all(not h['verified'] and h['confidence'] <= .7 for h in state['hypotheses'].values()))

    def test_negative_fact_contradicts_claim_naming_its_path_or_port(self):
        state, _ = run_cycle(None, cycle([proposal('The site may expose an /admin path'),
                                          proposal('Port 8443 may host a management console', refs=('job-port',)),
                                          proposal('The /admin path may have returned 404 earlier')],
                                         evidence=(HTTP, PORT)))
        admin, console, negative = (h['id'] for h in state['hypotheses'].values())
        probe = {'job_id': 'job-probe', 'output': [
            {'kind': 'http_path', 'locator': 'http://192.0.2.1:8080/admin', 'summary': 'status 404 length 0'},
            {'kind': 'port', 'locator': '192.0.2.1:8443/tcp', 'summary': 'tcp/8443 closed'}]}
        state, report = run_cycle(state, cycle([], evidence=(probe,)))
        self.assertEqual({c['hypothesis'] for c in report['contradictions']['from_facts']}, {admin, console})
        self.assertEqual(state['hypotheses'][admin]['status'], 'contested')
        self.assertEqual(state['hypotheses'][negative]['status'], 'active')   # claim already asserts the negative

    def test_positive_fact_or_unrelated_path_is_not_a_contradiction(self):
        state, _ = run_cycle(None, cycle([proposal('The site may expose an /admin path')]))
        probe = {'job_id': 'job-probe', 'output': [
            {'kind': 'http_path', 'locator': 'http://192.0.2.1:8080/admin', 'summary': 'status 200 length 512'},
            {'kind': 'http_path', 'locator': 'http://192.0.2.1:8080/administrator', 'summary': 'status 404'}]}
        state, report = run_cycle(state, cycle([], evidence=(probe,)))
        self.assertEqual(report['contradictions']['from_facts'], [])

    def test_summary_puts_claims_about_reviewed_evidence_first(self):
        claims = ['The root page may be a vendor default', 'Directory listing may be enabled',
                  'A reverse proxy may front the application']
        state, _ = run_cycle(None, cycle([proposal(c, refs=('job-http',)) for c in claims]
                                         + [proposal('Port claim may be about tcp 8080',
                                                                         refs=('job-port',))],
                                         evidence=(HTTP, PORT)))
        focused = planner_summary(state, limit=1, focus=['job-port'])
        self.assertEqual(focused['live_hypotheses'][0]['support'], ['job-port'])
        self.assertEqual(focused['omitted_live_hypotheses'], 3)

    def test_unhedged_security_assertions_are_not_hypotheses(self):
        for text in ('Anonymous FTP login is enabled on the host.', 'The host is affected by CVE-2007-2447.',
                     'The SSH service is secure and not exploitable.'):
            accepted, challenges, _ = supervise(proposal(text), {'job-http'}, {'job-http'}, empty_state())
            self.assertFalse(accepted, text)
            self.assertIn('unhedged_assertion', challenges)
        for text in ('Anonymous FTP login might be enabled; untested.', 'The host is probably a default install.'):
            self.assertTrue(supervise(proposal(text), {'job-http'}, {'job-http'}, empty_state())[0], text)

    def test_access_denied_separates_existence_from_unauthenticated_access(self):
        root = {'job_id': 'job-root', 'output': [{'kind': 'http', 'locator': 'http://192.0.2.1', 'summary': 'HTTP 200'}]}
        state, _ = run_cycle(None, cycle([
            proposal('The /manager path may be accessible without authentication', refs=('job-root',)),
            proposal('A manager application may exist at /manager', refs=('job-root',)),
            proposal('The /manager path may be reachable', refs=('job-root',))], evidence=(root,)))
        public, exists, ambiguous = (h['id'] for h in state['hypotheses'].values())
        probe = {'job_id': 'job-403', 'output': [
            {'kind': 'http_path', 'locator': 'http://192.0.2.1/manager', 'summary': 'status 403 length 287'}]}
        state, report = run_cycle(state, cycle([], evidence=(probe,)))
        relations = {c['hypothesis']: c['relation'] for c in report['contradictions']['from_facts']}
        self.assertEqual(relations, {public: 'contradicts', exists: 'supports'})
        self.assertEqual(state['hypotheses'][public]['status'], 'contested')
        self.assertIn('job-403', state['hypotheses'][exists]['support'])
        self.assertEqual(state['hypotheses'][ambiguous]['status'], 'active')

    def test_superseded_support_contests_instead_of_rejecting(self):
        opened = {'job_id': 'job-open', 'output': [{'kind': 'port', 'locator': '192.0.2.1:3306/tcp', 'summary': 'tcp/3306 open'}]}
        state, _ = run_cycle(None, cycle([proposal('Port 3306 may expose MySQL', refs=('job-open',))], evidence=(opened,)))
        hid = next(iter(state['hypotheses']))
        filtered = {'job_id': 'job-later', 'output': [{'kind': 'port', 'locator': '192.0.2.1:3306/tcp', 'summary': 'tcp/3306 filtered'}]}
        state, report = run_cycle(state, cycle([], evidence=(filtered,)))
        self.assertEqual(state['hypotheses'][hid]['status'], 'contested')
        self.assertTrue(state['hypotheses'][hid]['requires_revalidation'])
        self.assertEqual(report['contradictions']['rejected'], [])
        self.assertEqual(report['decision']['action'], 'collect_missing_information')

    def test_claim_key_is_order_insensitive(self):
        self.assertEqual(claim_key('admin path may be exposed'), claim_key('Exposed admin path'))


class ReasoningPersistence(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        # Exercise the real store against the in-memory ledger, not the fixture stub.
        self.events, self.pending = [], []
        self.session = SimpleNamespace(id='engagement', scope={'targets': ['192.0.2.1']}, metadata_={})

        async def commit():
            self.events.extend(copy.deepcopy(row.metadata_) for row in self.pending)
            self.pending.clear()
        db = SimpleNamespace(add=self.pending.append, commit=AsyncMock(side_effect=commit))
        cm = AsyncMock()
        cm.__aenter__.return_value = db
        self.stack = ExitStack()
        self.stack.enter_context(patch('memory.team_tasks.async_session', return_value=cm))
        self.stack.enter_context(patch('memory.team_tasks.owned_engagement', AsyncMock(return_value=self.session)))
        self.stack.enter_context(patch.object(TeamStore, '_events', AsyncMock(
            side_effect=lambda *args: copy.deepcopy(self.events))))

    async def asyncTearDown(self):
        self.stack.close()
        await super().asyncTearDown()

    async def test_cycles_persist_replay_idempotently_and_survive_restart(self):
        from memory.investigation_state import InvestigationStateStore
        store = InvestigationStateStore()
        hyp = proposal('The site may expose an administrative path', follow_up='bounded_http_paths')
        state, report = await store.advance('engagement', 'owner', 'run-1:a', cycle([hyp]))
        replay_state, replay = await store.advance('engagement', 'owner', 'run-1:a', cycle([hyp]))
        self.assertEqual(len(self.events), 1)
        self.assertEqual(replay['cycle'], report['cycle'])
        self.assertEqual(replay_state['hypotheses'].keys(), state['hypotheses'].keys())
        await store.advance('engagement', 'owner', 'run-1:b', cycle([hyp]))
        restored = await InvestigationStateStore().current('engagement', 'owner')
        self.assertEqual(restored['revision'], 2)
        self.assertEqual(restored['state']['cycle'], 2)
        self.assertEqual(restored['scope_digest'], digest(self.session.scope))
        self.assertIn('current', materialize(self.events)['investigation_reasoning'])

    async def test_scope_change_requires_revalidation(self):
        from memory.investigation_state import InvestigationStateStore
        store = InvestigationStateStore()
        await store.advance('engagement', 'owner', 'k1', cycle([proposal('The site may expose an administrative path')]))
        self.session.scope = {'targets': ['192.0.2.9']}
        state, _ = await store.advance('engagement', 'owner', 'k2', cycle([]))
        self.assertTrue(all(h['requires_revalidation'] for h in state['hypotheses'].values()))


class SupervisedReview(OfflineCase):
    async def review(self, engine, state, output, stdout='HTTP/1.1 200 OK'):
        from agents.orchestrator_agent import orchestrator_agent
        from memory.worker_jobs import worker_jobs
        prompts = []

        async def model(user, prompt, *args, **kwargs):
            prompts.append(json.loads(prompt))
            return {'success': True, 'content': json.dumps(output)}
        with patch.object(worker_jobs.store, 'get', AsyncMock(return_value={'session_id': 'engagement'})), \
                patch.object(worker_jobs.client, 'status', AsyncMock(return_value={
                    'stdout': stdout, 'stderr': '', 'exit_code': 0})), \
                patch.object(worker_jobs, 'verify_receipt', AsyncMock()), \
                patch.object(engine, '_persist', AsyncMock()), \
                patch.object(orchestrator_agent, 'query_llm_smart', side_effect=model), \
                patch.object(engine, '_emit', AsyncMock()) as emit, \
                patch.object(engine, '_write_decision_log', AsyncMock()), \
                patch('agents.orchestrator_agent.record_planner_diagnostic', AsyncMock()), \
                patch('memory.research.research_store.ingest_review', AsyncMock(return_value=[])) as ingest:
            await engine._review_investigation(state)
        assert emit.await_args is not None and ingest.await_args is not None
        return emit.await_args.args[1]['review'], ingest.await_args.args[3], prompts[0]

    async def test_supervisor_filters_research_and_prior_state_reaches_next_review(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        state.evidence_job_ids = ['owned-job']
        output = {'observations': ['HTTP 200'], 'limitations': [], 'hypotheses': [
            {'description': 'The server is confirmed vulnerable to RCE', 'evidence_job_ids': ['owned-job'],
             'follow_up': 'none', 'validation_criterion': 'None', 'confidence': .9},
            {'description': 'The response may come from a default installation page',
             'evidence_job_ids': ['owned-job'], 'follow_up': 'none', 'validation_criterion': 'Compare body',
             'alternative_explanations': ['Custom app'], 'confidence': .9}]}
        report, ingested, prompt = await self.review(engine, state, output)
        self.assertNotIn('prior_reasoning', prompt)
        self.assertEqual([h['description'] for h in ingested['hypotheses']],
                         ['The response may come from a default installation page'])
        self.assertLess(ingested['hypotheses'][0]['confidence'], .9)
        self.assertEqual(report['supervisor_rejected'][0]['challenges'], ['unsupported_conclusion', 'single_explanation', 'confidence_capped'])
        state.run_id = 'second-run'
        output['hypotheses'] = output['hypotheses'][1:]
        _, _, prompt = await self.review(engine, state, output, stdout='HTTP/1.1 200 OK\nServer: lab')
        prior = prompt['prior_reasoning']
        self.assertEqual(len(prior['live_hypotheses']), 1)
        self.assertIn('unsupported_conclusion', prior['rejected_claims'][0]['reasons'])

    async def test_reasoning_uses_canonical_ledger_ids_and_model_sees_job_ids(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        state.evidence_job_ids = ['owned-job']
        self.evidence_canonical['owned-job'] = 'ev-ledger-1'
        self.reasoning_aliases['ev-ledger-1'] = 'owned-job'
        output = {'observations': [], 'limitations': [], 'hypotheses': [
            {'description': 'The response may come from a default installation page',
             'evidence_job_ids': ['owned-job'], 'follow_up': 'none', 'validation_criterion': 'Compare body',
             'alternative_explanations': ['Custom app']}]}
        await self.review(engine, state, output)
        stored = next(iter(self.reasoning_records['engagement']['state']['hypotheses'].values()))
        self.assertEqual(stored['support'], ['ev-ledger-1'])
        state.run_id = 'second-run'
        _, _, prompt = await self.review(engine, state, output, stdout='HTTP/1.1 200 OK\nServer: lab')
        self.assertEqual(prompt['prior_reasoning']['live_hypotheses'][0]['support'], ['owned-job'])

    async def test_identical_receipt_facts_skip_the_model_review(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from agents.orchestrator_agent import orchestrator_agent
        from memory.worker_jobs import worker_jobs
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        state.evidence_job_ids = ['owned-job']
        output = {'observations': [], 'limitations': [], 'hypotheses': [
            {'description': 'The response may come from a default installation page',
             'evidence_job_ids': ['owned-job'], 'follow_up': 'none', 'validation_criterion': 'Compare body',
             'alternative_explanations': ['Custom app']}]}
        await self.review(engine, state, output)
        calls_before = state.model_calls
        state.run_id = 'second-run'
        query = AsyncMock()
        with patch.object(worker_jobs.store, 'get', AsyncMock(return_value={'session_id': 'engagement'})), \
                patch.object(worker_jobs.client, 'status', AsyncMock(return_value={
                    'stdout': 'HTTP/1.1 200 OK', 'stderr': '', 'exit_code': 0})), \
                patch.object(worker_jobs, 'verify_receipt', AsyncMock()), \
                patch.object(engine, '_persist', AsyncMock()), \
                patch.object(orchestrator_agent, 'query_llm_smart', query), \
                patch.object(engine, '_emit', AsyncMock()) as emit, \
                patch.object(engine, '_write_decision_log', AsyncMock()):
            await engine._review_investigation(state)
        query.assert_not_awaited()
        self.assertEqual(state.model_calls, calls_before)
        assert emit.await_args is not None
        event = emit.await_args.args[1]
        self.assertEqual((event['status'], event['review']['reason']), ('skipped', 'no_new_receipt_facts'))

    async def test_unknown_retraction_target_is_rejected(self):
        from agents.autonomous_engine import AutonomousEngine, InvestigationReviewError, SessionRunState
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        state.evidence_job_ids = ['owned-job']
        output = {'observations': [], 'hypotheses': [], 'limitations': [], 'retractions': [
            {'prior_hypothesis_id': 'h-fabricated', 'reason': 'x', 'evidence_job_ids': ['owned-job']}]}
        with self.assertRaises(InvestigationReviewError) as rejected:
            await self.review(engine, state, output)
        self.assertEqual(rejected.exception.code, 'invalid_review_evidence')

    async def test_planner_context_carries_reasoning_summary(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        reasoning, _ = run_cycle(None, cycle([proposal('The site may expose an administrative path')]))
        self.reasoning_records['engagement'] = {'state': reasoning}
        context = await engine._specialist_context(state)
        self.assertEqual(context['investigation_reasoning']['cycle'], 1)


class ReasoningEvaluation(OfflineCase):
    async def test_scripted_evaluation_is_reproducible(self):
        from evaluation.reasoning_eval import evaluate
        first = await evaluate('scripted')
        second = await evaluate('scripted')
        self.assertEqual(first['metrics'], second['metrics'])
        self.assertEqual(first['fixture_sha256'], second['fixture_sha256'])
        reasoning, baseline = first['metrics']['reasoning'], first['metrics']['baseline']
        self.assertEqual(reasoning['false_positive_rejection'], 1.0)
        self.assertEqual(reasoning['overclaims_reaching_research'], 0)
        self.assertEqual(reasoning['redundant_decisions'], 0)
        self.assertEqual(baseline['false_positive_rejection'], 0.0)
        self.assertGreater(baseline['duplicate_hypothesis_entries'], 0)


class ContextBudget(OfflineCase):
    def test_schema_compaction_keeps_every_constraint(self):
        from agents.autonomous_engine import review_schema
        from agents.orchestrator_agent import InvestigationReview
        from llm.context_budget import compact_json, compact_schema
        raw = InvestigationReview.model_json_schema()
        compact = review_schema({'job-1'}, {'bounded_http_paths': {}}, ['h-0123456789ab'])
        hyp = compact['$defs']['EvidenceHypothesis']
        self.assertIn('description', hyp['properties'])            # a field named "description" survives
        self.assertEqual(hyp['required'], raw['$defs']['EvidenceHypothesis']['required'])
        self.assertFalse(hyp['additionalProperties'])
        self.assertEqual(hyp['properties']['follow_up']['enum'], ['bounded_http_paths', 'none'])
        self.assertEqual(hyp['properties']['evidence_job_ids']['items']['enum'], ['job-1'])
        self.assertNotIn('default', hyp['properties']['confidence'])
        self.assertNotIn('"default":', compact_json(compact))
        self.assertNotIn('title', hyp)
        self.assertLess(len(compact_json(compact)), len(compact_json(compact_schema(raw))) + 200)
        self.assertLess(len(compact_json(compact_schema(raw))), len(compact_json(raw)))

    async def test_gated_evaluation_saves_calls_without_losing_supported_claims(self):
        from evaluation.reasoning_eval import evaluate
        result = await evaluate('scripted')
        gated, full = result['metrics']['reasoning_gated'], result['metrics']['reasoning']
        self.assertEqual(result['cost']['reasoning_gated']['model_calls'], 10)
        self.assertEqual(result['cost']['reasoning_gated']['skipped_reviews'], 3)
        self.assertEqual(gated['supported_claims_live_at_end'], 1.0)
        for key in ('false_positive_rejection', 'contradiction_handling', 'decision_accuracy',
                    'decision_consistency', 'replanning_on_evidence_change', 'overclaims_reaching_research'):
            self.assertEqual(gated[key], full[key], key)
        self.assertLess(result['cost']['reasoning_gated']['prompt_chars'], result['cost']['reasoning']['prompt_chars'])


class EvaluationAccounting(OfflineCase):
    def test_evaluation_uses_the_production_system_text(self):
        from agents.autonomous_engine import REVIEW_INSTRUCTION
        from agents.orchestrator_agent import orchestrator_agent
        from evaluation.reasoning_eval import production_system
        _, system = orchestrator_agent._ground_prompt('task', REVIEW_INSTRUCTION)
        self.assertEqual(production_system(REVIEW_INSTRUCTION), system)

    async def test_heldout_v3_targeted_defects_are_fixed(self):
        from pathlib import Path
        from evaluation.reasoning_eval import evaluate
        result = await evaluate('scripted', fixture=Path('evaluation/fixtures/reasoning/reasoning-heldout-v3.json'))
        counts = result['metrics']['reasoning']['counts']
        self.assertEqual((counts['fp_rejected'], counts['fp']), (4, 4))
        self.assertEqual((counts['contradiction_handled'], counts['contradiction_expected']), (3, 3))
        self.assertEqual((counts['stale_contested'], counts['stale_expected']), (2, 2))
        self.assertEqual((counts['ambiguity_kept_live'], counts['ambiguity_expected']), (3, 3))
        self.assertEqual(counts['tp_accepted'], counts['tp'])


class RealLabEvidenceConflict(OfflineCase):
    """Replay of real P2/P5 receipts: httpx HTTP 200 (job ac5747a7) then nmap all ports filtered (job 339f5c74)."""

    def test_conflicting_receipts_force_reverification(self):
        httpx_fact = {'job_id': '2e064b9d-d9e1-52d9-9668-d16ed80b09d3', 'output': [
            {'kind': 'http', 'locator': 'http://192.168.77.20', 'summary': 'HTTP 200: Metasploitable2 - Linux'}]}
        nmap_facts = {'job_id': '31347928-fa6d-5095-8481-767a228124af', 'output': [
            {'kind': 'service', 'locator': '192.168.77.20', 'summary': f'tcp/{port} filtered'}
            for port in (21, 22, 80, 139, 445)]}
        state, _ = run_cycle(None, cycle([], evidence=(httpx_fact,), follow={}))
        state, report = run_cycle(state, cycle([], evidence=(nmap_facts,), follow={}))
        conflicts = report['contradictions']['evidence_conflicts']
        self.assertEqual([(c['host'], c['port']) for c in conflicts], [('192.168.77.20', '80')])
        self.assertEqual(report['decision']['action'], 'collect_missing_information')
        rationale = next(r['rationale'] for r in report['priorities'] if r['action'] == 'collect_missing_information')
        self.assertIn('re-verification', rationale)
        self.assertEqual(planner_summary(state)['open_evidence_conflicts'][0]['port'], '80')
        # A later receipt for the same host and port supersedes the open conflict.
        recovered = {'job_id': 'job-later', 'output': [{'kind': 'service', 'locator': '192.168.77.20', 'summary': 'tcp/80 open'}]}
        state, _ = run_cycle(state, cycle([], evidence=(recovered,), follow={}))
        self.assertEqual(state['conflicts'][conflicts[0]['id']]['status'], 'superseded_by_new_receipt')

    def test_summary_port_reaches_hypothesis_contradiction(self):
        root = {'job_id': 'job-root', 'output': [{'kind': 'http', 'locator': 'http://192.168.77.20', 'summary': 'HTTP 200'}]}
        state, _ = run_cycle(None, cycle([proposal('Port 80 may host the training web application',
                                                   refs=('job-root',))], evidence=(root,), follow={}))
        nmap = {'job_id': 'job-nmap', 'output': [{'kind': 'service', 'locator': '192.168.77.20', 'summary': 'tcp/80 filtered'}]}
        state, report = run_cycle(state, cycle([], evidence=(nmap,), follow={}))
        self.assertEqual(len(report['contradictions']['from_facts']), 1)
        self.assertEqual(next(iter(state['hypotheses'].values()))['status'], 'contested')


class SpecialistFacts(OfflineCase):
    def test_task_context_carries_receipt_facts_and_conflicts(self):
        from orchestrator.reasoning import task_reasoning_context
        httpx_fact = {'job_id': 'ev-http', 'output': [{'kind': 'http', 'locator': 'http://192.168.77.20', 'summary': 'HTTP 200'}]}
        nmap = {'job_id': 'ev-nmap', 'output': [{'kind': 'service', 'locator': '192.168.77.20', 'summary': 'tcp/80 filtered'}]}
        state, _ = run_cycle(None, cycle([], evidence=(httpx_fact,), follow={}))
        state, _ = run_cycle(state, cycle([], evidence=(nmap,), follow={}))
        context = task_reasoning_context(state, ['ev-nmap'])
        self.assertEqual([f['summary'] for f in context['observed_facts']], ['tcp/80 filtered'])
        self.assertEqual(context['open_evidence_conflicts'][0]['port'], '80')
        self.assertEqual(task_reasoning_context(state, ['ev-unrelated']), {})
