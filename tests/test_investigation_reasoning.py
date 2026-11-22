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
    async def review(self, engine, state, output):
        from agents.orchestrator_agent import orchestrator_agent
        from memory.worker_jobs import worker_jobs
        prompts = []

        async def model(user, prompt, *args, **kwargs):
            prompts.append(json.loads(prompt))
            return {'success': True, 'content': json.dumps(output)}
        with patch.object(worker_jobs.store, 'get', AsyncMock(return_value={'session_id': 'engagement'})), \
                patch.object(worker_jobs.client, 'status', AsyncMock(return_value={
                    'stdout': 'HTTP/1.1 200 OK', 'stderr': '', 'exit_code': 0})), \
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
        _, _, prompt = await self.review(engine, state, output)
        prior = prompt['prior_reasoning']
        self.assertEqual(len(prior['live_hypotheses']), 1)
        self.assertIn('unsupported_conclusion', prior['rejected_claims'][0]['reasons'])

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
