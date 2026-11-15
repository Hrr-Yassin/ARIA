"""Synthetic review crash recovery using real SQL events, never live inference."""
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import unittest
import uuid
from unittest.mock import AsyncMock, patch

ENABLED = os.environ.get('ARIA_INTEGRATION') == '1'


class SyntheticCrash(RuntimeError):
    pass


@unittest.skipUnless(ENABLED, 'requires explicitly provisioned disposable *_test database')
class ReviewRecoveryPostgres(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        from sqlalchemy.engine import make_url
        if not (make_url(os.environ['DATABASE_URL']).database or '').endswith('_test'):
            raise RuntimeError('Disposable *_test database required')
        subprocess.run([sys.executable, '-B', '-m', 'alembic', 'upgrade', 'head'], check=True)

    async def asyncSetUp(self):
        from agents.autonomous_engine import SessionRunState
        from memory.database_models import User, PentestSession, DecisionLog, async_session, engine
        from memory.worker_jobs import SQLJobStore
        await engine.dispose()
        owner = 'review-owner-' + uuid.uuid4().hex[:12]
        sid = 'review-session-' + uuid.uuid4().hex[:12]
        self.job = str(uuid.uuid4())
        stdout = '80/tcp open http'
        async with async_session() as db:
            db.add(User(id=owner, username=owner, password_hash='unused'))
            await db.flush()
            db.add(PentestSession(id=sid, user_id=owner, target='192.0.2.1',
                                  scope={'targets': ['192.0.2.1']}))
            await db.flush()
            db.add(DecisionLog(id=SQLJobStore.key(self.job), session_id=sid, user_id=owner,
                decision_type='worker_job', metadata_={
                    'job_id': self.job, 'session_id': sid, 'user_id': owner,
                    'state': 'succeeded', 'exit_code': 0,
                    'output_hash': hashlib.sha256(stdout.encode()).hexdigest(),
                    'stderr_hash': hashlib.sha256(b'').hexdigest()}))
            await db.commit()
        self.state = SessionRunState(sid, owner, 'discovery', '192.0.2.1', 'expert',
                                     owner_id=owner, evidence_job_ids=[self.job])
        self.snapshot = {'stdout': stdout, 'stderr': '', 'exit_code': 0, 'state': 'succeeded'}

    async def asyncTearDown(self):
        from memory.database_models import engine
        await engine.dispose()

    def response(self, description):
        return {'success': True, 'content': json.dumps({
            'observations': [], 'limitations': ['Synthetic fixture only'],
            'hypotheses': [{'description': description, 'evidence_job_ids': [self.job],
                            'follow_up': 'none', 'validation_criterion': 'Compare harmless fixture controls',
                            'alternative_explanations': ['Intended public behavior']}],
        })}

    async def test_crash_after_ingestion_reuses_exact_response_without_provider_repeat(self):
        from agents.autonomous_engine import AutonomousEngine
        from agents.orchestrator_agent import orchestrator_agent
        from memory.research import research_store
        original_ingest = research_store.ingest_review

        async def ingest_then_crash(*args):
            await original_ingest(*args)
            raise SyntheticCrash('Interrupted after committed ingestion, before final marker')

        query = AsyncMock(side_effect=[self.response('First synthetic candidate'),
                                       self.response('Different candidate from a repeated model call')])
        with patch('memory.worker_jobs.worker_jobs.client.status',
                   AsyncMock(return_value=self.snapshot)), \
             patch.object(orchestrator_agent, 'query_llm_smart', query):
            first = AutonomousEngine()
            with patch.object(first, '_persist', AsyncMock()), \
                 patch.object(research_store, 'ingest_review', side_effect=ingest_then_crash):
                with self.assertRaises(SyntheticCrash):
                    await first._review_investigation(self.state)
            before = await research_store.view(self.state.session_id, self.state.owner_id)
            self.assertEqual(len(before['queue']), 1)
            restored = AutonomousEngine()
            with patch.object(restored, '_persist', AsyncMock()), \
                 patch.object(restored, '_emit', AsyncMock()), \
                 patch.object(restored, '_write_decision_log', AsyncMock()):
                await restored._review_investigation(self.state)
            after = await research_store.view(self.state.session_id, self.state.owner_id)
        self.assertEqual(len(after['queue']), 1)
        self.assertEqual(before['queue'][0]['id'], after['queue'][0]['id'])
        self.assertEqual(after['queue'][0]['claim'], 'First synthetic candidate')
        query.assert_awaited_once()
        self.assertEqual(self.state.model_calls, 1)

    async def test_concurrent_claims_have_one_creator_and_no_replay_authority(self):
        from memory.investigation_reviews import ReviewJournal
        store = ReviewJournal()
        claims = await asyncio.gather(*[
            store.acquire(self.state.session_id, self.state.owner_id,
                          self.state.run_id, [self.job]) for _ in range(5)])
        self.assertEqual(sum(claim['created'] for claim in claims), 1)
        self.assertEqual(len({claim['id'] for claim in claims}), 1)
        self.assertEqual({claim['state'] for claim in claims}, {'requested'})

    async def test_unknown_provider_outcome_blocks_without_a_second_physical_call(self):
        from agents.autonomous_engine import AutonomousEngine, InvestigationReviewError
        from agents.orchestrator_agent import orchestrator_agent
        from memory.investigation_reviews import ReviewJournal
        await ReviewJournal().acquire(self.state.session_id, self.state.owner_id,
                                      self.state.run_id, [self.job])
        with patch('memory.worker_jobs.worker_jobs.client.status',
                   AsyncMock(return_value=self.snapshot)), \
             patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock()) as query:
            with self.assertRaises(InvestigationReviewError) as blocked:
                await AutonomousEngine()._review_investigation(self.state)
        self.assertEqual(blocked.exception.code, 'review_outcome_unknown')
        query.assert_not_awaited()
        self.assertEqual(self.state.model_calls, 0)

    async def test_journal_ownership_receipt_binding_and_encrypted_content(self):
        from fastapi import HTTPException
        from memory.database_models import DecisionLog, async_session
        from memory.investigation_reviews import ReviewJournal, ReviewJournalError
        store = ReviewJournal()
        claim = await store.acquire(self.state.session_id, self.state.owner_id,
                                    self.state.run_id, [self.job])
        raw = self.response('Private synthetic journal sentinel')['content']
        await store.capture(claim, raw)
        saved = await store.acquire(self.state.session_id, self.state.owner_id,
                                    self.state.run_id, [self.job])
        self.assertFalse(saved['created'])
        self.assertEqual(store.response(saved), raw)
        self.assertNotIn('Private synthetic journal sentinel', json.dumps(saved))
        with self.assertRaises(HTTPException):
            await store.acquire(self.state.session_id, 'another-owner',
                                self.state.run_id, [self.job])
        with self.assertRaises(ReviewJournalError):
            await store.acquire(self.state.session_id, self.state.owner_id,
                                self.state.run_id, ['different-receipt'])
        async with async_session() as db:
            row = await db.get(DecisionLog, claim['id'])
            row.metadata_ = {**row.metadata_, 'response_sha256': '0' * 64}
            await db.commit()
        corrupted = await store.acquire(self.state.session_id, self.state.owner_id,
                                        self.state.run_id, [self.job])
        with self.assertRaises(ReviewJournalError):
            store.response(corrupted)

    async def test_recorded_provider_failure_is_not_retried_on_recovery(self):
        from agents.autonomous_engine import AutonomousEngine, InvestigationReviewError
        from agents.orchestrator_agent import orchestrator_agent
        with patch('memory.worker_jobs.worker_jobs.client.status',
                   AsyncMock(return_value=self.snapshot)), \
             patch.object(orchestrator_agent, 'query_llm_smart',
                          AsyncMock(return_value={'success': False, 'error': 'provider_timeout'})) as query:
            for _ in range(2):
                engine = AutonomousEngine()
                with patch.object(engine, '_persist', AsyncMock()):
                    with self.assertRaises(InvestigationReviewError) as blocked:
                        await engine._review_investigation(self.state)
                self.assertEqual(blocked.exception.code, 'review_provider_timeout')
        query.assert_awaited_once()
        self.assertEqual(self.state.model_calls, 1)

    async def test_hard_process_exit_after_ingestion_recovers_saved_response(self):
        from agents.autonomous_engine import AutonomousEngine
        from agents.orchestrator_agent import orchestrator_agent
        from memory.research import research_store
        # This child owns no live worker/model. It exits without finally blocks
        # after real SQL ingestion, simulating a process dying at that boundary.
        writer = '''
import asyncio, json, os
from unittest.mock import AsyncMock, patch
from agents.autonomous_engine import AutonomousEngine, SessionRunState
from agents.orchestrator_agent import orchestrator_agent
from memory.research import research_store
data = json.loads(os.environ['ARIA_REVIEW_FIXTURE'])
state = SessionRunState(data['sid'], data['owner'], 'discovery', '192.0.2.1', 'expert',
    owner_id=data['owner'], run_id=data['run_id'], evidence_job_ids=[data['job']])
original = research_store.ingest_review
async def committed_then_exit(*args):
    await original(*args)
    os._exit(73)
async def run():
    engine = AutonomousEngine()
    with patch('memory.worker_jobs.worker_jobs.client.status', AsyncMock(return_value=data['snapshot'])), \\
         patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value=data['response'])), \\
         patch.object(engine, '_persist', AsyncMock()), \\
         patch.object(research_store, 'ingest_review', side_effect=committed_then_exit):
        await engine._review_investigation(state)
asyncio.run(run())
'''
        fixture = {'sid': self.state.session_id, 'owner': self.state.owner_id,
                   'run_id': self.state.run_id, 'job': self.job,
                   'snapshot': self.snapshot, 'response': self.response('Process crash candidate')}
        child = await asyncio.to_thread(subprocess.run,
            [sys.executable, '-B', '-c', writer],
            env={**os.environ, 'ARIA_REVIEW_FIXTURE': json.dumps(fixture)},
            capture_output=True, timeout=30)
        self.assertEqual(child.returncode, 73, 'Fixture child must reach the committed crash boundary')
        before = await research_store.view(self.state.session_id, self.state.owner_id)
        self.assertEqual(len(before['queue']), 1)
        self.state.model_calls = 1  # The synthetic attempt preceded the crash.
        engine = AutonomousEngine()
        with patch('memory.worker_jobs.worker_jobs.client.status',
                   AsyncMock(return_value=self.snapshot)), \
             patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock()) as query, \
             patch.object(engine, '_persist', AsyncMock()), \
             patch.object(engine, '_emit', AsyncMock()), \
             patch.object(engine, '_write_decision_log', AsyncMock()):
            await engine._review_investigation(self.state)
        query.assert_not_awaited()
        after = await research_store.view(self.state.session_id, self.state.owner_id)
        self.assertEqual(len(after['queue']), 1)
        self.assertEqual(after['queue'][0]['id'], before['queue'][0]['id'])
        self.assertEqual(after['queue'][0]['claim'], 'Process crash candidate')
        self.assertEqual(self.state.model_calls, 1)
