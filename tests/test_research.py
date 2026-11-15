"""Research lifecycle, provenance, prioritization and semantic graph regressions."""
import copy
from contextlib import ExitStack
from types import SimpleNamespace
import uuid
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from pydantic import ValidationError
from memory.research import (ApplicationModel, CreateHypothesis, Hypothesis,
    ModelNode, ModelEdge, ResearchStore, ResearchTransition, priority)
from memory.team_tasks import TeamStore, CreateTask, TaskSpec, team_store, digest, materialize
from tests.support import OfflineCase


def hypothesis(**changes):
    return Hypothesis(**{**dict(title='Private object isolation', claim='Another controlled account may read an owner object',
        vulnerability_class='idor_bola', supporting_evidence=['e1'],
        alternative_explanations=['A generic public response may resemble the private object'],
        prerequisites=['Two authorized synthetic accounts and a private object'],
        validation_strategy='Compare original private content under owner and outsider identities',
        positive_controls=['Owner reads the private object'],
        negative_controls=['Outsider cannot read a nonexistent object'], confidence=.3,
        uncertainty=['Cross-account behavior has not been tested']), **changes})


class ResearchLifecycle(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.events=[];self.pending=[]
        self.session=SimpleNamespace(id='engagement', scope={'targets':['lab.test']}, metadata_={})
        async def commit():
            self.events.extend(copy.deepcopy(row.metadata_) for row in self.pending);self.pending.clear()
        self.db=SimpleNamespace(add=self.pending.append,commit=AsyncMock(side_effect=commit))
        cm=AsyncMock();cm.__aenter__.return_value=self.db
        self.stack=ExitStack()
        self.stack.enter_context(patch('memory.team_tasks.async_session',return_value=cm))
        self.ownership=self.stack.enter_context(patch('memory.team_tasks.owned_engagement',AsyncMock(return_value=self.session)))
        self.stack.enter_context(patch.object(TeamStore,'_events',AsyncMock(side_effect=lambda *args:copy.deepcopy(self.events))))
        self.store=ResearchStore()
        for ref in ('e1','e2','e3'):
            self.events.append({'collection':'evidence','entity_id':ref,'sequence':len(self.events)+1,
                'id':str(uuid.uuid4()),'data':{'id':ref,'hashes':{'content_sha256':digest({'source':ref})},
                'source_kind':'chat','source_id':ref}})

    async def asyncTearDown(self):
        self.stack.close()
        await super().asyncTearDown()

    async def create(self, **changes):
        event=await self.store.create('engagement','owner',CreateHypothesis(request_id=uuid.uuid4(),hypothesis=hypothesis(**changes)))
        return event['data']

    async def advance(self, item, state, **changes):
        body=ResearchTransition(request_id=uuid.uuid4(),expected_revision=item['revision'],state=state,reason='Controlled laboratory investigation',**changes)
        return (await self.store.transition('engagement','owner',item['id'],body))['data']

    async def test_multiple_hypotheses_priority_history_and_restart(self):
        slow=await self.create(estimated_cost_microusd=1000000)
        fast=await self.create(estimated_cost_microusd=10, information_value=.9)
        fast=await self.advance(fast,'HYPOTHESIZED')
        fast=await self.advance(fast,'PLANNED')
        fast=await self.advance(fast,'TESTED',evidence_references=['e2'])
        with self.assertRaises(HTTPException):await self.advance(fast,'CONFIRMED')
        fast=await self.advance(fast,'INCONCLUSIVE')
        fast=await self.advance(fast,'HYPOTHESIZED')
        restored=await ResearchStore().view('engagement','owner')
        self.assertEqual(len(restored['hypotheses']),2)
        self.assertEqual(restored['queue'][0]['id'],fast['id'])
        self.assertEqual([h['state'] for h in fast['history']],['OBSERVED','HYPOTHESIZED','PLANNED','TESTED','INCONCLUSIVE','HYPOTHESIZED'])
        self.assertEqual(materialize(self.events)['research_hypotheses'][fast['id']],fast)
        self.assertGreater(priority(fast),priority(slow))

    async def test_idempotency_revision_forged_refs_and_storage_failure(self):
        body=CreateHypothesis(request_id=uuid.uuid4(),hypothesis=hypothesis())
        first=await self.store.create('engagement','owner',body)
        self.assertTrue((await self.store.create('engagement','owner',body))['duplicate'])
        with self.assertRaises(HTTPException):await self.store.create('engagement','owner',body.model_copy(update={'hypothesis':hypothesis(claim='Different operation')}))
        item=first['data']
        with self.assertRaises(HTTPException):await self.advance(item,'CONFIRMED')
        item=await self.advance(item,'HYPOTHESIZED')
        with self.assertRaises(HTTPException):await self.advance(first['data'],'HYPOTHESIZED')
        with self.assertRaises(HTTPException):await self.create(supporting_evidence=['foreign-source'])
        self.db.commit.side_effect=RuntimeError('unavailable')
        before=len(self.events)
        with self.assertRaises(RuntimeError):await self.create()
        self.assertEqual(len(self.events),before)

    async def test_scope_or_evidence_change_invalidates_queue_and_test(self):
        item=await self.advance(await self.create(),'HYPOTHESIZED')
        self.session.scope={'targets':['other.test']}
        with self.assertRaises(HTTPException):await self.advance(item,'PLANNED')
        view=await self.store.view('engagement','owner')
        self.assertEqual(view['queue'],[])
        self.assertTrue(view['hypotheses'][0]['requires_revalidation'])
        item=await self.advance(item,'INCONCLUSIVE')
        item=await self.advance(item,'HYPOTHESIZED')
        self.events[0]['data']['hashes']['content_sha256']='changed'
        with self.assertRaises(HTTPException):await self.advance(item,'PLANNED')

    async def test_semantic_model_binds_ownership_roles_transitions_and_scope(self):
        nodes=[ModelNode(id=key,kind=kind,label=key,evidence_references=['e1'])
            for key,kind in [('alice','identity'),('record','object'),('admin','role'),('draft','state'),('paid','state')]]
        edges=[ModelEdge(source=a,target=b,relation=r,condition='Supported by controlled evidence',evidence_references=['e1'])
            for a,b,r in [('alice','record','owns'),('alice','admin','assumes_role'),('draft','paid','transitions_to')]]
        body=ApplicationModel(request_id=uuid.uuid4(),expected_revision=0,nodes=nodes,edges=edges,uncertainty=['Role mapping requires validation'])
        result=await self.store.save_model('engagement','owner',body)
        self.assertEqual(result['data']['revision'],1)
        item=await self.create(related_assets=['record'],related_components=['alice'])
        body=body.model_copy(update={'request_id':uuid.uuid4(),'expected_revision':1})
        await self.store.save_model('engagement','owner',body)
        self.assertFalse((await self.store.view('engagement','owner'))['hypotheses'][0]['context_current'])
        with self.assertRaises(HTTPException):await self.create(related_assets=['unknown'])
        for bad in [ModelNode(id='remote',kind='asset',label='outside',locator='https://outside.test',evidence_references=['e1']),
                    ModelNode(id='secret',kind='endpoint',label='query',locator='https://lab.test/?token=credential',evidence_references=['e1'])]:
            with self.assertRaises(HTTPException):await self.store.save_model('engagement','owner',ApplicationModel(
                request_id=uuid.uuid4(),expected_revision=2,nodes=[bad],edges=[],uncertainty=['Unreviewed']))

    async def test_owner_and_authentication_boundary(self):
        self.ownership.side_effect=HTTPException(404,'Owned engagement not found')
        with self.assertRaises(HTTPException):await self.create()
        response=await self.client.get('/api/team/engagement/research')
        self.assertEqual(response.status_code,401)
        self.assertEqual(len(self.events),3)

    async def test_invalid_nan_and_missing_controls_rejected(self):
        for changes in ({'confidence':float('nan')},{'positive_controls':[]},{'alternative_explanations':[]},{'negative_controls':[]}):
            with self.assertRaises(ValidationError):hypothesis(**changes)

    async def test_model_evidence_and_scope_must_be_revalidated_before_reopening(self):
        body = ApplicationModel(request_id=uuid.uuid4(), expected_revision=0,
            nodes=[ModelNode(id='asset', kind='asset', label='Lab asset', evidence_references=['e2'])],
            edges=[], uncertainty=['Synthetic ownership needs validation'])
        await self.store.save_model('engagement', 'owner', body)
        item = await self.advance(await self.create(), 'HYPOTHESIZED')
        self.events[1]['data']['hashes']['content_sha256'] = 'changed graph evidence'
        view = await self.store.view('engagement', 'owner')
        self.assertFalse(view['application_model_current'])
        self.assertFalse(view['queue'])
        with self.assertRaises(HTTPException): await self.advance(item, 'PLANNED')
        with self.assertRaises(HTTPException): await self.create()
        item = await self.advance(item, 'INCONCLUSIVE')
        with self.assertRaises(HTTPException): await self.advance(item, 'HYPOTHESIZED')
        await self.store.save_model('engagement', 'owner', body.model_copy(update={
            'request_id':uuid.uuid4(), 'expected_revision':1}))
        item = await self.advance(item, 'HYPOTHESIZED')
        self.session.scope = {'targets':['different.test']}
        self.assertFalse((await self.store.view('engagement', 'owner'))['application_model_current'])
        with self.assertRaises(HTTPException): await self.advance(item, 'PLANNED')

    async def test_planner_receives_ranked_evidence_controls_and_no_stale_graph(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        await self.create(information_value=.1, estimated_cost_microusd=1000000)
        preferred = await self.create(information_value=.9, estimated_cost_microusd=1)
        view = await self.store.view('engagement', 'owner')
        with patch('memory.research.research_store.view', AsyncMock(return_value=view)):
            context = await AutonomousEngine()._specialist_context(
                SessionRunState('engagement','owner','discovery','lab.test','expert'))
        self.assertEqual(context['research_queue'][0]['id'], preferred['id'])
        self.assertEqual(context['research_queue'][0]['supporting_evidence'], ['e1'])
        self.assertTrue(context['research_queue'][0]['negative_controls'])
        view.update(application_model={'nodes':[{'id':'stale'}]}, application_model_current=False)
        with patch('memory.research.research_store.view', AsyncMock(return_value=view)):
            context = await AutonomousEngine()._specialist_context(
                SessionRunState('engagement','owner','discovery','lab.test','expert'))
        self.assertFalse(context['application_model']['nodes'])

    async def test_cancelled_specialist_does_not_project_retained_results(self):
        ledger={'tasks':[{'id':'cancelled', 'state':'cancelled',
            'result':{'hypotheses':[{'description':'Discarded candidate', 'evidence_references':['e1']}],
                      'evidence_references':['e1']}, 'evidence_inputs':['e1']}]}
        with patch('memory.research.team_store.view',AsyncMock(return_value=ledger)), \
                patch.object(self.store,'create',AsyncMock()) as create:
            await self.store.sync_specialists('engagement','owner',['cancelled'])
        create.assert_not_awaited()

    async def test_specialist_context_omits_stale_research_and_marks_current_as_unverified(self):
        from agents.result_contract import AgentResult
        from orchestrator.team_coordinator import TeamCoordinator
        current = await self.create()
        stale = {**current, 'id': 'stale', 'scope_digest': digest({'targets': ['old.test']})}
        self.events.append({'collection': 'research_hypotheses', 'entity_id': 'stale',
            'sequence': len(self.events) + 1, 'id': str(uuid.uuid4()), 'data': stale})
        task = (await team_store.create('engagement', 'owner', CreateTask(
            request_id=uuid.uuid4(), task=TaskSpec(owner_role='correlation',
                objective='Review only current saved research', evidence_inputs=['e1'],
                expected_output='Evidence-linked uncertainty', completion_criteria=['State limitations']))))['data']
        specialist = SimpleNamespace(process=AsyncMock(return_value={'agent_result': AgentResult(
            interpreted_request=task['objective'], uncertainty=['No finding verified']).model_dump()}))
        coordinator = TeamCoordinator()
        with patch.object(coordinator, 'specialists', return_value={'correlation': specialist}):
            await coordinator.run('engagement', 'owner', task['id'], str(uuid.uuid4()), 'expert')
        context = specialist.process.await_args.args[2]['research_context']
        self.assertEqual([item['id'] for item in context['hypotheses']], [current['id']])
        self.assertEqual(context['omitted_stale_hypotheses'], 1)
        self.assertIn('untrusted research assertions', context['verification'])
