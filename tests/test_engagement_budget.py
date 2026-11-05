"""Physical-call accounting, conservative reservations and unknown provider costs."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
from llm.base_llm import usage_metrics
from llm.engagement_budget import (
    ModelAccounting, ModelLimits, engagement_context, task_context, reservation_ceiling,
)
from llm.pool_manager import LLMPoolManager
from tests.support import OfflineCase


class EngagementBudgets(OfflineCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.accounting=ModelAccounting()
        self.session=SimpleNamespace(metadata_={})
        self.rows=[]
        self.db=SimpleNamespace(add=self.rows.append,commit=AsyncMock())
        cm=AsyncMock();cm.__aenter__.return_value=self.db
        self.cm=cm
        self.model_token=engagement_context.set({'session_id':'engagement','owner':'owner'})
        self.task_token=task_context.set(None)
        self.factory=patch('llm.engagement_budget.async_session',return_value=cm)
        self.owned=patch('llm.engagement_budget.owned_engagement',AsyncMock(return_value=self.session))
        self.factory.start();self.owned.start()

    async def asyncTearDown(self):
        self.factory.stop();self.owned.stop()
        task_context.reset(self.task_token);engagement_context.reset(self.model_token)
        await super().asyncTearDown()

    async def configure(self, **changes):
        await self.accounting.configure('engagement','owner',ModelLimits(
            tariffs=[{'provider':'groq','model':'test','microusd_per_million':1000000}],**changes))

    async def test_limits_default_deny_unpriced_and_missing_engagement(self):
        with self.assertRaises(HTTPException):
            await self.accounting.reserve('owner','groq','test','prompt','')
        engagement_context.set(None)
        with self.assertRaises(HTTPException):
            await self.accounting.reserve('owner','groq','test','prompt','')
        self.assertEqual(self.rows,[])

    async def test_reservations_survive_changed_limits_and_missing_usage(self):
        await self.configure(max_calls=1)
        attempt=await self.accounting.reserve('owner','groq','test','prompt','')
        self.assertEqual(self.session.metadata_['model_usage']['calls'],1)
        row=next(row for row in self.rows if row.id==attempt['id'])
        self.db.get=AsyncMock(return_value=row)
        self.db.execute=AsyncMock(return_value=SimpleNamespace(scalar_one=lambda:self.session))
        await self.accounting.settle(attempt,{'success':False})
        self.assertEqual(self.session.metadata_['model_usage']['unknown_cost_calls'],1)
        self.assertEqual(self.session.metadata_['model_usage']['unknown_usage_calls'],1)
        reserved=self.session.metadata_['model_usage']['reserved_tokens']
        await self.configure(max_calls=1)
        self.assertEqual(self.session.metadata_['model_usage']['reserved_tokens'],reserved)
        with self.assertRaises(HTTPException):
            await ModelAccounting().reserve('owner','groq','test','next','')
        await self.accounting.settle(attempt,{'success':False})
        self.assertEqual(self.session.metadata_['model_usage']['unknown_cost_calls'],1)

    async def test_token_cost_limits_and_overrun_stop(self):
        for limits in ({'max_tokens':1},{'max_cost_microusd':1}):
            self.session.metadata_={}
            await self.configure(**limits)
            with self.assertRaises(HTTPException):
                await self.accounting.reserve('owner','groq','test','x','')
        self.session.metadata_={}
        await self.configure()
        attempt=await self.accounting.reserve('owner','groq','test','x','')
        row=next(row for row in self.rows if row.id==attempt['id'])
        self.db.get=AsyncMock(return_value=row)
        self.db.execute=AsyncMock(return_value=SimpleNamespace(scalar_one=lambda:self.session))
        await self.accounting.settle(attempt,{'success':True,'tokens_used':attempt['reserved_tokens']+1})
        with self.assertRaises(HTTPException):
            await self.accounting.reserve('owner','groq','test','x','')

    async def test_storage_failure_prevents_physical_call_and_failover_counts(self):
        manager=LLMPoolManager()
        rows=[SimpleNamespace(id=str(i),provider='groq',encrypted_key=manager.encrypt_key('offline-provider-value'),is_active=True,
            requests_used=0,requests_limit=10,cooldown_until=None,last_error='',label='test') for i in range(2)]
        manager.load_user_keys('owner',rows)
        calls=[]
        async def physical(*args):
            calls.append('physical')
            return {'success':len(calls)==2,'content':'{}','tokens_used':10}
        client=SimpleNamespace(query=AsyncMock(side_effect=physical))
        async def reserve(*args):
            calls.append('reserved')
            return {'id':str(len(calls))}
        # Use a separate sequence for two actual attempts; the first fails.
        client.query.side_effect=[{'success':False,'error':'rate_limited'}, {'success':True,'content':'{}','tokens_used':10}]
        with patch.object(manager,'_reserve_key',AsyncMock(return_value=True)),patch.dict('llm.pool_manager.PROVIDER_CLIENTS',{'groq':MagicMock(return_value=client)}),patch('llm.engagement_budget.model_accounting.reserve',AsyncMock(side_effect=reserve)) as reservations,patch('llm.engagement_budget.model_accounting.settle',AsyncMock()) as settlement:
            result=await manager._query_for_task('owner','output_analysis','x')
        self.assertTrue(result['success'])
        self.assertEqual(client.query.await_count,2)
        self.assertEqual(reservations.await_count,2)
        self.assertEqual(settlement.await_count,2)
        manager.load_user_keys('owner',rows);client.query.reset_mock()
        with patch.object(manager,'_reserve_key',AsyncMock(return_value=True)),patch.dict('llm.pool_manager.PROVIDER_CLIENTS',{'groq':MagicMock(return_value=client)}),patch('llm.engagement_budget.model_accounting.reserve',AsyncMock(side_effect=RuntimeError('storage unavailable'))):
            with self.assertRaises(RuntimeError):
                await manager._query_for_task('owner','output_analysis','x')
        client.query.assert_not_awaited()

    async def test_provider_usage_preserves_unknown_and_rounds_reported_cost(self):
        self.assertEqual(usage_metrics({}),{'tokens_used':None,'cost_microusd':None})
        self.assertEqual(usage_metrics({'total_tokens':12,'cost':'0.0000011'}),{'tokens_used':12,'cost_microusd':2})
        self.assertIsNone(usage_metrics({'total_tokens':True,'cost':'NaN'})['tokens_used'])
        self.assertGreater(reservation_ceiling('🔬','',1000000)[0],4096)

    async def test_task_limits_and_cancelled_runs_deny_further_provider_calls(self):
        await self.configure()
        task_context.set({'id':'task-one','run_id':'run-one'})
        task={'id':'task-one','state':'running','run_id':'run-one',
              'budget':{'max_model_calls':0,'max_tokens':50000}}
        def events(*args):
            return [{'collection':'tasks','entity_id':'task-one','sequence':1,'data':task}]
        with patch('memory.team_tasks.team_store._events',AsyncMock(side_effect=events)):
            with self.assertRaises(HTTPException) as error:
                await self.accounting.reserve('owner','groq','test','x','')
            self.assertEqual(error.exception.status_code,429)
            task['budget']['max_model_calls']=10
            task['state']='cancelled'
            with self.assertRaises(HTTPException) as error:
                await self.accounting.reserve('owner','groq','test','x','')
            self.assertEqual(error.exception.status_code,409)
        self.assertNotIn('model_usage',self.session.metadata_)

    async def test_duplicate_tariffs_are_rejected_before_configuration(self):
        from pydantic import ValidationError
        tariff={'provider':'groq','model':'test','microusd_per_million':1000000}
        with self.assertRaises(ValidationError): ModelLimits(tariffs=[tariff,tariff])
