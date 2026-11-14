"""Hosted transport must send real schemas and preserve unknown usage."""
from unittest.mock import AsyncMock, patch
from types import SimpleNamespace
from llm.base_llm import response_schema
from llm.openrouter_client import OpenRouterClient, provider_receipt
from tests.support import OfflineCase


class OpenRouterTransport(OfflineCase):
    async def test_schema_output_cap_and_usage(self):
        schema={'type':'object','properties':{'answer':{'type':'string'}},'required':['answer'],'additionalProperties':False}
        response=SimpleNamespace(status_code=200,raise_for_status=lambda:None,
            json=lambda:{'model':'deepseek/deepseek-v4-flash','choices':[{'finish_reason':'stop','message':{'content':'{"answer":"ok"}'}}],
                         'usage':{'total_tokens':18,'cost':0.000003}})
        client=AsyncMock();client.post.return_value=response
        cm=AsyncMock();cm.__aenter__.return_value=client
        token=response_schema.set(schema)
        try:
            with patch('llm.openrouter_client.httpx.AsyncClient',return_value=cm):
                hosted=OpenRouterClient(api_key='offline')
                hosted.tariff={'endpoint':'fixture/fp8','input_usd_per_million':'0.09','output_usd_per_million':'0.18'}
                result=await hosted.query('question')
        finally:
            response_schema.reset(token)
        payload=client.post.call_args.kwargs['json']
        self.assertEqual(payload['response_format']['json_schema']['schema'],schema)
        self.assertLessEqual(payload['max_tokens'],4096)
        self.assertFalse(payload['provider']['allow_fallbacks'])
        self.assertEqual(payload['provider']['only'],['fixture/fp8'])
        self.assertEqual(payload['provider']['max_price'],{'prompt':0.09,'completion':0.18})
        self.assertTrue(result['success'])
        self.assertEqual(result['tokens_used'],18)
        self.assertEqual(result['cost_microusd'],3)

    async def test_receipt_preserves_exact_costs_and_filters_unrelated_data(self):
        data={'id':'generation-fixture','model':'deepseek/deepseek-v4-flash','provider':'Fixture',
              'secret':'must not persist','usage':{'prompt_tokens':216,'completion_tokens':75,'total_tokens':291,
              'cost':'0.0000053802','cost_details':{'upstream_inference_cost':'0.0000053802',
              'upstream_inference_prompt_cost':'0.0000031752','upstream_inference_completions_cost':'0.000002205'}}}
        receipt=provider_receipt(data)
        self.assertEqual(receipt['cost'],'0.0000053802')
        self.assertNotIn('secret',receipt)
        from integration.openrouter_paid_acceptance import verify_receipt
        attempt={'state':'succeeded','provider_usage':receipt,'reported_tokens':291,
            'reported_cost_microusd':6,'reserved_tokens':9000,'reserved_cost_microusd':300,
            'tariff':{'input_usd_per_million':'0.0147','output_usd_per_million':'0.0294'}}
        self.assertEqual(verify_receipt(attempt)['total_usd'],'0.0000053802')
        for field,value in [('cost','NaN'),('total_tokens',292),('upstream_inference_prompt_cost','0')]:
            original=receipt[field];receipt[field]=value
            with self.assertRaises(AssertionError):verify_receipt(attempt)
            receipt[field]=original

    async def test_truncated_response_retains_usage_for_settlement(self):
        response=SimpleNamespace(status_code=200,raise_for_status=lambda:None,
            json=lambda:{'model':'deepseek/deepseek-v4-flash','id':'fixture',
                'choices':[{'finish_reason':'length','message':{'content':'{'}}],
                'usage':{'prompt_tokens':2,'completion_tokens':3,'total_tokens':5,'cost':'0.000001'}})
        client=AsyncMock();client.post.return_value=response
        cm=AsyncMock();cm.__aenter__.return_value=client
        with patch('llm.openrouter_client.httpx.AsyncClient',return_value=cm):
            result=await OpenRouterClient(api_key='offline').query('question')
        self.assertFalse(result['success'])
        self.assertEqual(result['tokens_used'],5)
        self.assertEqual(result['provider_usage']['id'],'fixture')
        self.assertEqual(result['provider_usage']['finish_reason'],'length')
        self.assertEqual(result['error'],'model_output_truncated')

    async def test_failed_output_can_have_an_independently_reconciled_bill(self):
        from integration.openrouter_paid_acceptance import verify_receipt
        attempt={'state':'failed', 'provider_usage':{
            'id':'fixture', 'model':'deepseek/deepseek-v4-flash', 'provider':'Fixture',
            'prompt_tokens':1, 'completion_tokens':1, 'total_tokens':2,
            'cost':'0.0000002', 'upstream_inference_cost':'0.0000002',
            'upstream_inference_prompt_cost':'0.0000001', 'upstream_inference_completions_cost':'0.0000001'},
            'reported_tokens':2, 'reserved_tokens':9000, 'reported_cost_microusd':1,
            'reserved_cost_microusd':1000,
            'tariff':{'input_usd_per_million':'0.1', 'output_usd_per_million':'0.1'}}
        with self.assertRaises(AssertionError): verify_receipt(attempt)
        self.assertEqual(verify_receipt(attempt, require_success=False)['total_usd'],'2E-7')
        attempt['reported_cost_microusd']=0
        with self.assertRaises(AssertionError): verify_receipt(attempt, require_success=False)
