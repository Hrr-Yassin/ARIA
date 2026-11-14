"""Tariff discovery rejects ambiguous, stale and fabricated pricing offline."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException
from llm.provider_tariffs import select_quote, checked_quote, fetch_quote
from tests.support import OfflineCase


def fixture_quote():
    model = 'deepseek/deepseek-v4-flash'
    catalog = [{'id': model, 'supported_parameters': ['response_format', 'structured_outputs']}]
    endpoints = {'id': model, 'endpoints': [{'tag': 'fixture/fp8', 'status': 0,
        'supported_parameters': ['response_format', 'structured_outputs', 'temperature', 'max_tokens'],
        'pricing': {'prompt': '0.0000000147', 'completion': '0.0000000294'}}]}
    return model, catalog, endpoints


class ProviderTariffs(OfflineCase):
    async def test_exact_decimal_prices_and_expiry(self):
        quote = select_quote(*fixture_quote())
        tariff = SimpleNamespace(model=quote['model'], provider='openrouter',
                                 quote_id=quote['id'], microusd_per_million=29400)
        metadata = {'model_tariffs': {tariff.model: quote}}
        self.assertEqual(checked_quote(metadata, tariff)['input_usd_per_million'], '0.0147000000')
        for field, value in [('expires_at', (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()),
                             ('expires_at', 'invalid'), ('id', 'forged'), ('model', 'another')]:
            old = quote[field]; quote[field] = value
            with self.assertRaises(HTTPException): checked_quote(metadata, tariff)
            quote[field] = old
        tariff.microusd_per_million = 1
        with self.assertRaises(HTTPException): checked_quote(metadata, tariff)

    async def test_invalid_catalog_endpoints_and_prices_deny(self):
        for value in [None, '0', '-1', 'NaN', 'Infinity', 'invalid']:
            model, catalog, endpoints = fixture_quote()
            endpoints['endpoints'][0]['pricing']['completion'] = value
            with self.assertRaises(HTTPException): select_quote(model, catalog, endpoints)
        model, catalog, endpoints = fixture_quote()
        with self.assertRaises(HTTPException): select_quote(model, [], endpoints)
        endpoints['endpoints'][0]['supported_parameters'].remove('structured_outputs')
        with self.assertRaises(HTTPException): select_quote(model, catalog, endpoints)
        model, catalog, endpoints = fixture_quote()
        endpoints['endpoints'][0]['pricing']['request'] = '0.001'
        with self.assertRaises(HTTPException): select_quote(model, catalog, endpoints)

    async def test_authentication_failure_is_sanitized_and_never_infers(self):
        db = SimpleNamespace(execute=AsyncMock(return_value=SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: [SimpleNamespace(encrypted_key='cipher')]))))
        client = AsyncMock(); client.get.side_effect = RuntimeError('secret sentinel')
        cm = AsyncMock(); cm.__aenter__.return_value = client
        with patch('llm.pool_manager.pool_manager.decrypt_key', return_value='secret sentinel'), patch('llm.provider_tariffs.httpx.AsyncClient', return_value=cm):
            with self.assertRaises(HTTPException) as error: await fetch_quote(db, 'owner', 'test')
        self.assertNotIn('secret sentinel', str(error.exception))
        client.post.assert_not_awaited()
