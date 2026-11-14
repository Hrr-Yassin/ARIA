"""Non-billable, owner-key authenticated OpenRouter tariff discovery.

Quotes are separate from spending approval. Only text endpoints advertising
structured outputs and no additional request charges are eligible.
"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import uuid

import httpx
from fastapi import HTTPException
from sqlalchemy import select

from memory.database_models import UserAPIKey

QUOTE_TTL = timedelta(hours=24)


def tariff_error(message: str) -> HTTPException:
    return HTTPException(409, {'code': 'model_tariff_invalid', 'message': message})


def price(value) -> Decimal:
    try:
        result = Decimal(str(value))
        if not result.is_finite() or result <= 0:
            raise ValueError
        return result
    except (InvalidOperation, ValueError):
        raise tariff_error('Provider returned missing or invalid token prices') from None


def select_quote(model: str, catalog: list, endpoints: dict) -> dict:
    matches = [item for item in catalog if item.get('id') == model]
    if len(matches) != 1 or endpoints.get('id') != model:
        raise tariff_error('Configured model is unavailable to this account')
    if not {'response_format', 'structured_outputs'} <= set(matches[0].get('supported_parameters', [])):
        raise tariff_error('Configured model does not advertise structured output support')
    eligible = []
    for endpoint in endpoints.get('endpoints', []):
        if endpoint.get('status') != 0 or not endpoint.get('tag'):
            continue
        if not {'response_format', 'structured_outputs', 'temperature', 'max_tokens'} <= set(endpoint.get('supported_parameters', [])):
            continue
        pricing = endpoint.get('pricing', {})
        try:
            incoming, outgoing = price(pricing.get('prompt')), price(pricing.get('completion'))
            # Cache reads cannot exceed the reserved input rate. Reject unknown
            # nonzero charges rather than silently excluding them from accounting.
            if any(Decimal(str(v)) != 0 for k, v in pricing.items()
                   if k not in {'prompt', 'completion', 'input_cache_read', 'discount'}):
                continue
            if Decimal(str(pricing.get('input_cache_read', 0))) > incoming:
                continue
        except (HTTPException, InvalidOperation, ValueError):
            continue
        eligible.append((incoming + outgoing, endpoint['tag'], incoming, outgoing))
    if not eligible:
        raise tariff_error('No priced structured-output endpoint is available')
    _, tag, incoming, outgoing = min(eligible)
    now = datetime.now(timezone.utc)
    return {'id': str(uuid.uuid4()), 'provider': 'openrouter', 'model': model,
            'endpoint': tag, 'input_usd_per_million': str(incoming * 1000000),
            'output_usd_per_million': str(outgoing * 1000000),
            'microusd_per_million': int((max(incoming, outgoing) * 10**12).to_integral_value(rounding=ROUND_CEILING)),
            'retrieved_at': now.isoformat(), 'expires_at': (now + QUOTE_TTL).isoformat(),
            'source': 'https://openrouter.ai/api/v1/models/' + model + '/endpoints',
            'authenticated': True, 'structured_outputs': True}


def checked_quote(metadata: dict, tariff) -> dict:
    quote = (metadata.get('model_tariffs') or {}).get(tariff.model)
    if not quote or quote.get('id') != tariff.quote_id or quote.get('provider') != tariff.provider or quote.get('model') != tariff.model:
        raise tariff_error('Refresh the authenticated tariff before approving this model')
    try:
        expiry = datetime.fromisoformat(quote['expires_at'])
        fresh = datetime.now(timezone.utc) < expiry <= datetime.now(timezone.utc) + QUOTE_TTL
    except (KeyError, ValueError, TypeError):
        fresh = False
    if not fresh:
        raise tariff_error('Tariff expired; refresh pricing and approve again')
    if tariff.microusd_per_million != quote['microusd_per_million']:
        raise tariff_error('Approved tariff must match the verified provider price')
    return quote


async def fetch_quote(db, owner: str, model: str) -> dict:
    from llm.pool_manager import pool_manager
    keys = (await db.execute(select(UserAPIKey).where(
        UserAPIKey.user_id == owner, UserAPIKey.provider == 'openrouter',
        UserAPIKey.is_active.is_(True)).order_by(UserAPIKey.created_at))).scalars().all()
    if not keys:
        raise tariff_error('Add an active OpenRouter key first')
    try:
        key = pool_manager.decrypt_key(keys[0].encrypted_key)
        async with httpx.AsyncClient(timeout=30, trust_env=False, follow_redirects=False) as client:
            async def get(path):
                response = await client.get('https://openrouter.ai/api/v1/' + path,
                                            headers={'Authorization': 'Bearer ' + key})
                response.raise_for_status()
                return response.json()['data']
            await get('key')  # Public catalogs alone do not prove authentication.
            catalog = await get('models/user')
            endpoints = await get('models/' + model + '/endpoints')
            return select_quote(model, catalog, endpoints)
    except HTTPException:
        raise
    except Exception:
        # Never propagate HTTP objects, headers, key metadata or provider bodies.
        raise tariff_error('OpenRouter authentication or pricing lookup failed; approval is blocked') from None
