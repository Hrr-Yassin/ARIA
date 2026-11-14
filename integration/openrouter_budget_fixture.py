"""Disposable PostgreSQL browser fixture; never load in a real deployment."""
import asyncio
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy.engine import make_url

if os.environ.get('ARIA_BUDGET_FIXTURE') != '1' or not (make_url(os.environ['DATABASE_URL']).database or '').startswith('aria_budget_') or not make_url(os.environ['DATABASE_URL']).database.endswith('_test'):
    raise RuntimeError('Disposable budget fixture database required')

from fastapi import Depends, HTTPException
from api.auth import TokenData, get_current_user
from api.main import app
from config.settings import settings
from llm import provider_tariffs
from llm.engagement_budget import engagement_context, model_accounting
from memory.database_models import async_session
from memory.program_policy import owned_engagement

mode = 'ok'


async def fixture_quote(db, owner, model):
    await asyncio.sleep(.5)
    if mode == 'failure':
        raise provider_tariffs.tariff_error('Mock provider unavailable')
    params = ['response_format', 'structured_outputs', 'temperature', 'max_tokens']
    return provider_tariffs.select_quote(model, [{'id': model, 'supported_parameters': params}], {
        'id': model, 'endpoints': [{'tag': 'synthetic/fp8', 'status': 0,
        'supported_parameters': params, 'pricing': {'prompt': '0.00000009', 'completion': '0.00000018'}}]})


provider_tariffs.fetch_quote = fixture_quote


@app.post('/_fixture/{sid}/{action}')
async def control(sid: str, action: str, user: TokenData = Depends(get_current_user)):
    global mode
    async with async_session() as db:
        session = await owned_engagement(db, sid, user.user_id)
        if action in {'failure', 'ok'}:
            mode = action
        elif action in {'stale', 'missing'}:
            metadata = dict(session.metadata_ or {})
            quotes = dict(metadata.get('model_tariffs') or {})
            if action == 'stale':
                quotes[settings.OPENROUTER_MODEL] = {**quotes[settings.OPENROUTER_MODEL],
                    'expires_at': (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()}
            else:
                quotes = {}
            metadata['model_tariffs'] = quotes
            session.metadata_ = metadata
            await db.commit()
        elif action != 'call':
            raise HTTPException(400, 'Unknown fixture control')
    if action == 'call':
        token = engagement_context.set({'session_id': sid, 'owner': user.user_id})
        try:
            attempt = await model_accounting.reserve(user.user_id, 'openrouter', settings.OPENROUTER_MODEL, 'synthetic', '')
            await model_accounting.settle(attempt, {'success': True, 'tokens_used': 10, 'cost_microusd': 1})
            return {'settled': True}
        finally:
            engagement_context.reset(token)
    return {'action': action}
