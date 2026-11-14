"""One-at-a-time paid acceptance through normal owner-bound pool accounting.

Requires an existing human approval in ARIA. Never configures budgets, changes
models, refunds reservations or dispatches target tools. Stops on unknown usage.
"""
import argparse
import asyncio
from decimal import Decimal, ROUND_CEILING
import json
from pathlib import Path

import httpx
from sqlalchemy import select

from api.auth import authenticate_socket_token
from config.settings import settings
from llm.base_llm import response_schema
from llm.engagement_budget import engagement_context, model_accounting
from llm.pool_manager import pool_manager
from memory.database_models import async_session, engine, PentestSession, UserAPIKey

SID = '1f2e2cd2-c37d-4c00-a1ba-5134705f89dd'
OUT = Path('.local-lab/openrouter-paid')


def verify_receipt(attempt: dict, *, require_success: bool = True) -> dict:
    """Reconcile the provider's actual response usage with durable SQL billing."""
    usage = attempt.get('provider_usage') or {}
    assert attempt['state'] in {'succeeded', 'failed'}
    if require_success:
        assert attempt['state'] == 'succeeded'
    assert usage.get('model') == 'deepseek/deepseek-v4-flash'
    assert usage.get('id') and usage.get('provider')
    for field in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
        assert type(usage.get(field)) is int and usage[field] >= 0
    assert usage['total_tokens'] == usage['prompt_tokens'] + usage['completion_tokens']
    incoming = Decimal(usage['upstream_inference_prompt_cost'])
    outgoing = Decimal(usage['upstream_inference_completions_cost'])
    cost = Decimal(usage['cost'])
    assert all(value.is_finite() and value >= 0 for value in (incoming, outgoing, cost))
    assert incoming + outgoing == cost == Decimal(usage['upstream_inference_cost'])
    quote = attempt['tariff']
    assert incoming <= Decimal(quote['input_usd_per_million']) * usage['prompt_tokens'] / 1000000
    assert outgoing <= Decimal(quote['output_usd_per_million']) * usage['completion_tokens'] / 1000000
    assert attempt['reported_tokens'] == usage['total_tokens'] <= attempt['reserved_tokens']
    assert attempt['reported_cost_microusd'] == int((cost * 1000000).to_integral_value(rounding=ROUND_CEILING))
    assert attempt['reported_cost_microusd'] <= attempt['reserved_cost_microusd']
    return {'input_usd':str(incoming), 'output_usd':str(outgoing), 'total_usd':str(cost),
            'input_tokens':usage['prompt_tokens'], 'output_tokens':usage['completion_tokens'],
            'basis':'OpenRouter response usage receipt reconciled with SQL settlement'}


async def generation_receipt(owner: str, request_id: str) -> dict:
    async with async_session() as db:
        row = (await db.execute(select(UserAPIKey).where(UserAPIKey.user_id == owner,
            UserAPIKey.provider == 'openrouter', UserAPIKey.is_active.is_(True)))).scalars().first()
        key = pool_manager.decrypt_key(row.encrypted_key)
    async with httpx.AsyncClient(trust_env=False, timeout=30) as client:
        for _ in range(5):
            response = await client.get('https://openrouter.ai/api/v1/generation',
                params={'id':request_id}, headers={'Authorization':'Bearer '+key})
            if response.is_success:
                data = response.json()['data']
                return {k:data.get(k) for k in ('id','model','provider_name','total_cost',
                    'upstream_inference_cost','tokens_prompt','tokens_completion',
                    'native_tokens_prompt','native_tokens_completion','native_tokens_reasoning',
                    'cache_discount','latency','generation_time')}
            if response.status_code != 404:
                raise RuntimeError('Provider generation receipt unavailable')
            await asyncio.sleep(1)
    raise RuntimeError('Provider generation receipt not available within verification deadline')


async def run(stage: str):
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / (stage + '.json')
    if path.exists():
        raise RuntimeError('Stage already attempted; inspect its receipt before any further inference')
    token = json.loads(Path('.local-lab/intelligence/auth.json').read_text())['token']
    identity = await authenticate_socket_token(token)
    before = await model_accounting.status(SID, identity.user_id)
    assert before['approved_at'], 'Owner approval is required'
    assert before['limits']['max_cost_microusd'] <= 2000000, 'Mission ceiling must not exceed $2'
    assert before['limits']['max_cost_microusd'] > 0
    assert not before['usage'].get('stopped'), 'Accounting stopped; no further inference allowed'
    assert settings.LLM_ROUTING == 'cloud' and settings.OPENROUTER_MODEL == 'deepseek/deepseek-v4-flash'
    assert len(before['limits']['tariffs']) == 1 and before['limits']['tariffs'][0]['model'] == settings.OPENROUTER_MODEL
    for previous in before['attempts']:
        verify_receipt(previous, require_success=False)  # Failed output can still have a reconciled bill.
    await pool_manager.refresh_user_keys(identity.user_id)
    preflight = await pool_manager.planner_preflight(identity.user_id, SID)
    assert preflight['ready'] and preflight['provider'] == 'openrouter', preflight
    report = {'stage':stage, 'session_id':SID, 'before_usage':before['usage'], 'status':'started'}
    path.write_text(json.dumps(report, indent=2))
    context = engagement_context.set({'session_id':SID, 'owner':identity.user_id})
    try:
        if stage == 'exhaustion':
            from fastapi import HTTPException
            try:
                await model_accounting.reserve(identity.user_id, 'openrouter', settings.OPENROUTER_MODEL,
                    'x' * (before['limits']['max_tokens'] + 1), '', check_only=True)
            except HTTPException as exc:
                assert exc.status_code == 429 and exc.detail['code'] == 'model_budget_exhausted'
            else:
                raise AssertionError('Oversized request was admitted')
            after = await model_accounting.status(SID, identity.user_id)
            assert before['usage'] == after['usage'] and before['attempts'] == after['attempts']
            report.update(status='passed', physical_calls=0, ledger_unchanged=True,
                basis='Real token ceiling rejected in read-only preflight; monetary ceiling covered in disposable PostgreSQL tests')
            return
        if stage == 'smoke':
            schema = response_schema.set({'type':'object','properties':{'ready':{'type':'boolean'}},
                'required':['ready'],'additionalProperties':False})
            try:
                result = await pool_manager.query_for_task(identity.user_id, 'attack_planning',
                    'Return exactly {"ready":true}. This is an authorized accounting acceptance test.',
                    'Return only the requested JSON object.')
            finally: response_schema.reset(schema)
            report['result'] = {k:v for k,v in result.items() if k != 'key_label'}
            if result.get('success'):
                assert json.loads(result['content']) == {'ready':True}
        else:
            from agents.orchestrator_agent import OrchestratorAgent
            from security_tools.adapters import ADAPTERS, decode, validate
            async with async_session() as db:
                session = await db.get(PentestSession, SID)
                scope = session.scope
                target = session.target
            planner = OrchestratorAgent()
            result = await planner._bounded_assessment_plan(identity.user_id, {
                'original_objective':'Determine which of the explicitly scoped TCP ports are open. Generate a plan only; do not execute.',
                'target':target, 'goal':'port_discovery', 'engagement_scope':scope,
                'scope_ports':scope.get('ports', []), 'worker_capabilities':{
                    'typed_adapters':{ADAPTERS[name].capability:1 for name in ('nmap','httpx')}},
                'completed_observations':[], 'completion_criteria':'port_discovery',
                'validation_feedback':[]}, 'expert', session_id=SID)
            report['result'] = result
            assert result.get('commands'), 'Structured planner returned no admissible commands'
            command = result['commands'][0]['command']
            adapter, _ = decode(command)
            validate(command, scope)
            assert adapter.name == 'nmap'
        after = await model_accounting.status(SID, identity.user_id)
        report['after_usage'] = after['usage']
        new_attempts = [a for a in after['attempts'] if a['id'] not in {a['id'] for a in before['attempts']}]
        report['attempts'] = new_attempts
        assert len(new_attempts) == 1, 'Only one physical call is allowed per acceptance stage'
        attempt = new_attempts[0]
        receipt = attempt.get('provider_usage') or {}
        assert attempt['state'] == 'succeeded', 'Provider call failed; inspect usage before continuing'
        assert not after['usage'].get('stopped'), 'Accounting is not reconciled; stop immediately'
        assert receipt.get('total_tokens') == receipt.get('prompt_tokens', -1) + receipt.get('completion_tokens', -1)
        assert receipt.get('id') and receipt.get('cost') is not None
        report['verified_accounting'] = verify_receipt(attempt)
        try:
            generation = await generation_receipt(identity.user_id, receipt['id'])
        except RuntimeError as exc:
            # Response usage is OpenRouter's documented primary accounting
            # source. A missing optional historical record is disclosed, not
            # substituted with a fabricated receipt or a second inference.
            report['generation_lookup'] = str(exc)
        else:
            report['generation'] = generation
            assert Decimal(str(generation['total_cost'])) == Decimal(receipt['cost']), 'Provider costs disagree'
            assert generation['model'] == settings.OPENROUTER_MODEL
        report['status'] = 'passed'
    except Exception as exc:
        report['status'] = 'failed'
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:300]
        # Read the ledger even when parsing or accounting verification fails.
        after = await model_accounting.status(SID, identity.user_id)
        report['after_usage'] = after['usage']
        report['attempts'] = [a for a in after['attempts'] if a['id'] not in {a['id'] for a in before['attempts']}]
        raise
    finally:
        engagement_context.reset(context)
        path.write_text(json.dumps(report, indent=2))
        await engine.dispose()
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=['smoke','planner','exhaustion'])
    asyncio.run(run(parser.parse_args().stage))
