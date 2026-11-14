"""Equivalent bounded Qwen/DeepSeek triage with independent laboratory controls.

Identical six-case batches, schemas, observations and 2048 output tokens per arm.
A named run preserves old failures. No automatic retries or worker execution.
"""
import argparse
import asyncio
from decimal import Decimal
import json
from pathlib import Path
import re
import time
from typing import Literal

from pydantic import Field, create_model
from evaluation.research_lab import cases, observe, benchmark
from memory.team_tasks import Strict, digest

OUT = Path('.local-lab/research-benchmark')
SYSTEM = ('Triage synthetic security observations. Alice owns private objects and has the privileged role; '
    'Bob is an unprivileged outsider in another tenant. Revoked sessions must be denied. '
    'Integer parameters must reject expressions. Quantities must be nonnegative; purchases require '
    'a quoted state and charge price 10 per item. Select only plausible violations with the matching '
    'verification template and a brief alternative explanation. Generic HTTP success without private '
    'content does not prove exposure. An independent verifier reproduces candidates with fresh controls. '
    'Return compact JSON. No commands or target requests.')
TEMPLATES = {
    'identity_control': 'Owner read, outsider read, nonexistent-object negative control',
    'integer_control': 'Invalid-integer request, owner read, nonexistent-object control',
    'workflow_control': 'Quoted purchase, zero-quantity control, disputed state/quantity transition',
}


async def main(arm: str, run_id: str = 'batched-v2') -> None:
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,60}', run_id):
        raise ValueError('Invalid run identity')
    folder = OUT / run_id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (arm + '.json')
    if path.exists():
        raise RuntimeError('Arm already attempted; inspect retained results before a named new run')
    rows = cases()
    observation_path = folder / 'observations.json'
    if observation_path.exists():
        observations = json.loads(observation_path.read_text())
    else:
        observations = {c['id']: await observe(c) for c in rows}
        observation_path.write_text(json.dumps(observations, indent=2))
    contexts = [{'case_id':c['id'], 'class':c['class'], 'observations':[
        {k:r[k] for k in ('method','path','identity','status','body','request_body') if k in r}
        for r in observations[c['id']]['evidence']]} for c in rows]
    report = {'arm':arm, 'run_id':run_id, 'scenario_digest':digest(contexts),
        'output_cap':2048, 'batch_size':6, 'status':'started', 'model_calls':0,
        'batches':[], 'candidates':[], 'tokens':0, 'unknown_usage_calls':0, 'cost_usd':'0'}
    from llm.base_llm import response_schema, response_output_limit
    from config.settings import settings
    context_token = None
    limit_token = response_output_limit.set(2048)
    started = time.monotonic()
    try:
        if arm == 'qwen':
            from llm.local_client import LocalClient
            client = LocalClient(model='qwen3:4b-instruct', temperature=.1)
            assert await client.available(), 'Exact historical Qwen baseline unavailable'
            report['model'] = client.model
        else:
            from api.auth import authenticate_socket_token
            from llm.engagement_budget import engagement_context, model_accounting
            from llm.pool_manager import pool_manager
            from integration.openrouter_paid_acceptance import SID, verify_receipt
            identity = await authenticate_socket_token(json.loads(Path('.local-lab/intelligence/auth.json').read_text())['token'])
            ledger = await model_accounting.status(SID, identity.user_id)
            assert ledger['approved_at'] and 0 < ledger['limits']['max_cost_microusd'] <= 2000000
            assert not ledger['usage'].get('stopped')
            for attempt in ledger['attempts']:
                verify_receipt(attempt, require_success=False)
            assert settings.LLM_ROUTING == 'cloud' and settings.OPENROUTER_MODEL == 'deepseek/deepseek-v4-flash'
            assert settings.OPENROUTER_MAX_OUTPUT_TOKENS >= 2048
            context_token = engagement_context.set({'session_id':SID, 'owner':identity.user_id})
            await pool_manager.refresh_user_keys(identity.user_id)
            report['model'] = settings.OPENROUTER_MODEL
        for offset in range(0, len(rows), 6):
            batch = contexts[offset:offset+6]
            CaseID = Literal[tuple(c['case_id'] for c in batch)]
            Selection = create_model('ResearchSelection', __base__=Strict,
                case_id=(CaseID,...), template=(Literal['identity_control','workflow_control','integer_control'],...),
                alternative=(str, Field(min_length=1,max_length=60)))
            Decision = create_model('ResearchDecisions', __base__=Strict,
                candidates=(list[Selection], Field(max_length=6)))
            schema = Decision.model_json_schema()
            token = response_schema.set(schema)
            record = {'offset':offset, 'schema_digest':digest(schema), 'status':'started'}
            report['batches'].append(record)
            path.write_text(json.dumps(report, indent=2))
            tick = time.monotonic()
            try:
                prompt = json.dumps({'scenarios':batch, 'available_templates':TEMPLATES},separators=(',',':'))
                if arm == 'qwen':
                    result = await client.query(prompt, SYSTEM)
                    report['model_calls'] += 1
                else:
                    before_ids = {a['id'] for a in ledger['attempts']}
                    result = await pool_manager.query_for_task(identity.user_id, 'attack_planning', prompt, SYSTEM)
                    ledger = await model_accounting.status(SID, identity.user_id)
                    attempts = [a for a in ledger['attempts'] if a['id'] not in before_ids]
                    report['model_calls'] += len(attempts)
                    record['attempts'] = attempts  # Sanitized accounting fields, including failure receipts.
                    report['mission_usage'] = ledger['usage']
                    assert len(attempts) == 1, 'Expected exactly one physical call'
                    receipt = verify_receipt(attempts[0], require_success=False)
                    report['cost_usd'] = str(Decimal(report['cost_usd']) + Decimal(receipt['total_usd']))
                    assert not ledger['usage'].get('stopped'), 'Unreconciled ledger; stop'
                record.update(seconds=round(time.monotonic()-tick,3), tokens=result.get('tokens_used'))
                if result.get('tokens_used') is None:
                    report['unknown_usage_calls'] += 1
                else:
                    report['tokens'] += result['tokens_used']
                if not result.get('success'):
                    raise RuntimeError(result.get('error', 'Model unavailable'))
                parsed = Decision.model_validate_json(result['content'])
                selections = [s.model_dump() for s in parsed.candidates]
                assert len({s['case_id'] for s in selections}) == len(selections), 'Duplicate scenario'
                report['candidates'].extend(selections)
                record['status'] = 'passed'
            except Exception as exc:
                record.update(status='failed', error=str(exc)[:300], seconds=round(time.monotonic()-tick,3))
                raise
            finally:
                response_schema.reset(token)
                path.write_text(json.dumps(report, indent=2))
        report.update(await benchmark(report['candidates'], observations))
        metrics = report['metrics']
        confirmed = metrics['confirmed_vulnerabilities']
        metrics.update(model_tokens=report['tokens'], cost_usd=report['cost_usd'],
            tokens_per_confirmed=report['tokens']/confirmed if confirmed else None,
            cost_per_confirmed_usd=str(Decimal(report['cost_usd'])/confirmed) if confirmed else None,
            hypothesis_alternative_nonempty_rate=sum(bool(c['alternative'].strip()) for c in report['candidates'])/len(report['candidates']) if report['candidates'] else 0,
            failed_model_calls=0, automatic_model_retries=0)
        report['status'] = 'passed'
    except Exception as exc:
        report.update(status='failed', error_type=type(exc).__name__, error=str(exc)[:300])
        raise
    finally:
        report['model_seconds'] = round(time.monotonic()-started,3)
        response_output_limit.reset(limit_token)
        if context_token is not None:
            engagement_context.reset(context_token)
        if arm == 'deepseek':
            from memory.database_models import engine
            await engine.dispose()
        path.write_text(json.dumps(report, indent=2))
        print(json.dumps({k:v for k,v in report.items() if k not in {'cases','candidates','batches'}}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('arm', choices=['qwen','deepseek'])
    parser.add_argument('--run-id', default='batched-v2')
    args = parser.parse_args()
    asyncio.run(main(args.arm, args.run_id))
