"""P5 real collaboration on authorized lab evidence (DeepSeek V4 Flash via OpenRouter).

Runs the production CollaborationCoordinator and specialists in-process against
the real engagement ledger. Both workflows analyse the same two real receipts:
httpx ``HTTP 200: Metasploitable2 - Linux`` (job ac5747a7) and nmap ``tcp/* filtered``
(job 339f5c74, taken while the lab VM was shut off). No tool is dispatched.

Stages (each run explicitly):
  ``analyse``  create the single-specialist plan and the collaborative plan, advance both
  ``review``   after the owner completes the analyses, advance the collaborative plan
  ``report``   summarise ledger state and model accounting
Run: ``python -m integration.p5_live_collaboration <stage>``.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time
import uuid
from pathlib import Path

SID = 'c5486358-599b-4c07-89f3-f590096a3c80'
EVIDENCE = {'httpx': '2e064b9d-d9e1-52d9-9668-d16ed80b09d3', 'nmap': '31347928-fa6d-5095-8481-767a228124af'}
OUT = Path('.local-lab/p5/collaboration')
OBJECTIVE = ('Interpret the retained authorized observations of the lab host 192.168.77.20. State what is supported, '
             'what is uncertain or contradictory, and what should be re-verified. Do not claim vulnerabilities.')


async def identity():
    from api.auth import authenticate_socket_token
    token = json.loads(Path('.local-lab/intelligence/auth.json').read_text())['token']
    return await authenticate_socket_token(token)


def plans():
    from orchestrator.collaboration import Delegation, DelegationPlan
    single = DelegationPlan(request_id=uuid.UUID('5a5a0000-0000-4000-8000-000000000031'), objective=OBJECTIVE,
        max_concurrency=1, delegations=[Delegation(key='single-vuln', role='vuln', objective=OBJECTIVE + ' Single specialist.',
            evidence_inputs=[EVIDENCE['httpx'], EVIDENCE['nmap']], completion_criteria=['Cite evidence', 'State uncertainty'])])
    collab = DelegationPlan(request_id=uuid.UUID('5a5a0000-0000-4000-8000-000000000032'), objective=OBJECTIVE,
        max_concurrency=1, delegations=[
            Delegation(key='analysis-web', role='web_intel', objective=OBJECTIVE + ' Interpret the HTTP receipt.',
                       evidence_inputs=[EVIDENCE['httpx']], completion_criteria=['Cite evidence', 'State uncertainty']),
            Delegation(key='analysis-ports', role='vuln', objective=OBJECTIVE + ' Interpret the TCP receipt.',
                       evidence_inputs=[EVIDENCE['nmap']], completion_criteria=['Cite evidence', 'State uncertainty']),
            Delegation(key='cross-review', role='correlation', prerequisites=['analysis-web', 'analysis-ports'],
                       objective=OBJECTIVE + ' Challenge both analyses against both receipts.',
                       evidence_inputs=[EVIDENCE['httpx'], EVIDENCE['nmap']],
                       completion_criteria=['Each claim supported, rejected or inconclusive with evidence'])])
    return single, collab


async def accounting(owner):
    from llm.engagement_budget import model_accounting
    status = await model_accounting.status(SID, owner)
    return status['usage'], status['attempts']


async def stage(name: str) -> dict:
    from llm.pool_manager import openrouter_only
    from memory.database_models import engine
    from orchestrator.collaboration import CollaborationCoordinator
    openrouter_only.set(True)
    ident = await identity()
    owner = ident.user_id
    coordinator = CollaborationCoordinator()
    OUT.mkdir(parents=True, exist_ok=True)
    usage_before, attempts_before = await accounting(owner)
    seen = {a['id'] for a in attempts_before}
    record: dict = {'stage': name, 'usage_before': usage_before}
    started = time.perf_counter()
    try:
        single_body, collab_body = plans()
        if name == 'analyse':
            single = await coordinator.create_plan(SID, owner, single_body)
            collab = await coordinator.create_plan(SID, owner, collab_body)
            t = time.perf_counter()
            record['single'] = await coordinator.advance(SID, owner, single['id'], skill='expert')
            record['single_seconds'] = round(time.perf_counter() - t, 2)
            t = time.perf_counter()
            record['collaborative'] = await coordinator.advance(SID, owner, collab['id'], skill='expert')
            record['collaborative_seconds'] = round(time.perf_counter() - t, 2)
        elif name == 'review':
            from memory.team_tasks import team_store
            plan_id = next(p['id'] for p in (await team_store.view(SID, owner))['orchestration_plans']
                           if p['objective'] == OBJECTIVE and 'cross-review' in p['task_ids'])
            t = time.perf_counter()
            record['collaborative'] = await coordinator.advance(SID, owner, plan_id, skill='expert')
            record['collaborative_seconds'] = round(time.perf_counter() - t, 2)
    finally:
        usage_after, attempts_after = await accounting(owner)
        record['usage_after'] = usage_after
        record['attempts'] = [{k: a.get(k) for k in ('id', 'state', 'model', 'reserved_tokens', 'reported_tokens',
                                                    'reserved_cost_microusd', 'reported_cost_microusd', 'task_id')}
                              | {'latency_ms': (a.get('timings') or {}).get('provider_ms') or a.get('latency_ms'),
                                 'provider': (a.get('provider_usage') or {}).get('provider')}
                              for a in attempts_after if a['id'] not in seen]
        record['wall_seconds'] = round(time.perf_counter() - started, 2)
        await engine.dispose()
    (OUT / f'{name}.json').write_text(json.dumps(record, indent=1, default=str))
    return record


async def report() -> dict:
    from memory.database_models import engine
    from memory.team_tasks import team_store
    ident = await identity()
    view = await team_store.view(SID, ident.user_id)
    tasks = {t['id']: t for t in view['tasks']}
    out = {}
    for plan in view['orchestration_plans']:
        if plan['objective'] != OBJECTIVE:
            continue
        out[plan['id']] = {'status': plan['status'], 'supervision': plan.get('supervision'), 'tasks': {
            key: {'state': tasks.get(tid, {}).get('state'), 'role': tasks.get(tid, {}).get('owner_role'),
                  'hypotheses': [(h.get('description'), h.get('evidence_references'), h.get('disposition'))
                                 for h in ((tasks.get(tid) or {}).get('result') or {}).get('hypotheses', [])],
                  'uncertainty': ((tasks.get(tid) or {}).get('result') or {}).get('uncertainty'),
                  'rejections': ((tasks.get(tid) or {}).get('result') or {}).get('rejections')}
            for key, tid in plan['task_ids'].items()}}
    await engine.dispose()
    (OUT / 'report.json').write_text(json.dumps(out, indent=1, default=str))
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('stage', choices=['analyse', 'review', 'report'])
    args = parser.parse_args()
    result = asyncio.run(report() if args.stage == 'report' else stage(args.stage))
    print(json.dumps(result, indent=1, default=str)[:12000])
