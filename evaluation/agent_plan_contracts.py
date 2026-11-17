"""Controlled legacy planner entry-point contract reproduction; no model calls."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import asyncio
import hashlib
import json
from pathlib import Path
import socket
from unittest.mock import AsyncMock, patch

FIXTURE=Path('evaluation/fixtures/agent-plan-contracts-v1.json')
SOURCES=('agents/attack_planner_agent.py','agents/orchestrator_agent.py')


async def measure() -> dict:
    import tests  # Ephemeral offline configuration; no production credentials.
    from tests.test_access import OWNER
    from agents.attack_planner_agent import AttackPlannerAgent
    from agents.orchestrator_agent import OrchestratorAgent
    packet=json.loads(FIXTURE.read_text())
    rows=[]
    for case in packet['cases']:
        agent={'planner':AttackPlannerAgent,'orchestrator':OrchestratorAgent}[case['agent']]()
        with ExitStack() as stack:
            stack.enter_context(patch.object(socket.socket,'connect',side_effect=AssertionError('Offline fixture')))
            stack.enter_context(patch.object(socket,'getaddrinfo',side_effect=AssertionError('Offline fixture')))
            stack.enter_context(patch('api.auth.current_identity',AsyncMock(return_value=OWNER)))
            stack.enter_context(patch('api.session_access.get_accessible_session',AsyncMock(return_value={
                'user_id':'owner','target':'192.0.2.1','scope':{'targets':['192.0.2.1'],'ports':[80]}})))
            stack.enter_context(patch('memory.session_manager.session_manager.get_chat_logs',AsyncMock(return_value=[])))
            stack.enter_context(patch('memory.worker_jobs.worker_jobs.client.capabilities',AsyncMock(return_value={'tools':['curl','nmap']})))
            stack.enter_context(patch.object(agent,'get_context',return_value=''))
            stack.enter_context(patch.object(agent,'get_similar_cases',AsyncMock(return_value='')))
            stack.enter_context(patch.object(agent,'store_discovery'))
            stack.enter_context(patch('memory.playbook_store.playbook_store.get_best_playbook',AsyncMock(return_value=None)))
            stack.enter_context(patch('llm.pool_manager.pool_manager.query_for_task',AsyncMock(return_value={
                'success':True,'content':case['provider_content']})))
            public=await agent.process('contract-fixture','owner',{'target':'192.0.2.1',
                'goal_type':'discovery','original_objective':packet['objective'],
                'user_input':'Explain recorded HTTP headers'},'expert')
        actual={'status':public['agent_result']['status'],'commands':public.get('commands',[])}
        rows.append({**case,'actual':actual,'public_result':public,'passed':actual==case['expected'],
                     'sample_size':1,'method':'actual wrapped planner entry point with controlled provider response',
                     'confidence':'high for this contract reproduction; no model-quality inference'})
    return {'schema':'aria.plan-contract.measurement.v1','kind':packet['kind'],
            'created_at':datetime.now(timezone.utc).isoformat(),'requirement':packet['requirement'],
            'fixture':str(FIXTURE),'fixture_sha256':hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            'source_sha256':{p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in SOURCES},
            'rows':rows,'passed':sum(r['passed'] for r in rows),'assessed':len(rows),
            'model_calls':0,'target_actions':0,'independent_human_assessment':False,
            'limitations':packet['limitations']}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=asyncio.run(measure())
    with args.output.open('x') as handle:handle.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'passed':result['passed'],'assessed':result['assessed'],'model_calls':0,'output':str(args.output)}))


if __name__=='__main__':main()
