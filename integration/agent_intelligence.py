"""Actual existing-agent local inference with unchanged owned-session accounting.

Only supplied synthetic evidence and process-local memory are used. Shared
ownership/budget gates remain real;worker dispatch/proposals and nonloopback
network are forbidden. Never retries a case or replaces an unknown outcome.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import time
from urllib.parse import urlsplit
from unittest.mock import AsyncMock, patch

from evaluation.agent_intelligence import TARGET, digest

ROOT=Path(__file__).resolve().parents[1]


def public_content(content: str) -> dict | None:
    """Retain public JSON fields;never expose provider-private reasoning fields."""
    try:
        value=json.loads(content)
    except (TypeError,ValueError):return None
    private={'react_trace','reasoning_chain','chain_of_thought','reasoning','thought','thinking'}
    def project(item):
        if isinstance(item,dict):return {k:project(v) for k,v in item.items() if k not in private}
        if isinstance(item,list):return [project(v) for v in item]
        return item
    return project(value) if isinstance(value,dict) else None


async def main(args) -> int:
    from config.settings import settings
    from sqlalchemy.engine import make_url
    from memory.database_models import PentestSession,async_session,engine
    from llm.engagement_budget import model_accounting
    from llm.pool_manager import pool_manager
    from llm.base_llm import response_output_limit,response_schema,output_limit
    from llm.local_client import LocalClient
    from llm.validation_budget import ValidationBudget,current_budget
    from agents.recon_agent import recon_agent
    from agents.scan_agent import scan_agent
    from agents.vuln_agent import vuln_agent
    from agents.attack_planner_agent import attack_planner_agent
    from agents.orchestrator_agent import orchestrator_agent
    from agents.correlation_agent import correlation_agent
    from agents.coordinator_agent import coordinator_agent
    from agents.web_intel_agent import web_intel_agent
    from memory.vector_store import vector_store
    from memory.knowledge_cache import knowledge_cache
    from memory.attack_knowledge_base import attack_kb

    assert settings.LLM_ROUTING=='local' and settings.LOCAL_LLM_MODEL in {'qwen3:4b-instruct','qwen3.5:0.8b'}
    assert urlsplit(settings.LOCAL_LLM_URL).hostname in {'127.0.0.1','localhost','::1'}
    assert not args.output.exists(),'Never repeat/overwrite a previous attempted cohort'
    args.output.mkdir(mode=0o700,parents=True)
    plan=json.loads(args.protocol.read_text());admission=json.loads(args.admission.read_text())
    selected=([next(case for case in plan['cases'] if case['case_id']==name) for name in args.case]
              if args.case else list(plan['cases']))
    assert selected and (not args.case or {case['case_id'] for case in selected}==set(args.case))
    prior=json.loads(args.handoff_run.read_text()) if args.handoff_run else None
    if prior is not None:
        assert prior['protocol_sha256']==digest(plan) and prior['model']==settings.LOCAL_LLM_MODEL
        assert not ({c['case_id'] for c in selected} & {c['case_id'] for c in prior['cases']}), \
            'Retain attempted cases;only new cases may continue this lineage'
    sid,owner=admission['session_id'],admission['owner_id']
    async with async_session() as db:
        row=await db.get(PentestSession,sid)
        assert row is not None and row.user_id==owner and TARGET in row.scope.get('targets',[])
        scope=dict(row.scope)
    before=await model_accounting.status(sid,owner)
    assert before['approved_at'] and not before['usage'].get('stopped')
    assert before['limits']['max_calls']==20 and before['limits']['max_tokens']==200000
    assert before['limits']['max_cost_microusd']==1000000
    assert (await pool_manager.planner_preflight(owner,sid))['ready'] is True
    maximum_calls=min(len(selected),plan['model_call_ceiling'],before['limits']['max_calls']-before['usage']['calls'])
    maximum_tokens=before['limits']['max_tokens']-before['usage']['reserved_tokens']
    budget=ValidationBudget(max_calls=maximum_calls,max_tokens=maximum_tokens,
        ledger_path=str(args.output/'validation-budget.json'))
    report={'schema':'aria.agent-intelligence.run.v1','kind':'actual_existing_agent_run',
        'status':'IN_PROGRESS','scripted_responses':False,'protocol_sha256':digest(plan),
        'started_at':datetime.now(timezone.utc).isoformat(),'pid':__import__('os').getpid(),
        'provider':'local','model':settings.LOCAL_LLM_MODEL,'temperature':settings.LLM_TEMPERATURE,
        'output_token_ceiling':plan['output_token_ceiling'],'accounting_before':before['usage'],
        'selected_cases':[c['case_id'] for c in selected],
        'prior_handoff_run_sha256':digest(prior) if prior is not None else None,
        'limits':{k:before['limits'][k] for k in ('max_calls','max_tokens','max_cost_microusd')},
        'cases':[],'accounting_reconciled':False,'actual_target_tool_dispatches':0,
        'scope':'Controlled process-local evidence;real owned-session model accounting;no worker execution',
        'limitations':['Small author-written development cases;no independent senior reference.',
            'Configured cloud service routing unchanged;this child uses local-only routing.',
            'Case evidence and discovery memory are synthetic and never saved as live findings.']}
    import httpx
    base=settings.LOCAL_LLM_URL.removesuffix('/v1')
    try:
        async with httpx.AsyncClient(timeout=3,trust_env=False,follow_redirects=False) as client:
            tags=(await client.get(base+'/api/tags')).json()
        report['model_artifact']=next({key:model.get(key) for key in ('name','digest','size','modified_at')}
            for model in tags.get('models',[]) if model.get('name')==settings.LOCAL_LLM_MODEL)
    except (httpx.HTTPError,ValueError,StopIteration):
        report['model_artifact']={'name':settings.LOCAL_LLM_MODEL,'digest':None,'limitation':'Artifact digest unavailable'}
    source_paths=[p for directory in ('agents','llm','orchestrator','memory','security','config')
                  for p in sorted((ROOT/directory).rglob('*.py'))]
    source_paths += [ROOT/'evaluation/agent_intelligence.py',Path(__file__).resolve()]
    report['source_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    path=args.output/'run.json'
    def persist():path.write_text(json.dumps(report,indent=2)+'\n')
    persist()
    agents={'recon':recon_agent,'scan':scan_agent,'vuln':vuln_agent,'exploit':attack_planner_agent,
        'orchestrator':orchestrator_agent,'correlation':correlation_agent,
        'coordinator':coordinator_agent,'web_intel':web_intel_agent}
    original_query=pool_manager.query_for_task
    original_local_query=LocalClient.query
    captured=[]
    provider_inputs=[]
    async def observed_local_query(client,prompt,system=''):
        provider_inputs.append({'prompt':prompt,'system':system,'response_schema':response_schema.get(),
            'output_token_ceiling':output_limit(768 if response_schema.get() else 192),
            'temperature':client.temperature,'model':client.model})
        return await original_local_query(client,prompt,system)
    async def observed_query(user_id,task_type,prompt,system=''):
        assert user_id==owner
        record={'task_type':task_type,'prompt':prompt,'system':system,
                'prompt_system_sha256':digest({'prompt':prompt,'system':system})}
        captured.append(record)
        result=await original_query(user_id,task_type,prompt,system)
        record.update({key:result.get(key) for key in ('success','error','provider','model','attempt_id',
            'logical_request_id','tokens_used','cost_microusd','timings','reserved_attempts')})
        record['provider_content_sha256']=hashlib.sha256(str(result.get('content','')).encode()).hexdigest()
        record['public_json']=public_content(result.get('content',''))
        return result
    allowed_ports={make_url(settings.DATABASE_URL).port or 5432,urlsplit(settings.LOCAL_LLM_URL).port or 80}
    original_connect=socket.socket.connect
    def bounded_connect(sock,address):
        if sock.family in (socket.AF_INET,socket.AF_INET6):
            if address[0] not in {'127.0.0.1','::1'} or address[1] not in allowed_ports:
                raise RuntimeError('Nonbenchmark network attempt denied')
        return original_connect(sock,address)
    original_lookup=socket.getaddrinfo
    def bounded_lookup(host,port,*args,**kwargs):
        if host not in {'127.0.0.1','::1','localhost',b'127.0.0.1',b'::1',b'localhost'}:
            raise RuntimeError('Nonbenchmark DNS lookup denied')
        return original_lookup(host,port,*args,**kwargs)
    caps={'tools':['curl','nmap'],'allowed_networks':[TARGET+'/32'],'allowed_tcp_ports':[80]}
    token=current_budget.set(budget);output_token=response_output_limit.set(plan['output_token_ceiling'])
    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(pool_manager,'query_for_task',observed_query))
            stack.enter_context(patch.object(LocalClient,'query',observed_local_query))
            stack.enter_context(patch('memory.worker_jobs.worker_jobs.client.capabilities',AsyncMock(return_value=caps)))
            stack.enter_context(patch('memory.execution_authorization.execution_authorization.propose',AsyncMock(side_effect=RuntimeError('Benchmark forbids proposals'))))
            stack.enter_context(patch('memory.execution_authorization.execution_authorization.execute',AsyncMock(side_effect=RuntimeError('Benchmark forbids execution'))))
            stack.enter_context(patch('memory.vector_store._embedder.available',return_value=False))
            stack.enter_context(patch.object(socket.socket,'connect',bounded_connect))
            stack.enter_context(patch.object(socket,'getaddrinfo',bounded_lookup))
            for case in selected:
                vector_store.clear_session(sid);knowledge_cache._local.pop(sid,None);attack_kb._sessions.pop(sid,None)
                evidence=[{**entry,'session_id':sid,'owner_id':owner,'provenance':'synthetic_benchmark_fixture',
                           'source_id':entry['id']} for entry in case['evidence']]
                for entry in evidence:vector_store.add(sid,entry['summary'],{'evidence_id':entry['id']},agent='fixture')
                if case['role']!='scan':
                    knowledge_cache.store(sid,'nmap',TARGET,'','',{'findings':[{'title':'Synthetic TCP observation','evidence':'80/tcp open http'}]})
                    attack_kb.update_host_ports(sid,TARGET,[{'port':80,'service':'http','version':''}])
                attack_kb.set_attack_goal(sid,'discovery','Synthetic bounded benchmark;no execution',TARGET)
                handoff=None
                if case.get('handoff_from'):
                    sources=report['cases']+(prior['cases'] if prior is not None else [])
                    source=next(r for r in sources if r['case_id']==case['handoff_from'])
                    assert source.get('actual_model_success') is True
                    handoff={'from_case':source['case_id'],'source_response_sha256':digest(source),
                             'unverified_public_result':source.get('public_result')}
                    vector_store.add(sid,json.dumps(handoff,separators=(',',':')),agent='vuln')
                data={'original_objective':case['objective'],'objective':case['objective'],
                    'user_input':case['objective'],'description':case['objective'],'target':TARGET,
                    'requested_ports':[80],'team_task':True,'team_evidence':evidence,
                    'goal_type':'discovery','current_phase':'vulnerability_analysis',
                    'tools_run':['nmap','curl'] if case['role'] in {'vuln','correlation','coordinator'} else [],
                    'http_data':{'status':200,'headers':{'Content-Type':'text/html'},'body':'Welcome to the public home page'}}
                if case['role']=='orchestrator':
                    data.update(autonomous_mode=True,goal='discovery',engagement_scope=scope,
                        worker_capabilities=caps,completed_observations=['port_discovery'],
                        completion_criteria='Durable TCP and HTTP observations;HTTP not yet received')
                if handoff:data['research_context']={'handoff':handoff,'verification':'unverified analyst output'}
                record={'case_id':case['case_id'],'role':case['role'],
                    'actual_agent_name':agents[case['role']].agent_name,
                    'input_sha256':digest(data),'concrete_input':data,'handoff':handoff,'status':'IN_PROGRESS'}
                report['cases'].append(record);captured=[];provider_inputs=[];persist()
                print(json.dumps({'case':case['case_id'],'stage':'STARTED','model':settings.LOCAL_LLM_MODEL}),flush=True)
                started=time.monotonic()
                try:
                    result=await agents[case['role']].process(sid,owner,data,'intermediate')
                    record.update(public_result=result,status='COLLECTED')
                except Exception as error:record.update(status='FAILED',error_type=type(error).__name__)
                record.update(wall_seconds=time.monotonic()-started,provider_records=captured,
                    provider_inputs=provider_inputs,
                    actual_model_success=bool(captured) and all(r.get('success') is True for r in captured),
                    inference_kind='actual_local_model' if captured else 'deterministic_agent_route')
                ledger=await model_accounting.status(sid,owner)
                record['accounting_after']=ledger['usage'];persist()
                print(json.dumps({'case':case['case_id'],'stage':record['status'],
                    'physical_model_attempts':len([r for r in captured if r.get('attempt_id')]),
                    'actual_model_success':record['actual_model_success'],'seconds':round(record['wall_seconds'],3)}),flush=True)
                if (record['status']=='FAILED' or ledger['usage'].get('stopped')
                        or any(r.get('success') is not True for r in captured)):
                    report['status']='STOPPED_WITHOUT_RETRY';break
        after=await model_accounting.status(sid,owner)
        ids={r['attempt_id'] for case in report['cases'] for r in case.get('provider_records',[]) if r.get('attempt_id')}
        attempts=[a for a in after['attempts'] if a['id'] in ids]
        assert len(attempts)==len(ids) and all(a['provider']=='local' and a['model']==settings.LOCAL_LLM_MODEL for a in attempts)
        assert after['usage']['calls']-before['usage']['calls']==len(ids)
        assert after['usage']['reserved_cost_microusd']==before['usage']['reserved_cost_microusd']
        report.update(accounting_after=after['usage'],durable_attempts=attempts,
            accounting_reconciled=True,physical_model_attempts=len(ids))
        assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==value for name,value in report['source_sha256'].items())
        if report['status']=='IN_PROGRESS':report['status']='COLLECTED'
    finally:
        current_budget.reset(token);response_output_limit.reset(output_token)
        report['finished_at']=datetime.now(timezone.utc).isoformat();persist();await engine.dispose()
    return 0 if report['status']=='COLLECTED' else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--admission',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',action='append',help='Only unattempted frozen cases;never retry a timed-out case')
    parser.add_argument('--handoff-run',type=Path,help='Retained same-protocol prior analyst result')
    raise SystemExit(asyncio.run(main(parser.parse_args())))
