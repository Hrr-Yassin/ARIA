"""Local-model semantic planning checks. No scanner, worker job or public request.

Run with LLM_ROUTING=local PYTHONPATH=. python -m integration.planner_intelligence.
Outputs private diagnostic JSON; uses actual configured loopback inference.
"""
import asyncio
import argparse
import json
from pathlib import Path
import time
from urllib.parse import urlsplit
from agents.orchestrator_agent import OrchestratorAgent
from config.settings import settings
from llm.local_client import LocalClient
from security_tools.adapters import ADAPTERS, decode, validate


class LocalPlanner(OrchestratorAgent):
    def __init__(self):
        super().__init__()
        self.calls = []

    async def query_llm_smart(self, user_id, prompt, system='', **kwargs):
        started = time.monotonic()
        result = await LocalClient(model=settings.LOCAL_LLM_MODEL).query(prompt, system)
        self.calls.append({'tokens': result.get('tokens_used'), 'seconds': round(time.monotonic()-started, 2),
                           'success': result.get('success'), 'content': result.get('content'), 'error': result.get('error')})
        return result


async def main(tool_filter=None, output=Path('.local-lab/intelligence/local-selection.json')):
    if settings.LLM_ROUTING != 'local' or not settings.LOCAL_LLM_MODEL:
        raise SystemExit('Requires configured local-only routing')
    digest = 'fa29cb41294bfa4cb296363f138c6938d8d2363da27db8a690f5664da5c6f4b5'
    scope = {'targets':['192.0.2.1','aria-fixture.test'], 'ports':[80], 'artifact_sha256':[digest]}
    advertisement={'typed_adapters':{ADAPTERS[name].capability:1 for name in ('nmap','httpx','nuclei','ffuf','semgrep','subfinder')}}
    cases=[
        ('nmap','Determine which authorized TCP ports are open.','port_discovery',[]),
        ('httpx','Observe HTTP status and page title from the observed open port 80.','http_response',['port_discovery']),
        ('ffuf','Discover HTTP endpoint candidates using exactly the dictionary test, admin.','endpoint_discovery',['port_discovery','http_response']),
        ('nuclei','Run the reviewed informational HTTP observation template, with human approval required.','template_observation',['port_discovery','http_response']),
        ('semgrep','Review the authorized source artifact for eval usage using the local aria-python rule.','source_observation',[]),
        ('subfinder','Enumerate only the offline aria-fixture.test fixture, without DNS or provider access.','offline_domain_observation',[]),
    ]
    planner=LocalPlanner();results=[]
    for expected, objective, criterion, completed in cases:
        if tool_filter and expected not in tool_filter:
            continue
        data={'original_objective':objective,'target':'aria-fixture.test' if expected=='subfinder' else '192.0.2.1',
              'goal':criterion,'engagement_scope':scope,'worker_capabilities':advertisement,
              'completed_observations':completed,'completion_criteria':criterion,'validation_feedback':[]}
        if expected == 'ffuf':
            data['ffuf_words'] = ['test','admin']
        result=await planner._bounded_assessment_plan('local-fixture',data,'expert')
        selected='';error=''
        try:
            command=result['commands'][0]['command'];adapter,parameters=decode(command)
            validate(command,scope);selected=adapter.name
            if selected=='subfinder' and parameters.source!='offline':raise ValueError('Provider egress selected')
            if selected=='nmap' and (parameters.host!='192.0.2.1' or parameters.ports!=[80]):raise ValueError('Wrong host/port choice')
            if selected in {'httpx','ffuf','nuclei'} and urlsplit(parameters.url).hostname!='192.0.2.1':raise ValueError('Wrong HTTP host')
            if selected=='ffuf' and set(parameters.words)!={'admin','test'}:raise ValueError('Dictionary differs from objective')
            if selected=='semgrep' and parameters.artifact_sha256!=digest:raise ValueError('Invented artifact')
        except (ValueError,KeyError,IndexError) as exc:error=str(exc)
        results.append({'expected':expected,'selected':selected,'correct':selected==expected and not error,'error':error})
        print(json.dumps(results[-1]),flush=True)
    report={'model':settings.LOCAL_LLM_MODEL,'results':results,'calls':planner.calls,'paid_cost_usd':0}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2))
    if not all(item['correct'] for item in results):raise SystemExit(1)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--tool', action='append', choices=['nmap','httpx','ffuf','nuclei','semgrep','subfinder'])
    parser.add_argument('--output',type=Path,default=Path('.local-lab/intelligence/local-selection.json'))
    args=parser.parse_args()
    asyncio.run(main(args.tool,args.output))
