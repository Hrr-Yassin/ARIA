"""Local authenticated Burp Community connector. Disabled until release gates pass."""
import asyncio
import ipaddress
import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from api.auth import get_current_user, TokenData
from api.session_access import get_accessible_session
from config.settings import settings
from memory import burp_community as community
from memory.execution_authorization import execution_authorization
from memory.worker_jobs import worker_jobs
from memory.session_manager import session_manager

router = APIRouter()


async def local_connector(request: Request, user: TokenData = Depends(get_current_user)):
    if not settings.BURP_COMMUNITY_ENABLED: raise HTTPException(503,'Burp Community release gate is disabled')
    if not settings.BURP_CONNECTOR_USER_ID: raise HTTPException(503,'Bind the desktop connector to an ARIA user account')
    if user.user_id!=settings.BURP_CONNECTOR_USER_ID: raise HTTPException(403,'Desktop captures belong to another ARIA account')
    if not request.client or not ipaddress.ip_address(request.client.host).is_loopback:
        raise HTTPException(403,'Connector requires a direct loopback connection')


class Pair(BaseModel):
    url: str = Field(max_length=8192)
    request_b64: str = Field(max_length=90000)
    response_b64: str = Field(max_length=1400000)
    authentication_label: str = Field(default='anonymous',max_length=80)


@router.get('/capabilities')
async def capabilities(user: TokenData = Depends(get_current_user)):
    return {'edition':'Community', 'enabled':settings.BURP_COMMUNITY_ENABLED and user.user_id==settings.BURP_CONNECTOR_USER_ID, 'scanner':False,
        'selected_history_import':True, 'repeater_staging':True, 'request_bound_replay':True,
        'approved_worker_checks':['GET','HEAD'], 'authenticated_replay':'requires_engagement_configuration', 'mutations':'requires_engagement_configuration',
        'default_port':80, 'check_timeout_seconds':10, 'request_budget':20}


@router.post('/{session_id}/import', dependencies=[Depends(local_connector)])
async def import_selected(session_id: str, body: Pair, user: TokenData = Depends(get_current_user)):
    session = await get_accessible_session(session_id,user)
    try: pair = community.inspect_pair(body.url,body.request_b64,body.response_b64,session.get('scope',{}),body.authentication_label)
    except (ValueError,TypeError) as exc: raise HTTPException(422,str(exc)) from None
    return await community.import_pair(session_id,pair)


@router.get('/{session_id}/map', dependencies=[Depends(local_connector)])
async def endpoint_map(session_id: str, user: TokenData = Depends(get_current_user), offset: int = 0, limit: int = 100):
    await get_accessible_session(session_id,user)
    if offset<0 or not 1<=limit<=200: raise HTTPException(422,'Invalid evidence page')
    logs = await session_manager.get_chat_logs(session_id,limit=limit+1,offset=offset,msg_types=['burp_evidence'])
    has_more=len(logs)>limit
    if has_more: logs=logs[1:]
    return {'has_more':has_more,'next_offset':offset+len(logs),'endpoints':[{'evidence_id':entry['id'], **entry['data']['summary']}
        for entry in logs if entry.get('type')=='burp_evidence'], 'scanner':False,
        'limitations':['Map is paginated by imported capture records; import selection defines coverage']}


@router.post('/{session_id}/{evidence_id}/repeater', dependencies=[Depends(local_connector)])
async def repeater(session_id: str,evidence_id: str,user: TokenData = Depends(get_current_user)):
    session = await get_accessible_session(session_id,user)
    evidence = await community.get_evidence(session_id,evidence_id)
    source = community.original(evidence)
    community.inspect_pair(source['url'],source['request_b64'],source['response_b64'],session['scope'])
    if len(settings.BURP_CONNECTOR_TOKEN)<32: raise HTTPException(503,'Connector token is not configured')
    try:
        async with httpx.AsyncClient(timeout=10,trust_env=False,follow_redirects=False) as client:
            headers = {'Authorization':'Bearer '+settings.BURP_CONNECTOR_TOKEN}
            from memory.web_actions import connector_base
            base=connector_base()
            caps = await client.get(base+'/capabilities',headers=headers)
            caps.raise_for_status()
            if caps.json().get('edition')!='COMMUNITY': raise HTTPException(409,'Burp Community is required')
            response = await client.post(base+'/repeater',headers=headers,
                data={'url':source['url'],'request_b64':source['request_b64'],'evidence_id':evidence_id})
            response.raise_for_status()
        return {'status':'staged','evidence_id':evidence_id,'network_request_sent':False}
    except httpx.HTTPError: raise HTTPException(503,'Burp connector is disconnected or refused staging') from None


@router.post('/{session_id}/{evidence_id}/check-proposal', dependencies=[Depends(local_connector)])
async def check_proposal(session_id: str,evidence_id: str,user: TokenData = Depends(get_current_user)):
    session = await get_accessible_session(session_id,user)
    data = await community.get_evidence(session_id,evidence_id)
    command = community.check_command(data,session['scope'])
    proposal = await execution_authorization.propose(user.user_id,session_id,command,'curl',require_approval=True,turn_id=evidence_id)
    return {'action_id':proposal.id,'status':proposal.status,'command':proposal.command,'evidence_id':evidence_id,
        'policy':'Explicit approval required. This availability check sends no captured custom headers. No mutations or authenticated replay.'}


class Check(BaseModel):
    action_id: str = Field(max_length=36)


@router.post('/{session_id}/{evidence_id}/check', dependencies=[Depends(local_connector)])
async def approved_check(session_id: str,evidence_id: str,body: Check,user: TokenData = Depends(get_current_user)):
    async with community.LOCKS.setdefault(session_id,asyncio.Lock()):
        session = await get_accessible_session(session_id,user)
        data = await community.get_evidence(session_id,evidence_id)
        proposal,_ = await execution_authorization._load(body.action_id,user.user_id,session_id,requester=True)
        if proposal.turn_id!=evidence_id or proposal.status!='approved': raise HTTPException(403,'Explicit approval for this evidence is required')
        jobs = await worker_jobs.list_status(user.user_id,session_id)
        if len(jobs)>=20: raise HTTPException(409,'Engagement request budget exhausted')
        await worker_jobs.resume_session(user.user_id,session_id)
        result = await execution_authorization.execute(user.user_id,session_id,community.check_command(data,session['scope']),
            tool='curl',action_id=body.action_id,timeout=10)
        comparison = {'evidence_id':evidence_id,'job_id':result.get('job_id'),'exit_code':result.get('exit_code'),
            'baseline':data['summary'].get('response_preview','')[:1000], 'observation':result.get('stdout','')[:1000],
            'limitation':'Availability check differs from the captured request headers; this is not vulnerability verification'}
        from security.redaction import redact
        comparison = redact(comparison)
        await session_manager.add_chat_log(session_id,'tool_output','Burp evidence availability comparison','burp_comparison',comparison)
        return comparison


@router.post('/{session_id}/analyze', dependencies=[Depends(local_connector)])
async def analyze_map(session_id: str,user: TokenData = Depends(get_current_user)):
    session = await get_accessible_session(session_id,user)
    mapped = await endpoint_map(session_id,user)
    from agents.web_intel_agent import web_intel_agent
    return await web_intel_agent.process(session_id,user.user_id,{
        'user_input':'Map these observed endpoints, parameters and authentication contexts. Propose bounded tests with expected evidence; label all vulnerabilities as hypotheses.',
        'target':session['target'],'http_data':mapped},user.skill_level)


class Mutation(BaseModel):
    method: str | None = Field(default=None,max_length=10)
    path: str | None = Field(default=None,max_length=8192)
    headers: dict[str,str] = Field(default_factory=dict,max_length=64)
    body_b64: str | None = Field(default=None,max_length=90000)


class ReplayProposal(BaseModel):
    mutation: Mutation | None = None


class ReplayDecision(BaseModel):
    decision: str


@router.post('/{session_id}/{evidence_id}/replay-proposals',dependencies=[Depends(local_connector)])
async def replay_proposal(session_id: str,evidence_id: str,body: ReplayProposal,user: TokenData=Depends(get_current_user)):
    await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    try: return await web_actions.propose(session_id,user.user_id,evidence_id,body.mutation.model_dump(exclude_none=True) if body.mutation else None)
    except (ValueError,TypeError,UnicodeError): raise HTTPException(422,'Invalid replay request or mutation') from None


@router.post('/{session_id}/replays/{action_id}/decision',dependencies=[Depends(local_connector)])
async def replay_decision(session_id: str,action_id: str,body: ReplayDecision,user: TokenData=Depends(get_current_user)):
    await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    return await web_actions.decide(session_id,user.user_id,action_id,body.decision)


@router.post('/{session_id}/replays/{action_id}/execute',dependencies=[Depends(local_connector)])
async def replay_execute(session_id: str,action_id: str,user: TokenData=Depends(get_current_user)):
    await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    return await web_actions.execute(session_id,user.user_id,action_id)


@router.get('/{session_id}/replays/{action_id}',dependencies=[Depends(local_connector)])
async def replay_status(session_id: str,action_id: str,user: TokenData=Depends(get_current_user)):
    await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    return await web_actions.status(session_id,user.user_id,action_id)


@router.post('/{session_id}/replays/{action_id}/cancel',dependencies=[Depends(local_connector)])
async def replay_cancel(session_id: str,action_id: str,user: TokenData=Depends(get_current_user)):
    await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    return await web_actions.cancel(session_id,user.user_id,action_id)


@router.get('/{session_id}/replays',dependencies=[Depends(local_connector)])
async def replay_list(session_id: str,user: TokenData=Depends(get_current_user)):
    await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    return {'actions':await web_actions.list(session_id,user.user_id)}


@router.post('/{session_id}/replays/cancel-all',dependencies=[Depends(local_connector)])
async def replay_cancel_all(session_id: str,user: TokenData=Depends(get_current_user)):
    await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    return await web_actions.cancel_all(session_id,user.user_id)


class CaptureSelection(BaseModel):
    capture_ids: list[str] = Field(min_length=1,max_length=20)


@router.get('/{session_id}/proxy-history',dependencies=[Depends(local_connector)])
async def proxy_history(session_id: str,user: TokenData=Depends(get_current_user)):
    session=await get_accessible_session(session_id,user)
    from memory.web_actions import web_actions
    from worker.policy import validate_worker_command
    import shlex
    data=await web_actions.connector('GET','/history')
    captures=[]
    for capture in data.get('captures',[])[:100]:
        try: validate_worker_command(shlex.join(['curl','-I',capture['url']]),session['scope'])
        except (ValueError,KeyError): continue
        captures.append(capture)
    return {'captures':captures,'scanner':False}


@router.post('/{session_id}/import-selected',dependencies=[Depends(local_connector)])
async def import_history_selection(session_id: str,body: CaptureSelection,user: TokenData=Depends(get_current_user)):
    session=await get_accessible_session(session_id,user)
    import re
    if any(not re.fullmatch('[0-9a-f]{64}',capture) for capture in body.capture_ids): raise HTTPException(422,'Invalid capture selection')
    from memory.web_actions import web_actions
    selected=await web_actions.connector('POST','/history/selected',{'ids':','.join(body.capture_ids)})
    results=[]
    for capture in selected.get('captures',[]):
        try: pair=community.inspect_pair(capture['url'],capture['request_b64'],capture['response_b64'],session['scope'])
        except (ValueError,KeyError): raise HTTPException(422,'Selected capture violates scope or HTTP framing') from None
        results.append(await community.import_pair(session_id,pair))
    return {'imported':results}
