"""Disposable HTTP/WS browser fixtures. Never import this server in production.
Providers and execution outcomes are synthetic; real client, sockets and cache run.
"""
import asyncio
import json
import os
import uuid
from pathlib import Path
import tests  # Ephemeral process-only configuration; no owner credentials.
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import api.main as pages
from worker.policy import validate_worker_command

ROOT=Path(__file__).resolve().parents[1]
WEB=Path(os.environ.get('ARIA_BROWSER_WEB',ROOT/'web'))
FILE=Path(os.environ['ARIA_BROWSER_STATE'])
pages.WEB_DIR=WEB
app=FastAPI()
app.mount('/static',StaticFiles(directory=WEB/'static'),name='static')
state=json.loads(FILE.read_text()) if FILE.exists() else {'sessions':{
    'a':{'session_id':'a','name':'Fixture Alpha','target':'192.0.2.1','scope':{'targets':['192.0.2.1'],'ports':[80]},'logs':[{'role':'user','content':'Saved Alpha prompt'},{'role':'assistant','content':'Saved Alpha response'}]},
    'b':{'session_id':'b','name':'Fixture Beta','target':'192.0.2.2','scope':{'targets':['192.0.2.2'],'ports':[80]},'logs':[{'role':'user','content':'Saved Beta prompt'},{'role':'assistant','content':'Saved Beta response'}]}},
    'runs':{},'keys':[],'profile':'intermediate','proposals':{},'replays':{},'counts':{},'errors':{},'delays':{},'phase':'awaiting_approval','expired':False,'disconnects':0,'burp_enabled':False}


def save(): FILE.write_text(json.dumps(state))
def count(key): state['counts'][key]=state['counts'].get(key,0)+1; save()
def json_response(data,status=200): return JSONResponse(data,status_code=status)
def session_logs(sid): return state['sessions'][sid]['logs']
def bump(run,phase,active=True): run.update(run_state=phase,active=active,version=run.get('version',0)+1); save()


@app.get('/')
@app.get('/chat/{session_id}')
async def index(session_id=''): return pages.render_page(WEB/'index.html')
@app.get('/login')
@app.get('/login.html')
async def login_page(): return pages.render_page(WEB/'login.html')
@app.post('/__control')
async def control(request: Request):
    state.update(await request.json()); save(); return state
@app.get('/__control')
async def inspect(): return state


@app.api_route('/api/{path:path}',methods=['GET','POST','PATCH','DELETE'])
async def api(path: str,request: Request):
    route='/api/'+path
    method=request.method
    payload=await request.body()
    body=json.loads(payload) if payload and request.headers.get('content-type','').startswith('application/json') else {}
    if route=='/api/login':
        if body.get('username')!='fixture-owner' or body.get('password')!='fixture-only': return json_response({'detail':'Invalid credentials'},401)
        state['expired']=False; save()
        response=json_response({'token':'fixture-token','user_id':'owner','username':'fixture-owner','role':'pentester','skill_level':state['profile']})
        response.set_cookie('pentestai_token','fixture-token',httponly=True,samesite='strict')
        return response
    if state['expired'] or (request.headers.get('authorization') or 'Bearer '+request.cookies.get('pentestai_token',''))!='Bearer fixture-token': return json_response({'detail':'Token expired'},401)
    if route in state['errors']: return json_response({'detail':'Injected API failure'},state['errors'][route])
    if route in state['delays']: await asyncio.sleep(state['delays'][route])
    if route=='/api/logout': state['expired']=True; save(); return {'status':'logged_out'}
    if route=='/api/profile':
        if method=='PATCH': state['profile']=body['skill_level']; save()
        return {'username':'fixture-owner','skill_level':state['profile']}
    if route=='/api/keys/':
        if method=='POST': state['keys'].append({'id':str(uuid.uuid4()),'provider':body['provider'],'label':body['label'],'is_active':True}); save()
        return {'keys':state['keys']}
    if route.startswith('/api/keys/') and method=='DELETE': state['keys']=[k for k in state['keys'] if k['id']!=path.split('/')[-1]]; save(); return {'status':'deleted'}
    if route=='/api/session/list': return {'sessions':[{k:v for k,v in s.items() if k!='logs'} for s in state['sessions'].values()]}
    if route=='/api/session/new':
        sid=str(uuid.uuid4()); state['sessions'][sid]={'session_id':sid,'name':body['name'],'target':body['target'],'scope':{'targets':[body['target']],'ports':[80]},'logs':[]}; save(); return state['sessions'][sid]
    if route.startswith('/api/session/'):
        sid=path.split('/')[1]
        if sid not in state['sessions']: return json_response({'detail':'Ownership denied'},403)
        if path.endswith('/restore'):
            offset=int(request.query_params.get('offset','0')); logs=session_logs(sid)
            return {'logs':logs[max(0,len(logs)-offset-100):len(logs)-offset],'has_more':len(logs)>offset+100}
        return state['sessions'][sid]
    if route=='/api/v8/input':
        sid=body['session_id']; count('prompts')
        turn=str(uuid.uuid4()); text=body['user_input']; session_logs(sid).append({'role':'user','content':text,'data':{'turn_id':turn}})
        if text=='report': result={'type':'report_select','commands':[],'formats':[{'id':'markdown','label':'Markdown'}]}
        else: result={'commands':[{'tool':'curl','command':'curl -I http://'+state['sessions'][sid]['target'],'purpose':'Observe HTTP headers','turn_id':turn}], 'suggested_reply':'Bounded HTTP observation proposed','current_phase':'recon'}
        session_logs(sid).append({'role':'assistant','content':result.get('suggested_reply','Choose a report format'),'data':result}); save(); return result
    if route=='/api/execution/proposals':
        sid=body['session_id']
        try: checked=validate_worker_command(body['command'],state['sessions'][sid]['scope'])
        except (ValueError,KeyError): return json_response({'detail':'Scope refused'},403)
        action=str(uuid.uuid4()); proposal={'action_id':action,'session_id':sid,'command':checked.command,'tool':checked.tool,'status':'pending','risk_color':'orange'}
        state['proposals'][action]=proposal; save(); return proposal
    if route.startswith('/api/execution/'):
        action=path.split('/')[1]; proposal=state['proposals'][action]
        if proposal['status']!='pending': return json_response({'detail':'Already decided'},409)
        proposal['status']='approved' if body['decision']=='approve' else 'rejected'; save(); return proposal
    if route=='/api/kali/execute':
        action=state['proposals'].get(body.get('action_id'),{})
        if action.get('status')!='approved' or action.get('session_id')!=body['session_id']: return json_response({'detail':'Approval required'},403)
        action['status']='consumed'; count('executions')
        result={'stdout':'HTTP/1.1 200 OK\r\nServer: controlled-fixture\r\n','stderr':'','exit_code':0,'job_id':str(uuid.uuid4())}
        session_logs(body['session_id']).append({'role':'tool_output','content':result['stdout'],'data':result}); save(); return result
    if route=='/api/report/generate':
        result={'type':'report','filename':'pentest_report_'+('1'*32)+'.md','format':body['format']}
        session_logs(body['session_id']).append({'role':'assistant','type':'report','content':'Report generated','data':result}); save(); return result
    if route.startswith('/api/report/download/'):
        from fastapi.responses import Response
        return Response('Fixture report: evidence references; synthetic provider/worker; verification incomplete',headers={'Content-Disposition':'attachment; filename=fixture.md'})
    if route=='/api/tool-results': return {'suggested_reply':'Observed HTTP response. Vulnerability verification remains incomplete.'}
    if route.startswith('/api/pentest/'):
        parts=path.split('/'); sid=parts[1]
        if sid not in state['sessions']: return json_response({'detail':'Ownership denied'},403)
        if path.endswith('/kb-snapshot'): return {'hosts':[],'timeline':[]}
        if path.endswith('/decision-log'): return {'entries':[]}
        if path.endswith('/playbooks'): return {'playbooks':[]}
        if '/autonomous/' in path:
            run=state['runs'].get(sid,{'active':False})
            if path.endswith('/start'):
                if run.get('active'): return {'status':'already_running'}
                if body.get('goal')=='initial_access': return {'active':False,'run_state':'blocked','reason':'Verified access capability unavailable','reason_code':'unsupported_goal'}
                run={'active':True,'run_state':state['phase'],'run_id':str(uuid.uuid4()),'max_steps':body.get('max_steps',3),'version':1,'waiting_approval':state['phase']=='awaiting_approval','pending_action_id':'auto-'+sid}
                state['runs'][sid]=run; count('auto_starts'); save(); return {'status':'started'}
            if path.endswith('/status'): return run
            if path.endswith('/approvals'): return {'pending':[]}
            if path.endswith('/approve'):
                if body['decision']=='reject': bump(run,'blocked',False)
                else: bump(run,'executing')
                return {'status':'recorded'}
            if path.endswith('/stop'):
                bump(run,'cancelling')
                async def finish(): await asyncio.sleep(.3); bump(run,'blocked',False)
                asyncio.create_task(finish()); return {'pending':1,'status':'cancellation_pending'}
    if route=='/api/burp/capabilities': return {'enabled':state['burp_enabled'],'scanner':False,'request_bound_replay':True}
    if route.startswith('/api/burp/'):
        parts=path.split('/'); sid=parts[1]
        if path.endswith('/map'): return {'endpoints':[{'evidence_id':'e1','method':'GET','url':'http://192.0.2.1/','authentication_context':'anonymous'}]}
        if path.endswith('/repeater'): count('staged'); return {'status':'staged','network_request_sent':False}
        if parts[-1]=='replays': return {'actions':list(state['replays'].values())}
        if path.endswith('/replay-proposals'):
            action=str(uuid.uuid4()); result={'action_id':action,'state':'pending','request_digest':'1'*64,'result':{'summary':{'method':body.get('mutation',{}).get('method','GET') if body.get('mutation') else 'GET','url':'http://192.0.2.1/','authentication_context':'anonymous'}}}
            state['replays'][action]=result; save(); return result
        if 'replays' in parts:
            action=parts[3]; result=state['replays'][action]
            if path.endswith('/decision'): result['state']='approved' if body['decision']=='approve' else 'rejected'; save(); return result
            if path.endswith('/execute'):
                if result['state']!='approved': return json_response({'detail':'Approval required'},403)
                result['state']='completed'; result['result']['comparison']={'status_line':'HTTP/1.1 200 OK','verification_status':'observation'}; count('replays'); save(); return result
            if path.endswith('/cancel'): result['state']='cancelled'; save(); return result
            return result
    return {}


@app.websocket('/api/pentest/ws/{sid}/auto')
async def events(ws: WebSocket,sid: str):
    await ws.accept()
    message=await ws.receive_json()
    if message.get('token')!='fixture-token' or state['expired']: await ws.close(code=4401); return
    if state['disconnects']:
        state['disconnects']-=1; save(); await ws.close(code=1001); return
    previous=-1
    try:
        while True:
            run=state['runs'].get(sid,{})
            if run.get('version',0)!=previous:
                previous=run.get('version',0); phase=run.get('run_state','blocked')
                event={'type':'waiting_approval' if phase=='awaiting_approval' else 'auto_activity' if run.get('active') else 'auto_complete',
                    'status':'waiting_approval' if phase=='awaiting_approval' else phase,'action':phase,'action_id':'auto-'+sid,'step':1,'risk_color':'orange'}
                await ws.send_json(event)
            try:
                message=await asyncio.wait_for(ws.receive(),timeout=.1)
                if message.get('type')=='websocket.disconnect': return
            except asyncio.TimeoutError: pass
    except (WebSocketDisconnect,RuntimeError): pass
