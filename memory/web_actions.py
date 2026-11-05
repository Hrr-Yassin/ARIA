"""Request-bound approvals, durable admission and exact Community replay.
Original credentials stay encrypted; connector permits are single-use and signed.
"""
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit
import httpx
from fastapi import HTTPException
from sqlalchemy import select, func
from config.settings import settings
from memory.database_models import async_session, PentestSession, WebAction, ChatLog, User
from memory.execution_authorization import digest
from memory.burp_community import inspect_pair, original, get_evidence
from security.encryption import evidence_cipher
from security.redaction import redact

ADMITTED = {'claimed','completed','failed','unknown','cancel_requested','cancelled_after_dispatch'}
TERMINAL = {'completed','failed','cancelled','cancelled_after_dispatch'}


def seal(value):
    return evidence_cipher().encrypt(json.dumps(value).encode()).decode()


def unseal(value):
    return json.loads(evidence_cipher().decrypt(value.encode()))


def scope_binding(session):
    return digest({'owner':session.user_id, 'scope':session.scope, 'status':str(session.status),'auth_revision':getattr(session,'_web_auth_revision',0)})


def replay_spec(data, scope, mutation=None):
    source = original(data)
    raw = base64.b64decode(source['request_b64'],validate=True)
    head, _, body = raw.partition(b'\r\n\r\n')
    lines = head.decode('iso-8859-1').split('\r\n')
    method, path, version = lines[0].split(' ')
    headers = [(line.split(':',1)[0],line.split(':',1)[1].strip()) for line in lines[1:]]
    url = source['url']
    if mutation:
        if scope.get('web_mutations') is not True:
            raise HTTPException(403,'Engagement does not authorize HTTP mutations')
        method = mutation.get('method') or method
        path = mutation.get('path') or path
        if not path.startswith('/') or path.startswith('//') or any(c in path for c in '\r\n #'):
            raise HTTPException(422,'Mutation path must remain a relative HTTP request target')
        forbidden = {'host','content-length','transfer-encoding','connection','proxy-authorization'}
        replacements = mutation.get('headers') or {}
        for key,value in replacements.items():
            if key.lower() in forbidden or any(c in key+value for c in '\r\n'):
                raise HTTPException(422,'Mutation header changes transport framing')
        replaced = {key.lower() for key in replacements}
        headers = [(key,value) for key,value in headers if key.lower() not in replaced|{'content-length'}]
        headers.extend(replacements.items())
        if mutation.get('body_b64') is not None:
            body = base64.b64decode(mutation['body_b64'],validate=True)
        if body: headers.append(('Content-Length',str(len(body))))
        parts = urlsplit(url)
        url = urlunsplit((parts.scheme,parts.netloc,path.split('?',1)[0],path.split('?',1)[1] if '?' in path else '', ''))
        raw = (f'{method} {path} {version}\r\n'+'\r\n'.join(f'{key}: {value}' for key,value in headers)+'\r\n\r\n').encode('iso-8859-1')+body
    checked = inspect_pair(url,base64.b64encode(raw).decode(),source['response_b64'],scope)
    if checked['authenticated'] and scope.get('web_authenticated_replay') is not True:
        raise HTTPException(403,'Authenticated replay requires explicit engagement configuration')
    parts = urlsplit(url)
    return {'url':url,'request_b64':base64.b64encode(raw).decode(),
        'request_digest':hashlib.sha256(raw).hexdigest(), 'target':parts.hostname,'port':80,
        'timeout_ms':10000,'summary':checked['summary'], 'mutation':bool(mutation),
        'baseline_response_b64':source['response_b64']}


def public(row):
    return {'action_id':row.id,'session_id':row.session_id,'evidence_id':row.evidence_id,
        'state':row.state,'request_digest':row.request_digest,'expires_at':row.expires_at.isoformat(),
        'result':row.result or {}}


def connector_base():
    parts=urlsplit(settings.BURP_CONNECTOR_URL)
    if parts.scheme!='http' or parts.hostname not in {'127.0.0.1','::1'} or parts.username or parts.password or parts.path not in {'','/'} or parts.query or parts.fragment:
        raise HTTPException(503,'Connector URL must be an explicit loopback HTTP origin')
    return settings.BURP_CONNECTOR_URL.rstrip('/')


class WebActions:
    async def _session(self, db, session_id, user_id):
        row = (await db.execute(select(PentestSession).where(PentestSession.id==session_id).with_for_update())).scalar_one_or_none()
        if row is None or row.user_id!=user_id or str(getattr(row.status,'value',row.status))!='active':
            raise HTTPException(403,'Active owned engagement required')
        owner=await db.get(User,user_id)
        if owner is None or not owner.is_active: raise HTTPException(403,'Active principal required')
        from security.credentials import auth_revision
        row._web_auth_revision=auth_revision(owner)
        return row

    async def propose(self, session_id, user_id, evidence_id, mutation=None):
        data = await get_evidence(session_id,evidence_id)
        async with async_session() as db:
            session = await self._session(db,session_id,user_id)
            spec = replay_spec(data,session.scope or {},mutation)
            row = WebAction(id=str(uuid.uuid4()),session_id=session_id,requester_id=user_id,
                evidence_id=evidence_id,state='pending',request_digest=spec['request_digest'],scope_digest=scope_binding(session),
                protected_spec=seal(spec),result={'summary':spec['summary'],'operation':'mutation' if mutation else 'replay'},
                expires_at=datetime.utcnow()+timedelta(minutes=10))
            db.add(row)
            await db.commit()
            return public(row)

    async def _load(self,db,session_id,user_id,action_id,check_scope=True):
        session = await self._session(db,session_id,user_id)
        row = (await db.execute(select(WebAction).where(WebAction.id==action_id).with_for_update())).scalar_one_or_none()
        if row is None or row.session_id!=session_id or row.requester_id!=user_id:
            raise HTTPException(403,'Replay action does not belong to this engagement and requester')
        if check_scope and row.scope_digest!=scope_binding(session):
            raise HTTPException(403,'Replay scope changed; create a new proposal')
        return session,row

    async def decide(self,session_id,user_id,action_id,decision):
        if decision not in {'approve','reject'}: raise HTTPException(422,'Invalid replay decision')
        async with async_session() as db:
            _,row = await self._load(db,session_id,user_id,action_id)
            if row.state!='pending' or row.expires_at<=datetime.utcnow(): raise HTTPException(409,'Replay approval is not pending or has expired')
            row.state='approved' if decision=='approve' else 'rejected'
            row.updated_at=datetime.utcnow()
            row.result={**row.result,'decision':decision,'actor_id':user_id}
            await db.commit()
            return public(row)

    async def connector(self,method,path,data=None):
        if len(settings.BURP_CONNECTOR_TOKEN)<32: raise HTTPException(503,'Connector token is not configured')
        try:
            async with httpx.AsyncClient(timeout=12,trust_env=False,follow_redirects=False) as client:
                response=await client.request(method,connector_base()+path,
                    headers={'Authorization':'Bearer '+settings.BURP_CONNECTOR_TOKEN},data=data)
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError,ValueError):
            raise HTTPException(503,'Community connector unavailable; a claimed replay will not be resubmitted') from None

    async def execute(self,session_id,user_id,action_id):
        async with async_session() as db:
            session,row=await self._load(db,session_id,user_id,action_id)
            if row.state in ADMITTED or row.state in TERMINAL: return public(row)
            if row.state!='approved' or row.expires_at<=datetime.utcnow(): raise HTTPException(403,'Explicit unexpired request-bound approval required')
            caps=await self.connector('GET','/capabilities')
            if caps.get('edition')!='COMMUNITY' or caps.get('active_replay') is not True:
                raise HTTPException(409,'Community connector does not advertise replay capability')
            consumed=await db.scalar(select(func.count()).select_from(WebAction).where(WebAction.session_id==session_id,WebAction.state.in_(ADMITTED)))
            budget=min(int((session.scope or {}).get('web_request_budget',20)),20)
            if consumed>=budget: raise HTTPException(409,'Engagement replay budget exhausted')
            spec=unseal(row.protected_spec)
            row.state='claimed'
            row.updated_at=datetime.utcnow()
            # Required commit precedes the physical connector request; no retry on ambiguity.
            await db.commit()
            expires=int(row.expires_at.replace(tzinfo=timezone.utc).timestamp())
            signed='\n'.join([row.id,session_id,row.request_digest,spec['target'],str(spec['port']),str(spec['timeout_ms']),str(expires),str(budget)])
            permit=hmac.new(settings.BURP_CONNECTOR_TOKEN.encode(),signed.encode(),hashlib.sha256).hexdigest()
            form={'action_id':row.id,'session_id':session_id,'request_digest':row.request_digest,
                'target':spec['target'],'port':str(spec['port']),'timeout_ms':str(spec['timeout_ms']),
                'expires_at':str(expires),'budget':str(budget),'request_b64':spec['request_b64'],'permit':permit}
        try:
            result=await self.connector('POST','/jobs',form)
        except HTTPException:
            result={'state':'unknown','reason_code':'connector_outcome_unknown'}
        return await self._record(session_id,user_id,action_id,result)

    async def _record(self,session_id,user_id,action_id,result):
        async with async_session() as db:
            _,row=await self._load(db,session_id,user_id,action_id,check_scope=False)
            state=result.get('state','unknown')
            if state not in {'queued','running','completed','failed','unknown','cancel_requested','cancelled'}:
                state='unknown'
            row.state=('cancel_requested' if row.state=='cancel_requested' else 'claimed') if state in {'queued','running'} else 'cancelled_after_dispatch' if state=='cancelled' else state
            if result.get('response_b64') and state=='completed':
                raw=base64.b64decode(result['response_b64'],validate=True)
                if len(raw)>1048576: raise HTTPException(502,'Connector response exceeds evidence limit')
                spec=unseal(row.protected_spec)
                baseline=base64.b64decode(spec['baseline_response_b64'])
                from memory.burp_community import credential_values
                secrets=credential_values(base64.b64decode(spec['request_b64']))
                row.protected_response=seal({'response_b64':result['response_b64']})
                comparison={'status_line':raw.partition(b'\r\n')[0].decode('iso-8859-1'),
                    'response_sha256':hashlib.sha256(raw).hexdigest(),'baseline_sha256':hashlib.sha256(baseline).hexdigest(),
                    'changed':raw!=baseline,'response_bytes':len(raw),'response_preview':redact(raw.decode('iso-8859-1')[:16000],secrets),
                    'verification_status':'observation','evidence_id':row.evidence_id}
                row.result={**row.result,'comparison':comparison}
                if await db.get(ChatLog,row.id) is None:
                    db.add(ChatLog(id=row.id,session_id=session_id,role='tool_output',msg_type='burp_replay',
                        content=json.dumps(comparison),data={'schema_version':1,'source':'burp_community_replay',
                            'action_id':row.id,'evidence_id':row.evidence_id,'comparison':comparison}))
            if result.get('reason_code'): row.result={**row.result,'reason_code':result['reason_code']}
            row.updated_at=datetime.utcnow()
            await db.commit()
            return public(row)

    async def status(self,session_id,user_id,action_id):
        async with async_session() as db:
            _,row=await self._load(db,session_id,user_id,action_id,check_scope=False)
            response=public(row)
        if response['state'] in {'claimed','unknown','cancel_requested'}:
            try: result=await self.connector('GET','/jobs/'+action_id)
            except HTTPException: return response
            return await self._record(session_id,user_id,action_id,result)
        return response

    async def cancel(self,session_id,user_id,action_id):
        async with async_session() as db:
            _,row=await self._load(db,session_id,user_id,action_id,check_scope=False)
            if row.state in TERMINAL|{'rejected'}: return public(row)
            remote=row.state in ADMITTED
            row.state='cancel_requested' if remote else 'cancelled'
            await db.commit()
            response=public(row)
        if remote:
            try: result=await self.connector('POST','/jobs/'+action_id+'/cancel',{})
            except HTTPException: return response
            return await self._record(session_id,user_id,action_id,result)
        return response

    async def list(self,session_id,user_id):
        async with async_session() as db:
            await self._session(db,session_id,user_id)
            rows=(await db.execute(select(WebAction).where(WebAction.session_id==session_id,
                WebAction.requester_id==user_id).order_by(WebAction.updated_at.desc()).limit(100))).scalars().all()
            return [public(row) for row in rows]

    async def cancel_all(self,session_id,user_id):
        rows=await self.list(session_id,user_id)
        results=[]
        for row in rows:
            if row['state'] not in TERMINAL|{'rejected'}:
                results.append(await self.cancel(session_id,user_id,row['action_id']))
        return {'pending':sum(row['state']=='cancel_requested' for row in results),'actions':results}

    async def revoke_principal(self,user_id):
        remote=[]
        async with async_session() as db:
            rows=(await db.execute(select(WebAction).where(WebAction.requester_id==user_id,
                WebAction.state.in_({'pending','approved','claimed','unknown','cancel_requested'})).with_for_update())).scalars().all()
            for row in rows:
                if row.state in ADMITTED:
                    row.state='cancel_requested'; remote.append(row.id)
                else: row.state='cancelled'
            await db.commit()
        pending=0
        for action_id in remote:
            try: result=await self.connector('POST','/jobs/'+action_id+'/cancel',{})
            except HTTPException: pending+=1; continue
            async with async_session() as db:
                row=await db.get(WebAction,action_id)
                if row is not None and row.requester_id==user_id and row.state=='cancel_requested':
                    if result.get('state')=='cancelled': row.state='cancelled_after_dispatch'
                    elif result.get('state') not in {'completed','failed'}: pending+=1
                    else: row.state='unknown'; pending+=1
                    await db.commit()
        return {'pending':pending,'actions_cancelled_or_requested':len(rows)}

    async def recover(self):
        async with async_session() as db:
            rows=(await db.execute(select(WebAction).where(WebAction.state.in_({'claimed','cancel_requested'})).with_for_update())).scalars().all()
            for row in rows:
                row.state='unknown'
                row.result={**row.result,'reason_code':'restart_reconciliation_no_replay'}
            await db.commit()


web_actions=WebActions()
