"""Community evidence and bounded HTTP checks; no Burp Scanner operations."""
import asyncio
import base64
import hashlib
import hmac
from config.settings import settings
import ipaddress
import json
import shlex
from urllib.parse import urlsplit, parse_qs
from fastapi import HTTPException
from sqlalchemy import select
from memory.database_models import async_session, PentestSession, ChatLog
from security.encryption import evidence_cipher
from security.redaction import redact
from worker.policy import validate_worker_command

LOCKS = {}


def inspect_pair(url, request_b64, response_b64, scope, auth_context='anonymous'):
    parts = urlsplit(url)
    if parts.scheme != 'http' or parts.port not in {None,80} or parts.username or parts.password or parts.fragment:
        raise ValueError('This release supports explicit HTTP targets on TCP80 only')
    ipaddress.ip_address(parts.hostname)
    validate_worker_command(shlex.join(['curl','-I',url]), scope)
    raw, response = base64.b64decode(request_b64, validate=True), base64.b64decode(response_b64, validate=True)
    if len(raw)>65536 or len(response)>1048576: raise ValueError('Evidence size limit exceeded')
    head, sep, body = raw.partition(b'\r\n\r\n')
    if not sep: raise ValueError('Expected an HTTP/1 request with CRLF headers')
    lines = head.decode('iso-8859-1').split('\r\n')
    method, path, version = lines[0].split(' ')
    if method not in {'GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE'} or version not in {'HTTP/1.0','HTTP/1.1'}:
        raise ValueError('Unsupported request line')
    expected = (parts.path or '/') + ('?'+parts.query if parts.query else '')
    if path != expected: raise ValueError('Request target differs from evidence URL')
    headers = []
    for line in lines[1:]:
        name, value = line.split(':',1)
        if not name or name.strip()!=name or any(c.isspace() for c in name): raise ValueError('Invalid header name')
        headers.append((name.lower(), value.strip()))
    hosts = [v for k,v in headers if k=='host']
    if len(hosts)!=1 or hosts[0] not in {parts.hostname, parts.hostname+':80'}: raise ValueError('Host does not match target')
    if any(k in {'transfer-encoding','proxy-authorization'} for k,v in headers):
        raise ValueError('Ambiguous framing or proxy headers are unsupported')
    lengths = [v for k,v in headers if k=='content-length']
    if len(lengths)>1 or (lengths and int(lengths[0])!=len(body)) or (body and not lengths):
        raise ValueError('Invalid request body length')
    authenticated = any(k in {'authorization','cookie','x-api-key'} for k,v in headers)
    auth_fingerprint = hmac.new(settings.SECRET_KEY.encode(), json.dumps([(k,v) for k,v in headers if k in {'authorization','cookie','x-api-key'}]).encode(), hashlib.sha256).hexdigest()[:16] if authenticated else 'anonymous'
    digest = hashlib.sha256(raw+b'\0'+response+b'\0'+auth_fingerprint.encode()).hexdigest()
    secrets = credential_values(raw)
    summary = redact({'url':url, 'method':method, 'endpoint':parts.path or '/',
        'parameters':sorted(parse_qs(parts.query)), 'authentication_context':auth_fingerprint,
        'authentication_label':auth_context, 'request_headers':dict(headers),
        'response_preview':response.decode('iso-8859-1')[:16000]},secrets)
    # Never disclose a raw query string in the public endpoint map.
    summary['url'] = parts.scheme+'://'+parts.netloc+(parts.path or '/')
    return {'digest':digest, 'summary':summary, 'authenticated':authenticated,
        'original':{'url':url, 'request_b64':request_b64, 'response_b64':response_b64}}


async def import_pair(session_id, pair):
    async with async_session() as db:
        await db.execute(select(PentestSession).where(PentestSession.id==session_id).with_for_update())
        existing = (await db.execute(select(ChatLog).where(ChatLog.session_id==session_id,
            ChatLog.msg_type=='burp_evidence', ChatLog.data['digest'].as_string()==pair['digest']))).scalar_one_or_none()
        if existing: return {'evidence_id':existing.id, 'duplicate':True}
        row = ChatLog(session_id=session_id, role='tool_output', msg_type='burp_evidence',
            content=json.dumps(pair['summary']), data={'schema_version':1, 'source':'burp_community_selected_history',
                'digest':pair['digest'], 'authenticated':pair['authenticated'], 'summary':pair['summary'],
                'protected_original':evidence_cipher().encrypt(json.dumps(pair['original']).encode()).decode()})
        db.add(row)
        await db.commit()
        return {'evidence_id':row.id, 'duplicate':False}


async def get_evidence(session_id, evidence_id):
    async with async_session() as db:
        row = (await db.execute(select(ChatLog).where(ChatLog.id==evidence_id,
            ChatLog.session_id==session_id, ChatLog.msg_type=='burp_evidence'))).scalar_one_or_none()
        if not row: raise HTTPException(404,'Evidence not found in this engagement')
        return row.data


def original(data):
    return json.loads(evidence_cipher().decrypt(data['protected_original'].encode()))


def check_command(data, scope):
    if data['authenticated']: raise HTTPException(409,'Authenticated replay requires a separately validated credential transport; use Repeater manually')
    source = original(data)
    pair = inspect_pair(source['url'], source['request_b64'], source['response_b64'], scope)
    raw = base64.b64decode(source['request_b64'])
    head, _, body = raw.partition(b'\r\n\r\n')
    method = pair['summary']['method']
    if method not in {'GET','HEAD'} or body:
        raise HTTPException(409,'Worker checks support bodyless GET/HEAD only; mutations require an explicitly configured extension capability')
    # Disclose the exact check: GET/HEAD availability, without captured custom headers.
    argv = ['curl','--max-time','10'] + (['-I'] if method=='HEAD' else []) + [source['url']]
    return validate_worker_command(shlex.join(argv), scope).command


def credential_values(raw):
    """Known request credentials also redact reflected response values."""
    from urllib.parse import parse_qs
    from security.redaction import SENSITIVE
    head,_,body=raw.partition(b'\r\n\r\n')
    secrets=[]
    for line in head.decode('iso-8859-1').split('\r\n')[1:]:
        key,_,value=line.partition(':')
        if SENSITIVE.search(key):
            secrets.append(value.strip())
            if key.lower()=='authorization': secrets.append(value.strip().split(' ',1)[-1])
            if key.lower()=='cookie': secrets.extend(part.split('=',1)[-1].strip() for part in value.split(';'))
    for key,values in parse_qs(body.decode('utf-8',errors='replace')).items():
        if SENSITIVE.search(key): secrets.extend(values)
    try:
        payload=json.loads(body)
        def collect(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if SENSITIVE.search(key) and isinstance(item,str): secrets.append(item)
                    elif isinstance(item,(dict,list)): collect(item)
            elif isinstance(value,list):
                for item in value: collect(item)
        collect(payload)
    except (ValueError,UnicodeError): pass
    request_line=head.decode('iso-8859-1').split('\r\n',1)[0]
    if '?' in request_line:
        query=request_line.split('?',1)[1].split(' ',1)[0]
        for key,values in parse_qs(query).items():
            if SENSITIVE.search(key) or key.lower()=='token': secrets.extend(values)
    return secrets
