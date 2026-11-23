"""Owner-scoped traffic inspection over retained and passively imported records."""
import hashlib
import json
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography.fernet import InvalidToken
from fastapi import HTTPException
from sqlalchemy import and_, or_, select

from memory.database_models import ChatLog, PentestSession, async_session
from memory.program_policy import owned_engagement
from security.encryption import evidence_cipher
from security.har import HAR_CAPTURE_TYPE, MAX_HAR_ENTRIES, mapping, media_type, media_type_value, preview, reviewed_previews, safe_headers

METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE', 'CONNECT'})
PROTOCOLS = {'http/1.0': 'HTTP/1.0', 'http/1.1': 'HTTP/1.1', 'http/2': 'HTTP/2', 'http/2.0': 'HTTP/2',
             'h2': 'HTTP/2', 'http/3': 'HTTP/3', 'http/3.0': 'HTTP/3', 'h3': 'HTTP/3'}
FRAMINGS = frozenset({'no_response_observed', 'bodyless', 'validated_chunked', 'content_length',
                     'close_delimited_capture'})
BURP_SOURCE = 'burp_community_selected_history'
WORKER_SOURCE = 'authenticated_worker_receipt'
HAR_SOURCE = 'sanitized_har_import'
CAPTURE_SOURCES = (
    ('burp_evidence', BURP_SOURCE), ('application_capture', WORKER_SOURCE), (HAR_CAPTURE_TYPE, HAR_SOURCE),
)


def recorded_time(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        timestamp = datetime.fromisoformat(value)
        return timestamp.astimezone(timezone.utc).isoformat() if timestamp.utcoffset() is not None else None
    except (OverflowError, ValueError):
        return None


def byte_count(value: object, maximum: int = 2**53 - 1) -> int | None:
    return value if type(value) is int and 0 <= value <= maximum else None


def destination(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 8192 or any(ord(char) < 32 for char in value):
        return None
    try:
        url = urlsplit(value)
        port = url.port
    except ValueError:
        return None
    if url.scheme not in {'http', 'https'} or url.username is not None or url.password is not None:
        return None
    host = url.hostname
    if not host or not re.fullmatch(r'[a-zA-Z0-9.:-]{1,253}', host):
        return None
    address = '[' + host + ']' if ':' in host else host
    return url.scheme + '://' + address + (':' + str(port) if port is not None else '')


def project_capture(record_id: str, imported_at: datetime | None, summary: object, source: str = BURP_SOURCE) -> dict:
    data = mapping(summary)
    method = data.get('method')
    status = data.get('response_status')
    har = source == HAR_SOURCE
    elapsed = data.get('latency_ms') if har else None
    protocol = data.get('response_protocol')
    framing = data.get('response_framing')
    return {
        'id': record_id,
        'source': source,
        'imported_at': (imported_at if imported_at.tzinfo else imported_at.replace(tzinfo=timezone.utc)).isoformat()
        if imported_at else None,
        'captured_at': recorded_time(data.get('captured_at')) if har else None,
        'latency_ms': elapsed if (type(elapsed) is int or type(elapsed) is float) and 0 <= elapsed <= 2**53 - 1 else None,
        'destination': destination(data.get('origin') if source == WORKER_SOURCE else data.get('url')),
        'method': method if isinstance(method, str) and method in METHODS else None,
        'request_content_type': media_type_value(data.get('request_content_type')) if har else media_type(data.get('request_headers')),
        'response_content_type': media_type_value(data.get('response_content_type')) if har else media_type(data.get('response_headers')),
        'response_status': status if type(status) is int and (100 if har else 200) <= status <= 599 else None,
        'request_body_bytes': byte_count(data.get('request_body_bytes')) if har else None,
        'response_body_bytes': byte_count(data.get('response_body_bytes'), 2**53 - 1 if har else 1048576),
        'response_content_bytes': byte_count(data.get('response_content_bytes')) if har else None,
        'protocol': PROTOCOLS.get(protocol.lower()) if isinstance(protocol, str) else None,
        'framing': framing if isinstance(framing, str) and framing in FRAMINGS else None,
    }


def capture_rows(sid: str, owner: str):
    source = ChatLog.data['source'].as_string()
    return select(ChatLog.id, ChatLog.created_at).join(PentestSession).where(
        ChatLog.session_id == sid, PentestSession.user_id == owner,
        or_(*(and_(ChatLog.msg_type == kind, source == provenance) for kind, provenance in CAPTURE_SOURCES)),
    )


async def retained_traffic(sid: str, owner: str, before: str | None, limit: int) -> dict:
    async with async_session() as db:
        records = capture_rows(sid, owner)
        if before:
            cursor = (await db.execute(records.where(ChatLog.id == before))).one_or_none()
            if cursor is None:
                raise HTTPException(404, 'Capture cursor unavailable in this engagement')
            if cursor.created_at is None:
                records = records.where(ChatLog.created_at.is_(None), ChatLog.id < cursor.id)
            else:
                records = records.where(or_(ChatLog.created_at < cursor.created_at,
                    and_(ChatLog.created_at == cursor.created_at, ChatLog.id < cursor.id),
                    ChatLog.created_at.is_(None)))
        query = records.add_columns(ChatLog.data['summary'], ChatLog.data['source'].as_string()).order_by(
            ChatLog.created_at.desc().nulls_last(), ChatLog.id.desc())
        page = (await db.execute(query.limit(limit + 1))).all()
    return {
        'schema_version': 'aria.mission.traffic.v1',
        'session_id': sid,
        'captures': [project_capture(record_id, created, summary, source) for record_id, created, summary, source in page[:limit]],
        'next_before': page[limit - 1][0] if len(page) > limit else None,
    }


def har_records(archive: object, include_bodies: bool) -> tuple[list[dict], int]:
    log = mapping(mapping(archive).get('log'))
    entries = log.get('entries')
    if log.get('version') != '1.2' or not isinstance(entries, list) or not entries:
        raise HTTPException(422, 'Expected a HAR 1.2 archive with at least one entry')
    if len(entries) > MAX_HAR_ENTRIES:
        raise HTTPException(413, 'HTTP archive entry limit exceeded')
    records = []
    for entry in entries:
        request = mapping(mapping(entry).get('request'))
        response = mapping(mapping(entry).get('response'))
        url, method = request.get('url'), request.get('method')
        origin = destination(url)
        if not isinstance(url, str) or not origin or not isinstance(method, str) or method not in METHODS or not response:
            continue
        content = mapping(response.get('content'))
        request_media = media_type(request.get('headers')) or media_type_value(mapping(request.get('postData')).get('mimeType'))
        response_media = media_type(response.get('headers')) or media_type_value(content.get('mimeType'))
        request_preview, response_preview = reviewed_previews(url, request, response, request_media, response_media, include_bodies)
        status, protocol, elapsed = response.get('status'), response.get('httpVersion'), entry.get('time')
        records.append({'summary': {
            'url': origin, 'method': method, 'captured_at': recorded_time(entry.get('startedDateTime')),
            'latency_ms': elapsed if (type(elapsed) is int or type(elapsed) is float) and 0 <= elapsed <= 2**53 - 1 else None,
            'request_content_type': request_media, 'response_content_type': response_media,
            'request_body_bytes': byte_count(request.get('bodySize')), 'response_body_bytes': byte_count(response.get('bodySize')),
            'response_content_bytes': byte_count(content.get('size')),
            'response_status': status if type(status) is int and 100 <= status <= 599 else None,
            'response_protocol': PROTOCOLS.get(protocol.lower()) if isinstance(protocol, str) else None,
            'response_framing': 'no_response_observed' if type(status) is int and status == 0 else None,
        }, 'inspection': {'request': {**safe_headers(request.get('headers')), 'preview': request_preview},
                          'response': {**safe_headers(response.get('headers')), 'preview': response_preview}}})
    if not records:
        raise HTTPException(422, 'The archive contains no supported HTTP exchanges')
    return records, len(entries) - len(records)


def canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def har_metadata_content(capture_id: str, summary: dict) -> str:
    return canonical({'source': HAR_SOURCE, 'capture_id': capture_id, 'metadata': summary}).decode()


def verified_har_inspection(sid: str, capture_id: str, summary: object, sealed: object) -> dict | None:
    if not isinstance(summary, dict) or not isinstance(sealed, str):
        return None
    try:
        payload = mapping(json.loads(evidence_cipher().decrypt(sealed.encode())))
        if (payload.get('session_id'), payload.get('capture_id')) != (sid, capture_id):
            return None
        bound_summary = payload.get('summary')
        if not isinstance(bound_summary, dict) or canonical(bound_summary) != canonical(summary):
            return None
    except (InvalidToken, ValueError, TypeError, RecursionError):
        return None
    inspection = mapping(payload.get('inspection'))
    return inspection if set(inspection) == {'request', 'response'} else None


async def retain_har(sid: str, owner: str, archive: object, include_bodies: bool) -> dict:
    records, skipped = har_records(archive, include_bodies)
    occurrences: Counter[str] = Counter()
    imports = {}
    for record in records:
        fingerprint = hashlib.sha256(canonical(record)).hexdigest()
        occurrences[fingerprint] += 1
        key = str(uuid.uuid5(uuid.NAMESPACE_URL, f'aria-har:{sid}:{fingerprint}:{occurrences[fingerprint]}'))
        imports[key] = record
    async with async_session() as db:
        await owned_engagement(db, sid, owner)
        existing = set((await db.execute(select(ChatLog.id).where(ChatLog.session_id == sid,
            ChatLog.msg_type == HAR_CAPTURE_TYPE, ChatLog.id.in_(imports)))).scalars().all())
        cipher = evidence_cipher()
        for key, record in imports.items():
            if key in existing:
                continue
            summary = record['summary']
            sealed = cipher.encrypt(canonical({'session_id': sid, 'capture_id': key, **record})).decode()
            db.add(ChatLog(id=key, session_id=sid, role='tool_output', msg_type=HAR_CAPTURE_TYPE,
                content=har_metadata_content(key, summary),
                data={'source': HAR_SOURCE, 'summary': summary, 'sealed_inspection': sealed}))
        await db.commit()
    return {'schema_version': 'aria.mission.har-import.v1', 'session_id': sid,
            'imported': len(imports) - len(existing), 'duplicates': len(existing),
            'skipped': skipped, 'capture_ids': list(imports)}


async def retained_capture(sid: str, owner: str, capture_id: str) -> dict:
    async with async_session() as db:
        query = capture_rows(sid, owner).where(ChatLog.id == capture_id).add_columns(
            ChatLog.data['summary'], ChatLog.data['source'].as_string(), ChatLog.data['sealed_inspection'].as_string())
        row = (await db.execute(query)).one_or_none()
    if row is None:
        raise HTTPException(404, 'Capture unavailable in this engagement')
    record_id, created, summary, source, sealed = row
    state = 'historical_metadata'
    if source == HAR_SOURCE:
        state = 'inspection_unavailable'
        inspection = verified_har_inspection(sid, record_id, summary, sealed)
        if inspection is not None:
            return {'schema_version': 'aria.mission.traffic.capture.v1', 'session_id': sid,
                    'capture': project_capture(record_id, created, summary, source), **inspection}
    return {'schema_version': 'aria.mission.traffic.capture.v1', 'session_id': sid,
            'capture': project_capture(record_id, created, summary, source),
            **{side: {**safe_headers(mapping(summary).get(side + '_headers')), 'preview': preview(state)}
               for side in ('request', 'response')}}
