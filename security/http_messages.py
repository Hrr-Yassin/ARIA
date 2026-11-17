"""Bounded HTTP/1 capture parsing; never opens a connection or follows a URL."""
from __future__ import annotations

import re

TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


def headers(lines: list[str]) -> list[tuple[str, str]]:
    """Preserve duplicate fields while rejecting ambiguous names/control bytes."""
    result = []
    if len(lines) > 256:
        raise ValueError('Too many captured HTTP fields')
    for line in lines:
        name, sep, value = line.partition(':')
        if not sep or not TOKEN.fullmatch(name) or re.search(r'[\x00-\x08\x0a-\x1f\x7f]', value):
            raise ValueError('Invalid captured HTTP field')
        result.append((name.lower(), value.strip(' \t')))
    return result


def content_length(fields: list[tuple[str, str]]) -> int | None:
    values = [v for k, v in fields if k == 'content-length']
    if len(values) > 1 or (values and not re.fullmatch(r'[0-9]{1,10}', values[0])):
        raise ValueError('Ambiguous or invalid Content-Length')
    return int(values[0]) if values else None


def chunked_length(body: bytes) -> int:
    """Validate bounded chunk framing without disclosing or executing content."""
    offset = total = 0
    for _ in range(10000):
        end = body.find(b'\r\n', offset)
        if end < 0:
            break
        line = body[offset:end]
        size = line.split(b';', 1)[0]
        if not re.fullmatch(b'[0-9A-Fa-f]{1,8}', size) or re.search(b'[\x00-\x1f\x7f]', line):
            break
        length = int(size, 16)
        offset = end + 2
        if not length:
            if body[offset:] == b'\r\n':
                return total
            trailer = body[offset:]
            if trailer.endswith(b'\r\n\r\n'):
                parsed = headers(trailer[:-4].decode('iso-8859-1').split('\r\n'))
                if not any(k in {'content-length', 'transfer-encoding', 'host'} for k, _ in parsed):
                    return total
            break
        if length > len(body) - offset or body[offset + length:offset + length + 2] != b'\r\n':
            break
        total += length
        offset += length + 2
    raise ValueError('Invalid captured chunk framing')


def response_metadata(raw: bytes, request_method: str) -> dict:
    """Parse one final HTTP/1 response; absent captures remain explicit unknowns."""
    if not raw:
        return {'response_status': None, 'response_protocol': None, 'response_headers': [],
                'response_body_bytes': None, 'response_framing': 'no_response_observed'}
    head, sep, body = raw.partition(b'\r\n\r\n')
    if not sep or len(head) > 65536:
        raise ValueError('Invalid or oversized captured response headers')
    lines = head.decode('iso-8859-1').split('\r\n')
    status = re.fullmatch(r'(HTTP/1\.[01]) ([2-5][0-9]{2})(?: [^\x00-\x1f\x7f]*)?', lines[0])
    if not status:
        raise ValueError('Expected one final HTTP/1 response')
    fields = headers(lines[1:])
    length = content_length(fields)
    encodings = [v.lower() for k, v in fields if k == 'transfer-encoding']
    if encodings and (length is not None or encodings != ['chunked']):
        raise ValueError('Ambiguous or unsupported response transfer framing')
    code = int(status[2])
    if request_method == 'HEAD' or code in {204, 304}:
        if body:
            raise ValueError('Unexpected response body for HEAD/204/304')
        if code == 204 and (length is not None or encodings):
            raise ValueError('Invalid204response framing')
        size, framing = 0, 'bodyless'
    elif encodings:
        size, framing = chunked_length(body), 'validated_chunked'
    else:
        if length is not None and length != len(body):
            raise ValueError('Captured response length mismatch')
        size = len(body)
        framing = 'content_length' if length is not None else 'close_delimited_capture'
    return {'response_status': code, 'response_protocol': status[1],
            'response_headers': fields, 'response_body_bytes': size, 'response_framing': framing}
