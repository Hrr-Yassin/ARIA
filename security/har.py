"""Bounded display projections for selected HTTP archive records."""
import json
import re
from collections.abc import Iterable
from itertools import islice
from urllib.parse import parse_qsl, urlsplit

from security.redaction import SENSITIVE, deployment_secrets, redact

HAR_CAPTURE_TYPE = 'mission_har_capture'
MAX_HAR_BYTES = 1024 * 1024
MAX_HAR_ENTRIES = 100
MAX_PREVIEW_INPUT = 32 * 1024
MAX_PREVIEW_CHARS = 4096
MAX_HEADERS = 256

MEDIA_TYPES = frozenset({'application/json', 'application/problem+json', 'application/xml',
                         'application/x-www-form-urlencoded', 'application/octet-stream',
                         'text/html', 'text/plain', 'text/css', 'text/javascript', 'multipart/form-data'})
ENCODINGS = frozenset({'br', 'chunked', 'compress', 'deflate', 'gzip', 'identity', 'zstd'})
PRIVATE_HEADERS = frozenset({'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'x-api-key',
                             'x-auth-token', 'x-csrf-token', 'x-xsrf-token'})
PRIVATE_NAME = re.compile(r'csrf|xsrf|credential|session[-_]?id|token|^(?:key|sid|session|pin)$', re.I)
FIELD_PAIR = re.compile(r'''(?<![\w-])(?P<key>[\w-]{1,128})["']?[ \t]*[:=][ \t]*(?P<value>"[^"\n]*"|'[^'\n]*'|[^\s,;}&]+)''')
HIDDEN_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff\u202a-\u202e\u2066-\u2069]')


def mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def header_rows(headers: object) -> Iterable[tuple[str, str]]:
    if isinstance(headers, dict):
        values = islice(headers.items(), MAX_HEADERS)
    elif isinstance(headers, list):
        values = ((row.get('name'), row.get('value')) for row in headers[:MAX_HEADERS] if isinstance(row, dict))
    else:
        return
    for name, value in values:
        if isinstance(name, str) and len(name) <= 128 and isinstance(value, str):
            yield name.lower(), value


def media_type_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.partition(';')[0].strip().lower()
    return candidate if candidate in MEDIA_TYPES else 'other'


def media_type(headers: object) -> str | None:
    values = [value for name, value in header_rows(headers) if name == 'content-type']
    return media_type_value(values[0]) if len(values) == 1 else None


def safe_headers(headers: object) -> dict:
    """Use recognized field names and closed value grammars, including credential markers."""
    omitted = len(headers) if isinstance(headers, (dict, list)) else 0
    visible = []
    for name, raw in header_rows(headers):
        value = None
        if name in PRIVATE_HEADERS:
            value = '[REDACTED]'
        elif name == 'content-type':
            value = media_type_value(raw)
        elif name == 'content-length' and re.fullmatch(r'[0-9]{1,10}', raw):
            value = raw
        elif name in {'content-encoding', 'transfer-encoding', 'accept-encoding'} and len(raw) <= 80:
            tokens = [item.strip().lower() for item in raw.split(',')]
            if all(token in ENCODINGS for token in tokens):
                value = ', '.join(tokens)
        elif name == 'cache-control' and len(raw) <= 120:
            tokens = [item.strip().lower() for item in raw.split(',')]
            if all(re.fullmatch(r'no-cache|no-store|private|public|must-revalidate|(?:s-maxage|max-age)=[0-9]{1,10}',
                                token) for token in tokens):
                value = ', '.join(tokens)
        if value is not None:
            visible.append({'name': name, 'value': value})
    return {'headers': visible, 'omitted_headers': omitted - len(visible)}


def private_name(name: str) -> bool:
    return bool(SENSITIVE.search(name) or PRIVATE_NAME.search(name))


def named_secrets(value: object, private: bool = False) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from named_secrets(item, private or private_name(key))
    elif isinstance(value, list):
        for item in value:
            yield from named_secrets(item, private)
    elif private and type(value) in (str, int, float):
        yield str(value)


def capture_secrets(url: str, request: dict, response: dict) -> Iterable[str]:
    yield from deployment_secrets()
    for _, value in parse_qsl(urlsplit(url).query, keep_blank_values=False, max_num_fields=256):
        yield value
    for message in (request, response):
        for name, value in header_rows(message.get('headers')):
            if private_name(name) or name.startswith('x-'):
                yield value
            if name in ('authorization', 'proxy-authorization'):
                yield value.partition(' ')[2].strip()
            if name in ('cookie', 'set-cookie'):
                for part in value.split(';'):
                    yield part.partition('=')[2].strip()
        post = mapping(message.get('postData'))
        for parameters in (message.get('cookies'), message.get('queryString'), post.get('params')):
            if isinstance(parameters, list):
                for item in parameters:
                    value = mapping(item).get('value')
                    if isinstance(value, str):
                        yield value
        if media_type_value(post.get('mimeType')) == 'application/x-www-form-urlencoded' and isinstance(post.get('text'), str):
            for _, value in parse_qsl(post['text'], keep_blank_values=False, max_num_fields=256):
                yield value


def preview(state: str, *, format: str | None = None, text: str | None = None, truncated: bool = False) -> dict:
    return {'state': state, 'format': format, 'text': text, 'truncated': truncated}


def reviewed_previews(url: str, request: dict, response: dict, request_media: str | None,
                      response_media: str | None, include_bodies: bool) -> tuple[dict, dict]:
    """Retain excerpts only when the owner selects already-reviewed body text."""
    sections = (mapping(request.get('postData')), mapping(response.get('content')))
    prepared = []
    secrets: set[str] = set()
    for section, media in zip(sections, (request_media, response_media), strict=True):
        raw = section.get('text')
        if not isinstance(raw, str):
            prepared.append((preview('missing'), None))
        elif not include_bodies:
            prepared.append((preview('not_selected'), None))
        elif section.get('encoding'):
            prepared.append((preview('encoded'), None))
        elif len(raw) > MAX_PREVIEW_INPUT:
            prepared.append((preview('oversized', truncated=True), None))
        elif media in ('application/json', 'application/problem+json'):
            try:
                parsed = json.loads(raw)
                secrets.update(named_secrets(parsed))
            except (ValueError, RecursionError):
                prepared.append((preview('invalid_json'), None))
            else:
                prepared.append((preview('available', format='json'), parsed))
        elif media in ('text/plain', 'text/html', 'text/css', 'text/javascript', 'application/xml'):
            secrets.update(match['value'].strip('"\'') for match in FIELD_PAIR.finditer(raw)
                           if private_name(match['key']))
            prepared.append((preview('available', format='text'), raw))
        else:
            prepared.append((preview('unsupported_media'), None))
    if any(record['state'] == 'available' for record, _ in prepared):
        try:
            secrets.update(value for value in capture_secrets(url, request, response) if value)
        except ValueError:
            return preview('redaction_unavailable'), preview('redaction_unavailable')
        secrets.discard('')
        if len(secrets) > 256:
            return preview('redaction_unavailable'), preview('redaction_unavailable')

    short = [re.escape(value) for value in secrets if len(value) < 4]
    short_pattern = re.compile(r'(?<!\w)(?:' + '|'.join(short) + r')(?!\w)') if short else None

    def clean_text(value: str) -> str:
        value = HIDDEN_CHARS.sub('', value)
        value = redact(value, secrets)
        if short_pattern:
            value = short_pattern.sub('[REDACTED]', value)
        return value

    def clean_json(value):
        if isinstance(value, dict):
            return {clean_text(key): '[REDACTED]' if private_name(key) else clean_json(item) for key, item in value.items()}
        if isinstance(value, list):
            return [clean_json(item) for item in value]
        if isinstance(value, str):
            return clean_text(value)
        return '[REDACTED]' if type(value) in (int, float) and str(value) in secrets else value

    result = []
    for record, parsed in prepared:
        if record['state'] == 'available':
            try:
                if record['format'] == 'json':
                    content = json.dumps(clean_json(parsed), ensure_ascii=True, allow_nan=False, indent=2)
                else:
                    cleaned = FIELD_PAIR.sub(lambda match: match[0][:match.start('value') - match.start()] + '[REDACTED]'
                        if private_name(match['key']) else match[0], parsed)
                    content = clean_text(cleaned)
                record = preview('available', format=record['format'], text=content[:MAX_PREVIEW_CHARS],
                                 truncated=len(content) > MAX_PREVIEW_CHARS)
            except (ValueError, RecursionError):
                record = preview('invalid_json')
        result.append(record)
    return result[0], result[1]
