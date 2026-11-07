"""Container-only HTTP client: one request, no redirects/retries/proxies, bounded IO."""
import base64
import hashlib
import http.client
import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from worker.http_profile import cipher, decode


def run(plan):
    key = Path('/run/aria-http-key').read_text().strip()
    spec = decode(plan['protected_http'], plan['http_command'], key)
    parts = urlsplit(spec['url'])
    connection_class = http.client.HTTPSConnection if parts.scheme == 'https' else http.client.HTTPConnection
    kwargs = {'timeout': 10}
    if parts.scheme == 'https':
        kwargs['context'] = ssl.create_default_context()
    connection = connection_class(parts.hostname, parts.port, **kwargs)
    try:
        target = (parts.path or '/') + ('?' + parts.query if parts.query else '')
        body_bytes = spec.get('body', '').encode('ascii')
        connection.putrequest(spec['method'], target, skip_host=True, skip_accept_encoding=True)
        connection.putheader('Host', parts.netloc)
        for name, value in spec['headers'].items():
            connection.putheader(name, value)
        body_headers = ''
        if spec['method'] == 'PUT':
            connection.putheader('Content-Type', 'application/json')
            connection.putheader('Content-Length', str(len(body_bytes)))
            body_headers = 'Content-Type: application/json\r\nContent-Length: ' + str(len(body_bytes)) + '\r\n'
        request_raw = (spec['method'] + ' ' + target + ' HTTP/1.1\r\nHost: ' + parts.netloc + '\r\n' +
                       ''.join(name + ': ' + value + '\r\n' for name, value in spec['headers'].items()) + body_headers + '\r\n').encode('iso-8859-1') + body_bytes
        connection.endheaders(body_bytes or None)
        response = connection.getresponse()
        body = response.read(32769)
        head = ('HTTP/1.1 ' + str(response.status) + ' ' + response.reason + '\r\n' +
                '\r\n'.join(name + ': ' + value for name, value in response.getheaders()) + '\r\n\r\n').encode('iso-8859-1')
        raw = head + body
        if len(raw) > 32768:
            raise ValueError('Bounded response exceeded')
        protected = cipher(key).encrypt(json.dumps({'response_b64': base64.b64encode(raw).decode(),
                                                  'request_b64': base64.b64encode(request_raw).decode()}).encode()).decode()
        print(json.dumps({'profile': 'aria-http-v1', 'status': response.status,
                          'response_sha256': hashlib.sha256(raw).hexdigest(), 'protected_response': protected}))
        return 0
    except Exception:
        # Never log reflected bodies, credentials or exception strings.
        print(json.dumps({'profile': 'aria-http-v1', 'error': 'bounded_http_failed'}))
        return 1
    finally:
        connection.close()
