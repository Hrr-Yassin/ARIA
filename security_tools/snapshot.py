"""A single bounded GET, used only inside the isolated worker container."""
import http.client
from urllib.parse import urlsplit


def fetch(url: str) -> tuple[int, list[tuple[str, str]], bytes]:
    from security_tools.models import URLInput
    URLInput(url=url)
    parsed = urlsplit(url)
    cls = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
    connection = cls(parsed.hostname, parsed.port, timeout=5)
    try:
        connection.request('GET', parsed.path or '/', headers={'User-Agent': 'ARIA-observer/1', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        body = response.read(32769)
        if len(body) > 32768 or not 100 <= response.status <= 599 or 300 <= response.status <= 399:
            raise ValueError('Response exceeds observation policy')
        headers = response.getheaders()
        if sum(len(k) + len(v) for k, v in headers) > 16384:
            raise ValueError('Response headers exceed bound')
        return response.status, headers, body
    finally:
        connection.close()
