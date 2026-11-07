"""Bounded public HTTPS policy retrieval with DNS pinning and no redirects/proxies."""
import asyncio
import hashlib
import ipaddress
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_BODY = 200000


class PolicyText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'noscript'}:
            self.hidden += 1
        if not self.hidden and tag in {'p', 'li', 'div', 'br', 'h1', 'h2', 'h3', 'h4', 'tr'}:
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'noscript'}:
            self.hidden = max(0, self.hidden - 1)
        if not self.hidden and tag in {'p', 'li', 'div', 'h1', 'h2', 'h3', 'h4', 'tr'}:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def public_addresses(records: list) -> list[str]:
    addresses = sorted({record[4][0] for record in records})
    if not addresses or len(addresses) > 32:
        raise ValueError('Invalid DNS answer')
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (not ip.is_global or ip.is_multicast or ip.is_reserved
                or getattr(ip, 'ipv4_mapped', None) is not None):
            raise ValueError('Policy retrieval requires public addresses')
    return addresses


async def fetch_policy(url: str) -> dict:
    """No cookies, credentials, redirects, compression, ambient proxies or retries."""
    parts = urlsplit(url)
    if (parts.scheme != 'https' or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.fragment or parts.port not in {None, 443} or len(url) > 2048
            or any(ord(c) < 33 or ord(c) > 126 for c in url)):
        raise ValueError('Use a public HTTPS policy URL on port 443')
    async with asyncio.timeout(15):
        records = await asyncio.get_running_loop().getaddrinfo(parts.hostname, 443, type=socket.SOCK_STREAM)
        addresses = public_addresses(records)
        # Connect to the validated numeric IP; TLS validates the original hostname.
        reader, writer = await asyncio.open_connection(addresses[0], 443, ssl=ssl.create_default_context(),
                                                       server_hostname=parts.hostname, limit=16384)
        try:
            path = parts.path or '/'
            if parts.query:
                path += '?' + parts.query
            writer.write((f'GET {path} HTTP/1.1\r\nHost: {parts.hostname}\r\n'
                          'User-Agent: ARIA-Policy-Importer/1\r\nAccept: text/html,text/plain\r\n'
                          'Accept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii'))
            await writer.drain()
            head = await reader.readuntil(b'\r\n\r\n')
            lines = head.decode('iso-8859-1').split('\r\n')
            status = lines[0].split(' ', 2)
            if len(status) < 2 or status[0] not in {'HTTP/1.0', 'HTTP/1.1'} or status[1] != '200':
                raise ValueError('Policy page unavailable; use manual import for redirects or authenticated pages')
            headers = {}
            for line in lines[1:]:
                if not line:
                    continue
                name, value = line.split(':', 1)
                key = name.lower()
                if key in headers:
                    raise ValueError('Ambiguous response headers')
                headers[key] = value.strip()
            kind = headers.get('content-type', '').split(';')[0].strip().lower()
            if kind not in {'text/html', 'text/plain'} or headers.get('content-encoding', 'identity') != 'identity':
                raise ValueError('Expected an uncompressed HTML or text policy')
            data = bytearray()
            if 'transfer-encoding' in headers:
                if headers['transfer-encoding'].lower() != 'chunked' or 'content-length' in headers:
                    raise ValueError('Unsupported response framing')
                while True:
                    size_line = await reader.readuntil(b'\r\n')
                    if len(size_line) > 32:
                        raise ValueError('Invalid chunk')
                    size = int(size_line.strip(), 16)
                    if size < 0 or len(data) + size > MAX_BODY:
                        raise ValueError('Policy exceeds import limit')
                    if size == 0:
                        break
                    data.extend(await reader.readexactly(size))
                    if await reader.readexactly(2) != b'\r\n':
                        raise ValueError('Invalid chunk framing')
            else:
                length = int(headers.get('content-length', MAX_BODY + 1))
                if length < 0 or ('content-length' in headers and length > MAX_BODY):
                    raise ValueError('Policy exceeds import limit')
                while len(data) <= MAX_BODY:
                    chunk = await reader.read(min(16384, MAX_BODY + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                if len(data) > MAX_BODY or ('content-length' in headers and len(data) != length):
                    raise ValueError('Policy response is oversized or incomplete')
            raw = bytes(data)
            text = raw.decode('utf-8', errors='strict')
            if kind == 'text/html':
                parser = PolicyText()
                parser.feed(text)
                text = '\n'.join(line.strip() for line in ''.join(parser.parts).splitlines() if line.strip())
            if len(text.strip()) < 40:
                raise ValueError('No readable policy; use manual text import')
            return {'text': text, 'response_sha256': hashlib.sha256(raw).hexdigest()}
        finally:
            writer.close()
            await writer.wait_closed()
