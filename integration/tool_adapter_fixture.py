"""Disposable loopback HTTP contract fixture. Runs no scanners or external requests.

Run: .venv/bin/python -B -m integration.tool_adapter_fixture
The ordinary offline suite mocks sockets. This separate check opens only an
OS-assigned loopback port and cleans up its own server/thread on every outcome.
"""
import http.server
import threading
import tests  # Ephemeral test-process secrets; no production .env changes.
from security_tools.snapshot import fetch


class Fixture(http.server.BaseHTTPRequestHandler):
    hits=[]
    def log_message(self,*args):pass
    def do_GET(self):
        self.hits.append(self.path)
        if self.path=='/redirect':
            self.send_response(302);self.send_header('Location','/forbidden');self.end_headers();return
        body=b'x'*32769 if self.path=='/oversize' else b'<html><title>ARIA deterministic fixture</title></html>'
        self.send_response(200);self.send_header('Content-Type','text/html')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)


def main():
    server=http.server.HTTPServer(('127.0.0.1',0),Fixture)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        url=f'http://127.0.0.1:{server.server_port}'
        status,headers,body=fetch(url+'/')
        assert status==200 and b'ARIA deterministic fixture' in body
        for path in ('/redirect','/oversize'):
            try:fetch(url+path)
            except ValueError:pass
            else:raise AssertionError('Fixture policy was not enforced')
        assert Fixture.hits==['/','/redirect','/oversize'],Fixture.hits
        print('PASS: single-response fixture, redirect refusal, response byte limit; no scanners executed')
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':main()
