"""Real JVM/HTTP/persistent-file connector tests; the HTTP sender is a controlled fixture.
No model, owner database, Burp license, or external target is used.
"""
import base64
import hashlib
import hmac
import json
import os
import select
import secrets
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path
import httpx

ROOT=Path(__file__).resolve().parents[1]


class CommunityBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work=tempfile.TemporaryDirectory(prefix='aria-community-boundary-')
        cls.classes=Path(cls.work.name)/'classes'; cls.classes.mkdir()
        subprocess.run(['javac','--release','17','-d',str(cls.classes),str(ROOT/'burp-community/src/aria/ReplayBoundary.java'),str(ROOT/'integration/java/ReplayFixtureServer.java')],check=True)

    @classmethod
    def tearDownClass(cls): cls.work.cleanup()

    def setUp(self):
        self.token=secrets.token_hex(32)
        self.directory=tempfile.TemporaryDirectory(prefix='aria-replay-ledger-')
        self.ledger=Path(self.directory.name)/'jobs.properties'
        self.start()

    def start(self):
        self.process=subprocess.Popen(['java','-cp',str(self.classes),'aria.ReplayFixtureServer',str(self.ledger)],env={**os.environ,'ARIA_FIXTURE_TOKEN':self.token},stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if not select.select([self.process.stdout],[],[],10)[0]: raise RuntimeError('JVM fixture did not start')
        port=int(self.process.stdout.readline().strip())
        self.client=httpx.Client(base_url='http://127.0.0.1:'+str(port),headers={'Authorization':'Bearer '+self.token},timeout=5,trust_env=False)

    def stop(self):
        self.client.close(); self.process.terminate(); self.process.wait(timeout=10)
        self.process.stdout.close(); self.process.stderr.close()

    def tearDown(self): self.stop(); self.directory.cleanup()

    def proposal(self,raw=None,session=None,action=None,budget=20,timeout=10000):
        raw=raw or b'GET / HTTP/1.1\r\nHost: 192.0.2.1\r\nAuthorization: Bearer synthetic-fixture-token\r\n\r\n'
        data={'action_id':action or str(uuid.uuid4()),'session_id':session or str(uuid.uuid4()),'request_digest':hashlib.sha256(raw).hexdigest(),
            'target':'192.0.2.1','port':'80','timeout_ms':str(timeout),'expires_at':str(int(time.time())+60),'budget':str(budget),'request_b64':base64.b64encode(raw).decode()}
        self.sign(data); return data

    def sign(self,data):
        value='\n'.join(data[key] for key in ['action_id','session_id','request_digest','target','port','timeout_ms','expires_at','budget'])
        data['permit']=hmac.new(self.token.encode(),value.encode(),hashlib.sha256).hexdigest()

    def wait(self,action,states):
        deadline=time.monotonic()+6
        while time.monotonic()<deadline:
            result=self.client.get('/jobs/'+action).json()
            if result['state'] in states: return result
            time.sleep(.03)
        self.fail('Connector did not reach '+str(states))

    def test_exact_credentials_duplicate_budget_and_restart(self):
        first=self.proposal(budget=1)
        self.assertEqual(self.client.post('/jobs',data=first).status_code,200)
        self.assertEqual(self.wait(first['action_id'],{'completed'})['state'],'completed')
        self.assertEqual(self.client.post('/jobs',data=first).status_code,200)
        stats=self.client.get('/stats').json()
        self.assertEqual(stats['calls'],1)
        self.assertEqual(stats['captured_b64'],first['request_b64'])
        extra=self.proposal(session=first['session_id'],budget=1)
        self.assertEqual(self.client.post('/jobs',data=extra).status_code,422)
        self.stop(); self.start()
        self.assertEqual(self.client.post('/jobs',data=first).json()['state'],'unknown')
        self.assertEqual(self.client.get('/stats').json()['calls'],0)
        self.assertNotIn('synthetic-fixture-token',self.ledger.read_text())
        self.assertEqual(self.ledger.stat().st_mode&0o777,0o600)

    def test_modified_unsigned_expired_scope_and_framing_requests_never_send(self):
        attempts=[]
        bad=self.proposal(); bad['permit']='0'*64; attempts.append(bad)
        bad=self.proposal(); bad['expires_at']=str(int(time.time())-2); self.sign(bad); attempts.append(bad)
        bad=self.proposal(); bad['target']='198.51.100.1'; self.sign(bad); attempts.append(bad)
        bad=self.proposal(); bad['port']='22'; self.sign(bad); attempts.append(bad)
        bad=self.proposal(); bad['request_b64']=base64.b64encode(b'GET /changed HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n').decode(); attempts.append(bad)
        attempts.append(self.proposal(b'POST / HTTP/1.1\r\nHost: 192.0.2.1\r\nContent-Length: 2\r\n\r\nabc'))
        for data in attempts: self.assertEqual(self.client.post('/jobs',data=data).status_code,422)
        self.assertEqual(self.client.get('/stats').json()['calls'],0)
        self.assertEqual(self.client.post('/jobs',data=self.proposal(),headers={'Authorization':'Bearer invalid'}).status_code,403)

    def test_running_cancellation_and_deadline_have_acknowledged_terminal_states(self):
        for timeout in [10000,200]:
            data=self.proposal(b'GET /slow HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n',timeout=timeout)
            self.assertEqual(self.client.post('/jobs',data=data).status_code,200)
            self.wait(data['action_id'],{'running'})
            if timeout==10000: self.client.post('/jobs/'+data['action_id']+'/cancel')
            self.assertEqual(self.wait(data['action_id'],{'cancelled'})['state'],'cancelled')

    def test_storage_failure_prevents_sender_admission(self):
        os.chmod(self.directory.name,0o500)
        try: self.assertEqual(self.client.post('/jobs',data=self.proposal()).status_code,422)
        finally: os.chmod(self.directory.name,0o700)
        self.assertEqual(self.client.get('/stats').json()['calls'],0)


if __name__=='__main__': unittest.main(verbosity=2)
