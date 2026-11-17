"""Negative audit fixtures; no elapsed duration is actually exercised here."""
from collections import Counter
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import uuid

from integration.reliability_endurance_evidence import EXPECTED, validate_endurance


class EnduranceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.session = str(uuid.uuid4())
        self.work = {'synthetic':True,'benchmark_passed':True,'session_id':self.session,
            'expected_operations':12,'recorded_operations':12,'simulated_runtime_starts':12,
            'duplicate_dispatches':0,'lost_operations':0,'unauthorized_dispatches':0,
            'actual_external_provider_calls':0,'actual_tools_executed':0,'wall_seconds':7,
            'counters':{'forbidden_network_attempts':0},'operations':[
                {'number':n,'state':state,'expected_state':state,'job_id':str(uuid.uuid4()),
                 'events':[{'state':state}]} for n,state in enumerate(EXPECTED,1)]}
        self.result = {'status':'VERIFIED','synthetic':True,'application_transport':'in_process_ASGI',
            'requested_seconds':900,'elapsed_seconds':900.001,'completed_batches':1,
            'recorded_operations':12,'availability_samples':1,'availability_failures':0,
            'batch_failures':0,'actual_tools_executed':0,'physical_external_provider_calls':0,
            'duplicate_dispatches':0,'lost_operations':0,'unauthorized_dispatches':0,
            'maximum_database_connections':2,'expected_faults':dict(Counter(EXPECTED)),
            'cpu_seconds':1,'initial_rss_kb':1000,'current_rss_kb':1001,
            'rss_growth_kb':1,'sampled_peak_rss_kb':1001}
        self.sample = {'elapsed_seconds':1,'available':True,'api_readiness_wall_ms':2,
            'database_connections':2,'current_rss_kb':1001,'memory_available_kb':1024*1024,
            'disk_available_bytes':1024*1024*1024}
        (self.root/'batch-0001').mkdir()
        self.write_all()

    def write_all(self):
        for name,data in (('result.json',self.result),('checkpoint.json',self.result),
                          ('source-manifest.json',{'fixture.py':'a'*64}),
                          ('batch-0001/workload.json',self.work)):
            (self.root/name).write_text(json.dumps(data)+'\n')
        (self.root/'samples.jsonl').write_text(json.dumps(self.sample)+'\n')
        (self.root/'batches.jsonl').write_text(json.dumps({'number':1,'passed':True,
            'session_id':self.session,'wall_seconds':7})+'\n')

    def check(self):
        return validate_endurance(self.root,900)

    def test_consistent_unsigned_artifacts_report_only_their_bounded_scope(self):
        result=self.check()
        self.assertEqual(result['operations'],12)
        self.assertTrue(result['synthetic'])
        self.assertEqual(len(result['sha256']),6)
        self.assertIn('not independent clock attestation',result['limitations'][0])

    def test_short_cancelled_partial_and_wrong_duration_never_pass(self):
        for status in ('CANCELLED','IN_PROGRESS','FAILED','HARNESS_SMOKE_PASSED'):
            self.result['status']=status;self.write_all()
            with self.subTest(status=status),self.assertRaises(ValueError):self.check()
        self.result['status']='VERIFIED';self.result['elapsed_seconds']=899.999;self.write_all()
        with self.assertRaises(ValueError):self.check()
        self.result['elapsed_seconds']=900.001;self.result['requested_seconds']=7200;self.write_all()
        with self.assertRaises(ValueError):self.check()

    def test_missing_raw_batch_or_source_provenance_never_pass(self):
        for name in ('batch-0001/workload.json','samples.jsonl','source-manifest.json','result.json'):
            self.write_all();(self.root/name).unlink()
            with self.subTest(name=name),self.assertRaises(ValueError):self.check()

    def test_duplicate_job_foreign_session_and_changed_outcome_never_pass(self):
        self.work['operations'][1]['job_id']=self.work['operations'][0]['job_id'];self.write_all()
        with self.assertRaises(ValueError):self.check()
        self.work['operations'][1]['job_id']=str(uuid.uuid4());self.work['session_id']=str(uuid.uuid4());self.write_all()
        with self.assertRaises(ValueError):self.check()
        self.work['session_id']=self.session;self.work['operations'][0]['state']='cancelled';self.write_all()
        with self.assertRaises(ValueError):self.check()

    def test_unknown_bool_nonfinite_and_unavailable_measurements_fail(self):
        for key,value in (('duplicate_dispatches',None),('lost_operations',True),
                          ('elapsed_seconds',float('nan')),('cpu_seconds',float('inf'))):
            old=self.result[key];self.result[key]=value;self.write_all()
            with self.subTest(key=key),self.assertRaises(ValueError):self.check()
            self.result[key]=old
        for key,value in (('available',False),('error_type','TimeoutError'),
                          ('database_connections',None),('memory_available_kb',1)):
            old=dict(self.sample);self.sample[key]=value;self.write_all()
            with self.subTest(key=key),self.assertRaises(ValueError):self.check()
            self.sample=old

    def test_final_checkpoint_and_raw_counts_must_agree(self):
        (self.root/'checkpoint.json').write_text('{}')
        with self.assertRaises(ValueError):self.check()
        self.result['completed_batches']=2;self.write_all()
        with self.assertRaises(ValueError):self.check()

    def test_requested_smoke_or_boolean_duration_is_not_acceptance(self):
        for duration in (20,True,28801):
            with self.subTest(duration=duration),self.assertRaises(ValueError):
                validate_endurance(self.root,duration)

    def test_legacy_fifteen_minute_rusage_is_not_claimed_as_sampled_peak(self):
        self.result.pop('sampled_peak_rss_kb')
        self.result['peak_rss_kb']=1002
        self.write_all()
        self.assertTrue(self.check()['legacy_rusage_peak_only'])
        self.result['requested_seconds']=14400;self.result['elapsed_seconds']=14400
        self.write_all()
        with self.assertRaises(ValueError):validate_endurance(self.root,14400)

    def test_post_readiness_diagnostic_loss_stays_unavailable_without_inventing_outage(self):
        self.result['availability_samples']=2;self.write_all()
        diagnostic={**self.sample,'elapsed_seconds':5,'error_type':'AttributeError','database_connections':None}
        with (self.root/'samples.jsonl').open('a') as file:file.write(json.dumps(diagnostic)+'\n')
        result=self.check()
        self.assertEqual(result['unavailable_database_samples'],1)
        self.assertEqual(result['diagnostic_error_types'],{'AttributeError':1})
        diagnostic['available']=False
        (self.root/'samples.jsonl').write_text(json.dumps(self.sample)+'\n'+json.dumps(diagnostic)+'\n')
        with self.assertRaises(ValueError):self.check()
