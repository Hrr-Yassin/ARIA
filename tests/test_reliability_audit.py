"""Incomplete evidence cannot become a complete or passing audit."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import copy
from unittest.mock import patch

from integration import reliability_audit as audit


class ReliabilityAuditTests(unittest.TestCase):
    def owner_deferral(self):
        return audit.read_json(Path(__file__).resolve().parents[1] /
            'docs/operational-reliability-owner-decision.json')

    def test_owner_deferral_can_close_engineering_audit_but_never_full_mission(self):
        reqs=[{'requirement_id':rid,'status':status} for rid,status in (
            ('P08-03','VERIFIED'),('P08-04','DEFERRED_BY_OWNER'),
            ('P09-01','VERIFIED'),('P10-01','NOT_STARTED'),
            ('P14-02','DEFERRED_BY_OWNER'))]
        durations={'2h':'VERIFIED','4h':'VERIFIED','8h':'DEFERRED_BY_OWNER'}
        self.assertFalse(audit.completion_claim(reqs,durations,'VERIFIED',self.owner_deferral()))
        with self.assertRaises(ValueError):
            audit.completion_claim(reqs,durations,'VERIFIED')
        for rid in ('P08-04','P14-02'):
            changed=copy.deepcopy(reqs)
            next(r for r in changed if r['requirement_id']==rid)['status']='VERIFIED'
            with self.subTest(rid=rid),self.assertRaises(ValueError):
                audit.completion_claim(changed,durations,'VERIFIED',self.owner_deferral())

    def test_owner_deferral_cannot_hide_other_failures_or_weaken_duration_evidence(self):
        reqs=[{'requirement_id':rid,'status':status} for rid,status in (
            ('P08-01','FAILED'),('P08-03','VERIFIED'),
            ('P08-04','DEFERRED_BY_OWNER'),('P09-01','VERIFIED'))]
        durations={'2h':'VERIFIED','4h':'VERIFIED','8h':'DEFERRED_BY_OWNER'}
        with self.assertRaises(ValueError):
            audit.completion_claim(reqs,durations,'VERIFIED',self.owner_deferral())
        reqs[0]['status']='VERIFIED'
        with self.assertRaises(ValueError):
            audit.completion_claim(reqs,{**durations,'4h':'IN_PROGRESS'},'VERIFIED',self.owner_deferral())
        for key,value in (('duration_seconds',14400),('duration_seconds',28800.0),
                          ('authority','model_suggested'),('disposition','VERIFIED'),
                          ('eight_hour_test_verified',True),('full_mission_complete',True),
                          ('operational_8_5_readiness_demonstrated',True),
                          ('additional_spending_or_target_authorization',True)):
            decision={**self.owner_deferral(),key:value}
            with self.subTest(key=key),self.assertRaises(ValueError):
                audit.completion_claim(reqs,durations,'VERIFIED',decision)

    def test_deferred_requirement_requires_exact_record_and_evidence(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);(root/'docs').mkdir()
            (root/'PLANS.md').write_text('### P08-04: Endurance\n- Status: DEFERRED_BY_OWNER\n'
                '- Acceptance criteria: Exact original criterion\n'
                '- Evidence / limitations: Explicit owner decision;no8h verification\n')
            with patch.object(audit,'ROOT',root),patch.object(audit,'REFERENCES',{'P08-04':('','')}):
                with self.assertRaises(ValueError):audit.requirements()
                (root/'docs/operational-reliability-owner-decision.json').write_text(
                    __import__('json').dumps(self.owner_deferral()))
                result=audit.requirements()[0]
                self.assertEqual(result['status'],'DEFERRED_BY_OWNER')
                self.assertIn('unverified',result['confidence'].lower())

    def test_historical_wall_gap_does_not_invent_measured_suspension(self):
        context=audit.endurance_clock_context({'elapsed_seconds':7200,
            'started_at':'2026-11-15T12:00:00+00:00','finished_at':'2026-11-15T15:02:00+00:00'})
        self.assertEqual(context['utc_timestamp_span_seconds'],10920)
        self.assertEqual(context['utc_span_minus_active_seconds'],3720)
        self.assertIsNone(context['suspended_seconds'])
        self.assertIn('unattributed',context['scope'])

    def test_unfinished_clock_diagnostics_do_not_imply_finished_wall_duration(self):
        context=audit.endurance_clock_context({'elapsed_seconds':4000,
            'boot_elapsed_seconds':15912,'suspended_seconds':11912})
        self.assertEqual(context['suspended_seconds'],11912)
        self.assertIsNone(context['utc_timestamp_span_seconds'])
        self.assertIsNone(context['utc_span_minus_active_seconds'])

    def test_clock_adjustment_difference_stays_signed_and_invalid_values_fail(self):
        result={'elapsed_seconds':600,'started_at':'2026-11-15T12:00:00+00:00',
            'finished_at':'2026-11-15T12:05:00+00:00'}
        self.assertEqual(audit.endurance_clock_context(result)['utc_span_minus_active_seconds'],-300)
        for key,value in (('elapsed_seconds',True),('elapsed_seconds',float('nan')),
                          ('suspended_seconds',-1),('boot_elapsed_seconds',float('inf'))):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                audit.endurance_clock_context({**result,key:value})

    def test_verified_requirement_without_criterion_or_evidence_is_rejected(self):
        base='### P08-04: Endurance\n- Status: VERIFIED\n'
        with TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(audit,'ROOT',root), \
                 patch.object(audit,'REFERENCES',{'P08-04':('','')}):
                for tail in ('','- Acceptance criteria: Complete exact duration\n',
                             '- Evidence / limitations: Completed run\n',
                             '- Acceptance criteria:   \n- Evidence / limitations: Completed run\n'):
                    (root/'PLANS.md').write_text(base+tail)
                    with self.subTest(tail=tail),self.assertRaises(ValueError):
                        audit.requirements()

    def test_unverified_requirement_keeps_unverified_confidence(self):
        with TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'PLANS.md').write_text('### P08-04: Endurance\n- Status: IN_PROGRESS\n'
                '- Acceptance criteria: Complete exact duration\n')
            with patch.object(audit,'ROOT',root), \
                 patch.object(audit,'REFERENCES',{'P08-04':('','')}):
                result=audit.requirements()[0]
                self.assertEqual(result['confidence'],'Unverified for full acceptance')
                self.assertTrue(result['confidence_basis'])

    def test_visible_confidence_does_not_imply_successful_discovery(self):
        with TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'PLANS.md').write_text('### P08-03: Visible\n- Status: VERIFIED\n'
                '- Acceptance criteria: Objective/limit/blocker stop\n'
                '- Evidence / limitations: Actual graphical budget blocker\n')
            with patch.object(audit,'ROOT',root), \
                 patch.object(audit,'REFERENCES',{'P08-03':('','')}):
                result=audit.requirements()[0]
                self.assertIn('blocker',result['confidence_basis'])
                self.assertIn('discovery remains unverified',result['confidence_basis'])

    def test_final_audit_and_endurance_claims_cannot_skip_unverified_requirements(self):
        reqs=[{'requirement_id':rid,'status':'VERIFIED'} for rid in ('P08-03','P08-04','P09-01')]
        durations={'2h':'VERIFIED','4h':'VERIFIED','8h':'VERIFIED'}
        self.assertTrue(audit.completion_claim(reqs,durations,'VERIFIED'))
        for key in ('2h','4h','8h'):
            with self.subTest(duration=key),self.assertRaises(ValueError):
                audit.completion_claim(reqs,{**durations,key:'IN_PROGRESS'},'VERIFIED')
        changed=copy.deepcopy(reqs);changed[1]['status']='IN_PROGRESS'
        with self.assertRaises(ValueError):audit.completion_claim(changed,durations,'VERIFIED')
        changed[-1]['status']='IN_PROGRESS'
        self.assertFalse(audit.completion_claim(changed,durations,'VERIFIED'))
        with self.assertRaises(ValueError):audit.completion_claim(reqs,durations,'BLOCKED')

    def visible_fixture(self):
        browser = {'run_id':'run','session_id':'session','status':'VERIFIED','target':'192.0.2.1',
            'server_build':'tested-build','directory':'fixture','human_decisions':[],
            'headless':False,'chromium_sandbox':True,'api_interaction_substitutions':False,
            'page_error_types':[],'objective':'Exact objective','screenshots':['terminal.png'],
            'terminal_observation':{'run_id':'run','run_state':'blocked','reason_code':'model_budget_denied',
                'source':'graphical_start_response'},
            'run_status':{'run_id':'run','run_state':'blocked','active':False,'original_objective':'Exact objective'}}
        durable = {'run_id':'run','session_id':'session','read_only':True,
            'collected_at':'2026-11-17T00:38:00+00:00','authorizations':[],'jobs':[],
            'run':{'run_state':'blocked','reason_code':'model_budget_denied','original_objective':'Exact objective'}}
        return browser, durable

    def test_immediate_graphical_start_blocker_is_bound_to_exact_durable_terminal(self):
        browser, durable = self.visible_fixture()
        result = audit.live_acceptance_summary(browser, durable, 'VERIFIED')
        self.assertEqual(result['durable_run_state'], 'blocked')
        self.assertIsNone(result['terminal_event'])
        self.assertEqual(result['terminal_observation']['source'], 'graphical_start_response')
        for field, value in (('headless',True),('chromium_sandbox',False),
                             ('api_interaction_substitutions',True),('page_error_types',['Error'])):
            changed=copy.deepcopy(browser);changed[field]=value
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.live_acceptance_summary(changed,durable,'VERIFIED')
        for path, key, value in (('terminal_observation','run_id','stale'),
                                ('terminal_observation','source','direct_api'),
                                ('terminal_observation','reason_code','different'),
                                ('run_status','active',True),
                                ('run_status','original_objective','other')):
            changed=copy.deepcopy(browser);changed[path][key]=value
            with self.subTest(path=path,key=key), self.assertRaises(ValueError):
                audit.live_acceptance_summary(changed,durable,'VERIFIED')

    def test_graphical_websocket_terminal_also_requires_matching_durable_state(self):
        browser,durable=self.visible_fixture()
        browser['terminal_event']=browser.pop('terminal_observation')
        browser['terminal_event']['type']='auto_complete'
        browser['terminal_event'].pop('source')
        self.assertEqual(audit.live_acceptance_summary(browser,durable,'VERIFIED')['status'],'VERIFIED')
        durable['run']['run_state']='awaiting_approval'
        with self.assertRaises(ValueError):
            audit.live_acceptance_summary(browser,durable,'VERIFIED')

    def tool_fixture(self):
        import uuid
        return {'status': 'VERIFIED', 'samples': [{'schema':'aria.fixture.tool-timing.v1',
            'tool':tool,'job_id':str(uuid.uuid4()),'session_id':str(uuid.uuid4()),'exit_code':0,
            'http_positive_control':tool=='curl','nmap_positive_control':tool=='nmap',
            'tool_wall_ms':0,'child_user_cpu_ms':0,'child_system_cpu_ms':0} for tool in ('curl','nmap')]}

    def test_tool_fixture_requires_positive_controls_strict_values_and_unique_identity(self):
        valid = self.tool_fixture()
        self.assertEqual(audit.verified_tool_samples(valid), valid['samples'])
        for field, value in (('exit_code',True),('exit_code',1),('tool_wall_ms',True),
                             ('tool_wall_ms',-1),('child_user_cpu_ms',float('nan')),
                             ('child_system_cpu_ms',None),('http_positive_control',False),
                             ('job_id','unbound'),('tool','unknown')):
            altered = copy.deepcopy(valid)
            altered['samples'][0][field] = value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                audit.verified_tool_samples(altered)
        duplicate = copy.deepcopy(valid)
        duplicate['samples'][1]['job_id'] = duplicate['samples'][0]['job_id']
        with self.assertRaises(ValueError):
            audit.verified_tool_samples(duplicate)

    def test_missing_tool_cohort_or_failed_run_never_proves_timing(self):
        valid = self.tool_fixture()
        for altered in ({}, {**valid,'status':'FAILED'}, {**valid,'samples':valid['samples'][:1]}):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                audit.verified_tool_samples(altered)

    def test_requirements_reject_missing_duplicate_unknown_and_invalid_status(self):
        a = ('### P06-01: Timing\n- Status: VERIFIED\n'
             '- Acceptance criteria: Explicit unavailable layers\n- Evidence / limitations: Scoped measurements\n')
        b = '### P08-03: Visible\n- Status: BLOCKED\n- Acceptance criteria: Objective/limit/blocker stop\n'
        with TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(audit, 'ROOT', root), \
                 patch.object(audit, 'REFERENCES', {'P06-01': ('', ''), 'P08-03': ('', '')}):
                for content in ('', a, a+a+b, a+b.replace('BLOCKED', 'PASS'), a+b+'### P99-01: Other\n- Status: VERIFIED\n'):
                    (root/'PLANS.md').write_text(content)
                    with self.subTest(content=content), self.assertRaises(ValueError):
                        audit.requirements()
                (root/'PLANS.md').write_text(a+b)
                self.assertEqual([r['status'] for r in audit.requirements()], ['VERIFIED', 'BLOCKED'])

    def test_regression_summary_requires_complete_passing_output(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)/'tests.log'
            for content in ('', 'Ran 734 tests in 33.518s\n',
                            'Ran 734 tests in 33.518s\n\nFAILED (failures=1)\n'):
                path.write_text(content)
                with self.subTest(content=content), self.assertRaises(ValueError):
                    audit.regression_result(path)
            path.write_text('fixture logs\nRan 734 tests in 33.518s\n\nOK\n')
            self.assertEqual(audit.regression_result(path), {'tests': 734, 'unittest_seconds': 33.518})

    def test_statistics_preserve_zero_and_keep_invalid_and_small_sample_p95_unavailable(self):
        result = audit.stats([None, True, -1, float('nan'), float('inf'), 0, 2])
        self.assertEqual(result, {'n': 2, 'mean': 1, 'median': 1, 'maximum': 2, 'p95': None})
        self.assertEqual(audit.stats(list(range(20)))['p95'], 18)
        self.assertIsNone(audit.stats([])['mean'])

    def test_stale_graphical_capture_cannot_override_bound_durable_expiry(self):
        browser = {'run_id': 'run', 'session_id': 'session', 'status': 'IN_PROGRESS',
            'target': '192.0.2.1', 'server_build': 'old-build', 'directory': 'fixture', 'human_decisions': []}
        durable = {'run_id': 'run', 'session_id': 'session', 'collected_at': '2026-11-15T14:38:14+00:00',
            'run': {'run_state': 'awaiting_approval'}, 'jobs': [],
            'authorizations': [{'id': 'expired', 'status': 'pending', 'expires_at': 1}]}
        result = audit.live_acceptance_summary(browser, durable, 'BLOCKED')
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['browser_capture_status'], 'IN_PROGRESS')
        self.assertEqual(result['durable_run_state'], 'awaiting_approval')
        self.assertEqual(result['expired_pending_action_ids'], ['expired'])
        self.assertEqual(result['worker_jobs'], 0)
        self.assertEqual(browser['status'], 'IN_PROGRESS')
        with self.assertRaises(ValueError):
            audit.live_acceptance_summary(browser, durable, 'VERIFIED')
        with self.assertRaises(ValueError):
            audit.live_acceptance_summary(browser, {**durable, 'session_id': 'foreign'}, 'BLOCKED')
