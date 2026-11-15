"""Strict planning and receipt-bound review regressions; no inference/network."""
import json
from unittest.mock import AsyncMock, patch
from pydantic import ValidationError
from tests.support import OfflineCase
from agents.orchestrator_agent import orchestrator_agent, AdapterPlan, AssessmentPlan
from llm.base_llm import response_schema
from security_tools.adapters import ADAPTERS, decode


class IntelligenceTests(OfflineCase):
    def record_review_timing(self, case, metrics):
        import os
        from pathlib import Path
        directory = os.environ.get('ARIA_RELIABILITY_ARTIFACT_DIR')
        if directory:
            path = Path(directory) / 'review-timing-fixtures.jsonl'
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('a') as file:
                file.write(json.dumps({'case': case, 'metrics': metrics}) + '\n')
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.review_diagnostics = self.enterContext(patch(
            'agents.orchestrator_agent.record_planner_diagnostic', AsyncMock()))

    async def test_review_schema_rejection_keeps_response_private_without_retry(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState, InvestigationReviewError
        from security.encryption import evidence_cipher
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        # Exact misspelled field observed in the live failure, with synthetic content.
        raw = json.dumps({'observations': [], 'hypotheses': [{
            'description': 'Unverified candidate', 'evidence_job_ids': ['unknown-job'],
            'follow_up': 'none', 'validation_criterion': 'Compare a controlled response',
            'alternative_explanforations': ['private-response-sentinel']}], 'limitations': []})
        engine = AutonomousEngine()
        with patch.object(engine, '_persist', AsyncMock()), patch.object(engine, '_emit', AsyncMock()) as emit, patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value={'success': True, 'content': raw})) as query:
            with self.assertRaises(InvestigationReviewError) as rejected:
                await engine._review_investigation(state)
        self.assertEqual(rejected.exception.code, 'invalid_review_output')
        self.assertGreaterEqual(rejected.exception.structured_validation_ms, 0)
        self.record_review_timing('invalid_schema', {'structured_validation_ms': rejected.exception.structured_validation_ms})
        self.assertNotIn('private-response-sentinel', str(rejected.exception))
        self.assertNotIn('alternative_explanforations', str(rejected.exception))
        query.assert_awaited_once()
        emit.assert_not_awaited()
        diagnostic = self.review_diagnostics.await_args.args
        self.assertEqual(diagnostic[:3], ('engagement', 'owner', 'review_response_private'))
        self.assertEqual(diagnostic[3]['run_id'], state.run_id)
        self.assertEqual(evidence_cipher().decrypt(diagnostic[3]['sealed'].encode()).decode(), raw)
        self.assertIsNone(response_schema.get())

    async def test_review_diagnostic_failure_prevents_acceptance(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState, InvestigationReviewError
        state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
        engine = AutonomousEngine()
        self.review_diagnostics.side_effect = RuntimeError('storage-private-sentinel')
        with patch.object(engine, '_persist', AsyncMock()), patch.object(engine, '_emit', AsyncMock()) as emit, patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value={'success': True, 'content': '{"observations":[],"hypotheses":[],"limitations":[]}'})):
            with self.assertRaises(InvestigationReviewError) as rejected:
                await engine._review_investigation(state)
        self.assertEqual(rejected.exception.code, 'review_diagnostic_unavailable')
        self.assertNotIn('storage-private-sentinel', str(rejected.exception))
        emit.assert_not_awaited()

    async def test_loop_errors_do_not_publish_exception_input(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState, InvestigationReviewError
        errors = [(RuntimeError('private-exception-sentinel'), 'failed', 'run_error'),
                  (InvestigationReviewError('invalid_review_output', 'Review schema rejected'), 'blocked', 'invalid_review_output')]
        for error, terminal, code in errors:
            with self.subTest(code=code):
                engine = AutonomousEngine()
                state = SessionRunState('engagement', 'owner', 'discovery', '192.0.2.1', 'expert')
                with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={})), patch.object(engine, '_check_goal_achieved', AsyncMock(side_effect=error)), patch.object(engine, '_persist', AsyncMock()), patch.object(engine, '_write_decision_log', AsyncMock()):
                    await engine._run_loop(state)
                self.assertEqual(state.run_state, terminal)
                self.assertEqual(state.reason_code, code)
                self.assertNotIn('private-exception-sentinel', json.dumps(state.activity_log))
                self.assertFalse(state.active)

    async def test_generic_json_is_not_a_plan_and_never_dispatched(self):
        for content in ['{}', '{"tool":"nmap","command":"nmap -p 80 192.0.2.1"}', '{"commands":[]}', '{"commands":[']:
            with self.subTest(content=content), patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value={'success':True,'content':content})):
                result = await orchestrator_agent._bounded_assessment_plan('owner', {}, 'expert')
                self.assertEqual(result['commands'], [])
                self.assertEqual(result['rejections'][0]['code'], 'malformed_planner_output')

    async def test_six_operations_use_typed_envelopes_and_schema(self):
        parameters = {
            'nmap': {'host':'192.0.2.1','ports':[80]},
            'httpx': {'url':'http://192.0.2.1/'},
            'nuclei': {'url':'http://192.0.2.1/'},
            'ffuf': {'url':'http://192.0.2.1/','words':['test']},
            'semgrep': {'artifact_sha256':'a'*64},
            'subfinder': {'domain':'aria-fixture.test','source':'offline'},
        }
        advertisement = {'typed_adapters':{ADAPTERS[name].capability:1 for name in parameters}}
        for name, values in parameters.items():
            async def model(*args, **kwargs):
                self.assertEqual(response_schema.get(), AdapterPlan.model_json_schema())
                return {'success':True,'content':json.dumps({'commands':[{'operation':{'tool':name,'parameters':values},'purpose':'Test bounded selection','expected_evidence':'Structured observation'}]})}
            with self.subTest(tool=name), patch.object(orchestrator_agent, 'query_llm_smart', side_effect=model):
                result = await orchestrator_agent._bounded_assessment_plan('owner', {'worker_capabilities':advertisement}, 'expert')
                adapter, parsed = decode(result['commands'][0]['command'])
                self.assertEqual(adapter.name, name)
                self.assertEqual(parsed, ADAPTERS[name].parameters(values))
        self.assertIsNone(response_schema.get())

    async def test_disabled_and_unadvertised_selections_are_rejected(self):
        for name in ['katana','playwright','sqlmap','zap']:
            with self.subTest(tool=name), self.assertRaises(ValidationError):
                AdapterPlan.model_validate({'commands':[{'operation':{'tool':name,'parameters':{'url':'http://192.0.2.1/'}},'purpose':'test','expected_evidence':'test'}]})
        result = {'commands':[{'operation':{'tool':'semgrep','parameters':{'artifact_sha256':'a'*64}},'purpose':'test','expected_evidence':'test'}]}
        with patch.object(orchestrator_agent, 'query_llm_smart', AsyncMock(return_value={'success':True,'content':json.dumps(result)})):
            output = await orchestrator_agent._bounded_assessment_plan('owner', {'worker_capabilities':{'typed_adapters':{'httpx.http.probe.v1':1}}}, 'expert')
        self.assertEqual(output['commands'], [])

    async def test_native_schema_and_truncation_are_enforced(self):
        import httpx
        from llm.local_client import LocalClient
        payloads=[]
        def handler(request):
            if request.url.path == '/api/version':
                return httpx.Response(200,json={'version':'fixture'})
            payloads.append(json.loads(request.content))
            return httpx.Response(200,json={'message':{'content':'{"commands":['},'done_reason':'length','prompt_eval_count':10,'eval_count':768})
        original=httpx.AsyncClient
        def client(**kwargs):return original(transport=httpx.MockTransport(handler),**kwargs)
        token=response_schema.set(AssessmentPlan.model_json_schema())
        try:
            with patch('llm.local_client.httpx.AsyncClient',side_effect=client):
                result=await LocalClient(model='fixture').query('prompt','system')
        finally:response_schema.reset(token)
        self.assertFalse(result['success'])
        self.assertEqual(result['error'],'model_output_truncated')
        self.assertEqual(result['tokens_used'],778)
        self.assertEqual(payloads[0]['format'],AssessmentPlan.model_json_schema())
        self.assertEqual(payloads[0]['options']['num_predict'],768)

    async def test_review_rejects_fabricated_evidence_references(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from memory.worker_jobs import worker_jobs
        engine=AutonomousEngine()
        state=SessionRunState('engagement','owner','discovery','192.0.2.1','expert')
        state.evidence_job_ids=['owned-job']
        output={'observations':['HTTP response'], 'hypotheses':[{'description':'Unverified','evidence_job_ids':['fabricated-job'],'follow_up':'none','validation_criterion':'Check response headers'}], 'limitations':[]}
        with patch.object(worker_jobs.store,'get',AsyncMock(return_value={'session_id':'engagement'})), patch.object(worker_jobs.client,'status',AsyncMock(return_value={'stdout':'HTTP/1.1 200 OK','stderr':'','exit_code':0})), patch.object(worker_jobs,'verify_receipt',AsyncMock()), patch.object(engine,'_persist',AsyncMock()), patch.object(orchestrator_agent,'query_llm_smart',AsyncMock(return_value={'success':True,'content':json.dumps(output)})), patch.object(engine,'_emit',AsyncMock()) as emit:
            with self.assertRaisesRegex(ValueError,'unknown evidence'):
                await engine._review_investigation(state)
        emit.assert_not_awaited()

    async def test_agent_boundary_uses_typed_scope_validation(self):
        from agents.result_contract import professional_result
        from security_tools.adapters import encode
        operation={'tool':'nmap','parameters':{'host':'192.0.2.1','ports':[80]}}
        command={'command':encode(operation),'purpose':'Discover scoped ports','expected_evidence':'Scoped TCP port states'}
        scope={'targets':['192.0.2.1'],'ports':[80]}
        result=professional_result('orchestrator',{'target':'192.0.2.1'},{'commands':[command]},scope,[],{'nmap'})
        self.assertEqual(len(result.proposed_actions),1)
        self.assertEqual(result.proposed_actions[0]['expected_evidence'],'Scoped TCP port states')
        for badscope, caps in [({'targets':['192.0.2.2'],'ports':[80]},{'nmap'}),(scope,set())]:
            denied=professional_result('orchestrator',{}, {'commands':[command]},badscope,[],caps)
            self.assertEqual(denied.proposed_actions,[])

    async def test_engine_accepts_typed_probe_for_missing_http_only(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from security_tools.adapters import encode
        engine=AutonomousEngine()
        state=SessionRunState('engagement','owner','http_check','192.0.2.1','expert',capabilities={'tools':[], 'typed_adapters':{'httpx.http.probe.v1':1}})
        proposal={'command':encode({'tool':'httpx','parameters':{'url':'http://192.0.2.1/'}})}
        with patch.object(orchestrator_agent,'process',AsyncMock(return_value={'commands':[proposal]})), patch('agents.autonomous_engine.execution_authorization._context',AsyncMock(return_value={'scope':{'targets':['192.0.2.1'],'ports':[80]}})):
            result=await engine._validated_plan(state,orchestrator_agent,[],[],[])
        self.assertEqual(result['tool'],'httpx')

    async def test_typed_dispatch_preserves_adapter_deadline(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from security_tools.adapters import encode
        engine=AutonomousEngine()
        state=SessionRunState('engagement','owner','discovery','192.0.2.1','expert')
        command=encode({'tool':'nmap','parameters':{'host':'192.0.2.1','ports':[80]}})
        with patch('agents.autonomous_engine.execution_authorization.execute',AsyncMock(return_value={'exit_code':1,'stdout':'','stderr':''})) as execute:
            await engine._execute_command(state,'nmap',command,action_id='authorized-action')
        self.assertEqual(execute.await_args.kwargs['timeout'],ADAPTERS['nmap'].timeout)
        self.assertEqual(execute.await_args.kwargs['action_id'],'authorized-action')

    async def test_rejected_response_is_private_and_errors_do_not_echo_input(self):
        from security.encryption import evidence_cipher
        raw='{"commands":[{"command":"sensitive-invalid-field"}]}'
        with patch.object(orchestrator_agent,'query_llm_smart',AsyncMock(return_value={'success':True,'content':raw})), patch('agents.orchestrator_agent.record_planner_diagnostic',AsyncMock()) as audit:
            result=await orchestrator_agent._bounded_assessment_plan('owner',{},'expert',session_id='engagement')
        self.assertEqual(audit.await_count,2)
        metadata=audit.await_args.args[3]
        self.assertEqual(evidence_cipher().decrypt(metadata['sealed'].encode()).decode(),raw)
        self.assertNotIn('sensitive-invalid-field',json.dumps(result))
        self.assertTrue(metadata['errors'])

    async def test_observed_wrong_http_tool_is_excluded_from_schema(self):
        from pathlib import Path
        raw=Path('tests/fixtures/planner/wrong_http_probe.json').read_text()
        async def model(*args,**kwargs):
            schema=json.dumps(response_schema.get())
            self.assertIn('HttpxPlanningOperation',schema)
            self.assertNotIn('NmapPlanningOperation',schema)
            return {'success':True,'content':raw}
        with patch.object(orchestrator_agent,'query_llm_smart',side_effect=model):
            result=await orchestrator_agent._bounded_assessment_plan('owner',{
                'goal':'discovery','completed_observations':['port_discovery'],
                'worker_capabilities':{'typed_adapters':{'nmap.tcp.connect.v1':1,'httpx.http.probe.v1':1}},
            },'expert')
        self.assertEqual(result['commands'],[])
        self.assertEqual(result['rejections'][0]['code'],'malformed_planner_output')

    async def test_review_normalizes_reverified_output_before_model_context(self):
        from pathlib import Path
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from memory.worker_jobs import worker_jobs
        from security_tools.adapters import encode, sha256
        fixture=json.loads(Path('tests/fixtures/security_tools/httpx.json').read_text())
        raw=json.loads(fixture['stdout']);raw['irrelevant']='untrusted-padding-'*200
        command=encode(fixture['request'])
        state=SessionRunState('engagement','owner','http_check','192.0.2.1','expert')
        state.evidence_job_ids=['owned-job'];state.executed_commands=[command]
        job={'session_id':'engagement','adapter_request_sha256':sha256(command),'scope':fixture['scope']}
        snapshot={'stdout':json.dumps(raw),'stderr':'','exit_code':0,'state':'succeeded'}
        async def model(user,prompt,*args,**kwargs):
            self.assertNotIn('untrusted-padding',prompt)
            self.assertIn('Synthetic fixture',prompt)
            return {'success':True,'content':json.dumps({'observations':['HTTP 200'],'hypotheses':[],'limitations':['No vulnerability verified']})}
        engine=AutonomousEngine()
        with patch.object(worker_jobs.store,'get',AsyncMock(return_value=job)), patch.object(worker_jobs.client,'status',AsyncMock(return_value=snapshot)), patch.object(worker_jobs,'verify_receipt',AsyncMock()) as verify, patch.object(engine,'_persist',AsyncMock()), patch.object(orchestrator_agent,'query_llm_smart',side_effect=model), patch.object(engine,'_emit',AsyncMock()) as emit, patch.object(engine,'_write_decision_log',AsyncMock()):
            await engine._review_investigation(state)
        verify.assert_awaited_once()
        self.assertEqual(emit.await_args.args[1]['review']['verification'],'unverified')

    async def test_exact_dictionary_is_enforced_beyond_prompt_wording(self):
        wrong={'commands':[{'operation':{'tool':'ffuf','parameters':{'url':'http://192.0.2.1/','words':['admin']}},'purpose':'Discover endpoints','expected_evidence':'HTTP paths'}]}
        async def model(*args,**kwargs):
            words=response_schema.get()['$defs']['FfufInput']['properties']['words']['const']
            self.assertEqual(words,['admin','test'])
            return {'success':True,'content':json.dumps(wrong)}
        with patch.object(orchestrator_agent,'query_llm_smart',side_effect=model):
            result=await orchestrator_agent._bounded_assessment_plan('owner',{
                'goal':'endpoint_discovery','ffuf_words':['test','admin'],
                'worker_capabilities':{'typed_adapters':{'httpx.http.probe.v1':1,'ffuf.http.paths.v1':1}},
            },'expert')
        self.assertEqual(result['commands'],[])

    async def test_free_text_unsafe_follow_up_is_not_an_action_contract(self):
        from agents.orchestrator_agent import InvestigationReview
        for hypothesis in [
            {'description':'Candidate','evidence_job_ids':['job'],'safe_follow_up':'dirsearch /etc/passwd with 1000 requests'},
            {'description':'Candidate','evidence_job_ids':['job'],'follow_up':'sqlmap','validation_criterion':'Probe'},
        ]:
            with self.subTest(hypothesis=hypothesis), self.assertRaises(ValidationError):
                InvestigationReview.model_validate({'observations':[],'hypotheses':[hypothesis],'limitations':[]})

    async def test_review_cannot_select_unavailable_follow_up(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from memory.worker_jobs import worker_jobs
        engine=AutonomousEngine();state=SessionRunState('engagement','owner','discovery','192.0.2.1','expert')
        state.evidence_job_ids=['owned-job']
        output={'observations':[],'hypotheses':[{'description':'Candidate','evidence_job_ids':['owned-job'],'follow_up':'bounded_http_paths','validation_criterion':'Observe public path status'}],'limitations':[]}
        with patch.object(worker_jobs.store,'get',AsyncMock(return_value={'session_id':'engagement'})), patch.object(worker_jobs.client,'status',AsyncMock(return_value={'stdout':'HTTP/1.1 200 OK','stderr':'','exit_code':0})), patch.object(worker_jobs,'verify_receipt',AsyncMock()), patch.object(engine,'_persist',AsyncMock()), patch.object(orchestrator_agent,'query_llm_smart',AsyncMock(return_value={'success':True,'content':json.dumps(output)})), patch.object(engine,'_emit',AsyncMock()) as emit:
            with self.assertRaisesRegex(ValueError,'unavailable'):
                await engine._review_investigation(state)
        emit.assert_not_awaited()

    async def test_observed_review_uses_receipt_facts_and_server_path_criterion(self):
        from pathlib import Path
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from memory.worker_jobs import worker_jobs
        from security_tools.adapters import encode, sha256
        output=json.loads(Path('tests/fixtures/planner/observed_typed_review.json').read_text())
        jid=output['hypotheses'][0]['evidence_job_ids'][0]
        command=encode({'tool':'httpx','parameters':{'url':'http://192.168.77.20'}})
        state=SessionRunState('engagement','owner','discovery','192.168.77.20','expert',capabilities={'typed_adapters':{'ffuf.http.paths.v1':1}})
        state.evidence_job_ids=[jid];state.executed_commands=[command]
        job={'session_id':'engagement','adapter_request_sha256':sha256(command),'scope':{'targets':['192.168.77.20'],'ports':[80]}}
        snapshot={'stdout':json.dumps({'url':'http://192.168.77.20','status_code':200,'title':'Metasploitable2 - Linux'}),'stderr':'','exit_code':0,'state':'succeeded'}
        engine=AutonomousEngine()
        with patch.object(worker_jobs.store,'get',AsyncMock(return_value=job)), patch.object(worker_jobs.client,'status',AsyncMock(return_value=snapshot)), patch.object(worker_jobs,'verify_receipt',AsyncMock()), patch.object(engine,'_persist',AsyncMock()), patch.object(orchestrator_agent,'query_llm_smart',AsyncMock(return_value={'success':True,'content':json.dumps(output)})), patch.object(engine,'_emit',AsyncMock()) as emit, patch.object(engine,'_write_decision_log',AsyncMock()):
            await engine._review_investigation(state)
        report=emit.await_args.args[1]['review']
        self.assertGreaterEqual(report['metrics']['structured_validation_ms'], 0)
        self.assertGreaterEqual(report['metrics']['result_preparation_ms'], 0)
        self.assertGreaterEqual(report['metrics']['projection_persistence_ms'], 0)
        self.record_review_timing('accepted_schema', report['metrics'])
        self.assertEqual(len(report['observations']),1)
        self.assertEqual(report['observations'][0]['kind'],'http')
        self.assertIn('query parameter',report['hypotheses'][0]['model_validation_criterion'])
        self.assertNotIn('query parameter',report['hypotheses'][0]['validation_criterion'])
        follow=report['proposed_investigations'][0]
        self.assertEqual(follow['operation']['parameters']['words'],['admin','test'])
        self.assertTrue(follow['requires_approval']);self.assertFalse(follow['executed'])
