"""Known worker incompatibilities cannot be represented as executable plans."""
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from agents.autonomous_engine import AutonomousEngine, SessionRunState
from memory.worker_jobs import WorkerJobs
from orchestrator.worker_preflight import worker_preflight
from security_tools.adapters import encode
from tests.support import OfflineCase
from tests.test_p1_workers import MemoryJobs, MockWorker


LIMITS = {'version': 1, 'networks': ['192.0.2.0/24'], 'tcp_ports': [80]}
CAPS = {'tools': ['nmap', 'curl', 'httpx'], 'execution_constraints': LIMITS}
SCOPE = {'targets': ['192.0.2.1'], 'ports': [80, 8080]}


class WorkerPreflightTests(OfflineCase):
    def test_legacy_constraints_are_unavailable_not_compatible(self):
        result = worker_preflight('curl -I http://192.0.2.1', SCOPE, {'tools': ['curl']})
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['reason_code'], 'worker_constraints_unavailable')

    def test_port_network_and_typed_checks_preserve_scope_and_worker_ceiling(self):
        cases = [
            ('curl -I http://192.0.2.1:80', SCOPE, 'compatible'),
            ('curl -I http://192.0.2.1:8080', SCOPE, 'blocked'),
            ('nmap -p 80 192.0.2.1', SCOPE, 'compatible'),
            ('nmap -p 8080 192.0.2.1', SCOPE, 'blocked'),
            ('curl -I http://198.51.100.1', {'targets': ['198.51.100.1']}, 'blocked'),
            ('curl -I http://lab.test', {'targets': ['lab.test']}, 'unavailable'),
            (encode({'tool':'httpx','parameters':{'url':'http://192.0.2.1:80'}}), SCOPE, 'compatible'),
            (encode({'tool':'httpx','parameters':{'url':'http://192.0.2.1:8080'}}), SCOPE, 'blocked'),
        ]
        for command, scope, status in cases:
            with self.subTest(command=command):
                self.assertEqual(worker_preflight(command, scope, CAPS)['status'], status)
        with self.assertRaises(ValueError):
            worker_preflight('curl -I http://203.0.113.1', SCOPE, CAPS)

    def test_invalid_metadata_never_grants_compatibility(self):
        for limits in ([], {}, {**LIMITS, 'version': True}, {**LIMITS, 'tcp_ports': [True]},
                       {**LIMITS, 'networks': ['0.0.0.0/0']}, {**LIMITS, 'extra': 'private-sentinel'}):
            with self.subTest(limits=limits):
                result = worker_preflight('curl -I http://192.0.2.1', SCOPE, {'execution_constraints': limits})
                self.assertEqual(result['reason_code'], 'worker_constraints_invalid')
                self.assertNotIn('private-sentinel', str(result))

    async def test_shared_worker_dispatch_denies_mismatch_before_submit(self):
        store, client = MemoryJobs(), MockWorker()
        client.capabilities = AsyncMock(return_value=CAPS)
        jobs = WorkerJobs(store, client, AsyncMock(return_value={'scope': SCOPE}))
        with patch('memory.worker_jobs.settings.KALI_AGENT_URL', 'http://fixture.invalid'):
            with self.assertRaises(HTTPException) as rejected:
                await jobs.execute('job', 'owner', 'engagement', 'curl -I http://192.0.2.1:8080', 10)
        self.assertEqual(rejected.exception.detail['code'], 'worker_port_incompatible')
        self.assertEqual(client.submits, 0)
        self.assertEqual((await store.get('job'))['worker_preflight']['status'], 'blocked')

    async def test_planner_preserves_mismatch_as_an_exact_blocker_without_proposal(self):
        from agents.orchestrator_agent import orchestrator_agent
        state = SessionRunState('engagement', 'owner', 'http_check', '192.0.2.1', 'expert', capabilities=CAPS)
        engine, feedback = AutonomousEngine(), []
        response = {'commands':[{'tool':'curl','command':'curl -I http://192.0.2.1:8080','purpose':'Synthetic observation'}]}
        with patch.object(engine, '_specialist_context', AsyncMock(return_value={})), \
             patch.object(orchestrator_agent, 'process', AsyncMock(return_value=response)), \
             patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={'scope': SCOPE})):
            result = await engine._validated_plan(state, orchestrator_agent, '', [], feedback)
        self.assertIsNone(result)
        self.assertEqual(state.reason_code, 'worker_port_incompatible')
        self.assertEqual(state.evidence_job_ids, [])
