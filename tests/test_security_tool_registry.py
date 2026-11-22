"""Registry contracts use synthetic documentation IPs; no tools or sockets execute."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

from config.security_tool_registry import (
    MANIFEST, Registry, RegistryError, ToolResult, load_registry,
)
from api.auth import get_current_user
from api.main import app
from memory.database_models import SessionStatus
from tests.support import OfflineCase
from tests.test_access import OWNER


def advertisement(**changes):
    return {"protocol": "aria-jobs-v1", "idempotency": True, "cancellation": True,
            "network_scope": True, "tools": ["curl", "nmap"], **changes}


def request(tool="curl", operation="http.headers", parameters=None, **changes):
    return {"schema_version": 1, "tool": tool, "operation": operation,
            "parameters": parameters if parameters is not None else {"url": "http://192.0.2.1:8080/"},
            **changes}


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = load_registry()
        self.scope = {"targets": ["192.0.2.1"], "ports": [8080]}

    def test_manifest_has_three_disabled_operations_and_schema_contracts(self):
        view = self.registry.catalog(advertisement())
        self.assertEqual(view["mode"], "catalog_only")
        self.assertEqual(sum(len(tool["operations"]) for tool in view["tools"]), 3)
        self.assertEqual(len(view["registry_digest"]), 64)
        self.assertEqual(set(view["input_schemas"]), {"http.headers.v1", "http.get.v1", "tcp.connect.v1"})
        for schema in view["input_schemas"].values():
            self.assertIs(schema["additionalProperties"], False)
        for tool in view["tools"]:
            self.assertFalse(tool["enabled"])
            self.assertFalse(tool["execution_available"])
            self.assertTrue(tool["worker_advertised"])
            self.assertIsNone(tool["version"])
            self.assertIsNone(tool["image_id"])
            self.assertEqual(tool["health"]["status"], "not_measured")
            self.assertIn("version_unpinned", tool["blocked_reasons"])

    def test_requests_validate_without_execution_or_dns(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
             patch("subprocess.Popen", side_effect=AssertionError("No execution")), \
             patch("asyncio.create_subprocess_exec", side_effect=AssertionError("No execution")):
            for operation in ("http.headers", "http.get"):
                result = self.registry.validate_request(request(operation=operation), self.scope)
                self.assertEqual(result.parameters, {"url": "http://192.0.2.1:8080/"})
            result = self.registry.validate_request(
                request("nmap", "tcp.connect", {"host": "192.0.2.1", "ports": [8080, 8080]}), self.scope)
            self.assertEqual(result.parameters["ports"], [8080])

    def test_unknown_tools_operations_and_free_form_fields_deny(self):
        cases = [
            request(tool="sh"), request(operation="http.post"), request(tool="nmap"),
            request(command="curl http://192.0.2.1"), request(approved=True),
            request(timeout=300), request(schema_version=True),
            request(parameters={"url": "http://192.0.2.1:8080/", "args": ["-L"]}),
            request(parameters={"url": ["http://192.0.2.1:8080/"]}),
        ]
        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(RegistryError):
                self.registry.validate_request(payload, self.scope)

    def test_declared_risk_never_downgrades_existing_worker_policy(self):
        from worker.policy import validate_worker_command
        examples = {
            "http.headers": "curl -I --max-time 10 http://192.0.2.1:8080/",
            "http.get": "curl --max-time 10 http://192.0.2.1:8080/",
            "tcp.connect": "nmap -p 8080 192.0.2.1",
        }
        for tool in self.registry.tools:
            for operation in tool.operations:
                self.assertEqual(operation.risk,
                                 validate_worker_command(examples[operation.id], self.scope).risk)

    def test_ambiguous_urls_and_shell_syntax_deny(self):
        for url in (
            "file:///etc/passwd", "ftp://192.0.2.1/", "http://user:pass@192.0.2.1/",
            "http://192.0.2.1/?x=1", "http://192.0.2.1/#fragment",
            "http://192.0.2.1:0/", "http://192.0.2.1:70000/",
            "http://192.0.2.1/{a,b}", "http://192.0.2.1/../private",
            "http://192.0.2.1/%2e%2e/private", "http://192.0.2.1/;id",
            "http://192.0.2.1/$(id)", "http://192.0.2.1/\n",
            "http://192.0.2.1./",
        ):
            with self.subTest(url=url), self.assertRaises(RegistryError):
                self.registry.validate_request(request(parameters={"url": url}), self.scope)

    def test_empty_scope_exclusions_and_ports_deny(self):
        for scope in ({}, {"targets": []}, {"targets": ["192.0.2.2"]},
                      {**self.scope, "ports": [80]}, {**self.scope, "ports": [True]},
                      {**self.scope, "exclusions": ["192.0.2.1"]}):
            with self.subTest(scope=scope), self.assertRaises(RegistryError):
                self.registry.validate_request(request(), scope)

    def test_tcp_rejects_network_ranges_invalid_ports_and_large_input(self):
        for parameters in (
            {"host": "192.0.2.0/24", "ports": [8080]},
            {"host": "http://192.0.2.1", "ports": [8080]},
            {"host": "-sS", "ports": [8080]},
            {"host": "192.0.2.1", "ports": [True]},
            {"host": "192.0.2.1", "ports": ["8080"]},
            {"host": "192.0.2.1", "ports": [65536]},
            {"host": "192.0.2.1", "ports": [80]},
            {"host": "192.0.2.1", "ports": []},
            {"host": "192.0.2.1", "ports": list(range(1, 34))},
        ):
            with self.subTest(parameters=parameters), self.assertRaises(RegistryError):
                self.registry.validate_request(request("nmap", "tcp.connect", parameters), self.scope)

    def test_exact_hostname_and_ipv6_scope(self):
        self.registry.validate_request(request(parameters={"url": "https://lab.example/"}),
                                       {"targets": ["lab.example"], "ports": [443]})
        self.registry.validate_request(request("nmap", "tcp.connect", {"host": "2001:db8::1", "ports": [443]}),
                                       {"targets": ["2001:db8::/64"], "ports": [443]})
        with self.assertRaises(RegistryError):
            self.registry.validate_request(request(parameters={"url": "https://sub.lab.example/"}),
                                           {"targets": ["lab.example"]})

    def test_program_policy_cannot_be_bypassed_by_structured_requests(self):
        # A reviewed program policy is distinct from an ordinary IP scope.
        scope = {**self.scope, "program_policy": {"state": "pending", "rules": {}}}
        for payload in (request(), request("nmap", "tcp.connect", {"host": "192.0.2.1", "ports": [8080]})):
            with self.assertRaises(RegistryError):
                self.registry.validate_request(payload, scope)

    def test_manifest_cannot_enable_execution_change_adapter_or_drop_controls(self):
        original = json.loads(MANIFEST.read_text())
        mutations = [
            lambda data: data.update(mode="execution"),
            lambda data: data["tools"][0].update(enabled=True),
            lambda data: data["tools"][0].update(enabled=0),
            lambda data: data["tools"][0].update(executable="/bin/sh"),
            lambda data: data["tools"][0]["health_check"].update(argv=["/bin/sh", "-c"]),
            lambda data: data["tools"][0]["resources"].update(read_only_root=False),
            lambda data: data["tools"][0]["resources"].update(tool_capabilities=["net_admin"]),
            lambda data: data["tools"][0]["network"].update(redirects=True),
            lambda data: data["tools"][0].update(audit_requirements=[]),
            lambda data: data["tools"][0]["operations"][0].update(required_permissions=["engagement.execute"]),
            lambda data: data["tools"][0]["operations"][0].update(capability="sh.exec.v1"),
            lambda data: data["tools"][0]["operations"][0]["limits"].update(timeout_seconds=11),
            lambda data: data["tools"][0]["operations"].append(copy.deepcopy(data["tools"][0]["operations"][0])),
            lambda data: data["tools"].append(copy.deepcopy(data["tools"][0])),
        ]
        for mutate in mutations:
            data = copy.deepcopy(original)
            mutate(data)
            with self.subTest(data=data), self.assertRaises(ValidationError):
                Registry.model_validate(data)

    def test_pin_pair_and_mutable_images_are_rejected(self):
        data = json.loads(MANIFEST.read_text())
        for version, image in (("latest", "sha256:" + "a" * 64), ("8.0.0", "curl:latest"),
                               ("8.0.0", None), (None, "sha256:" + "a" * 64)):
            with self.subTest(version=version, image=image):
                data["tools"][0].update(version=version, image_id=image)
                with self.assertRaises(ValidationError):
                    Registry.model_validate(data)
        data["tools"][0].update(version="8.0.0", image_id="sha256:" + "a" * 64)
        self.assertFalse(Registry.model_validate(data).catalog(advertisement())["tools"][0]["execution_available"])

    def test_manifest_bounds_duplicates_missing_and_corrupt_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            for raw in ('{"schema_version":1,"schema_version":2}', '{"tools":', "x" * 65537):
                path.write_text(raw)
                with self.assertRaises(RegistryError):
                    load_registry(path)
            with self.assertRaises(RegistryError):
                load_registry(Path(directory) / "absent.json")

    def test_discovery_filters_unknown_tools_and_preserves_unknown_health(self):
        catalog = self.registry.catalog(advertisement(tools=["curl", "sqlmap"]))
        self.assertTrue(catalog["tools"][0]["worker_advertised"])
        self.assertFalse(catalog["tools"][1]["worker_advertised"])
        self.assertEqual(catalog["agent_capabilities"]["scan"], ["nmap.tcp.connect.v1"])
        self.assertEqual(catalog["agent_capabilities"]["report"], [])
        self.assertEqual(catalog["agent_capabilities"]["correlation"], [])
        for change in ({"protocol": "legacy-execute"}, {"idempotency": 1},
                       {"network_scope": False}, {"tools": "curl"}, {"tools": ["curl", 2]}):
            with self.subTest(change=change), self.assertRaises(RegistryError):
                self.registry.catalog(advertisement(**change))

    def test_digest_is_stable_and_binds_the_entire_manifest(self):
        self.assertEqual(load_registry().digest, self.registry.digest)
        data = self.registry.model_dump()
        data["tools"][0]["operations"][0]["limits"]["min_interval_seconds"] = 2
        self.assertNotEqual(Registry.model_validate(data).digest, self.registry.digest)

    def test_output_schema_cannot_mark_scanner_results_verified(self):
        result = dict(schema_version=1, job_id="job", session_id="session", tool="curl",
                      operation="http.headers", registry_digest="a" * 64, request_digest="b" * 64,
                      state="succeeded", exit_code=0, tool_version="8.0.0",
                      image_id="sha256:" + "a" * 64, duration_ms=None,
                      evidence=[{"evidence_id": "existing-owned-evidence", "sha256": "c" * 64}],
                      verification="unverified", error_code="none")
        ToolResult.model_validate(result)
        for change in ({"verification": "verified"}, {"exit_code": None}, {"exit_code": 1},
                       {"exit_code": True}, {"evidence": [{"evidence_id": "x", "sha256": "bad"}]}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                ToolResult.model_validate({**result, **change})


class RegistryAPITests(OfflineCase):
    async def test_paused_owner_can_read_capability_audit_but_cannot_edit_restrictions(self):
        from datetime import datetime

        app.dependency_overrides[get_current_user] = lambda: OWNER
        capability = 'semgrep.source.scan.v1'
        session = SimpleNamespace(status=SessionStatus.PAUSED, attack_mode='lab', metadata_={},
            scope={'targets': ['192.0.2.10'], 'blocked_typed_capabilities': [capability]})
        session_result = SimpleNamespace(scalar_one_or_none=lambda: session)
        audit = SimpleNamespace(all=lambda: [('paused-audit', datetime(2026, 1, 1), capability)])
        database = SimpleNamespace(execute=AsyncMock(side_effect=[session_result, audit, session_result]),
                                   add=AsyncMock(), commit=AsyncMock())
        context = AsyncMock()
        context.__aenter__.return_value = database
        path = '/api/sessions/engagement/tool-restrictions'
        with patch('api.routers.tool_registry.async_session', return_value=context):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200)
            view = response.json()
            self.assertEqual(view['engagement_state'], 'paused')
            self.assertEqual(view['engagement_blockers'], ['engagement_inactive'])
            self.assertEqual(view['blocked'], [capability])
            self.assertEqual(view['audit'][capability]['record_id'], 'paused-audit')
            denied = await self.client.post(path, json={'capability': 'nmap.tcp.connect.v1'})
            self.assertEqual(denied.status_code, 409)
            database.execute.side_effect = None
            database.execute.return_value = SimpleNamespace(scalar_one_or_none=lambda: None)
            self.assertEqual((await self.client.get(path)).status_code, 404)
        read, _, write, missing = [call.args[0] for call in database.execute.await_args_list]
        for query in (read, write, missing):
            self.assertCountEqual(query.compile().params.values(), ['engagement', OWNER.user_id])
        self.assertNotIn('FOR UPDATE', str(read))
        self.assertIn('FOR UPDATE', str(write))
        database.add.assert_not_called()
        database.commit.assert_not_called()

    async def test_typed_profile_blockers_report_saved_state_without_worker_probe(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        targets = {'targets': ['192.0.2.10']}
        session = SimpleNamespace(status=SessionStatus.ACTIVE)
        database = SimpleNamespace(execute=AsyncMock(
            return_value=SimpleNamespace(scalar_one_or_none=lambda: session)))
        context = AsyncMock()
        context.__aenter__.return_value = database
        path = '/api/sessions/engagement/tool-restrictions'
        cases = [
            (targets, 'lab', {}, []),
            ({**targets, 'program_policy': {}}, 'lab', {}, ['program_policy']),
            ({**targets, 'mode': 'bug_bounty'}, 'lab', {}, ['bug_bounty_mode']),
            (targets, 'bug_bounty', {}, ['bug_bounty_mode']),
            ({}, 'lab', {'worker_blocked': True}, ['worker_execution_fenced', 'missing_scope']),
        ]
        with patch('api.routers.tool_registry.async_session', return_value=context), \
             patch('api.routers.tool_registry.worker_jobs.client.capabilities', AsyncMock()) as worker:
            for scope, mode, metadata, blockers in cases:
                with self.subTest(blockers=blockers, mode=mode):
                    session.scope, session.attack_mode, session.metadata_ = scope, mode, metadata
                    response = await self.client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()['engagement_blockers'], blockers)
                    self.assertNotIn('192.0.2.10', response.text)
            worker.assert_not_awaited()

    async def test_owner_can_add_a_durable_typed_capability_block(self):
        from datetime import datetime
        from fastapi import HTTPException
        from security_tools.adapters import ADAPTERS, AdapterError, encode

        app.dependency_overrides[get_current_user] = lambda: OWNER
        adapter = ADAPTERS['semgrep']
        session = SimpleNamespace(status=SessionStatus.ACTIVE, attack_mode='lab', metadata_={},
                                  scope={'targets': ['192.0.2.10']})
        database = SimpleNamespace(add=lambda row: events.append(row), commit=AsyncMock())
        events = []
        context = AsyncMock()
        context.__aenter__.return_value = database
        path = '/api/sessions/engagement/tool-restrictions'
        with patch('api.routers.tool_registry.async_session', return_value=context), \
             patch('api.routers.tool_registry.owned_engagement', AsyncMock(return_value=session)) as owned:
            self.assertEqual((await self.client.get(path)).json()['blocked'], [])
            for _ in range(2):
                result = await self.client.post(path, json={'capability': adapter.capability})
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()['blocked'], [adapter.capability])
            owned.assert_awaited_with(database, 'engagement', OWNER.user_id)
            database.commit.assert_awaited_once()
            self.assertEqual(events[0].metadata_, {'capability': adapter.capability})
            from security_tools.restrictions import check_capability
            with self.assertRaisesRegex(AdapterError, 'blocked for this engagement'):
                check_capability(encode({'schema_version': 1, 'tool': 'semgrep',
                                         'parameters': {'artifact_sha256': 'a' * 64}}), session.scope)
            from memory.execution_authorization import ExecutionAuthorization
            authorization = ExecutionAuthorization()
            command = encode({'schema_version': 1, 'tool': 'semgrep',
                              'parameters': {'artifact_sha256': 'a' * 64}})
            with self.assertRaises(HTTPException) as denied:
                authorization._validate(command, {'scope': session.scope})
            self.assertEqual(denied.exception.status_code, 403)
            self.assertEqual(denied.exception.detail['code'], 'capability_blocked')
            database.execute = AsyncMock(return_value=SimpleNamespace(
                all=lambda: [('audit-fixture', datetime(2026, 1, 1), adapter.capability)]))
            audit = (await self.client.get(path)).json()['audit']
            self.assertEqual(audit[adapter.capability], {
                'record_id': 'audit-fixture', 'recorded_at': '2026-01-01T00:00:00+00:00'})
            values = database.execute.await_args.args[0].compile().params.values()
            self.assertIn(OWNER.user_id, values)
            self.assertIn('engagement', values)
            owned.side_effect = HTTPException(404, 'Engagement not found')
            self.assertEqual((await self.client.post(path, json={'capability': adapter.capability})).status_code, 404)
            database.commit.assert_awaited_once()

    async def asyncTearDown(self):
        app.dependency_overrides.clear()
        await super().asyncTearDown()

    async def test_discovery_requires_identity_and_has_no_dispatch_route(self):
        self.assertEqual((await self.client.get("/api/tool-registry")).status_code, 401)
        app.dependency_overrides[get_current_user] = lambda: OWNER
        self.assertEqual((await self.client.post("/api/tool-registry", json=request())).status_code, 405)

    async def test_unconfigured_worker_never_contacts_remote(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch("config.settings.settings.KALI_AGENT_URL", ""), \
             patch("api.routers.tool_registry.worker_jobs.client.capabilities", AsyncMock()) as remote:
            response = await self.client.get("/api/tool-registry")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["worker"]["status"], "not_configured")
        self.assertEqual(response.json()["worker"]["typed_contract_status"], "unavailable")
        remote.assert_not_awaited()

    async def test_advertised_names_never_imply_version_health_or_execution(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch("config.settings.settings.KALI_AGENT_URL", "http://private-worker.invalid"), \
             patch("api.routers.tool_registry.worker_jobs.client.capabilities",
                   AsyncMock(return_value=advertisement(tools=["curl", "sqlmap"]))):
            response = await self.client.get("/api/tool-registry")
        data = response.json()
        self.assertEqual(data["worker"]["status"], "online")
        self.assertTrue(data["tools"][0]["worker_advertised"])
        self.assertFalse(data["tools"][1]["worker_advertised"])
        for tool in data["tools"]:
            self.assertIsNone(tool["observed_version"])
            self.assertFalse(tool["execution_available"])
        self.assertNotIn("private-worker", response.text)

    async def test_malformed_unreachable_and_timed_out_workers_fail_closed(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        for remote in (
            AsyncMock(side_effect=RuntimeError("private token")),
            AsyncMock(side_effect=TimeoutError("private timeout")),
            AsyncMock(return_value={"tools": ["curl"]}),
            AsyncMock(return_value=None),
            AsyncMock(return_value=[]),
            AsyncMock(return_value=advertisement(idempotency=1)),
        ):
            with patch("config.settings.settings.KALI_AGENT_URL", "http://private-worker.invalid"), \
                 patch("api.routers.tool_registry.worker_jobs.client.capabilities", remote):
                response = await self.client.get("/api/tool-registry")
            self.assertEqual(response.json()["worker"]["status"], "unreachable")
            self.assertEqual(response.json()["worker"]["typed_contract_status"], "unavailable")
            self.assertFalse(any(tool["worker_advertised"] for tool in response.json()["tools"]))
            self.assertNotIn("private", response.text)

    async def test_only_advertised_typed_profiles_expose_valid_declared_pins(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        capability = 'httpx.http.probe.v1'
        image = 'sha256:' + 'a' * 64
        pin = {'declared_version': '1.7.1', 'image_id': image}
        advertised = advertisement(tools=['curl', 'httpx'])
        advertised.update(typed_adapters={capability: 1}, typed_profile_pins={
            capability: pin, 'nmap.tcp.connect.v1': pin})
        with patch("config.settings.settings.KALI_AGENT_URL", "http://private-worker.invalid"), \
             patch("api.routers.tool_registry.worker_jobs.client.capabilities", AsyncMock(return_value=advertised)):
            response = await self.client.get("/api/tool-registry")
            rows = {row['tool']: row for row in response.json()['typed_adapters']}
            self.assertTrue(rows['httpx']['worker_available'])
            self.assertEqual(rows['httpx']['declared_version'], '1.7.1')
            self.assertEqual(rows['httpx']['image_id'], image)
            self.assertFalse(rows['httpx']['runtime_validated'])
            self.assertIsNone(rows['nmap']['declared_version'])
            pin['declared_version'] = 'private/invalid/location'
            pin['image_id'] = '/private/pin'
            response = await self.client.get("/api/tool-registry")
            rows = {row['tool']: row for row in response.json()['typed_adapters']}
            self.assertIsNone(rows['httpx']['declared_version'])
            self.assertIsNone(rows['httpx']['image_id'])
            self.assertNotIn('/private/', response.text)

    async def test_worker_contract_comparison_preserves_advertised_state(self):
        from security_tools.adapters import contract_digest

        app.dependency_overrides[get_current_user] = lambda: OWNER
        capability = 'semgrep.source.scan.v1'
        local_digest = contract_digest()
        other_digest = '0' * 64 if local_digest != '0' * 64 else '1' * 64
        worker = advertisement(tools=['curl', 'semgrep'], typed_adapters={capability: 1})
        cases = (
            ({'typed_registry_sha256': local_digest}, 'matched', local_digest),
            ({'typed_registry_sha256': other_digest}, 'mismatch', other_digest),
            ({}, 'not_reported', None),
            ({'typed_registry_sha256': None}, 'unavailable', None),
            ({'typed_registry_sha256': '/private/invalid/digest'}, 'invalid', None),
        )
        with patch('config.settings.settings.KALI_AGENT_URL', 'http://private-worker.invalid'), \
             patch('api.routers.tool_registry.worker_jobs.client.capabilities', AsyncMock()) as remote:
            for fields, status, observed in cases:
                with self.subTest(status=status):
                    remote.return_value = {**worker, **fields}
                    response = await self.client.get('/api/tool-registry')
                    self.assertEqual(response.status_code, 200)
                    data = response.json()
                    self.assertEqual(data['worker']['status'], 'online')
                    self.assertEqual(data['worker'].get('typed_contract_status'), status)
                    self.assertEqual(data['worker']['typed_registry_sha256'], observed)
                    self.assertNotIn('/private/', response.text)
                    row = next(row for row in data['typed_adapters'] if row['capability'] == capability)
                    self.assertTrue(row['worker_available'])
                    self.assertFalse(row['runtime_validated'])

    async def test_bad_registry_returns_sanitized_503_without_worker_call(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch("api.routers.tool_registry.load_registry", side_effect=RegistryError("private path")), \
             patch("api.routers.tool_registry.worker_jobs.client.capabilities", AsyncMock()) as remote:
            response = await self.client.get("/api/tool-registry")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private", response.text)
        remote.assert_not_awaited()


class PlanningRestrictionTests(OfflineCase):
    async def test_planner_rejects_blocked_capability_before_execution(self):
        from agents.autonomous_engine import AutonomousEngine, SessionRunState
        from agents.orchestrator_agent import orchestrator_agent
        from security_tools.adapters import encode
        scope = {'targets': ['192.0.2.1'], 'ports': [80], 'blocked_typed_capabilities': ['httpx.http.probe.v1']}
        command = encode({'tool': 'httpx', 'parameters': {'url': 'http://192.0.2.1'}})
        engine = AutonomousEngine()
        state = SessionRunState('engagement', 'owner', 'http_check', '192.0.2.1', 'expert',
                                capabilities={'typed_adapters': {'httpx.http.probe.v1': 1}})
        state.completed_observations = ['port_discovery']
        feedback: list = []
        with patch('agents.autonomous_engine.execution_authorization._context', AsyncMock(return_value={'scope': scope})), \
             patch.object(engine, '_specialist_context', AsyncMock(return_value={})), \
             patch.object(orchestrator_agent, 'process', AsyncMock(return_value={'commands': [{'command': command}]})):
            proposal = await engine._validated_plan(state, orchestrator_agent, [], [], feedback)
        self.assertIsNone(proposal)
        self.assertTrue(any('blocked by the engagement owner' in item for item in feedback))
