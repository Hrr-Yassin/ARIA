"""Registry contracts use synthetic documentation IPs; no tools or sockets execute."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

from config.security_tool_registry import (
    MANIFEST, Registry, RegistryError, ToolResult, load_registry,
)
from api.auth import get_current_user
from api.main import app
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
            self.assertFalse(any(tool["worker_advertised"] for tool in response.json()["tools"]))
            self.assertNotIn("private", response.text)

    async def test_bad_registry_returns_sanitized_503_without_worker_call(self):
        app.dependency_overrides[get_current_user] = lambda: OWNER
        with patch("api.routers.tool_registry.load_registry", side_effect=RegistryError("private path")), \
             patch("api.routers.tool_registry.worker_jobs.client.capabilities", AsyncMock()) as remote:
            response = await self.client.get("/api/tool-registry")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("private", response.text)
        remote.assert_not_awaited()
