"""Declarative, read-only security tool catalog. This module never dispatches jobs.

The legacy config.tools_registry module is planning metadata, not authority.
Only reviewed input models are registered here; manifests cannot import code,
supply command lines, enable tools, or grant execution permission.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Annotated, Literal, get_args, get_origin
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from worker.policy import validate_worker_command

MANIFEST = Path(__file__).with_name("security_tools.json")
MAX_MANIFEST_BYTES = 65536
Name = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
Sha256 = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
AUDIT_FIELDS = frozenset({
    "action_id", "job_id", "session_id", "owner_id", "scope_digest",
    "worker_epoch", "registry_digest", "request_digest", "image_id",
    "tool_version", "started_at", "finished_at", "exit_code", "output_hash",
    "evidence_ids",
})


class RegistryError(ValueError):
    """Public errors deliberately omit untrusted manifest/request content."""


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    @model_validator(mode="before")
    @classmethod
    def strict_literals(cls, data):
        # Python considers True == 1; protocol and policy literals must not.
        if isinstance(data, dict):
            for name, field in cls.model_fields.items():
                if name in data and get_origin(field.annotation) is Literal:
                    if not any(type(data[name]) is type(value) and data[name] == value
                               for value in get_args(field.annotation)):
                        raise ValueError("Invalid literal type or value")
        return data


class HTTPObservation(ClosedModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def bounded_url(cls, value: str) -> str:
        # Initial operations are unauthenticated, bodyless, single-URL requests.
        if (not value.isascii() or re.search(r"[\s\x00-\x1f\x7f]", value)
                or any(char in value for char in ('\\', '$', '\x60', '|', '&', '<', '>', ';', '{', '}'))
                or "?" in value or "#" in value):
            raise ValueError("Unsupported observation URL")
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.hostname.endswith(".") or parsed.port == 0):
            raise ValueError("Unsupported observation URL")
        from orchestrator.execution_policy import target_value
        target_value(value)
        from orchestrator.program_scope import canonical_path
        canonical_path(parsed.path or "/")
        return value


class TCPConnect(ClosedModel):
    host: str = Field(min_length=1, max_length=253)
    ports: list[Port] = Field(min_length=1, max_length=32)

    @field_validator("host")
    @classmethod
    def single_host(cls, value: str) -> str:
        from orchestrator.execution_policy import target_value
        if value != value.strip() or any(char in value for char in "/:?#"):
            # IPv6 literals are accepted separately; URLs and CIDRs are not.
            import ipaddress
            try:
                return str(ipaddress.IPv6Address(value))
            except ValueError:
                raise ValueError("A single hostname or IP is required") from None
        parsed = target_value(value)
        return parsed if isinstance(parsed, str) else str(parsed.network_address)

    @field_validator("ports")
    @classmethod
    def canonical_ports(cls, value: list[int]) -> list[int]:
        return sorted(set(value))


INPUT_MODELS = {
    ("curl", "http.headers"): HTTPObservation,
    ("curl", "http.get"): HTTPObservation,
    ("nmap", "tcp.connect"): TCPConnect,
}
PERMISSIONS = {
    "http.headers": {"engagement.execute", "network.http.observe"},
    "http.get": {"engagement.execute", "network.http.observe"},
    "tcp.connect": {"engagement.execute", "network.tcp.connect"},
}
OPERATION_RISK = {"http.headers": "green", "http.get": "orange", "tcp.connect": "orange"}
EXECUTABLES = {"curl": "/usr/bin/curl", "nmap": "/usr/bin/nmap"}
ROLES = Literal["recon", "scan", "vuln", "web_intel", "correlation", "report"]


class OperationRequest(ClosedModel):
    schema_version: Literal[1]
    tool: Name
    operation: Name
    parameters: dict


class EvidenceReference(ClosedModel):
    evidence_id: str = Field(min_length=1, max_length=100)
    sha256: Digest


class ToolResult(ClosedModel):
    """Future normalized receipt envelope; validation alone establishes no provenance."""
    schema_version: Literal[1]
    job_id: str = Field(min_length=1, max_length=100)
    session_id: str = Field(min_length=1, max_length=100)
    tool: Name
    operation: Name
    registry_digest: Digest
    request_digest: Digest
    state: Literal["succeeded", "failed", "cancelled", "unknown"]
    exit_code: int | None
    tool_version: str = Field(pattern=r"^[0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9.+_-]*)$")
    image_id: Sha256
    duration_ms: Annotated[int, Field(ge=0)] | None
    evidence: list[EvidenceReference] = Field(max_length=64)
    verification: Literal["unverified"]
    error_code: Literal[
        "none", "tool_unavailable", "capability_unavailable", "authorization_denied",
        "scope_denied", "timeout", "resource_exhausted", "worker_unavailable",
        "invalid_output", "cancelled", "unknown",
    ]

    @model_validator(mode="after")
    def consistent_exit(self):
        if self.state in {"succeeded", "failed"}:
            if self.exit_code is None or ((self.state == "succeeded") != (self.exit_code == 0)):
                raise ValueError("Inconsistent terminal exit status")
        if self.state == "succeeded" and self.error_code != "none":
            raise ValueError("Successful result cannot carry an execution error")
        return self


class Resources(ClosedModel):
    # Current worker envelope; different envelopes require a reviewed model.
    cpus: Literal[1]
    memory_mib: Literal[256]
    memory_swap_mib: Literal[256]
    pids: Literal[64]
    nofile: Literal[256]
    tmpfs_mib: Literal[32]
    shm_mib: Literal[8]
    read_only_root: Literal[True]
    tool_uid: Literal[65534]
    tool_capabilities: list[Name] = Field(max_length=0)
    no_new_privileges: Literal[True]


class Network(ClosedModel):
    transport: Literal["tcp"]
    destinations: Literal["engagement_scope_intersect_worker_ceiling"]
    dns: Literal["resolve_once_pin_all_answers"]
    redirects: Literal[False]
    proxy: Literal[False]
    external_services: Literal[False]


class ExecutionLimits(ClosedModel):
    timeout_seconds: int = Field(ge=1, le=300)
    max_concurrency: Literal[1]
    min_interval_seconds: int = Field(ge=1, le=86400)
    max_targets: Literal[1]
    max_ports: int = Field(ge=1, le=32)
    stdout_bytes: int = Field(ge=1, le=100000)
    stderr_bytes: int = Field(ge=1, le=10000)


class HealthCheck(ClosedModel):
    argv: list[str] = Field(min_length=2, max_length=2)
    timeout_seconds: Literal[5]
    network: Literal["none"]


class Operation(ClosedModel):
    id: Name
    capability: Name
    input_schema: Name
    output_schema: Literal["aria.tool.result.v1"]
    required_permissions: list[Name] = Field(min_length=2, max_length=8)
    approval: Literal["existing_execution_authorization"]
    risk: Literal["green", "orange"]
    agent_roles: list[ROLES] = Field(min_length=1, max_length=6)
    limits: ExecutionLimits


class Tool(ClosedModel):
    name: Name
    version: Annotated[str, Field(pattern=r"^[0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9.+_-]*)$")] | None
    category: Literal["http_tls", "recon"]
    container_profile: Name
    image_id: Sha256 | None
    executable: str
    enabled: Literal[False]  # Phase boundary: a JSON edit cannot enable execution.
    resources: Resources
    network: Network
    audit_requirements: list[Name] = Field(min_length=len(AUDIT_FIELDS), max_length=32)
    health_check: HealthCheck
    operations: list[Operation] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def reviewed_definition(self):
        if self.name not in EXECUTABLES or self.executable != EXECUTABLES[self.name]:
            raise ValueError("No reviewed tool definition")
        if (self.version is None) != (self.image_id is None):
            raise ValueError("Version and immutable image identity must be pinned together")
        if set(self.audit_requirements) != AUDIT_FIELDS or len(self.audit_requirements) != len(AUDIT_FIELDS):
            raise ValueError("Incomplete audit requirements")
        if self.health_check.argv != [self.executable, "--version"]:
            raise ValueError("Unreviewed health check")
        ids = [operation.id for operation in self.operations]
        if len(set(ids)) != len(ids):
            raise ValueError("Duplicate operation")
        for operation in self.operations:
            if (self.name, operation.id) not in INPUT_MODELS:
                raise ValueError("No reviewed operation adapter")
            if (operation.input_schema != operation.id + ".v1"
                    or operation.capability != self.name + "." + operation.id + ".v1"
                    or set(operation.required_permissions) != PERMISSIONS[operation.id]):
                raise ValueError("Operation contract mismatch")
            if (operation.risk != OPERATION_RISK[operation.id]
                    or operation.limits.timeout_seconds > (30 if self.name == "nmap" else 10)):
                raise ValueError("Unreviewed risk or timeout")
        return self


class Registry(ClosedModel):
    schema_version: Literal[1]
    mode: Literal["catalog_only"]
    tools: list[Tool] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def unique_tools(self):
        if len({tool.name for tool in self.tools}) != len(self.tools):
            raise ValueError("Duplicate tool")
        return self

    @property
    def digest(self) -> str:
        return hashlib.sha256(json.dumps(
            self.model_dump(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def validate_request(self, payload: dict, scope: dict) -> OperationRequest:
        """Validate a planning request against server-loaded scope; NEVER authorize it.

        No shell, worker, database, resolver or model is invoked. DNS/IP ceiling,
        current principal, approval, budgets and receipt checks remain mandatory
        at the existing execution boundary in a later integration phase.
        """
        try:
            request = OperationRequest.model_validate(payload)
            tool = next(tool for tool in self.tools if tool.name == request.tool)
            operation = next(op for op in tool.operations if op.id == request.operation)
            parameters = INPUT_MODELS[(tool.name, operation.id)].model_validate(request.parameters)
            if isinstance(parameters, HTTPObservation):
                argv = ["curl", *(['-I'] if operation.id == "http.headers" else []),
                        "--max-time", str(operation.limits.timeout_seconds), parameters.url]
            else:
                if len(parameters.ports) > operation.limits.max_ports:
                    raise ValueError("Too many ports")
                # Reuse the existing reviewed worker policy, including program policy.
                argv = ["nmap", "-p", ",".join(map(str, parameters.ports)), parameters.host]
            validate_worker_command(shlex.join(argv), scope)
            if isinstance(parameters, TCPConnect) and "ports" in scope:
                from worker.policy import ports
                if not set(parameters.ports).issubset(ports(scope["ports"])):
                    raise ValueError("Ports exceed scope")
            if isinstance(parameters, HTTPObservation) and "ports" in scope:
                from worker.policy import ports
                url = urlsplit(parameters.url)
                port = url.port or (443 if url.scheme == "https" else 80)
                if port not in ports(scope["ports"]):
                    raise ValueError("Port exceeds scope")
            return request.model_copy(update={"parameters": parameters.model_dump()})
        except (ValueError, TypeError, KeyError, AttributeError, StopIteration):
            raise RegistryError("Operation schema or scope denied the request") from None

    def catalog(self, advertised: dict | None = None) -> dict:
        """Names advertised by jobs-v1 are observations, not version/health proof."""
        names = set()
        if advertised is not None:
            try:
                names = set(WorkerAdvertisement.model_validate(advertised).tools)
            except (ValueError, TypeError):
                raise RegistryError("Invalid worker capability advertisement") from None
        entries = []
        mapping = {role: [] for role in ("recon", "scan", "vuln", "web_intel", "correlation", "report")}
        for tool in self.tools:
            entry = tool.model_dump()
            reasons = ["catalog_only", "tool_disabled", "structured_dispatch_not_implemented"]
            if tool.version is None:
                reasons.append("version_unpinned")
            if tool.image_id is None:
                reasons.append("image_unpinned")
            if tool.name not in names:
                reasons.append("worker_tool_unavailable")
            entry.update(
                worker_advertised=tool.name in names,
                observed_version=None,
                health={"status": "not_measured", "checked_at": None},
                execution_available=False, blocked_reasons=reasons)
            for operation in tool.operations:
                for role in operation.agent_roles:
                    mapping[role].append(operation.capability)
            entries.append(entry)
        from security_tools.adapters import catalog as adapter_catalog, contract_digest
        typed_adapters = adapter_catalog(advertised)
        pins = (advertised or {}).get('typed_profile_pins')
        for adapter in typed_adapters:
            pin = pins.get(adapter['capability']) if adapter['worker_available'] and isinstance(pins, dict) else None
            version = pin.get('declared_version') if isinstance(pin, dict) else None
            image = pin.get('image_id') if isinstance(pin, dict) else None
            adapter['declared_version'] = (
                version if isinstance(version, str) and len(version) <= 64
                and re.fullmatch(r'[0-9]+(?:\.[0-9]+)+[a-zA-Z0-9.+_-]*', version) else None)
            adapter['image_id'] = image if isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image) else None
            for role in adapter['agent_roles']:
                if adapter['capability'] not in mapping[role]:
                    mapping[role].append(adapter['capability'])
        return {
            "typed_adapters": typed_adapters,
            "typed_registry_sha256": contract_digest(),
            "schema": "aria.tool.registry.v1", "mode": self.mode,
            "registry_digest": self.digest, "tools": entries, "agent_capabilities": mapping,
            "input_schemas": {op.id + ".v1": INPUT_MODELS[(tool.name, op.id)].model_json_schema()
                              for tool in self.tools for op in tool.operations},
            "request_schema": OperationRequest.model_json_schema(),
            "output_schemas": {"aria.tool.result.v1": ToolResult.model_json_schema()},
            "authorization": "Discovery and schema validation never grant execution permission",
            "limits_status": "Requirements for future adapters; no registry dispatch exists",
        }


class WorkerAdvertisement(ClosedModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    protocol: Literal["aria-jobs-v1"]
    idempotency: Literal[True]
    cancellation: Literal[True]
    network_scope: Literal[True]
    tools: list[Name] = Field(max_length=64)


def load_registry(path: Path = MANIFEST) -> Registry:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise ValueError("Manifest exceeds bound")
        # Duplicate JSON keys must not silently replace security declarations.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate manifest key")
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=unique)
        return Registry.model_validate(data)
    except (OSError, ValueError, TypeError, RecursionError):
        raise RegistryError("Tool registry is unavailable or invalid") from None
