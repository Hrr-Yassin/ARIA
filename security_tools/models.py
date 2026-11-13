"""Closed input/output contracts; callers cannot supply flags, files or executables."""
from typing import Annotated, Literal
from urllib.parse import parse_qsl, urlsplit
import re

from pydantic import Field, field_validator, model_validator
from config.security_tool_registry import ClosedModel, HTTPObservation, TCPConnect

Digest = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Identifier = Annotated[str, Field(pattern=r'^[a-z][a-z0-9_-]{0,63}$')]


class URLInput(HTTPObservation):
    pass


class HttpxInput(URLInput):
    pass


class KatanaInput(URLInput):
    depth: int = Field(default=1, ge=1, le=2)


class PlaywrightInput(URLInput):
    pass


class NucleiInput(URLInput):
    template: Literal['http-observation'] = 'http-observation'


class ZapInput(URLInput):
    pass


class FfufInput(URLInput):
    words: list[str] = Field(min_length=1, max_length=16)

    @field_validator('words')
    @classmethod
    def safe_words(cls, value):
        if any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', word) for word in value):
            raise ValueError('Only bounded path segments are supported')
        return sorted(set(value))


class SqlmapInput(ClosedModel):
    url: str = Field(min_length=1, max_length=2048)
    parameter: Identifier

    @model_validator(mode='after')
    def bounded_query(self):
        parts = urlsplit(self.url)
        URLInput(url=self.url.split('?', 1)[0])
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        if (parts.fragment or len(pairs) != 1 or pairs[0][0] != self.parameter
                or not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', pairs[0][1])
                or parts.query != self.parameter + '=' + pairs[0][1]):
            raise ValueError('One explicit simple GET parameter is required')
        return self


class SemgrepInput(ClosedModel):
    artifact_sha256: Digest
    rules: Literal['aria-python'] = 'aria-python'


class SubfinderInput(ClosedModel):
    domain: str = Field(min_length=3, max_length=253)
    source: Literal['crtsh'] = 'crtsh'

    @field_validator('domain')
    @classmethod
    def domain_name(cls, value):
        if not re.fullmatch(r'(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
            raise ValueError('An explicit lowercase domain is required')
        return value


class Observation(ClosedModel):
    kind: Literal['service', 'http', 'url', 'finding', 'code', 'domain', 'browser', 'injection']
    locator: str = Field(max_length=2048)
    summary: str = Field(max_length=512)
    severity: Literal['info', 'low', 'medium', 'high', 'critical', 'unknown'] = 'unknown'
    # Scanner reports remain candidates, including reports that name a vulnerability.
    verification: Literal['unverified'] = 'unverified'


class AdapterOutput(ClosedModel):
    tool: str
    observations: list[Observation] = Field(max_length=128)
    error: Literal['none', 'invalid_output', 'tool_failed', 'timeout', 'resource_exhausted', 'cancelled', 'unknown']
    truncated: bool = False


class NmapOutput(AdapterOutput):
    tool: Literal['nmap'] = 'nmap'


class HttpxOutput(AdapterOutput):
    tool: Literal['httpx'] = 'httpx'


class KatanaOutput(AdapterOutput):
    tool: Literal['katana'] = 'katana'


class PlaywrightOutput(AdapterOutput):
    tool: Literal['playwright'] = 'playwright'


class NucleiOutput(AdapterOutput):
    tool: Literal['nuclei'] = 'nuclei'


class ZapOutput(AdapterOutput):
    tool: Literal['zap'] = 'zap'


class FfufOutput(AdapterOutput):
    tool: Literal['ffuf'] = 'ffuf'


class SqlmapOutput(AdapterOutput):
    tool: Literal['sqlmap'] = 'sqlmap'


class SemgrepOutput(AdapterOutput):
    tool: Literal['semgrep'] = 'semgrep'


class SubfinderOutput(AdapterOutput):
    tool: Literal['subfinder'] = 'subfinder'


class AdapterRequest(ClosedModel):
    schema_version: Literal[1] = 1
    tool: Literal['nmap', 'httpx', 'katana', 'playwright', 'nuclei', 'zap', 'ffuf', 'sqlmap', 'semgrep', 'subfinder']
    parameters: dict


class Provenance(ClosedModel):
    job_id: str
    session_id: str
    request_sha256: Digest
    registry_sha256: Digest
    output_sha256: Digest
    stderr_sha256: Digest
    adapter_revision: Literal[1] = 1
    # Null unless independently measured by a deployed profile. Never infer from names.
    tool_version: str | None = None
    declared_tool_version: str | None = None
    image_id: Annotated[str, Field(pattern=r'^sha256:[0-9a-f]{64}$')] | None = None
    receipt_verified: Literal[True] = True
    verification: Literal['unverified'] = 'unverified'


class AdapterAttestation(ClosedModel):
    capability: str = Field(max_length=100)
    request_sha256: Digest
    registry_sha256: Digest
    image_id: str = Field(pattern=r'^sha256:[0-9a-f]{64}$')
    declared_tool_version: str = Field(max_length=64)
    binary_sha256: Digest
