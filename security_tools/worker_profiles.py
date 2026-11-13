"""Worker-owned deployment pins. Empty configuration means no executable adapters."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Literal
from pydantic import Field
from security_tools.models import ClosedModel, Digest
from security_tools.adapters import ADAPTERS, AdapterError, decode, sha256, contract_digest


class Profile(ClosedModel):
    image_id: str = Field(pattern=r'^sha256:[0-9a-f]{64}$')
    tool_version: str = Field(pattern=r'^[0-9]+(?:\.[0-9]+)+(?:[a-zA-Z0-9.+_-]*)$')
    binary_sha256: Digest
    # Content-addressed assets are baked into this image; no submitted host mounts.
    assets: dict[str, Digest] = Field(default_factory=dict, max_length=8)
    artifacts: list[Digest] = Field(default_factory=list, max_length=16)
    passive_sources: list[Literal['crtsh']] = Field(default_factory=list, max_length=1)


def load_profiles(path: str | None) -> dict[str, Profile]:
    if not path:
        return {}
    raw = Path(path).read_bytes()
    if len(raw) > 32768:
        raise AdapterError('Profile file exceeds bound')
    def unique(pairs):
        data = {}
        for key, value in pairs:
            if key in data:
                raise AdapterError('Duplicate profile key')
            data[key] = value
        return data
    data = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(data, dict) or not set(data).issubset(ADAPTERS):
        raise AdapterError('Unknown profile')
    result = {name: Profile.model_validate(value) for name, value in data.items()}
    for name, profile in result.items():
        expected = {'http-observation.yaml'} if name == 'nuclei' else {'aria-python.yaml'} if name == 'semgrep' else set()
        if name == 'subfinder' and profile.assets:
            expected = {'subfinder-offline.jsonl'}
        if set(profile.assets) != expected:
            raise AdapterError('Required asset pins do not match')
        if profile.artifacts and name != 'semgrep':
            raise AdapterError('Unexpected source artifacts')
        if profile.passive_sources and name != 'subfinder':
            raise AdapterError('Unexpected third-party egress')
    return result


async def prepare_tool(command: str, scope: dict, ceiling: list[str], allowed_ports: list[int],
                       profiles: dict[str, Profile], resolver=None) -> dict:
    from worker.policy import prepare, resolve
    resolver = resolver or resolve
    adapter, parameters = decode(command)
    adapter.validate_scope(parameters, scope)
    profile = profiles.get(adapter.name)
    if profile is None:
        raise AdapterError('Worker adapter profile is unavailable')
    profile = Profile.model_validate(profile)
    if adapter.name == 'subfinder' and parameters.source == 'offline':
        if set(profile.assets) != {'subfinder-offline.jsonl'}:
            raise AdapterError('Offline fixture is not installed and pinned')
        plan = {'argv': [], 'networks': [], 'ports': [1], 'hosts': {}}
    elif adapter.name == 'semgrep':
        if parameters.artifact_sha256 not in profile.artifacts:
            raise AdapterError('Source artifact is not installed in the worker image')
        plan = {'argv': [], 'networks': [], 'ports': [1], 'hosts': {}}
    elif adapter.name == 'subfinder':
        if profile.passive_sources != ['crtsh']:
            raise AdapterError('Worker passive provider egress is unavailable')
        # Provider destinations are fixed in code and still intersect the independent
        # worker ceiling. DNS is resolved once by the controller, not by tools.
        provider_scope = {'targets': ['crt.sh'], 'ports': [443], 'exclusions': scope.get('exclusions', [])}
        plan = await prepare('curl --max-time 5 https://crt.sh/', provider_scope, ceiling, allowed_ports, resolver)
    elif adapter.name == 'nmap':
        import shlex
        argv = adapter.argv(parameters)
        plan = await prepare(shlex.join(['nmap', *argv[1:]]), scope, ceiling, allowed_ports, resolver)
    else:
        import shlex
        url = parameters.url.split('?', 1)[0]
        plan = await prepare(shlex.join(['curl', '--max-time', '5', url]), scope, ceiling, allowed_ports, resolver)
        from urllib.parse import urlsplit
        url_parts = urlsplit(url)
        plan['ports'] = [url_parts.port or (443 if url_parts.scheme == 'https' else 80)]
    # Native argv is reconstructed inside the image as well. The controller's
    # network plan comes from the existing resolve/pin/ceiling/exclusion policy.
    plan.update(adapter_request=command, adapter_scope=scope, adapter_profile=profile.model_dump(),
                image_id=profile.image_id, adapter_name=adapter.name,
                argv=['/usr/local/bin/python', '-m', 'security_tools.runner'])
    plan['adapter_attestation'] = {
        'capability': adapter.capability, 'request_sha256': sha256(command),
        'registry_sha256': contract_digest(), 'image_id': profile.image_id,
        'declared_tool_version': profile.tool_version, 'binary_sha256': profile.binary_sha256}
    return plan
