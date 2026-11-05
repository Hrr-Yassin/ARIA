"""Reviewed program scopes: a deliberately bounded HTTP observation capability."""
import ipaddress
import re
import shlex
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Literal


class AssetRule(BaseModel):
    model_config = ConfigDict(extra='forbid')
    host: str = Field(min_length=1, max_length=253)
    path: str = '/'
    ports: list[int] = Field(min_length=1, max_length=16)
    schemes: list[Literal['http', 'https']] = Field(min_length=1, max_length=2)
    source_rule: int = Field(ge=0)

    @field_validator('host')
    @classmethod
    def valid_host(cls, host: str) -> str:
        host = host.lower().rstrip('.')
        bare = host[2:] if host.startswith('*.') else host
        try:
            ipaddress.ip_address(bare)
            if host.startswith('*.'):
                raise ValueError('An IP cannot be wildcarded')
        except ValueError:
            if not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?', bare):
                raise ValueError('Use an exact ASCII hostname/IP or a leading *.hostname') from None
        return host

    @field_validator('path')
    @classmethod
    def valid_path(cls, path: str) -> str:
        return canonical_path(path)

    @field_validator('ports')
    @classmethod
    def valid_ports(cls, ports: list[int]) -> list[int]:
        if any(not 1 <= port <= 65535 for port in ports):
            raise ValueError('Invalid TCP port')
        return sorted(set(ports))


class ExecutionRules(BaseModel):
    model_config = ConfigDict(extra='forbid')
    assets: list[AssetRule] = Field(min_length=1, max_length=64)
    exclusions: list[AssetRule] = Field(default_factory=list, max_length=64)
    third_party_exclusions: list[AssetRule] = Field(default_factory=list, max_length=64)
    automation: Literal['allowed', 'prohibited', 'unknown'] = 'unknown'
    accounts_confirmed: bool = False
    prerequisites_confirmed: bool = False
    permission_confirmed: bool = False
    eligible_classes: list[Literal['http_observation']] = Field(min_length=1, max_length=1)
    max_requests: int = Field(ge=1, le=1000)
    concurrency: int = Field(ge=1, le=5)
    min_interval_seconds: float = Field(ge=1, le=86400, allow_inf_nan=False)
    # All enabled behavior must be explicitly supported by source-linked rules.
    automation_source_rule: int = Field(ge=0)
    budget_source_rule: int = Field(ge=0)
    accounts_source_rule: int = Field(ge=0)
    prerequisites_source_rule: int = Field(ge=0)
    classes_source_rule: int = Field(ge=0)
    exclusions_source_rule: int = Field(ge=0)


def canonical_path(path: str) -> str:
    # Reject ambiguous encodings instead of guessing how a target normalizes them.
    if (not path.startswith('/') or '//' in path or '%' in path or '\\' in path
            or any(part in {'.', '..'} for part in path.split('/'))
            or not re.fullmatch(r'/[A-Za-z0-9_./~-]*', path)):
        raise ValueError('Use an unambiguous absolute URL path')
    return path


def host_matches(host: str, rule: str) -> bool:
    if rule.startswith('*.'):
        suffix = rule[1:]
        return host.endswith(suffix) and host != rule[2:]
    return host == rule


def asset_matches(url: str, asset: dict) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or '').lower().rstrip('.')
    port = parts.port if parts.port is not None else (443 if parts.scheme == 'https' else 80)
    path = canonical_path(parts.path or '/')
    prefix = asset['path'].rstrip('/')
    return (host_matches(host, asset['host']) and parts.scheme in asset['schemes']
            and port in asset['ports'] and (not prefix or path == prefix or path.startswith(prefix + '/')))


def validate_program_command(command: str, scope: dict):
    from orchestrator.execution_policy import PolicyError, ValidatedCommand
    try:
        policy = scope['program_policy']
        if policy['state'] != 'active':
            raise ValueError('Policy requires review')
        rules = ExecutionRules.model_validate(policy['rules']).model_dump()
        if (rules['automation'] != 'allowed' or not rules['accounts_confirmed']
                or not rules['prerequisites_confirmed'] or not rules['permission_confirmed']):
            raise ValueError('Permission is unknown or prohibited')
        if not isinstance(command, str) or len(command) > 4096 or any(c in command for c in '\n\r\0`$|&<>\\;'):
            raise ValueError('Unsupported syntax')
        argv = shlex.split(command)
        if not argv or argv[0] != 'curl':
            raise ValueError('Program policies enable only bounded curl GET/HEAD observations')
        targets = []
        i = 1
        while i < len(argv):
            arg = argv[i]
            if arg in {'-I', '--head', '-s', '-S', '-i', '-sI', '-Is'}:
                i += 1
            elif arg in {'-m', '--max-time'} and i + 1 < len(argv) and re.fullmatch(r'[1-9][0-9]?', argv[i + 1]):
                i += 2
            elif arg.startswith(('http://', 'https://')):
                targets.append(arg)
                i += 1
            else:
                raise ValueError('Option or action is prohibited')
        if len(targets) != 1:
            raise ValueError('Exactly one request target is required')
        url = urlsplit(targets[0])
        if (not url.hostname or '*' in url.hostname or url.username is not None or url.password is not None or url.fragment
                or any(c in targets[0] for c in '{}[]')
                or any(c.isspace() for c in targets[0]) or url.hostname.endswith('.')):
            raise ValueError('Ambiguous request target')
        if any(asset_matches(targets[0], asset) for asset in rules['exclusions'] + rules['third_party_exclusions']):
            raise ValueError('Excluded asset')
        if not any(asset_matches(targets[0], asset) for asset in rules['assets']):
            raise ValueError('Outside reviewed scope')
        return ValidatedCommand(shlex.join(argv), 'curl', 'green', tuple(targets))
    except (ValueError, TypeError, KeyError, IndexError):
        raise PolicyError('Command is not permitted by the reviewed program policy') from None
