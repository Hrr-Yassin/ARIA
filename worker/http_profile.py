"""Bodyless authenticated HTTP profile. Credentials never occur in commands.

Both controllers must explicitly provision HTTP_REPLAY_KEY. The worker repeats
scope, identity/digest and request-shape validation before container creation.
"""
import hashlib
import json
import os
import re
import shlex
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from orchestrator.execution_policy import PolicyError, ValidatedCommand

PROFILE = 'aria-http'


def cipher(key=None):
    return Fernet((key if key is not None else os.environ.get('HTTP_REPLAY_KEY', '')).encode())


def available():
    try:
        cipher()
        return True
    except (ValueError, TypeError):
        return False


def fingerprint(spec):
    return hashlib.sha256(json.dumps(spec, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def command_for(identity_id, capture_id, spec):
    return shlex.join([PROFILE, identity_id, capture_id, fingerprint(spec), spec['method'], spec['url']])


def parse(command):
    args = shlex.split(command)
    if len(args) != 6 or args[0] != PROFILE:
        raise PolicyError('Invalid structured HTTP command')
    for value in args[1:3]:
        if str(uuid.UUID(value)) != value:
            raise PolicyError('Canonical identity and capture handles required')
    if not re.fullmatch('[0-9a-f]{64}', args[3]) or args[4] not in {'GET', 'HEAD'}:
        raise PolicyError('Invalid structured HTTP digest or method')
    parts = urlsplit(args[5])
    if (parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment or any(c in args[5] for c in '\r\n\x00')):
        raise PolicyError('HTTP replay supports bodyless GET/HEAD without query, userinfo or fragment')
    parts.port
    return args


def validate(command, scope):
    from orchestrator.execution_policy import validate_command
    args = parse(command)
    if scope.get('web_authenticated_replay') is not True or scope.get('program_policy'):
        raise PolicyError('This authenticated profile requires explicit lab scope; program replay is not enabled')
    # Reuse the shared target policy and the worker's independent IP/port ceiling.
    validate_command(shlex.join(['curl', '-I', args[5]]), scope)
    return ValidatedCommand(shlex.join(args), PROFILE, 'red', (args[5],))


def decode(token, command, key=None):
    args = parse(command)
    spec = json.loads(cipher(key).decrypt(token.encode()))
    if (not isinstance(spec, dict) or set(spec) != {'method', 'url', 'headers', 'expires_at'}
            or spec['method'] != args[4] or spec['url'] != args[5] or fingerprint(spec) != args[3]):
        raise PolicyError('Encrypted HTTP request does not match approval')
    if datetime.fromisoformat(spec['expires_at']) <= datetime.now(timezone.utc):
        raise PolicyError('HTTP identity or evidence expired')
    headers = spec['headers']
    if not isinstance(headers, dict) or not 1 <= len(headers) <= 3:
        raise PolicyError('A controlled authenticated identity is required')
    for name, value in headers.items():
        if name not in {'authorization', 'cookie', 'x-api-key'} or not isinstance(value, str) or not 1 <= len(value) <= 2048:
            raise PolicyError('Unsupported authentication header')
        if any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise PolicyError('Invalid authentication header value')
    values = []
    for name, value in headers.items():
        values.append(value)
        if name == 'authorization':
            values.append(value.split(' ', 1)[-1])
        elif name == 'cookie':
            values.extend(part.partition('=')[2].strip() for part in value.split(';'))
    if any(value and value in spec['url'] for value in values):
        raise PolicyError('Credential-bearing URLs cannot enter approval commands')
    return spec


async def prepare_http(command, scope, ceiling, allowed_ports, token):
    from worker.policy import prepare
    checked = validate(command, scope)
    spec = decode(token, checked.command)
    plan = await prepare(shlex.join(['curl', '-I', spec['url']]), scope, ceiling, allowed_ports)
    parts = urlsplit(spec['url'])
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    if port not in plan['ports']:
        raise PolicyError('HTTP port exceeds worker ceiling')
    plan['ports'] = [port]
    plan['private_expires_at'] = spec['expires_at']
    plan['protected_http'] = token
    plan['http_command'] = checked.command
    plan['argv'] = ['/usr/local/bin/python', '-m', 'worker.http_runner']
    return plan


def public_receipt(stdout):
    """Only non-content receipt metadata may reach chat, logs or model adapters."""
    try:
        value = json.loads(stdout)
        if (value.get('profile') == 'aria-http-v1' and type(value.get('status')) is int
                and 100 <= value['status'] <= 599
                and re.fullmatch('[0-9a-f]{64}', value.get('response_sha256', ''))):
            return json.dumps({key: value[key] for key in ('profile', 'status', 'response_sha256')}, sort_keys=True)
    except (ValueError, TypeError, AttributeError):
        pass
    return json.dumps({'profile': 'aria-http-v1', 'error': 'bounded_http_failed'})
