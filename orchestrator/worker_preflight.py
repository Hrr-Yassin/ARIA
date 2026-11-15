"""Read-only compatibility checks; metadata never grants execution authority.

Legacy workers can omit constraints. That is explicitly unavailable, never a
positive compatibility claim. The independent worker still makes final admission.
"""
from __future__ import annotations

import shlex
from urllib.parse import urlsplit


def worker_preflight(command: str, scope: dict, capabilities: dict) -> dict:
    def result(status, code, message):
        return {'status': status, 'reason_code': code, 'message': message}
    raw = capabilities.get('execution_constraints')
    if raw is None:
        return result('unavailable', 'worker_constraints_unavailable',
            'Worker policy limits are not advertised; final worker admission remains pending.')
    from worker.policy import networks, ports
    try:
        if (not isinstance(raw, dict) or set(raw) != {'version', 'networks', 'tcp_ports'}
                or type(raw['version']) is not int or raw['version'] != 1):
            raise ValueError('Invalid constraint contract')
        ceiling, allowed_ports = networks(raw['networks']), set(ports(raw['tcp_ports']))
    except (ValueError, TypeError, KeyError):
        return result('blocked', 'worker_constraints_invalid',
            'Worker policy metadata is invalid or unsupported; no compatibility was established.')
    if command.startswith('aria-http '):
        return result('unavailable', 'worker_admission_pending',
            'Protected HTTP replay requires its existing profile-specific worker admission.')
    from orchestrator.execution_policy import target_value, validate_command
    checked = validate_command(command, scope)
    requested_ports = None
    if command.startswith('aria-tool '):
        from security_tools.adapters import decode
        _, parameters = decode(command)
        if checked.tool == 'nmap':
            requested_ports = set(parameters.ports)
        elif isinstance(getattr(parameters, 'url', None), str):
            url = urlsplit(parameters.url)
            requested_ports = {url.port or (443 if url.scheme == 'https' else 80)}
    elif checked.tool == 'curl':
        requested_ports = {urlsplit(t).port or (443 if urlsplit(t).scheme == 'https' else 80)
                           for t in checked.targets}
    elif checked.tool == 'nmap':
        argv = shlex.split(checked.command)
        try:
            requested_ports = {int(p) for p in argv[argv.index('-p') + 1].split(',')}
        except (ValueError, IndexError):
            return result('blocked', 'worker_explicit_ports_required',
                'Worker compatibility requires an explicit numeric TCP port list.')
    if requested_ports is not None and not requested_ports.issubset(allowed_ports):
        return result('blocked', 'worker_port_incompatible',
            'Proposed TCP ports exceed the independently advertised worker policy limits.')
    resolution_pending = False
    for target in checked.targets:
        parsed = target_value(target)
        if isinstance(parsed, str):
            resolution_pending = True
        elif not any(parsed.version == network.version and parsed.subnet_of(network) for network in ceiling):
            return result('blocked', 'worker_network_incompatible',
                'Proposed target exceeds the independently advertised worker network limits.')
    if resolution_pending or requested_ports is None:
        return result('unavailable', 'worker_admission_pending',
            'Worker resolution or profile-specific admission remains pending; compatibility is not yet established.')
    return result('compatible', 'worker_constraints_compatible',
        'Proposal matches advertised worker limits; scope, approval, budget and final admission still apply.')
