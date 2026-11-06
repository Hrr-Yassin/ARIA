"""Resolve once, intersect engagement scope with an independent worker ceiling."""
import asyncio
import ipaddress
import shlex
import socket

from orchestrator.execution_policy import PolicyError, target_value, validate_command


def networks(values: list[str]) -> list:
    if not isinstance(values, list) or not 1 <= len(values) <= 64:
        raise PolicyError('Expected 1..64 explicit IP networks')
    if any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in values):
        raise PolicyError('Networks must be explicit IP/CIDR strings')
    result = [ipaddress.ip_network(value, strict=True) for value in values]
    if any(net.prefixlen == 0 for net in result):
        raise PolicyError('Default routes are not allowed')
    return result


def ports(values: list[int]) -> list[int]:
    if not isinstance(values, list) or not 1 <= len(values) <= 1024:
        raise PolicyError('Expected 1..1024 explicit TCP ports')
    if any(type(port) is not int or not 1 <= port <= 65535 for port in values):
        raise PolicyError('Invalid TCP port')
    return sorted(set(values))


async def resolve(host: str) -> list[str]:
    records = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        host, None, type=socket.SOCK_STREAM), timeout=5)
    addresses = sorted({str(ipaddress.ip_address(row[4][0])) for row in records})
    if not addresses or len(addresses) > 32:
        raise PolicyError('Unbounded or empty DNS answer')
    return addresses


def validate_worker_command(command: str, scope: dict):
    validated = validate_command(command, scope)
    argv = shlex.split(validated.command)
    if validated.tool not in {'curl', 'nmap'}:
        raise PolicyError('Worker supports only curl and Nmap TCP scans')
    if validated.tool == 'nmap':
        if any(arg in argv for arg in ('-sS', '-sC', '-A', '-O', '-sn', '--script')):
            raise PolicyError('Raw scans and scripts are not supported by this worker')
        if scope.get('ports'):
            try:
                requested = {int(value) for value in argv[argv.index('-p') + 1].split(',')}
            except (ValueError, IndexError):
                raise PolicyError('Scoped scans require an explicit numeric port list') from None
            if not requested or not requested.issubset(set(ports(scope['ports']))):
                raise PolicyError('Scan exceeds engagement ports')
    return validated


async def prepare(command: str, scope: dict, ceiling: list[str], allowed_ports: list[int], resolver=resolve) -> dict:
    if not isinstance(scope, dict) or len(scope.get('targets', [])) > 64 or len(scope.get('exclusions', [])) > 64:
        raise PolicyError('Invalid scope size')
    validated = validate_worker_command(command, scope)
    argv = shlex.split(validated.command)
    if validated.tool == 'nmap':
        argv[1:1] = ['-sT', '-Pn', '-n']
    ceiling = networks(ceiling)
    permitted_ports = ports(allowed_ports)
    if 'ports' in scope:
        permitted_ports = sorted(set(permitted_ports) & set(ports(scope['ports'])))
    if scope.get('program_policy'):
        from urllib.parse import urlsplit
        requested_url = urlsplit(validated.targets[0])
        requested_port = requested_url.port if requested_url.port is not None else (443 if requested_url.scheme == 'https' else 80)
        permitted_ports = sorted(set(permitted_ports) & {requested_port})
    if not permitted_ports:
        raise PolicyError('No permitted TCP ports')
    excluded = []
    if scope.get('program_policy'):
        for asset in scope['program_policy']['rules']['exclusions'] + scope['program_policy']['rules']['third_party_exclusions']:
            if '*' not in asset['host'] and asset['path'] == '/':
                try:
                    excluded.append(ipaddress.ip_network(asset['host']))
                except ValueError:
                    excluded.extend(ipaddress.ip_network(ip) for ip in await resolver(asset['host']))
    if (scope.get('program_policy') or scope.get('web_authenticated_replay') is True) and validated.tool == 'curl':
        # Config-free, no URL globbing/retries/redirects; include deterministic status evidence.
        argv[1:1] = ['-q', '--globoff', '-i', '--proto', '=http,https', '--max-redirs', '0',
                     '--write-out', '\nARIA_HTTP_STATUS:%{http_code}\n']
    for value in scope.get('exclusions', []):
        parsed = target_value(value)
        if isinstance(parsed, str):
            excluded.extend(ipaddress.ip_network(ip) for ip in await resolver(parsed))
        else:
            excluded.append(parsed)
    destinations, hosts = [], {}
    for target in validated.targets:
        parsed = target_value(target)
        if isinstance(parsed, str):
            addresses = await resolver(parsed)
            hosts[parsed] = addresses
            requested = [ipaddress.ip_network(ip) for ip in addresses]
        else:
            requested = [parsed]
        for net in requested:
            if not any(net.version == limit.version and net.subnet_of(limit) for limit in ceiling):
                raise PolicyError('Resolved target exceeds worker network ceiling')
            if any(net.version == deny.version and net.overlaps(deny) for deny in excluded):
                raise PolicyError('Resolved target overlaps an exclusion')
            destinations.append(str(net))
    if not destinations or len(destinations) > 128:
        raise PolicyError('Invalid destination count')
    return {'argv': argv, 'networks': sorted(set(destinations)), 'ports': permitted_ports,
            'hosts': hosts}


def firewall(plan: dict) -> str:
    """Filter after conntrack, before destination NAT (including Docker DNS)."""
    rules = ['table inet aria {',
             'chain output { type filter hook output priority -150; policy drop;']
    tcp_ports = ', '.join(str(port) for port in ports(plan['ports']))
    for raw in plan['networks']:
        net = ipaddress.ip_network(raw, strict=True)
        family = 'ip' if net.version == 4 else 'ip6'
        rules.append(f'{family} daddr {net} tcp dport {{ {tcp_ports} }} accept')
    rules.extend(['}', 'chain input { type filter hook input priority -150; policy drop;',
                  'ct state established accept', '}',
                  'chain forward { type filter hook forward priority -150; policy drop; }', '}'])
    return '\n'.join(rules) + '\n'
