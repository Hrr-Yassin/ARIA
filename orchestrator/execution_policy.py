"""Conservative tool adapters. Unknown syntax is rejected, never guessed safe."""
import ipaddress
import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedCommand:
    command: str
    tool: str
    risk: str
    targets: tuple


# Only reviewed options may reach the shell-string legacy worker. Values are
# reconstructed with shlex.join. Target files, shell wrappers, redirects,
# arbitrary scripts/configs and unknown tool options are deliberately excluded.
FLAGS = {
    'nmap': ('-sV -sS -sT -sn -sC -A -O -Pn -n -v -vv -p- --open --reason',
             '-p --top-ports --version-intensity --host-timeout --max-retries --script -oX'),
    'curl': ('-I -sI -Is --head -i -s -S -k --insecure -v --fail', '-m --max-time -A --user-agent -H --header -X --request -d --data --data-raw'),
    'whois': ('', ''), 'dig': ('+short +noall +answer', ''), 'host': ('-a -v', '-t'),
    'ping': ('-n -4 -6', '-c -W'),
    'nuclei': ('-silent -json -jsonl -nc', '-u -target -severity -tags -rate-limit -rl -timeout'),
    'nikto': ('-ssl -nointeractive', '-h -host -p -port -Tuning'),
    'gobuster': ('-q -k --no-error', '-u --url -d --domain -w --wordlist -t --threads -x --extensions -s --status-codes'),
    'hydra': ('-V -v -f -F -I', '-l -L -p -P -s -t -W'),
    'sqlmap': ('--batch --dbs --tables --columns --dump --current-user --current-db --is-dba --banner',
               '-u --url -p --level --risk --threads --technique -D -T -C'),
    'enum4linux': ('-a -U -S -P -G -o -r -n', '-u -p'),
    'smbclient': ('-N -L', '-U -p'),
    'searchsploit': ('-w --www -j --json --id --cve', ''),
}
TARGET_OPTIONS = {'-u', '--url', '-target', '-host', '-h', '--domain'}
RISK = {'whois': 'green', 'dig': 'green', 'host': 'green', 'searchsploit': 'green',
        'hydra': 'red', 'sqlmap': 'red', 'msfconsole': 'red', 'smbclient': 'red'}
SAFE_SCRIPTS = {'banner', 'http-title', 'http-headers', 'ssl-cert', 'ssh-hostkey', 'smb-os-discovery'}


def target_value(raw):
    value = raw.strip()
    if '://' in value or value.startswith('//'):
        parsed = urlsplit(value if '://' in value else 'smb:' + value)
        if parsed.scheme not in {'http', 'https', 'ssh', 'ftp', 'smb', 'rdp'} or parsed.username or parsed.password:
            raise PolicyError('Unsupported target URL')
        try:
            parsed.port  # validate malformed ports
            value = parsed.hostname or ''
        except ValueError:
            raise PolicyError('Invalid target port') from None
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError:
        if '/' in value or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
            raise PolicyError('Unparsed target') from None
        # Numeric strings that are not valid IPs are not hostnames.
        if re.fullmatch(r'[0-9.]+', value):
            raise PolicyError('Invalid IP target')
        return value.rstrip('.').lower()


def allowed_target(target, scope):
    parsed = target_value(target)
    allowed = [target_value(t) for t in scope.get('targets', [])]
    excluded = [target_value(t) for t in scope.get('exclusions', [])]
    def overlaps(a, b):
        if isinstance(a, str) or isinstance(b, str):
            return isinstance(a, str) and isinstance(b, str) and a == b
        return a.version == b.version and a.overlaps(b)
    if any(overlaps(parsed, e) for e in excluded):
        raise PolicyError('Excluded target')
    for item in allowed:
        if isinstance(parsed, str) and isinstance(item, str) and parsed == item:
            return
        if not isinstance(parsed, str) and not isinstance(item, str) and parsed.version == item.version and parsed.subnet_of(item):
            return
    raise PolicyError('Target is outside the explicit engagement scope')


def validate_command(command, scope, claimed_tool=''):
    if isinstance(scope, dict) and 'program_policy' in scope:
        from orchestrator.program_scope import validate_program_command
        checked = validate_program_command(command, scope)
        if claimed_tool and claimed_tool != checked.tool:
            raise PolicyError('Tool does not match command')
        return checked
    if not isinstance(scope, dict) or not isinstance(scope.get('targets'), list) or not scope['targets']:
        raise PolicyError('An explicit nonempty engagement scope is required')
    if not isinstance(scope.get('exclusions', []), list):
        raise PolicyError('Invalid exclusions')
    # Validate the complete scope, even for offline lookups.
    for target in scope['targets'] + scope.get('exclusions', []):
        if not isinstance(target, str):
            raise PolicyError('Invalid scope target')
        target_value(target)
    if not isinstance(command, str) or not command.strip() or len(command) > 4096:
        raise PolicyError('Invalid command length')
    if any(c in command for c in ('\n', '\r', '\x00', '`', '$', '|', '&', '<', '>','\\')):
        raise PolicyError('Shell expansion, chaining and redirection are not allowed')
    try:
        argv = shlex.split(command)
    except ValueError:
        raise PolicyError('Invalid command quoting') from None
    if not argv:
        raise PolicyError('Empty command')
    tool = argv[0]
    if claimed_tool and claimed_tool != tool:
        raise PolicyError('Tool does not match the command executable')
    if tool == 'aria-http':
        from worker.http_profile import validate
        return validate(command, scope)
    if tool not in FLAGS and tool != 'msfconsole':
        raise PolicyError('No reviewed adapter exists for this tool')
    if scope.get('mode') == 'bug_bounty' and tool in {'hydra', 'sqlmap', 'msfconsole'}:
        raise PolicyError('Tool is forbidden by engagement mode')
    targets = []
    risk = RISK.get(tool, 'orange')
    if tool == 'msfconsole':
        if argv[1:3] != ['-q', '-x'] or len(argv) != 4:
            raise PolicyError('Only the reviewed Metasploit command form is supported')
        module_seen = False
        remote_target_seen = False
        for statement in argv[3].split(';'):
            parts = statement.strip().split()
            if not parts:
                continue
            if parts[0] == 'use' and len(parts) == 2:
                if module_seen:
                    raise PolicyError('Only one module is permitted per proposal')
                from config.tools_registry import validate_msf_module
                valid, corrected, _ = validate_msf_module(parts[1])
                if not valid or corrected != parts[1]:
                    raise PolicyError('Unknown or unvalidated Metasploit module')
                module_seen = True
            elif parts[0] == 'set' and len(parts) == 3:
                if not module_seen:
                    raise PolicyError('Select the module before setting arguments')
                parameter, value = parts[1:]
                if parameter in {'RHOSTS', 'RHOST', 'LHOST'}:
                    targets.append(value)
                    remote_target_seen |= parameter in {'RHOSTS', 'RHOST'}
                elif parameter in {'RPORT', 'LPORT', 'TARGET'} and value.isdigit():
                    pass
                elif parameter == 'PAYLOAD' and re.fullmatch(r'[a-zA-Z0-9_/]+', value):
                    pass
                else:
                    raise PolicyError('Unsupported Metasploit parameter')
            elif parts[0] not in {'run', 'exploit', 'check', 'exit'} or len(parts) != 1:
                raise PolicyError('Unsupported Metasploit statement')
        if not module_seen or not remote_target_seen:
            raise PolicyError('A reviewed module and explicit target are required')
    else:
        if ';' in command:
            raise PolicyError('Command chaining is not allowed')
        switches, options = (set(group.split()) for group in FLAGS[tool])
        i = 1
        while i < len(argv):
            token = argv[i]
            if token in switches or (tool == 'nmap' and re.fullmatch(r'-T[0-5]', token)):
                i += 1
                continue
            if token in options:
                if i + 1 >= len(argv):
                    raise PolicyError('Missing option value')
                value = argv[i + 1]
                if value.startswith('-') and not (tool == 'nmap' and token == '-oX' and value == '-'):
                    raise PolicyError('Invalid option value')
                if tool == 'nmap' and token == '--script' and not set(value.split(',')).issubset(SAFE_SCRIPTS):
                    raise PolicyError('Custom or unreviewed scripts are not allowed')
                if tool == 'nmap' and token == '-oX' and value != '-':
                    raise PolicyError('Only stdout output is supported')
                if (token in TARGET_OPTIONS or (tool == 'gobuster' and token == '-d')) and not (tool == 'hydra' or (tool == 'enum4linux' and token == '-u')):
                    targets.append(value)
                if tool == 'curl':
                    if token in {'-d', '--data', '--data-raw', '-H', '--header'} and value.startswith('@'):
                        raise PolicyError('Reading local files is not allowed')
                    if token in {'-X', '--request'} and value.upper() not in {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}:
                        raise PolicyError('Unsupported HTTP method')
                    if token in {'-X', '--request', '-d', '--data', '--data-raw'}:
                        risk = 'red'
                i += 2
                continue
            if token.startswith('-') or token.startswith('+'):
                raise PolicyError('Unsupported tool option')
            if tool == 'searchsploit':
                i += 1
                continue
            if (tool == 'gobuster' and token in {'dir', 'dns'}) or (tool == 'dig' and token.upper() in {'A', 'AAAA', 'MX', 'TXT', 'NS', 'ANY'}) or (tool == 'hydra' and token in {'ssh', 'ftp', 'smb', 'rdp', 'http-get', 'http-post-form'}):
                i += 1
                continue
            targets.append(token)
            i += 1
        if tool == 'curl' and risk != 'red' and any(flag in argv for flag in ('-I', '-sI', '-Is', '--head')):
            risk = 'green'
    if not targets and tool != 'searchsploit':
        raise PolicyError('No explicit target could be validated')
    for target in targets:
        allowed_target(target, scope)
    return ValidatedCommand(shlex.join(argv), tool, risk, tuple(targets))
