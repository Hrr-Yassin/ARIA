"""Reviewed adapters: pure compilation, scope validation and bounded normalization.

The aria-tool token is a canonical data envelope, not a shell command. The shared
execution ledger binds it exactly; only the worker constructs native argv.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
import shlex
from pathlib import Path
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlsplit

from security_tools import models as m


class AdapterError(ValueError):
    pass


def canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def contract_digest() -> str:
    # Approval tokens bind the reviewed implementation as well as parameters.
    # API and worker must run matching revisions; upgrades require new proposals.
    root = Path(__file__).parent
    files = ('adapters.py', 'models.py', 'worker_profiles.py', 'runner.py', 'browser_runner.py', 'snapshot.py')
    return hashlib.sha256(b''.join((root / name).read_bytes() for name in files)).hexdigest()


@dataclass(frozen=True)
class Adapter:
    name: str
    operation: str
    input_model: type
    output_model: type
    executable: str
    timeout: int
    risk: str = 'orange'
    role: str = 'vuln'

    @property
    def capability(self) -> str:
        return f'{self.name}.{self.operation}.v1'

    def parameters(self, data: dict):
        try:
            return self.input_model.model_validate(data)
        except (ValueError, TypeError):
            raise AdapterError('Invalid tool parameters') from None

    def validate_scope(self, parameters, scope: dict) -> tuple[str, ...]:
        from orchestrator.execution_policy import allowed_target, validate_command
        if not isinstance(scope, dict) or 'program_policy' in scope:
            # Multi-request tool profiles do not inherit the single-request program budget.
            raise AdapterError('These adapters require explicit laboratory scope')
        if scope.get('mode') == 'bug_bounty':
            raise AdapterError('Adapter is unavailable in bug bounty mode')
        if not isinstance(scope.get('targets'), list) or not scope['targets']:
            raise AdapterError('An engagement scope is required')
        # Reuse complete legacy scope validation, including malformed exclusions.
        validate_command('searchsploit aria', scope)
        if self.name == 'semgrep':
            allowed = scope.get('artifact_sha256', [])
            if not isinstance(allowed, list) or parameters.artifact_sha256 not in allowed:
                raise AdapterError('Source artifact is not authorized')
            return ()
        if self.name == 'subfinder':
            allowed_target(parameters.domain, scope)
            # Third-party egress is separate from target scope; never infer approval.
            if parameters.source != 'offline' and scope.get('passive_sources') != ['crtsh']:
                raise AdapterError('Passive provider egress is not authorized')
            return (parameters.domain,)
        target = parameters.host if self.name == 'nmap' else parameters.url
        allowed_target(target, scope)
        if self.name == 'nmap':
            validate_command(shlex.join(['nmap', '-p', ','.join(map(str, parameters.ports)), target]), scope)
            from worker.policy import ports
            if 'ports' in scope and not set(parameters.ports).issubset(ports(scope['ports'])):
                raise AdapterError('TCP ports exceed scope')
        elif 'ports' in scope:
            from worker.policy import ports
            parsed = urlsplit(target)
            if (parsed.port or (443 if parsed.scheme == 'https' else 80)) not in ports(scope['ports']):
                raise AdapterError('HTTP port exceeds scope')
        return (target,)

    def argv(self, parameters) -> list[str]:
        """Fixed executable/options, no raw flags, environment or caller paths."""
        p = parameters
        exe = self.executable
        if self.name == 'nmap':
            return [exe, '-p', ','.join(map(str, p.ports)), '-oX', '-', p.host]
        if self.name == 'httpx':
            return [exe, '-u', p.url, '-json', '-silent', '-sc', '-title', '-td', '-threads', '1', '-rl', '1', '-timeout', '5', '-retries', '0', '-duc', '-no-fallback-scheme']
        if self.name == 'katana':
            return [exe, '-u', p.url, '-jsonl', '-silent', '-d', str(p.depth), '-ct', '10s', '-c', '1', '-p', '1', '-rl', '1', '-timeout', '5', '-retry', '0', '-dr', '-cs', '^' + re.escape(origin(p.url)) + r'(?:/|$)', '-duc']
        if self.name == 'playwright':
            return [exe, '-m', 'security_tools.browser_runner', p.url]
        if self.name == 'nuclei':
            return [exe, '-u', p.url, '-t', '/opt/aria/assets/http-observation.yaml', '-jsonl', '-silent', '-duc', '-ni', '-dr', '-rl', '1', '-c', '1', '-bs', '1', '-timeout', '5', '-retries', '0', '-omit-raw']
        if self.name == 'zap':
            # Imported, worker-fetched HTTP message; no spider, active scan or API listener.
            return [exe, '-cmd', '-silent', '-autorun', '/tmp/aria-zap.yaml']
        if self.name == 'ffuf':
            return [exe, '-u', p.url.rstrip('/') + '/FUZZ', '-w', '/tmp/aria-words', '-json', '-noninteractive', '-t', '1', '-rate', '1', '-timeout', '5', '-maxtime', '20', '-mc', 'all', '-s']
        if self.name == 'sqlmap':
            return [exe, '-u', p.url, '-p', p.parameter, '--batch', '--level=1', '--risk=1', '--threads=1', '--technique=B', '--timeout=5', '--retries=0', '--delay=1', '--disable-coloring', '--skip-waf', '--skip-heuristics', '--ignore-redirects', '--answers=follow=N', '--output-dir=/tmp/sqlmap', '--flush-session']
        if self.name == 'semgrep':
            return [exe, 'scan', '--config=/opt/aria/assets/aria-python.yaml', '--json', '--metrics=off', '--disable-version-check', '--no-git-ignore', '--jobs=1', '--timeout=5', '--max-memory=128', '--max-target-bytes=65536', '/opt/aria/source/' + p.artifact_sha256]
        if p.source == 'offline':
            return [exe, '-version']
        return [exe, '-d', p.domain, '-s', 'crtsh', '-json', '-silent', '-rl', '1', '-timeout', '5', '-max-time', '1', '-duc']

    def normalize(self, raw: str, parameters, scope: dict, exit_code: int = 0, state: str = 'succeeded'):
        if state not in {'succeeded', 'failed', 'cancelled'}:
            return self.output_model(observations=[], error='unknown')
        if state != 'succeeded' or exit_code:
            error = ('cancelled' if state == 'cancelled' else 'timeout' if exit_code == 124
                     else 'resource_exhausted' if exit_code in {137, -9} else 'tool_failed')
            return self.output_model(observations=[], error=error)
        try:
            if isinstance(raw, str) and len(raw.encode()) >= 100000:
                return self.output_model(observations=[], error='invalid_output', truncated=True)
            if not isinstance(raw, str) or '\x00' in raw:
                raise ValueError()
            rows = self._parse(raw, parameters)
            if len(rows) > 128:
                raise ValueError()
            observations = []
            for kind, locator, summary, severity in rows:
                if kind in {'http', 'url', 'browser'} or (kind == 'finding' and self.name != 'semgrep'):
                    # Returned locations are evidence, never permission to expand scope.
                    from orchestrator.execution_policy import allowed_target
                    m.URLInput(url=locator.split('?', 1)[0])
                    allowed_target(locator, scope)
                    if origin(locator) != origin(parameters.url):
                        raise ValueError()
                elif kind == 'domain':
                    if not locator.endswith('.' + parameters.domain) or locator == parameters.domain:
                        raise ValueError()
                    m.SubfinderInput(domain=locator)
                observations.append(m.Observation(kind=kind, locator=locator, summary=summary[:512], severity=severity))
            return self.output_model(observations=observations, error='none')
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, ET.ParseError, RecursionError):
            return self.output_model(observations=[], error='invalid_output')

    def _parse(self, raw, p):
        if self.name == 'nmap':
            # Nmap emits this exact, inert declaration. No external DTD or
            # internal entity definitions may enter the XML parser.
            raw = raw.replace('<!DOCTYPE nmaprun>', '')
            if '<!DOCTYPE' in raw or '<!ENTITY' in raw:
                raise ValueError()
            root = ET.fromstring(raw)
            finished = root.find('runstats/finished')
            if root.tag != 'nmaprun' or finished is None or finished.get('exit') != 'success':
                raise ValueError()
            rows = []
            for host in root.findall('host'):
                addresses = [a.attrib['addr'] for a in host.findall('address') if a.get('addrtype') in {'ipv4', 'ipv6'}]
                # A hostname may resolve to another address; retain it as scope-bound target.
                import ipaddress
                try:
                    requested = str(ipaddress.ip_address(p.host))
                except ValueError:
                    requested = None
                if not addresses or (requested and addresses != [requested]):
                    raise ValueError()
                for port in host.findall('ports/port'):
                    number = int(port.attrib['portid'])
                    state = port.find('state').attrib['state']
                    if port.attrib['protocol'] != 'tcp' or number not in p.ports or state not in {'open', 'closed', 'filtered', 'open|filtered', 'closed|filtered', 'unfiltered'}:
                        raise ValueError()
                    rows.append(('service', p.host, f'tcp/{number} {state}', 'info'))
            return rows
        if self.name == 'sqlmap':
            # sqlmap does not offer a stable stdout JSON contract. Accept only a
            # complete batch log; never infer a negative finding from truncated text.
            negative = 'all tested parameters do not appear to be injectable' in raw
            if ('ending @' not in raw or '[ERROR]' in raw
                    or '[CRITICAL]' in raw and not negative):
                raise ValueError()
            positive = bool(re.search(r'Parameter: ' + re.escape(p.parameter) + r' \(GET\)', raw)
                            and 'Type: boolean-based blind' in raw)
            if not positive and not negative:
                raise ValueError()
            return [('injection', p.url, 'Boolean-based injection candidate' if positive else 'No supported injection reported', 'unknown')]
        if self.name == 'zap':
            data = json.loads(raw)
            if not isinstance(data.get('site'), list):
                raise ValueError()
            rows = []
            for site in data['site']:
                for alert in site['alerts']:
                    for instance in alert['instances']:
                        rows.append(('finding', instance['uri'], alert['name'], {'0':'info','1':'low','2':'medium','3':'high'}[str(alert['riskcode'])]))
            return rows
        if self.name == 'semgrep':
            data = json.loads(raw)
            if data['errors'] or not isinstance(data['results'], list) or not isinstance(data['paths']['scanned'], list):
                raise ValueError()
            rows = []
            prefix = '/opt/aria/source/' + p.artifact_sha256 + '/'
            for item in data['results']:
                path = item['path']
                if not path.startswith(prefix) or '..' in path.split('/') or not isinstance(item['start']['line'], int):
                    raise ValueError()
                rows.append(('code', path[len(prefix):] + ':' + str(item['start']['line']), item['check_id'], 'unknown'))
            return rows
        items = []
        for line in raw.splitlines():
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError()
            items.append(item)
        rows = []
        for item in items:
            if self.name == 'httpx':
                code = item['status_code']
                if type(code) is not int or not 100 <= code <= 599:
                    raise ValueError()
                rows.append(('http', item['url'], f'HTTP {code}: {str(item.get("title", ""))[:256]}', 'info'))
            elif self.name == 'katana':
                if item['request'].get('method', 'GET') != 'GET':
                    raise ValueError()
                rows.append(('url', item['request']['endpoint'], 'Crawl URL candidate', 'info'))
            elif self.name == 'playwright':
                if item['url'] != p.url or type(item['status']) is not int or not 100 <= item['status'] <= 599:
                    raise ValueError()
                rows.append(('browser', item['url'], str(item['title']), 'info'))
            elif self.name == 'nuclei':
                if item['template-id'] != 'aria-http-observation' or item['type'] != 'http':
                    raise ValueError()
                rows.append(('finding', item['matched-at'], item['info']['name'], item['info']['severity']))
            elif self.name == 'ffuf':
                # ffuf -json emits JSON-lines, unlike its -of json file envelope.
                if type(item['status']) is not int or not 100 <= item['status'] <= 599:
                    raise ValueError()
                if item['url'] not in {p.url.rstrip('/') + '/' + word for word in p.words}:
                    raise ValueError()
                rows.append(('url', item['url'], f'HTTP {item["status"]}', 'info'))
            elif self.name == 'subfinder':
                summary = ('OFFLINE FIXTURE candidate; no provider query executed' if p.source == 'offline'
                           else 'Passive name candidate; not authorized for scanning')
                rows.append(('domain', item['host'], summary, 'info'))
        if self.name in {'httpx', 'playwright'} and len(rows) != 1:
            raise ValueError()
        return rows


def origin(url: str) -> str:
    p = urlsplit(url)
    return f'{p.scheme}://{p.netloc}'


ADAPTERS = {a.name: a for a in (
    Adapter('nmap', 'tcp.connect', m.TCPConnect, m.NmapOutput, '/usr/bin/nmap', 30, role='scan'),
    Adapter('httpx', 'http.probe', m.HttpxInput, m.HttpxOutput, '/opt/tools/httpx', 15, role='recon'),
    Adapter('katana', 'http.crawl', m.KatanaInput, m.KatanaOutput, '/opt/tools/katana', 20, role='web_intel'),
    Adapter('playwright', 'browser.observe', m.PlaywrightInput, m.PlaywrightOutput, '/usr/local/bin/python3.11', 20, role='web_intel'),
    Adapter('nuclei', 'http.observe', m.NucleiInput, m.NucleiOutput, '/opt/tools/nuclei', 20, 'red'),
    Adapter('zap', 'http.passive', m.ZapInput, m.ZapOutput, '/opt/zap/zap.sh', 60, role='web_intel'),
    Adapter('ffuf', 'http.paths', m.FfufInput, m.FfufOutput, '/opt/tools/ffuf', 25, 'red'),
    Adapter('sqlmap', 'http.boolean', m.SqlmapInput, m.SqlmapOutput, '/opt/tools/sqlmap', 60, 'red'),
    Adapter('semgrep', 'source.scan', m.SemgrepInput, m.SemgrepOutput, '/opt/semgrep/bin/semgrep', 30),
    Adapter('subfinder', 'domain.passive', m.SubfinderInput, m.SubfinderOutput, '/opt/tools/subfinder', 60, role='recon'),
)}


def request(data: dict):
    try:
        req = m.AdapterRequest.model_validate(data)
        adapter = ADAPTERS[req.tool]
        return adapter, adapter.parameters(req.parameters)
    except (ValueError, KeyError, TypeError):
        raise AdapterError('Invalid adapter request') from None


def encode(data: dict) -> str:
    adapter, parameters = request(data)
    raw = canonical({'schema_version': 1, 'tool': adapter.name, 'parameters': parameters.model_dump(),
                     'registry_sha256': contract_digest()})
    result = 'aria-tool ' + base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')
    if len(result) > 4096:
        raise AdapterError('Request exceeds command bound')
    return result


def decode(command: str):
    if not isinstance(command, str) or not re.fullmatch(r'aria-tool [A-Za-z0-9_-]{1,4086}', command):
        raise AdapterError('Invalid adapter envelope')
    token = command[10:]
    try:
        data = json.loads(base64.b64decode(token + '=' * (-len(token) % 4), altchars=b'-_', validate=True))
        if data.pop('registry_sha256') != contract_digest():
            raise ValueError()
        adapter, parameters = request(data)
        if encode(data) != command:
            raise ValueError()
        return adapter, parameters
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise AdapterError('Invalid adapter envelope') from None


def validate(command: str, scope: dict):
    from orchestrator.execution_policy import ValidatedCommand
    adapter, parameters = decode(command)
    targets = adapter.validate_scope(parameters, scope)
    return ValidatedCommand(command, adapter.name, adapter.risk, targets)


def catalog(advertisement: dict | None = None) -> list[dict]:
    advertised = (advertisement or {}).get('typed_adapters', {})
    return [{'tool': a.name, 'capability': a.capability, 'implemented': True,
             'input_schema': a.input_model.model_json_schema(), 'output_schema': a.output_model.model_json_schema(),
             'risk': a.risk, 'agent_roles': [a.role], 'timeout_seconds': a.timeout,
            'worker_available': isinstance(advertised, dict) and type(advertised.get(a.capability)) is int and advertised.get(a.capability) == 1,
             'authorization': 'existing_execution_authorization', 'runtime_validated': False}
            for a in ADAPTERS.values()]
