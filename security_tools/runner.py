"""Container-only supervisor with bounded pipes; never imported as a host executor."""
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

from security_tools.adapters import decode
from security_tools.worker_profiles import Profile


def file_digest(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024 * 1024:
        raise ValueError('Invalid pinned file')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Source artifact is not a regular directory')
    digest, size, count = hashlib.sha256(), 0, 0
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('Source artifact contains special files')
        if path.is_file():
            size += info.st_size
            count += 1
            if count > 128 or size > 1048576 or info.st_size > 65536:
                raise ValueError('Source artifact exceeds bound')
            digest.update(path.relative_to(root).as_posix().encode() + b'\0')
            digest.update(bytes.fromhex(file_digest(path)))
    if not count:
        raise ValueError('Empty source artifact')
    return digest.hexdigest()


def setup(plan: dict) -> list[str]:
    adapter, parameters = decode(plan['adapter_request'])
    adapter.validate_scope(parameters, plan['adapter_scope'])
    profile = Profile.model_validate(plan['adapter_profile'])
    executable = Path(adapter.executable)
    # Version + image are deployment declarations; binary and asset hashes are
    # independently checked here before spawning any scanner.
    if file_digest(executable) != profile.binary_sha256:
        raise ValueError('Tool binary digest mismatch')
    for name, expected in profile.assets.items():
        if name not in {'http-observation.yaml', 'aria-python.yaml', 'subfinder-offline.jsonl'} or file_digest(Path('/opt/aria/assets') / name) != expected:
            raise ValueError('Tool asset digest mismatch')
    if adapter.name == 'semgrep':
        if parameters.artifact_sha256 not in profile.artifacts or tree_digest(Path('/opt/aria/source') / parameters.artifact_sha256) != parameters.artifact_sha256:
            raise ValueError('Source artifact digest mismatch')
    if adapter.name == 'ffuf':
        Path('/tmp/aria-words').write_text('\n'.join(parameters.words) + '\n')
    if adapter.name == 'zap':
        prepare_zap(parameters.url)
        # ZAP derives its profile directory from Java's user.home property,
        # which otherwise remains /root even after the worker drops to nobody.
        # Keep that writable state inside the job's bounded tmpfs.
        Path('/tmp/aria-zap-home').mkdir(mode=0o700, parents=True, exist_ok=True)
    argv = adapter.argv(parameters)
    if adapter.name == 'nmap':
        argv[1:1] = ['-sT', '-Pn', '-n']  # Same constrained worker TCP profile.
    return argv


def prepare_zap(url: str) -> None:
    from security_tools.snapshot import fetch
    status, headers, body = fetch(url)
    # Import a single response rather than crawling or exposing a ZAP listener.
    har = {'log': {'version': '1.2', 'creator': {'name': 'ARIA', 'version': '1'}, 'entries': [{
        'startedDateTime': '2000-01-01T00:00:00Z', 'time': 0,
        'request': {'method': 'GET', 'url': url, 'httpVersion': 'HTTP/1.1', 'headers': [], 'queryString': [], 'cookies': [], 'headersSize': -1, 'bodySize': 0},
        'response': {'status': status, 'statusText': '', 'httpVersion': 'HTTP/1.1',
            'headers': [{'name': k, 'value': v} for k, v in headers], 'cookies': [],
            'content': {'size': len(body), 'mimeType': 'text/html', 'text': base64.b64encode(body).decode(), 'encoding': 'base64'},
            'redirectURL': '', 'headersSize': -1, 'bodySize': len(body)},
        'cache': {}, 'timings': {'send': 0, 'wait': 0, 'receive': 0}}]}}
    Path('/tmp/aria-message.har').write_text(json.dumps(har))
    config = {'env': {'contexts': [{'name': 'aria', 'urls': [url]}],
        'parameters': {'failOnError': True, 'progressToStdout': False}}, 'jobs': [
        {'type': 'import', 'parameters': {'type': 'har', 'fileName': '/tmp/aria-message.har', 'sendRequests': False, 'maxMessages': 1}},
        {'type': 'passiveScan-wait', 'parameters': {'maxDuration': 1}},
        {'type': 'report', 'parameters': {'template': 'traditional-json', 'reportDir': '/tmp', 'reportFile': 'aria-report', 'displayReport': False}}]}
    # JSON is valid YAML and avoids an optional serializer dependency.
    Path('/tmp/aria-zap.yaml').write_text(json.dumps(config))


async def supervise(argv: list[str], timeout: float, environment: dict) -> tuple[int, str, str]:
    child = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, cwd='/tmp', env=environment, start_new_session=True)
    async def read(stream, limit):
        result = bytearray()
        while chunk := await stream.read(4096):
            if len(result) + len(chunk) >= limit:
                raise OverflowError('Output exceeds bound')
            result.extend(chunk)
        return result.decode('utf-8', errors='strict')
    tasks = [asyncio.create_task(read(child.stdout, 100000)),
             asyncio.create_task(read(child.stderr, 10000)), asyncio.create_task(child.wait())]
    try:
        async with asyncio.timeout(max(0.01, timeout)):
            out, err, code = await asyncio.gather(*tasks)
        return code, out, err
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await child.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def main(plan: dict) -> int:
    adapter, parameters = decode(plan['adapter_request'])
    remaining = min(adapter.timeout, plan['deadline'] - time.time())
    if remaining <= 0:
        return 124
    argv = setup(plan)
    environment = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C.UTF-8',
        'PYTHONPATH': '/opt/aria',
        'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0',
        'JAVA_TOOL_OPTIONS': '-Xmx512m -XX:ActiveProcessorCount=1 -Duser.home=/tmp/aria-zap-home',
        'PLAYWRIGHT_BROWSERS_PATH': '/opt/chromium'}
    try:
        code, out, err = await supervise(argv, min(remaining, plan['deadline'] - time.time()), environment)
        if adapter.name == 'subfinder' and parameters.source == 'offline' and code == 0:
            out = Path('/opt/aria/assets/subfinder-offline.jsonl').read_text()
            err = ''
        if adapter.name == 'zap' and code == 0:
            report = Path('/tmp/aria-report.json')
            if report.stat().st_size >= 100000:
                raise OverflowError()
            out = report.read_text()
        sys.stdout.write(out)
        sys.stderr.write(err)
        return code
    except asyncio.TimeoutError:
        return 124
    except OverflowError:
        return 137


if __name__ == '__main__':
    # Invoked only by the privilege-dropped worker entrypoint with its full plan.
    try:
        sys.exit(asyncio.run(main(json.loads(base64.b64decode(sys.argv[1], validate=True)))))
    except (ValueError, OSError, KeyError, TypeError):
        sys.stderr.write('Tool profile or output validation failed\n')
        sys.exit(65)
