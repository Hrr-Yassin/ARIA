"""Local container CLI only. Never run a submitted command on the host."""
import asyncio
import base64
import json
import re
import os
import stat
from pathlib import Path


class DockerRuntime:
    def __init__(self, image: str, network: str = 'bridge', executable: str = 'docker') -> None:
        if executable not in {'docker', 'podman'}:
            raise ValueError('Runtime must be docker or podman')
        self.executable = executable
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise ValueError('WORKER_IMAGE must be an immutable local sha256 image ID')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', network) or network in {'host', 'none', 'container'}:
            raise ValueError('Worker requires a private Docker bridge network')
        self.image, self.network = image, network

    @staticmethod
    def name(job: dict) -> str:
        import uuid
        return 'aria-job-' + str(uuid.UUID(job['job_id']))

    async def cli(self, *args: str, limit: int = 120000, timeout: float = 15) -> tuple[int, bytes, bytes]:
        process = await asyncio.create_subprocess_exec(self.executable, *args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        async def read(stream):
            result = bytearray()
            while chunk := await stream.read(65536):
                result.extend(chunk[:max(0, limit - len(result))])
            return bytes(result)
        try:
            stdout, stderr, code = await asyncio.wait_for(asyncio.gather(
                read(process.stdout), read(process.stderr), process.wait()), timeout)
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        return code, stdout, stderr

    async def check(self) -> None:
        code, _, _ = await self.cli('image', 'inspect', self.image)
        if code:
            raise RuntimeError('Worker image is not installed locally')
        code, raw, _ = await self.cli('network', 'inspect', self.network)
        data = json.loads(raw)[0] if not code else {}
        if code or data.get('Driver', data.get('driver')) != 'bridge':
            raise RuntimeError('Worker requires a Docker bridge network')

    def key_directory(self, job: dict, create: bool = False) -> Path:
        root = Path('/tmp') / ('aria-worker-http-' + str(os.getuid()))
        if create:
            root.mkdir(mode=0o700, exist_ok=True)
        if root.exists() or root.is_symlink():
            info = root.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise RuntimeError('HTTP key directory is not private')
        directory = root / self.name(job)
        if directory.exists() or directory.is_symlink():
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise RuntimeError('HTTP job key directory is not private')
        return directory

    async def create(self, job: dict) -> None:
        payload = base64.b64encode(json.dumps({**job['plan'], 'deadline': job['deadline']}).encode()).decode()
        args = ['create', '--pull=never', '--name', self.name(job),
            '--label', 'aria.worker=jobs-v1', '--restart=no', '--network', self.network,
            '--read-only', '--cpus=1', '--memory=256m', '--memory-swap=256m',
            '--pids-limit=64', '--ulimit', 'nofile=256:256', '--shm-size=8m',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777',
            '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=SETPCAP',
            '--cap-add=SETUID', '--cap-add=SETGID', '--security-opt=no-new-privileges=true',
            '--log-driver=json-file', '--log-opt=max-size=1m', '--log-opt=max-file=1',
            '--dns=127.0.0.1', '--no-healthcheck']
        if job['plan'].get('protected_http'):
            # Private host directory; the mounted file is readable by the
            # unprivileged container, but never appears in argv/environment.
            directory = self.key_directory(job, create=True)
            directory.mkdir(mode=0o700)
            keyfile = directory / 'key'
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
            os.fchmod(fd, 0o444)  # The private parent protects host access; uid 65534 must read the mount.
            with os.fdopen(fd, 'w') as stream:
                stream.write(os.environ['HTTP_REPLAY_KEY'])
            args.extend(['--volume', str(keyfile) + ':/run/aria-http-key:ro,Z'])
        for host, addresses in job['plan']['hosts'].items():
            for address in addresses:
                args.extend(['--add-host', f'{host}:{address}'])
        code, _, _ = await self.cli(*args, self.image, payload)
        if code:
            raise RuntimeError('Container creation failed')

    async def start(self, job: dict) -> None:
        code, _, _ = await self.cli('start', self.name(job))
        if code:
            raise RuntimeError('Container start failed')

    async def inspect(self, job: dict) -> dict | None:
        code, raw, _ = await self.cli('container', 'ls', '-a', '--filter', 'name=' + self.name(job), '--format', '{{.Names}}')
        if code:
            raise RuntimeError('Cannot query container runtime')
        if self.name(job) not in {line.lstrip('/') for line in raw.decode().splitlines()}:
            return None
        code, raw, _ = await self.cli('inspect', self.name(job))
        if code:
            raise RuntimeError('Cannot inspect job container')
        data = json.loads(raw)[0]
        if data.get('Config', {}).get('Labels', {}).get('aria.worker') != 'jobs-v1':
            raise RuntimeError('Container identity mismatch')
        return data['State']

    async def stop(self, job: dict) -> bool:
        state = await self.inspect(job)
        if state and (state.get('Running') or state.get('Status') == 'restarting'):
            await self.cli('kill', '--signal=KILL', self.name(job))
        state = await self.inspect(job)
        if state and (state.get('Running') or state.get('Status') in {'restarting', 'paused'}):
            return False
        if state:
            code, _, _ = await self.cli('rm', self.name(job))
            if code:
                return False
        removed = await self.inspect(job) is None
        if removed and job.get('plan', {}).get('protected_http'):
            directory = self.key_directory(job)
            (directory / 'key').unlink(missing_ok=True)
            if directory.exists():
                directory.rmdir()
        return removed

    async def output(self, job: dict) -> tuple[str, str]:
        code, stdout, stderr = await self.cli('logs', self.name(job))
        if code:
            raise RuntimeError('Cannot collect job output')
        return stdout.decode('utf-8', errors='replace')[:100000], stderr.decode('utf-8', errors='replace')[:10000]
