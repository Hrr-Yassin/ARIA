"""Local container CLI only. Never run a submitted command on the host."""
import asyncio
import base64
import json
import re


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
        return await self.inspect(job) is None

    async def output(self, job: dict) -> tuple[str, str]:
        code, stdout, stderr = await self.cli('logs', self.name(job))
        if code:
            raise RuntimeError('Cannot collect job output')
        return stdout.decode('utf-8', errors='replace')[:100000], stderr.decode('utf-8', errors='replace')[:10000]
