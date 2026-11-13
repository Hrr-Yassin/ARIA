"""Trusted entrypoint: firewall first, drop privilege, then supervise a tool."""
import base64
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from worker.policy import firewall


def verify_limits(large: bool = False, root: Path = Path('/sys/fs/cgroup')) -> None:
    """Fail closed when a runtime silently ignores requested resource limits."""
    memory = (1024 if large else 256) * 1024 * 1024
    pids = 128 if large else 64
    try:
        actual_memory = int((root / 'memory.max').read_text().strip())
        actual_pids = int((root / 'pids.max').read_text().strip())
        quota, period = map(int, (root / 'cpu.max').read_text().split())
        if not (0 < actual_memory <= memory and 0 < actual_pids <= pids
                and 0 < quota <= period):
            raise ValueError()
    except (OSError, ValueError):
        raise RuntimeError('Required CPU/memory/PID enforcement is unavailable') from None


def main() -> int:
    plan = json.loads(base64.b64decode(sys.argv[1], validate=True))
    if len(sys.argv) == 2:
        remaining = plan['deadline'] - time.time()
        if remaining <= 0:
            return 124
        verify_limits(plan.get('adapter_name') in {'playwright', 'zap'})
        subprocess.run(['/usr/sbin/nft', '-f', '-'], input=firewall(plan).encode(),
                       check=True, timeout=min(5, remaining))
        # Clear bounding/inheritable/ambient caps before running submitted tools.
        os.execv('/usr/bin/setpriv', ['setpriv', '--bounding-set=-all', '--inh-caps=-all',
            '--ambient-caps=-all', '--reuid=65534', '--regid=65534', '--clear-groups',
            '--no-new-privs', sys.executable, '-m', 'worker.container_entry', sys.argv[1], 'supervise'])
    remaining = plan['deadline'] - time.time()
    if remaining <= 0:
        return 124
    if plan.get('protected_http'):
        if sys.argv[-1] == 'http':
            from worker.http_runner import run
            return run(plan)
        plan['argv'] = [sys.executable, '-m', 'worker.container_entry', sys.argv[1], 'http']
    if plan.get('adapter_request'):
        plan['argv'] = [sys.executable, '-m', 'security_tools.runner', sys.argv[1]]
    environment = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C.UTF-8'}
    child = subprocess.Popen(plan['argv'], env=environment,
                             cwd='/opt/aria' if plan.get('protected_http') or plan.get('adapter_request') else '/tmp',
                             start_new_session=True)
    try:
        return child.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        return 124
    finally:
        # Exiting PID 1 tears down the namespace, including detached descendants.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


if __name__ == '__main__':
    sys.exit(main())
