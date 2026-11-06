"""Trusted entrypoint: firewall first, drop privilege, then supervise a tool."""
import base64
import json
import os
import signal
import subprocess
import sys
import time

from worker.policy import firewall


def main() -> int:
    plan = json.loads(base64.b64decode(sys.argv[1], validate=True))
    if len(sys.argv) == 2:
        remaining = plan['deadline'] - time.time()
        if remaining <= 0:
            return 124
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
    environment = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C.UTF-8'}
    child = subprocess.Popen(plan['argv'], env=environment,
                             cwd='/opt/aria' if plan.get('protected_http') else '/tmp',
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
