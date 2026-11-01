"""Collect a bounded TCP-connect scan from Kali against the isolated demo target.

Requires the existing Kali QEMU guest agent and libvirt access on Fedora.
No exploit, password guessing, provider call or ARIA worker is involved.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
COMMAND = 'nmap -sT --open --max-retries 1 --host-timeout 30s -p 21,22,80,139,445 192.168.77.20'


def agent(command):
    return json.loads(subprocess.check_output([
        'virsh', '-c', 'qemu:///system', 'qemu-agent-command', 'kali', json.dumps(command)
    ], text=True))['return']


def main():
    pid = agent({'execute': 'guest-exec', 'arguments': {
        'path': '/usr/bin/nmap', 'arg': COMMAND.split()[1:], 'capture-output': True}})['pid']
    for _ in range(100):
        result = agent({'execute': 'guest-exec-status', 'arguments': {'pid': pid}})
        if result.get('exited'):
            output = base64.b64decode(result.get('out-data', '')).decode(errors='replace')
            path = ROOT / '.local-lab/nmap-demo.txt'
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as file:
                file.write(output)
            print(output)
            print('Saved .local-lab/nmap-demo.txt; no evidence was submitted to a provider.')
            raise SystemExit(result.get('exitcode', 1))
        time.sleep(.5)
    raise SystemExit('Guest scan status timed out; check the Kali console')


if __name__ == '__main__':
    main()
