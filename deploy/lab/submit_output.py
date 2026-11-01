"""Submit manually collected lab evidence. Does not execute commands.

Analysis may call the LLM provider configured for the local lab administrator.
"""
import argparse
import json
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', type=Path, required=True)
    parser.add_argument('--command', required=True)
    parser.add_argument('--target', default='192.168.77.20')
    parser.add_argument('--session-id')
    args = parser.parse_args()
    if args.file.stat().st_size > 1_000_000:
        parser.error('Keep the manual evidence file below 1 MB')
    login = dict(line.split(': ', 1) for line in (ROOT / '.local-lab/login.txt').read_text().splitlines())
    with httpx.Client(base_url='http://127.0.0.1:7000', timeout=180) as client:
        response = client.post('/api/login', json={'username': login['Username'], 'password': login['Password']})
        response.raise_for_status()
        client.headers['Authorization'] = 'Bearer ' + response.json()['token']
        sid = args.session_id
        if not sid:
            response = client.get('/api/session/list')
            response.raise_for_status()
            sid = next((item['session_id'] for item in response.json()['sessions']
                        if item['target'] == args.target), None)
        if not sid:
            response = client.post('/api/session/new', json={
                'target': args.target, 'name': 'Manual isolated lab',
                'scope': {'targets': [args.target], 'exclusions': []}})
            response.raise_for_status()
            sid = response.json()['session_id']
        print('Session:', sid)
        response = client.post('/api/tool-results', json={
            'session_id': sid, 'agent_type': 'scan', 'command': args.command,
            'stdout': args.file.read_text(), 'target': args.target})
        response.raise_for_status()
        # Evidence may contain secrets; save privately instead of dumping it into logs.
        output = ROOT / '.local-lab/last-analysis.json'
        import os
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as file:
            json.dump(response.json(), file, indent=2)
        print('Manual evidence submitted; analysis saved in .local-lab/last-analysis.json')
        print('Refresh/open this session in the browser. This is manual, unverified evidence.')


if __name__ == '__main__':
    main()
