"""Verify the installed lab without printing passwords or bearer tokens."""
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[2]
login = dict(line.split(': ', 1) for line in (ROOT / '.local-lab/login.txt').read_text().splitlines())
with httpx.Client(base_url='http://127.0.0.1:7000', timeout=15) as client:
    for path in ('/api/health', '/api/ready', '/login'):
        response = client.get(path)
        response.raise_for_status()
        print(path, response.status_code)
    response = client.post('/api/login', json={'username': login['Username'], 'password': login['Password']})
    response.raise_for_status()
    client.headers['Authorization'] = 'Bearer ' + response.json()['token']
    response = client.get('/api/session/list')
    response.raise_for_status()
    print('Administrator login and session listing passed; secrets were not printed.')
