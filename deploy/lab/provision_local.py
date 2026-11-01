"""One-time Fedora lab configuration. No global pip, no root, no secret output."""
import os
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parents[2]
os.chdir(ROOT)
STATE = ROOT / '.local-lab'
STATE.mkdir(mode=0o700, exist_ok=True)
STATE.chmod(0o700)


def private(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as file:
        file.write(content)


if not (ROOT / '.env').exists():
    from cryptography.fernet import Fernet
    password = secrets.token_hex(24)
    private(STATE / 'postgres.env', f'POSTGRES_DB=aria\nPOSTGRES_USER=aria\nPOSTGRES_PASSWORD={password}\n')
    private(ROOT / '.env', '\n'.join([
        f'SECRET_KEY={secrets.token_hex(32)}',
        f'FERNET_KEY={Fernet.generate_key().decode()}',
        f'KALI_AGENT_TOKEN={secrets.token_hex(32)}',
        f'DATABASE_URL=postgresql+asyncpg://aria:{password}@127.0.0.1:15432/aria',
        'REDIS_URL=redis://127.0.0.1:16379/0',
        f'REPORT_OUTPUT_DIR={ROOT}/reports',
        'ALLOWED_ORIGINS=["http://127.0.0.1:7000","http://localhost:7000"]',
        'KALI_AGENT_URL=', 'KALI_WORKER_PROTOCOL=jobs-v1',
        'AUTO_RISK_THRESHOLD=green_only', 'DEBUG=false', '',
    ]))
    print('Created private local configuration; automatic worker execution is unconfigured.')
else:
    print('Existing .env retained unchanged.')
