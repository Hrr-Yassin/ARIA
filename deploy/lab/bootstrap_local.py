"""Create one random local lab administrator; never reset an existing account."""
import asyncio
import os
from pathlib import Path
import secrets

from api.bootstrap_admin import create_admin
from memory.database_models import engine

ROOT = Path(__file__).resolve().parents[2]


async def main():
    path = ROOT / '.local-lab/login.txt'
    if path.exists():
        password = next(line.removeprefix('Password: ') for line in path.read_text().splitlines()
                        if line.startswith('Password: '))
    else:
        password = secrets.token_urlsafe(24)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as file:
            file.write(f'URL: http://127.0.0.1:7000/login\nUsername: labadmin\nPassword: {password}\n')
    from sqlalchemy import select
    from memory.database_models import async_session, User
    from security.credentials import verify_password
    async with async_session() as db:
        existing = (await db.execute(select(User).where(User.username == 'labadmin'))).scalar_one_or_none()
        if existing:
            if not verify_password(password, existing.password_hash):
                raise RuntimeError('Existing account differs; refusing to reset its password')
            print('Existing lab administrator retained.')
            await engine.dispose()
            return
    try:
        await create_admin('labadmin', password)
        print('Local administrator created; credentials are in .local-lab/login.txt (private).')
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())
