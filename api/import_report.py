"""Trusted operator migration for old reports: never infer ownership from names."""
import argparse
import asyncio
import hashlib
import os
import stat
import uuid
from pathlib import Path
from sqlalchemy import select
from config.settings import settings
from memory.database_models import PentestSession, async_session
from memory.report_artifacts import register_report


async def import_report(source: Path, session_id: str):
    if source.suffix not in {'.pdf', '.md', '.tex', '.html'}:
        raise ValueError('Unsupported report format')
    async with async_session() as db:
        session = (await db.execute(select(PentestSession).where(PentestSession.id == session_id))).scalar_one_or_none()
        if not session or not session.user_id:
            raise ValueError('A known engagement owner is required')
        owner_id = session.user_id
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode) or os.fstat(file.fileno()).st_size > 20_000_000:
            raise ValueError('Invalid report file')
        data = file.read(20_000_001)
    directory = Path(settings.REPORT_OUTPUT_DIR)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    filename = 'pentest_report_' + uuid.uuid4().hex + source.suffix
    destination = directory / filename
    created = False
    try:
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        created = True
        with os.fdopen(descriptor, 'wb') as file:
            file.write(data)
        await register_report(session_id, owner_id, filename, hashlib.sha256(data).hexdigest())
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return filename


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Import a report after independently verifying engagement ownership')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--session-id', required=True)
    args = parser.parse_args()
    print(asyncio.run(import_report(args.source, args.session_id)))
