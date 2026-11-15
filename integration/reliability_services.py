"""Run selected synthetic SQL checks in a newly created disposable database.

No existing database is migrated or reset. Credentials remain in child process
memory; private logs and a sanitized summary are retained under .local-lab.
The test database is retained for inspection, never automatically dropped.

    python -m integration.reliability_services
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from config.settings import settings

SUITES = (
    'integration.test_checkpoint_postgres',
    'integration.test_knowledge_store_postgres',
    'integration.test_campaign_postgres',
    'integration.test_observability_postgres',
    'integration.test_review_recovery_postgres',
    'integration.test_mission_state_postgres',
    'integration.test_reliability_workload_postgres',
    'integration.test_specialist_postgres',
    'integration.test_campaign_execution_postgres',
    'integration.test_endurance_postgres',
)


async def create_database() -> tuple[str, str]:
    """Create one unique database using the configured local PostgreSQL role."""
    url = make_url(settings.DATABASE_URL)
    if url.get_backend_name() != 'postgresql':
        raise RuntimeError('Reliability integration requires PostgreSQL')
    name = 'aria_reliability_' + uuid.uuid4().hex[:16] + '_test'
    admin = create_async_engine(url.set(database='postgres'),
                                isolation_level='AUTOCOMMIT',
                                connect_args={'timeout': 5})
    try:
        async with admin.connect() as db:
            # Identifier contains only the fixed prefix, hex UUID and suffix.
            await db.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        await admin.dispose()
    return name, url.set(database=name).render_as_string(hide_password=False)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', action='append', choices=SUITES)
    args = parser.parse_args()
    output = Path('.local-lab/operational-reliability')
    output.mkdir(parents=True, exist_ok=True)
    run_id = 'sql-' + uuid.uuid4().hex[:12]
    directory = output / run_id
    directory.mkdir(mode=0o700)
    summary = {'run_id': run_id, 'synthetic': True, 'owner_database_modified': False,
               'database_retained': True, 'suites': args.suite or list(SUITES)}
    started = time.monotonic()
    try:
        name, url = asyncio.run(create_database())
        summary['database'] = name
        # No Redis or worker reset. These suites use SQL and mock/forbidden I/O.
        env = {**os.environ, 'DATABASE_URL': url, 'ARIA_INTEGRATION': '1',
               'ARIA_RELIABILITY_ARTIFACT_DIR': str(directory.resolve())}
        cmd = [sys.executable, '-B', '-m', 'unittest', *summary['suites'], '-v']
        summary['command'] = [Path(sys.executable).name, '-B', '-m', 'unittest',
                              *summary['suites'], '-v']
        log_path = directory / 'tests.log'
        with log_path.open('w') as log:
            result = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
        log_path.chmod(0o600)
        summary.update(exit_code=result.returncode, log=str(log_path))
    except Exception as exc:
        # Never interpolate a connection URL or provider/configuration secret.
        summary.update(exit_code=1, error_type=type(exc).__name__)
    summary['duration_seconds'] = time.monotonic() - started
    summary_path = directory / 'summary.json'
    summary_path.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary), flush=True)
    return summary['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
