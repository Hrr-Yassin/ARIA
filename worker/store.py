"""Independent PostgreSQL ledger; install schema.sql explicitly before startup."""
import json
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


class JobStore:
    def __init__(self, url: str) -> None:
        if not url.startswith('postgresql+asyncpg://'):
            raise ValueError('Worker requires PostgreSQL with asyncpg')
        self.engine = create_async_engine(url, pool_pre_ping=True, pool_timeout=5,
                                          connect_args={'timeout': 5, 'command_timeout': 10})
        self.owner = None
        self.backend_pid = None

    async def open(self) -> None:
        try:
            self.owner = await self.engine.connect()
            if not await self.owner.scalar(text('SELECT pg_try_advisory_lock(1095911745, 1)')):
                raise RuntimeError('Another worker owns this database')
            self.backend_pid = await self.owner.scalar(text('SELECT pg_backend_pid()'))
            revision = await self.owner.scalar(text('SELECT version FROM aria_worker_schema WHERE singleton = true'))
            if revision != 1:
                raise RuntimeError('Install worker/schema.sql version 1 before startup')
            await self.owner.commit()
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        owner, self.owner = self.owner, None
        try:
            if owner is not None:
                # Session advisory locks must not remain in a pooled connection.
                try:
                    await owner.invalidate()
                finally:
                    await owner.close()
        finally:
            await self.engine.dispose()

    async def get(self, job_id: str) -> dict | None:
        async with self.engine.connect() as conn:
            raw = await conn.scalar(text('SELECT record FROM aria_worker_jobs WHERE job_id = :id'), {'id': job_id})
            return dict(raw) if raw else None

    async def save(self, job: dict) -> None:
        # A dedicated lock-owning connection fences a second server. Never permit
        # SQLAlchemy to silently replace a dead session and lose the advisory lock.
        if self.owner is None or self.backend_pid != await self.owner.scalar(text('SELECT pg_backend_pid()')):
            raise RuntimeError('Worker database ownership was lost; restart required')
        await self.owner.execute(text('''INSERT INTO aria_worker_jobs(job_id, record)
            VALUES (:id, CAST(:record AS jsonb))
            ON CONFLICT (job_id) DO UPDATE SET record = EXCLUDED.record'''),
            {'id': job['job_id'], 'record': json.dumps(job)})
        await self.owner.commit()

    async def active(self) -> list[dict]:
        async with self.engine.connect() as conn:
            rows = await conn.scalars(text("SELECT record FROM aria_worker_jobs WHERE record->>'state' NOT IN ('succeeded','failed','cancelled')"))
            return [dict(row) for row in rows]


    async def for_session(self, session_id: str) -> list[dict]:
        async with self.engine.connect() as conn:
            rows = await conn.scalars(text("SELECT record FROM aria_worker_jobs WHERE record->>'session_id' = :sid"),
                                      {'sid': session_id})
            return [dict(row) for row in rows]

    async def expire_http(self) -> None:
        from datetime import datetime, timezone
        if self.owner is None or self.backend_pid != await self.owner.scalar(text('SELECT pg_backend_pid()')):
            raise RuntimeError('Worker database ownership was lost')
        await self.owner.execute(text("""UPDATE aria_worker_jobs SET record =
            jsonb_set(record - 'protected_http', '{plan}',
                COALESCE(record->'plan', '{}'::jsonb) - 'protected_http')
                || '{"stdout":"","stderr":"","private_evidence_expired":true}'::jsonb
            WHERE record->>'state' IN ('succeeded','failed','cancelled')
              AND record->>'private_expires_at' <= :now"""),
            {'now': datetime.now(timezone.utc).isoformat()})
        await self.owner.commit()
