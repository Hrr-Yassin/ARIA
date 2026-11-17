"""Bounded, read-only Fedora dependency readiness before starting the API.

The service starts only the existing PostgreSQL/Redis containers separately.
This probe never migrates a database, alters configuration or submits work.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import json


async def wait_for_dependencies(check: Callable[[], Awaitable[None]], *,
                                timeout: float = 30, interval: float = .5) -> bool:
    """Return true only after a successful check, within a monotonic deadline."""
    if not 0 < timeout <= 120 or not 0 < interval <= timeout:
        raise ValueError('Bounded dependency deadline and interval required')
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while (remaining := deadline - loop.time()) > 0:
        try:
            await asyncio.wait_for(check(), timeout=min(remaining, 3))
            return True
        except Exception:
            # Only the final closed status is printed. SQL/Redis errors may
            # contain connection or credential details.
            await asyncio.sleep(min(interval, max(0, deadline - loop.time())))
    return False


async def main() -> int:
    from config.settings import settings
    from memory.database_models import engine, init_db
    import redis.asyncio as aioredis
    redis = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2,
                             socket_timeout=2)

    async def check():
        await init_db()  # Exact existing schema revision, no DDL or writes.
        if await redis.ping() is not True:
            raise RuntimeError('Redis readiness unavailable')

    try:
        ready = await wait_for_dependencies(check)
        print(json.dumps({'status': 'READY' if ready else 'BLOCKED',
            'reason_code': '' if ready else 'lab_dependencies_unavailable',
            'read_only': True}), flush=True)
        return 0 if ready else 1
    finally:
        try:
            await redis.aclose()
        finally:
            await engine.dispose()


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
