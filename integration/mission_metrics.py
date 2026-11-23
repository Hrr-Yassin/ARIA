"""Measure authenticated FastAPI reads against the disposable PostgreSQL fixture."""
from __future__ import annotations

from time import perf_counter, process_time

import httpx
import psutil
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine


async def measure_database_reads(
    client: httpx.AsyncClient, engine: AsyncEngine, authorization: dict[str, str], paths: dict[str, str],
) -> dict:
    queries: list[float] = []

    def before_cursor(connection, cursor, statement, parameters, context, many):
        context.aria_test_started = perf_counter()

    def after_cursor(connection, cursor, statement, parameters, context, many):
        queries.append(round((perf_counter() - context.aria_test_started) * 1000, 3))

    pool = engine.sync_engine
    event.listen(pool, 'before_cursor_execute', before_cursor)
    event.listen(pool, 'after_cursor_execute', after_cursor)
    process = psutil.Process()
    results = {}
    try:
        for name, path in paths.items():
            initial = await client.get(path, headers=authorization)
            initial.raise_for_status()
            samples = []
            for _ in range(5):
                queries.clear()
                began, cpu = perf_counter(), process_time()
                response = await client.get(path, headers=authorization)
                duration = perf_counter() - began
                used_cpu = process_time() - cpu
                response.raise_for_status()
                assert queries, f'{name} yielded no cursor timing'
                samples.append({'api_ms': round(1000 * duration, 3),
                                'handler_ms': float(response.headers['X-ARIA-Handler-Ms']),
                                'cursor_ms': list(queries),
                                'fixture_process_cpu_percent': round(100 * used_cpu / duration, 3),
                                'fixture_process_rss_bytes': process.memory_info().rss})
            results[name] = samples
    finally:
        event.remove(pool, 'before_cursor_execute', before_cursor)
        event.remove(pool, 'after_cursor_execute', after_cursor)
    return results
