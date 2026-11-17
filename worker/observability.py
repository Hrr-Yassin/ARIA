"""Local worker timings; no receipt, execution authority or content capture."""
from contextlib import asynccontextmanager, contextmanager
import asyncio
import json
import logging
import time
from typing import AsyncIterator, Iterator, Literal

log = logging.getLogger('uvicorn.error')


def _emit(record: dict) -> None:
    # Diagnostic logging is not the durable admission/receipt ledger. A broken
    # sink must not interrupt cancellation, release a claim or retry execution.
    try:
        log.info(json.dumps(record))
    except Exception:
        pass


@asynccontextmanager
async def admission(lock: asyncio.Lock, operation: Literal['submit', 'status', 'cancel', 'retention', 'recover', 'sweep'],
                    *, job_id: str | None = None, session_id: str | None = None) -> AsyncIterator[None]:
    """Measure mutex waiting separately from work performed while holding it."""
    started = time.monotonic_ns()
    acquired = None
    outcome = 'failed'
    try:
        await lock.acquire()
        acquired = time.monotonic_ns()
        yield
        outcome = 'returned'
    except asyncio.CancelledError:
        outcome = 'cancelled'
        raise
    finally:
        ended = time.monotonic_ns()
        if acquired is not None:
            lock.release()
        _emit({'event': 'worker_service_admission', 'operation': operation,
            'job_id': job_id, 'session_id': session_id, 'outcome': outcome,
            'queue_wait_ms': ((acquired if acquired is not None else ended) - started) / 1e6,
            'lock_held_ms': (ended - acquired) / 1e6 if acquired is not None else None})


@contextmanager
def runtime_stage(job: dict, stage: Literal['create', 'start', 'inspect', 'output', 'stop']) -> Iterator[None]:
    """Runtime-call duration includes CLI/backend work, never isolated tool CPU."""
    started = time.monotonic_ns()
    outcome = 'failed'
    try:
        yield
        outcome = 'returned'  # Does not claim termination acknowledgement or job success.
    except asyncio.CancelledError:
        outcome = 'cancelled'
        raise
    finally:
        _emit({'event': 'worker_runtime_stage', 'stage': stage,
            'job_id': job['job_id'], 'session_id': job['session_id'],
            'outcome': outcome, 'duration_ms': (time.monotonic_ns() - started) / 1e6})
