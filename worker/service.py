"""Durable admission, conservative recovery and verified cancellation."""
import asyncio
import hashlib
import json
import time

from fastapi import HTTPException
from worker.policy import prepare

TERMINAL = {'succeeded', 'failed', 'cancelled'}


def fingerprint(request: dict) -> str:
    return hashlib.sha256(json.dumps(request, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def snapshot(job: dict) -> dict:
    return {key: job[key] for key in ('job_id', 'session_id', 'state', 'terminated',
        'exit_code', 'stdout', 'stderr') if key in job}


class WorkerService:
    def __init__(self, store, runtime, ceiling: list[str], allowed_ports: list[int], max_jobs: int = 4, planner=prepare) -> None:
        self.store, self.runtime = store, runtime
        self.ceiling, self.allowed_ports = ceiling, allowed_ports
        self.max_jobs, self.planner = max_jobs, planner
        self.lock = asyncio.Lock()

    async def submit(self, request: dict) -> dict:
        async with self.lock:
            previous = await self.store.get(request['job_id'])
            if previous:
                if previous.get('fingerprint') != fingerprint(request):
                    raise HTTPException(409, 'Job ID already bound or cancelled before submission')
                return snapshot(previous)
            active = await self.store.active()
            if any(job['session_id'] == request['session_id'] and job['state'] == 'cancel_requested' for job in active):
                raise HTTPException(409, 'Engagement cancellation is unresolved')
            if len(active) >= self.max_jobs:
                raise HTTPException(429, 'Worker capacity reached; job was not admitted')
            if request.get('scope', {}).get('program_policy'):
                from orchestrator.program_scope import ExecutionRules
                rules = ExecutionRules.model_validate(request['scope']['program_policy']['rules'])
                history = await self.store.for_session(request['session_id'])
                admitted = [job for job in history if job.get('scope', {}).get('program_policy')]
                if len(admitted) >= rules.max_requests:
                    raise HTTPException(429, 'Worker engagement request budget exhausted')
                if sum(job['session_id'] == request['session_id'] for job in active) >= rules.concurrency:
                    raise HTTPException(429, 'Worker engagement concurrency exhausted')
                if any(job.get('overloaded') for job in admitted):
                    raise HTTPException(429, 'Worker engagement stopped after overload; use a new engagement after review')
                if admitted and time.time() < max(job.get('admitted_at', 0) for job in admitted) + rules.min_interval_seconds:
                    raise HTTPException(429, 'Worker engagement rate limit')
            try:
                plan = await self.planner(request['command'], request['scope'], self.ceiling, self.allowed_ports)
            except (ValueError, TypeError, KeyError, OSError, asyncio.TimeoutError):
                raise HTTPException(403, 'Worker scope or tool policy denied the job') from None
            job = {**request, 'fingerprint': fingerprint(request), 'plan': plan,
                   'deadline': time.time() + request['timeout'], 'state': 'queued', 'admitted_at': time.time()}
            await self.store.save(job)  # Durable ID precedes ANY container mutation.
            try:
                await self.runtime.create(job)
                await self.runtime.start(job)
                job['state'] = 'running'
                await self.store.save(job)
            except Exception:
                # Includes ambiguous create/start: never submit again automatically.
                await self._cancel(job)
                if job.get('terminated'):
                    job.update(state='failed', exit_code=-1, stderr='Worker could not start the isolated job')
                    await self.store.save(job)
            return snapshot(job)

    async def _cancel(self, job: dict, reason: str = 'Job terminated') -> dict:
        job['state'] = 'cancel_requested'
        job.setdefault('cancel_reason', reason)
        await self.store.save(job)  # Intent survives daemon/worker failure.
        try:
            confirmed = await self.runtime.stop(job)
        except Exception:
            confirmed = False
        if confirmed:
            job.update(state='cancelled', terminated=True, exit_code=-1, stdout='', stderr=job['cancel_reason'])
            await self.store.save(job)
        return snapshot(job)

    async def cancel(self, job_id: str, session_id: str) -> dict:
        async with self.lock:
            job = await self.store.get(job_id)
            if job and job['session_id'] != session_id:
                raise HTTPException(403, 'Job session mismatch')
            if not job:
                # Tombstone handles cancel arriving before a delayed POST /jobs.
                job = {'job_id': job_id, 'session_id': session_id, 'state': 'cancel_requested'}
                await self.store.save(job)
            if job['state'] in TERMINAL:
                return snapshot(job)
            return await self._cancel(job)

    async def status(self, job_id: str) -> dict:
        async with self.lock:
            job = await self.store.get(job_id)
            if not job:
                raise HTTPException(404, 'Unknown job')
            if job['state'] in TERMINAL:
                return snapshot(job)
            if job['state'] == 'cancel_requested':
                return await self._cancel(job)
            if time.time() >= job['deadline']:
                return await self._cancel(job, 'Worker job deadline exceeded')
            state = await self.runtime.inspect(job)
            if state is None:
                return await self._cancel(job, 'Job container is missing')
            # Runtime start/exit transitions are not evidence of cancellation.
            # Wait through created/configured/stopping states, bounded by deadline.
            if not state.get('Running') and state.get('Status') in {'exited', 'dead', 'stopped'}:
                stdout, stderr = await self.runtime.output(job)
                # Remove the container before saving a terminal receipt.
                if not await self.runtime.stop(job):
                    return await self._cancel(job)
                exit_code = int(state['ExitCode'])
                if job.get('scope', {}).get('program_policy'):
                    import re
                    codes = re.findall(r'ARIA_HTTP_STATUS:(\d{3})', stdout)
                    job['overloaded'] = not codes or codes[-1] in {'000', '429'} or int(codes[-1]) >= 500
                job.update(state='succeeded' if exit_code == 0 else 'failed',
                           exit_code=exit_code, stdout=stdout, stderr=stderr, terminated=True)
                await self.store.save(job)
            return snapshot(job)

    async def recover(self) -> None:
        async with self.lock:
            # Never resume/replay jobs after restart, even before their deadline.
            for job in await self.store.active():
                await self._cancel(job)

    async def sweep(self) -> None:
        for job in await self.store.active():
            await self.status(job['job_id'])
