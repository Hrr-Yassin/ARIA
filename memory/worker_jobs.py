"""Durable worker jobs. A transport cancellation is never a termination receipt."""
import asyncio
import hashlib
import json
import time
import uuid

import httpx
from fastapi import HTTPException
from sqlalchemy import select

from config.settings import settings
from memory.database_models import DecisionLog, PentestSession, async_session

TERMINAL = {'succeeded', 'failed', 'cancelled'}
STATES = TERMINAL | {'prepared', 'dispatching', 'queued', 'running', 'cancel_requested', 'unknown'}


class SQLJobStore:
    @staticmethod
    def key(job_id):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, 'aria-worker:' + job_id))

    async def create(self, job):
        async with async_session() as db:
            session = (await db.execute(select(PentestSession).where(PentestSession.id == job['session_id']).with_for_update())).scalar_one_or_none()
            if not session or (session.metadata_ or {}).get('worker_blocked'):
                raise HTTPException(409, 'Engagement execution is fenced')
            active = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == job['session_id'],
                DecisionLog.decision_type == 'worker_job', DecisionLog.metadata_['state'].as_string().not_in(TERMINAL)))).scalars().all()
            if len(active) >= 5 or any(r.metadata_['state'] in {'unknown', 'cancel_requested'} or r.metadata_.get('cancel_requested') for r in active):
                raise HTTPException(409, 'Engagement has active or unresolved worker jobs')
            db.add(DecisionLog(id=self.key(job['job_id']), session_id=job['session_id'],
                user_id=job['user_id'], decision_type='worker_job', metadata_=job))
            await db.commit()

    async def fence(self, session_id, resume=False):
        async with async_session() as db:
            session = (await db.execute(select(PentestSession).where(PentestSession.id == session_id).with_for_update())).scalar_one_or_none()
            if not session:
                raise HTTPException(403, 'Engagement access denied')
            metadata = dict(session.metadata_ or {})
            if resume:
                active = (await db.execute(select(DecisionLog).where(DecisionLog.session_id == session_id,
                    DecisionLog.decision_type == 'worker_job', DecisionLog.metadata_['state'].as_string().not_in(TERMINAL)))).scalars().all()
                if active and metadata.get('worker_blocked'):
                    raise HTTPException(409, 'Worker cancellation is unresolved')
                metadata['worker_blocked'] = False
            else:
                metadata['worker_blocked'] = True
                metadata['worker_epoch'] = int(metadata.get('worker_epoch', 0)) + 1
            session.metadata_ = metadata
            await db.commit()

    async def get(self, job_id):
        async with async_session() as db:
            row = (await db.execute(select(DecisionLog).where(
                DecisionLog.id == self.key(job_id), DecisionLog.decision_type == 'worker_job'))).scalar_one_or_none()
            return dict(row.metadata_) if row else None

    async def update(self, job_id, values, expected=None):
        async with async_session() as db:
            row = (await db.execute(select(DecisionLog).where(
                DecisionLog.id == self.key(job_id), DecisionLog.decision_type == 'worker_job').with_for_update())).scalar_one_or_none()
            if not row:
                raise ValueError('Unknown job')
            previous = dict(row.metadata_)
            if expected is not None and previous['state'] not in expected:
                return previous
            previous.update(values, revision=previous.get('revision', 0) + 1)
            row.metadata_ = previous
            await db.commit()
            return previous

    async def list(self, session_id=None):
        async with async_session() as db:
            query = select(DecisionLog).where(DecisionLog.decision_type == 'worker_job')
            if session_id is not None:
                query = query.where(DecisionLog.session_id == session_id)
            rows = (await db.execute(query)).scalars().all()
            return [dict(row.metadata_) for row in rows]


class WorkerClient:
    def __init__(self, transport=None):
        self.transport = transport

    async def request(self, method, path, payload=None, timeout=10):
        if not settings.KALI_AGENT_URL:
            raise HTTPException(503, 'Worker is not configured')
        async with httpx.AsyncClient(transport=self.transport, timeout=timeout, follow_redirects=False) as client:
            async with client.stream(method, settings.KALI_AGENT_URL.rstrip('/') + path,
                    headers={'Authorization': 'Bearer ' + settings.KALI_AGENT_TOKEN}, json=payload) as response:
                response.raise_for_status()
                content = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    if len(content) + len(chunk) > 1_000_000:
                        raise ValueError('Worker response exceeds limit')
                    content.extend(chunk)
                return json.loads(content)

    @staticmethod
    def snapshot(data, job):
        if (not isinstance(data, dict) or data.get('job_id') != job['job_id']
                or data.get('session_id') != job['session_id'] or data.get('state') not in STATES - {'prepared', 'dispatching', 'unknown'}):
            raise ValueError('Worker identity/state mismatch')
        state = data['state']
        if state == 'cancelled' and data.get('terminated') is not True:
            raise ValueError('Worker has not confirmed termination')
        if state in {'succeeded', 'failed'} and type(data.get('exit_code')) is not int:
            raise ValueError('Worker exit status is missing')
        if state in {'succeeded', 'failed'} and ((state == 'succeeded') != (data['exit_code'] == 0)):
            raise ValueError('Inconsistent worker exit status')
        return {**data, 'stdout': str(data.get('stdout', ''))[:100000], 'stderr': str(data.get('stderr', ''))[:10000]}

    async def capabilities(self):
        caps = await self.request('GET', '/capabilities')
        if not isinstance(caps, dict) or caps.get('protocol') != 'aria-jobs-v1' or caps.get('idempotency') is not True or caps.get('cancellation') is not True:
            raise ValueError('Worker lacks required job capabilities')

    async def submit(self, job, command, timeout):
        return self.snapshot(await self.request('POST', '/jobs', {'job_id': job['job_id'],
            'session_id': job['session_id'], 'command': command, 'timeout': timeout}, timeout=timeout+5), job)

    async def status(self, job):
        return self.snapshot(await self.request('GET', '/jobs/' + job['job_id']), job)

    async def cancel(self, job):
        return self.snapshot(await self.request('POST', '/jobs/' + job['job_id'] + '/cancel',
                                               {'session_id': job['session_id']}), job)


class WorkerJobs:
    def __init__(self, store=None, client=None, context_loader=None):
        self.store = store or SQLJobStore()
        self.client = client or WorkerClient()
        self.context_loader = context_loader
        self._cleanup_tasks = set()

    async def _authorize(self, user_id, session_id):
        if self.context_loader:
            return await self.context_loader(user_id, session_id)
        from memory.execution_authorization import authoritative_context
        return await authoritative_context(user_id, session_id, allow_inactive_session=True)

    async def record_snapshot(self, job, snapshot):
        # A late running response cannot undo acknowledged cancellation.
        values = {'state': snapshot['state']}
        if snapshot['state'] in TERMINAL:
            values['exit_code'] = snapshot.get('exit_code', -1)
            values['output_hash'] = hashlib.sha256(snapshot.get('stdout', '').encode()).hexdigest()
            values['stderr_hash'] = hashlib.sha256(snapshot.get('stderr', '').encode()).hexdigest()
        return await self.store.update(job['job_id'], values, expected=STATES - TERMINAL)

    async def cancel_job(self, job):
        if job['state'] in TERMINAL:
            return job
        if job['state'] == 'prepared':
            job = await self.store.update(job['job_id'], {'state': 'cancelled', 'cancel_requested': True}, expected={'prepared'})
            if job['state'] == 'cancelled':
                return job
        job = await self.store.update(job['job_id'], {'state': 'cancel_requested', 'cancel_requested': True}, expected=STATES - TERMINAL)
        if job['state'] in TERMINAL:
            return job
        if job['endpoint'] != settings.KALI_AGENT_URL or job.get('protocol') == 'legacy-execute':
            return await self.store.update(job['job_id'], {'state': 'unknown'}, expected=STATES - TERMINAL)
        try:
            snapshot = await self.client.cancel(job)
            return await self.record_snapshot(job, snapshot)
        except Exception:
            return await self.store.update(job['job_id'], {'state': 'unknown'}, expected=STATES - TERMINAL)

    async def _cancel_many(self, rows):
        # Commit every cancellation intent before waiting for any remote I/O.
        pending = [await self.store.update(j['job_id'], {'cancel_requested': True}, expected=STATES - TERMINAL)
                   for j in rows]
        future = asyncio.gather(*(self.cancel_job(j) for j in pending))
        self._cleanup_tasks.add(future)
        def done(completed):
            self._cleanup_tasks.discard(completed)
            if not completed.cancelled():
                completed.exception()  # Durable intents remain for recovery on failure.
        future.add_done_callback(done)
        return await asyncio.shield(future)

    async def drain_cleanup(self):
        await asyncio.gather(*list(self._cleanup_tasks), return_exceptions=True)

    async def cancel_session(self, user_id, session_id):
        await self._authorize(user_id, session_id)
        await self.store.fence(session_id)
        rows = [j for j in await self.store.list(session_id) if j['state'] not in TERMINAL]
        result = await self._cancel_many(rows)
        return {'cancelled': sum(j['state'] == 'cancelled' for j in result),
                'pending': sum(j['state'] not in TERMINAL for j in result),
                'jobs': [{'job_id': j['job_id'], 'state': j['state']} for j in result]}

    async def resume_session(self, user_id, session_id):
        await self._authorize(user_id, session_id)
        await self.store.fence(session_id, resume=True)

    async def status(self, user_id, session_id, job_id):
        await self._authorize(user_id, session_id)
        job = await self.store.get(job_id)
        if not job or job['session_id'] != session_id:
            raise HTTPException(403, 'Job access denied')
        return {'job_id': job_id, 'state': job['state'], 'cancel_requested': job.get('cancel_requested', False)}

    async def verify_receipt(self, user_id, session_id, job_id, stdout, stderr, exit_code):
        await self._authorize(user_id, session_id)
        job = await self.store.get(job_id)
        if (not job or job['session_id'] != session_id or job['state'] not in {'succeeded', 'failed'}
                or job.get('exit_code') != exit_code
                or job.get('output_hash') != hashlib.sha256(stdout.encode()).hexdigest()
                or job.get('stderr_hash') != hashlib.sha256(stderr.encode()).hexdigest()):
            raise HTTPException(403, 'Worker result does not match a durable receipt')
        return True

    async def list_status(self, user_id, session_id):
        await self._authorize(user_id, session_id)
        return [{'job_id': j['job_id'], 'state': j['state'], 'cancel_requested': j.get('cancel_requested', False)}
                for j in await self.store.list(session_id)]

    async def revoke_principal(self, user_id):
        """Internal cleanup after an authorized credential-revocation transaction."""
        rows = [j for j in await self.store.list() if j['user_id'] == user_id and j['state'] not in TERMINAL]
        for sid in {j['session_id'] for j in rows}:
            await self.store.fence(sid)
        result = await self._cancel_many(rows)
        return {'cancelled': sum(j['state'] == 'cancelled' for j in result),
                'pending': sum(j['state'] not in TERMINAL for j in result)}

    async def recover(self):
        # Recovery cancels/reconciles orphans, never replays a submission.
        jobs = await self.store.list()
        return [await self.cancel_job(j) for j in jobs if j['state'] not in TERMINAL]

    async def execute(self, job_id, user_id, session_id, command, timeout, authorization_check=None):
        if authorization_check is not None:
            await authorization_check()
        else:
            await self._authorize(user_id, session_id)
        job = {'job_id': job_id, 'user_id': user_id, 'session_id': session_id, 'state': 'prepared',
               'created_at': time.time(), 'deadline': time.time() + timeout,
               'endpoint': settings.KALI_AGENT_URL, 'protocol': settings.KALI_WORKER_PROTOCOL,
               'cancel_requested': False, 'revision': 0}
        await self.store.create(job)  # failure denies dispatch
        try:
            if settings.KALI_WORKER_PROTOCOL != 'legacy-execute':
                await self.client.capabilities()
            if authorization_check is not None:
                await authorization_check()
            job = await self.store.update(job_id, {'state': 'dispatching'}, expected={'prepared'})
            if job.get('cancel_requested') and job['state'] not in TERMINAL:
                job = await self.store.update(job_id, {'state': 'cancelled'}, expected=STATES - TERMINAL)
            if job['state'] != 'dispatching':
                return {'stdout': '', 'stderr': 'Cancelled before dispatch', 'exit_code': -1, 'job_id': job_id, 'status': job['state']}
            if settings.KALI_WORKER_PROTOCOL == 'legacy-execute':
                # Explicit compatibility mode: no remote termination guarantee.
                data = await self.client.request('POST', '/execute', {'command': command, 'session_id': session_id, 'timeout': timeout}, timeout+5)
                if not isinstance(data, dict) or type(data.get('exit_code')) is not int:
                    raise ValueError('Invalid legacy response')
                snapshot = {**data, 'stdout': str(data.get('stdout', ''))[:100000], 'stderr': str(data.get('stderr', ''))[:10000], 'state': 'succeeded' if data['exit_code'] == 0 else 'failed'}
            else:
                snapshot = await self.client.submit(job, command, timeout)
            while True:
                current = await self.record_snapshot(job, snapshot)
                if current['state'] in TERMINAL:
                    return {**snapshot, 'job_id': job_id, 'status': current['state'],
                            'exit_code': -1 if current['state'] == 'cancelled' else snapshot.get('exit_code', -1)}
                if current.get('cancel_requested'):
                    current = await self.cancel_job(current)
                    if current['state'] in TERMINAL:
                        return {'stdout': '', 'stderr': 'Worker terminated' if current['state'] == 'cancelled' else 'Completed during cancellation',
                                'exit_code': current.get('exit_code', -1), 'job_id': job_id, 'status': current['state']}
                if time.time() >= job['deadline']:
                    await self.cancel_job(await self.store.get(job_id))
                    raise HTTPException(504, 'Job deadline exceeded; inspect cancellation status')
                await asyncio.sleep(0.2)
                snapshot = await self.client.status(job)
        except asyncio.CancelledError:
            await asyncio.shield(self.cancel_job(await self.store.get(job_id)))
            raise
        except HTTPException:
            current = await self.store.get(job_id)
            if current and current["state"] not in TERMINAL:
                await self.cancel_job(current)
            raise
        except Exception:
            current = await self.store.get(job_id)
            if current and current['state'] not in TERMINAL:
                await self.cancel_job(current)
            raise HTTPException(502, 'Worker job failed; inspect durable job status') from None


worker_jobs = WorkerJobs()
