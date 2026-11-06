"""Launch separately: uvicorn worker.app:app --host 127.0.0.1 --port 7001 --workers 1."""
import asyncio
import hmac
import json
import os
from contextlib import asynccontextmanager
from uuid import UUID
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from worker.policy import networks, ports
from worker.runtime import DockerRuntime
from worker.service import WorkerService
from worker.store import JobStore
from worker.ownership import ControllerLock


class Submission(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    job_id: str
    session_id: str
    command: str = Field(min_length=1, max_length=4096)
    timeout: int = Field(ge=1, le=300)
    scope: dict
    protected_http: str | None = Field(default=None, max_length=12000)


class Retention(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    session_id: str
    expires_at: str = Field(max_length=50)


class Cancellation(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    session_id: str


def identifier(value: str) -> str:
    try:
        if str(UUID(value)) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(422, 'Canonical UUID required') from None
    return value


async def body(request: Request, model: type[BaseModel]) -> dict:
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > 16384:
            raise HTTPException(413, 'Worker request exceeds 16 KiB')
        data.extend(chunk)
    try:
        return model.model_validate_json(bytes(data)).model_dump()
    except ValidationError:
        # Do not reflect commands, credentials or raw validation input.
        raise HTTPException(422, 'Invalid worker request') from None


def create_app(service: WorkerService | None = None, token: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        if service is None:
            secret = os.environ['KALI_AGENT_TOKEN']
            if len(secret) < 32 or len(set(secret)) < 8:
                raise RuntimeError('Use a random worker token of at least 32 characters')
            ceiling = json.loads(os.environ['WORKER_ALLOWED_NETWORKS'])
            allowed_ports = json.loads(os.environ['WORKER_ALLOWED_PORTS'])
            networks(ceiling)
            ports(allowed_ports)
            store = JobStore(os.environ['WORKER_DATABASE_URL'])
            ownership = ControllerLock(os.environ.get('WORKER_STATE_DIR',
                str(Path.home() / '.local/state/aria-worker')))
            runtime = DockerRuntime(os.environ['WORKER_IMAGE'], os.environ.get('WORKER_NETWORK', 'bridge'),
                                    os.environ.get('WORKER_RUNTIME', 'docker'))
            try:
                ownership.open()
                await store.open()
                await runtime.check()
                app.state.service = WorkerService(store, runtime, ceiling, allowed_ports)
                app.state.token = secret
                await app.state.service.recover()
            except BaseException:
                await store.close()
                ownership.close()
                raise
        async def monitor():
            while True:
                try:
                    await app.state.service.sweep()
                    app.state.healthy = True
                except Exception:
                    app.state.healthy = False
                await asyncio.sleep(.5)
        app.state.healthy = True
        task = asyncio.create_task(monitor())
        try:
            yield
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            try:
                await app.state.service.recover()
            finally:
                if service is None:
                    try:
                        await store.close()
                    finally:
                        ownership.close()

    app = FastAPI(title='ARIA isolated worker', docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.service, app.state.token, app.state.healthy = service, token, True

    async def authenticate(request: Request):
        header = request.headers.get('authorization', '')
        expected = app.state.token
        if not expected or not hmac.compare_digest(header.encode(), ('Bearer ' + expected).encode()):
            raise HTTPException(401, 'Worker authentication required')

    @app.get('/capabilities', dependencies=[Depends(authenticate)])
    async def capabilities():
        if not app.state.healthy:
            raise HTTPException(503, 'Worker reconciliation unavailable')
        from worker.http_profile import available
        return {'authenticated_http_version': 1 if available() else 0, 'protocol': 'aria-jobs-v1', 'idempotency': True, 'cancellation': True,
                'network_scope': True, 'program_policy_version': 1, 'tools': ['curl', 'nmap'], 'max_timeout': 300}

    @app.post('/jobs', dependencies=[Depends(authenticate)])
    async def submit(request: Request):
        if not app.state.healthy:
            raise HTTPException(503, 'Worker reconciliation unavailable')
        data = await body(request, Submission)
        identifier(data['job_id'])
        identifier(data['session_id'])
        if data['protected_http'] is None:
            data.pop('protected_http')
        return await app.state.service.submit(data)

    @app.post('/jobs/{job_id}/retention', dependencies=[Depends(authenticate)])
    async def retention(job_id: str, request: Request):
        data = await body(request, Retention)
        return await app.state.service.retention(identifier(job_id), identifier(data['session_id']), data['expires_at'])

    @app.get('/jobs/{job_id}', dependencies=[Depends(authenticate)])
    async def status(job_id: str):
        return await app.state.service.status(identifier(job_id))

    @app.post('/jobs/{job_id}/cancel', dependencies=[Depends(authenticate)])
    async def cancel(job_id: str, request: Request):
        data = await body(request, Cancellation)
        return await app.state.service.cancel(identifier(job_id), identifier(data['session_id']))

    return app


app = create_app()
