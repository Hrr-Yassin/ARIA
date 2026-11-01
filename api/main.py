"""
PentestAI v10 — Main Application
FastAPI backend serving API + Web UI on Ubuntu.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from security.redaction import configure_logging
configure_logging()

import structlog
from fastapi import FastAPI, Request, HTTPException, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.auth import (
    LoginRequest, LoginResponse, authenticate_user, create_token, get_current_user, TokenData,
    auth_revision, revoke_credentials,
)
from api.routers import pentest as pentest_router
from api.routers import sessions as sessions_router
from api.routers import reports as reports_router
from api.routers import api_keys as api_keys_router
from api.routers import admin as admin_router
from config.settings import settings
from memory.database_models import init_db
from memory.session_manager import session_manager
from memory.knowledge_cache import knowledge_cache

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ARIA starting", version=settings.APP_VERSION)

    # Initialize database
    await init_db()

    # Initialize Redis
    await session_manager.initialize()
    await knowledge_cache.initialize_redis(session_manager._redis)
    from memory.vector_store import vector_store
    if session_manager._redis:
        try:
            await vector_store.load(session_manager._redis)
        except Exception:
            log.warning("vector_cache_restore_failed")

    from memory.worker_jobs import worker_jobs
    await worker_jobs.recover()

    # Ensure report directory
    Path(settings.REPORT_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    log.info("ARIA ready",
             api_port=settings.API_PORT,
             web_port=settings.WEB_PORT)
    yield

    from agents.autonomous_engine import autonomous_engine
    await autonomous_engine.shutdown()
    await worker_jobs.recover()
    await worker_jobs.drain_cleanup()
    if session_manager._redis:
        try:
            await vector_store.persist(session_manager._redis)
        except Exception:
            log.warning("vector_cache_flush_failed")
    await session_manager.close()
    log.info("ARIA shutdown")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

@app.middleware("http")
async def request_correlation(request: Request, call_next):
    import uuid
    from structlog.contextvars import bound_contextvars
    # Generate locally: arbitrary caller headers never become log fields.
    request_id = uuid.uuid4().hex
    with bound_contextvars(request_id=request_id):
        response = await call_next(request)
        log.info("http_request", method=request.method, status=response.status_code)
    response.headers["X-Request-ID"] = request_id
    return response


# ── Routers ──────────────────────────────────────────────────────────────

app.include_router(pentest_router.router, prefix="/api", tags=["pentest"])
app.include_router(sessions_router.router, prefix="/api/session", tags=["sessions"])
app.include_router(reports_router.router, prefix="/api/report", tags=["reports"])
app.include_router(api_keys_router.router, prefix="/api/keys", tags=["api-keys"])
app.include_router(admin_router.router, prefix="/api/admin", tags=["admin"])


# ── Auth Endpoints ───────────────────────────────────────────────────────

@app.post("/api/login")
async def login(body: LoginRequest, request: Request, response: Response):
    from security.login_throttle import login_throttle
    await login_throttle.reserve(body.username, request.client.host if request.client else "unknown", session_manager._redis)
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user.id, user.username, user.role.value, user.skill_level.value, auth_revision=auth_revision(user))
    response.set_cookie("pentestai_token", token, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", max_age=settings.JWT_EXPIRE_MINUTES * 60)
    return LoginResponse(
        token=token,
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        skill_level=user.skill_level.value,
        display_name=user.display_name or user.username,
    )


@app.post("/api/logout")
async def logout(response: Response, user: TokenData = Depends(get_current_user)):
    from memory.database_models import User, async_session
    from sqlalchemy import select
    async with async_session() as db:
        row = (await db.execute(select(User).where(User.id == user.user_id).with_for_update())).scalar_one_or_none()
        if not row:
            raise HTTPException(401, "Account unavailable")
        revoke_credentials(row)
        await db.commit()
    from agents.autonomous_engine import autonomous_engine
    from memory.worker_jobs import worker_jobs
    await autonomous_engine.revoke_principal(user.user_id)
    cancellation = await worker_jobs.revoke_principal(user.user_id)
    response.delete_cookie("pentestai_token", httponly=True, samesite="strict")
    return {"status": "revoked", "cancellation": cancellation}


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/api/ready")
async def readiness():
    import asyncio
    from sqlalchemy import text
    from memory.database_models import engine
    try:
        async with asyncio.timeout(3):
            await init_db()
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse({"status": "unavailable", "database": False}, status_code=503)
    return {"status": "ready", "database": True, "version": settings.APP_VERSION}


# ── Web UI Serving ───────────────────────────────────────────────────────

WEB_DIR = Path(__file__).parent.parent / "web"

# Serve /static/* with correct MIME types (JS, CSS, etc.)
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")


@app.get("/login", response_class=HTMLResponse)
async def serve_login():
    f = WEB_DIR / "login.html"
    if f.exists():
        return HTMLResponse(f.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Login page not found</h1>", status_code=404)


@app.get("/admin", response_class=HTMLResponse)
async def serve_admin():
    f = WEB_DIR / "admin.html"
    if f.exists():
        return HTMLResponse(f.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Admin page not found</h1>", status_code=404)


@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    f = WEB_DIR / "index.html"
    if f.exists():
        return HTMLResponse(f.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>PentestAI v9</h1><p>index.html not found</p>", status_code=404)


@app.get("/chat/{session_id}", response_class=HTMLResponse)
async def serve_chat(session_id: str):
    """Session-based routing — serve main UI for /chat/{session_id}"""
    f = WEB_DIR / "index.html"
    if f.exists():
        return HTMLResponse(f.read_text(encoding="utf-8"))
    raise HTTPException(404, "Not found")


# Only explicit UI routes and the confined StaticFiles mount serve files.
@app.get("/login.html", response_class=HTMLResponse)
async def login_alias():
    return await serve_login()


@app.get("/admin.html", response_class=HTMLResponse)
async def admin_alias():
    return await serve_admin()


@app.get("/index.html", response_class=HTMLResponse)
async def index_alias():
    return await serve_ui()


@app.get("/{path:path}")
async def catch_all(path: str):
    raise HTTPException(404, "Not found")


# ── Run ──────────────────────────────────────────────────────────────────

def run():
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST,
        port=settings.WEB_PORT,  # Serve everything on port 7000
        workers=1,
        reload=settings.DEBUG,
    )


if __name__ == "__main__":
    run()
