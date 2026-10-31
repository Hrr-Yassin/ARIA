"""
PentestAI v8 — Main Application
FastAPI backend serving API + Web UI on Ubuntu.
"""
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.auth import (
    LoginRequest, LoginResponse, authenticate_user, create_token, seed_default_users,
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
    log.info("PentestAI v9 starting...")

    # Initialize database
    await init_db()

    # Initialize Redis
    await session_manager.initialize()
    await knowledge_cache.initialize_redis(session_manager._redis)

    # Seed default users
    await seed_default_users()

    # Ensure report directory
    Path(settings.REPORT_OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

    log.info("PentestAI v8 ready",
             api_port=settings.API_PORT,
             web_port=settings.WEB_PORT)
    yield

    await session_manager.close()
    log.info("PentestAI v8 shutdown")


app = FastAPI(
    title="PentestAI v9",
    version="9.0.0",
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

# ── Routers ──────────────────────────────────────────────────────────────

app.include_router(pentest_router.router, prefix="/api", tags=["pentest"])
app.include_router(sessions_router.router, prefix="/api/session", tags=["sessions"])
app.include_router(reports_router.router, prefix="/api/report", tags=["reports"])
app.include_router(api_keys_router.router, prefix="/api/keys", tags=["api-keys"])
app.include_router(admin_router.router, prefix="/api/admin", tags=["admin"])


# ── Auth Endpoints ───────────────────────────────────────────────────────

@app.post("/api/login")
async def login(body: LoginRequest):
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user.id, user.username, user.role.value, user.skill_level.value)
    return LoginResponse(
        token=token,
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        skill_level=user.skill_level.value,
        display_name=user.display_name or user.username,
    )


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


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


_MIME = {
    ".js":    "application/javascript",
    ".mjs":   "application/javascript",
    ".css":   "text/css",
    ".html":  "text/html",
    ".json":  "application/json",
    ".png":   "image/png",
    ".jpg":   "image/jpeg",
    ".jpeg":  "image/jpeg",
    ".svg":   "image/svg+xml",
    ".ico":   "image/x-icon",
    ".woff":  "font/woff",
    ".woff2": "font/woff2",
    ".ttf":   "font/ttf",
    ".map":   "application/json",
}

@app.get("/{path:path}")
async def catch_all(path: str):
    from fastapi.responses import FileResponse
    f = WEB_DIR / path
    if f.exists() and f.is_file():
        media_type = _MIME.get(Path(path).suffix.lower())
        return FileResponse(str(f), media_type=media_type)
    # SPA fallback for client-side routing
    f = WEB_DIR / "index.html"
    if f.exists():
        return HTMLResponse(f.read_text(encoding="utf-8"))
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
