"""
PentestAI v8 — Admin Router
Admin panel endpoints: audit logs, user management, system monitoring.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
from sqlalchemy import func, select, update

from api.auth import require_admin, get_current_user, TokenData, hash_password
from security.credentials import revoke_credentials
from memory.database_models import (
    AuditLog,
    ChatLog,
    Finding,
    PentestSession,
    SessionStatus,
    SkillLevel,
    User,
    UserAPIKey,
    UserRole,
    async_session,
)
from memory.session_manager import session_manager

router = APIRouter()


# ── User Management ──────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    username: str
    password: str = Field(min_length=14, max_length=1024)
    role: str = "pentester"
    skill_level: str = "intermediate"
    display_name: Optional[str] = ""

class UpdateUserRequest(BaseModel):
    role: Optional[UserRole] = None
    skill_level: Optional[str] = None
    is_active: Optional[bool] = None
    display_name: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=14, max_length=1024)


@router.get("/users")
async def list_users(user: TokenData = Depends(require_admin)):
    async with async_session() as db:
        result = await db.execute(select(User).order_by(User.created_at.desc()))
        users = result.scalars().all()

        # Session counts per user
        sess_result = await db.execute(
            select(PentestSession.user_id, func.count(PentestSession.id).label("cnt"))
            .group_by(PentestSession.user_id)
        )
        session_counts = {r.user_id: r.cnt for r in sess_result}

        # API key quota per user (sum requests_used / requests_limit)
        key_result = await db.execute(
            select(UserAPIKey.user_id,
                   func.sum(UserAPIKey.requests_used).label("used"),
                   func.sum(UserAPIKey.requests_limit).label("lim"))
            .group_by(UserAPIKey.user_id)
        )
        quotas = {r.user_id: {"used": r.used or 0, "limit": r.lim or 0} for r in key_result}

    # Online detection via Redis (WS handler writes user_id to "online_users" set)
    online_set = set()
    try:
        if session_manager._redis:
            members = await session_manager._redis.smembers("online_users")
            online_set = {m.decode() if isinstance(m, bytes) else m for m in (members or [])}
    except Exception:
        pass

    return {"users": [{
        "id": u.id,
        "user_id": u.id,
        "username": u.username,
        "role": u.role.value,
        "skill_level": u.skill_level.value,
        "display_name": u.display_name,
        "is_active": u.is_active,
        "last_login": u.last_login.isoformat() if u.last_login else None,
        "created_at": u.created_at.isoformat() if u.created_at else "",
        "online": u.id in online_set,
        "session_count": session_counts.get(u.id, 0),
        "quota_used": quotas.get(u.id, {}).get("used", 0),
        "quota_limit": quotas.get(u.id, {}).get("limit", 0),
    } for u in users]}


@router.get("/sessions")
async def list_all_sessions(user: TokenData = Depends(require_admin)):
    from sqlalchemy.orm import selectinload

    async with async_session() as db:
        result = await db.execute(
            select(PentestSession)
            .options(
                selectinload(PentestSession.findings),
                selectinload(PentestSession.user),
            )
            .where(PentestSession.status != SessionStatus.ARCHIVED)
            .order_by(PentestSession.updated_at.desc())
        )
        sessions = result.scalars().unique().all()

    return {
        "sessions": [{
            "session_id": s.id,
            "name": s.name,
            "target": s.target,
            "user_id": s.user_id,
            "username": s.user.username if s.user else "",
            "status": s.status.value if s.status else "active",
            "phase": s.current_phase.value if s.current_phase else "scope",
            "created_at": s.created_at.isoformat() if s.created_at else "",
            "updated_at": s.updated_at.isoformat() if s.updated_at else "",
            "findings_count": len(s.findings) if s.findings else 0,
        } for s in sessions],
        "total": len(sessions),
    }


@router.post("/users")
async def create_user(body: CreateUserRequest, user: TokenData = Depends(require_admin)):
    async with async_session() as db:
        existing = await db.execute(select(User).where(User.username == body.username))
        if existing.scalar_one_or_none():
            raise HTTPException(400, "Username already exists")

        new_user = User(
            username=body.username,
            password_hash=hash_password(body.password),
            role=UserRole(body.role),
            skill_level=SkillLevel(body.skill_level),
            display_name=body.display_name or body.username,
        )
        db.add(new_user)
        await db.commit()
    return {"status": "created", "username": body.username}


@router.patch("/users/{user_id}")
async def update_user(user_id: str, body: UpdateUserRequest,
                      admin: TokenData = Depends(require_admin)):
    async with async_session() as db:
        result = await db.execute(select(User).where(User.id == user_id).with_for_update())
        u = result.scalar_one_or_none()
        if not u:
            raise HTTPException(404, "User not found")
        if body.role is not None:
            revoke_credentials(u)
            u.role = body.role
        if body.skill_level:
            u.skill_level = SkillLevel(body.skill_level)
        if body.is_active is not None:
            revoke_credentials(u)
            u.is_active = body.is_active
        if body.display_name is not None:
            u.display_name = body.display_name
        if body.password:
            revoke_credentials(u)
            u.password_hash = hash_password(body.password)
        await db.commit()
    if body.password or body.is_active is not None or body.role is not None:
        from agents.autonomous_engine import autonomous_engine
        from memory.worker_jobs import worker_jobs
        await autonomous_engine.revoke_principal(user_id)
        cancellation = await worker_jobs.revoke_principal(user_id)
        from memory.web_actions import web_actions
        cancellation["web_replays"] = await web_actions.revoke_principal(user_id)
        return {"status": "updated", "cancellation": cancellation}
    return {"status": "updated"}


@router.delete("/users/{user_id}")
async def delete_user(user_id: str, admin: TokenData = Depends(require_admin)):
    async with async_session() as db:
        result = await db.execute(select(User).where(User.id == user_id).with_for_update())
        u = result.scalar_one_or_none()
        if not u:
            raise HTTPException(404, "User not found")
        revoke_credentials(u)
        u.is_active = False
        await db.commit()
    from agents.autonomous_engine import autonomous_engine
    from memory.worker_jobs import worker_jobs
    await autonomous_engine.revoke_principal(user_id)
    cancellation = await worker_jobs.revoke_principal(user_id)
    from memory.web_actions import web_actions
    cancellation["web_replays"] = await web_actions.revoke_principal(user_id)
    return {"status": "deactivated", "cancellation": cancellation}


# ── Audit Logs ───────────────────────────────────────────────────────────

@router.get("/audit-logs")
async def get_audit_logs(session_id: Optional[str] = None,
                         target_user: Optional[str] = None,
                         limit: int = 100,
                         user: TokenData = Depends(require_admin)):
    try:
        logs = await session_manager.get_audit_logs(
            session_id if session_id else None,
            target_user if target_user else None,
            limit)
        return {"logs": logs, "total": len(logs)}
    except Exception as e:
        return {"logs": [], "total": 0, "error": str(e)}


@router.get("/activity")
async def get_activity(limit: int = 200, user: TokenData = Depends(require_admin)):
    """Get all recent activity across all sessions."""
    try:
        activities = []
        user_names = {}

        async with async_session() as db:
            user_result = await db.execute(select(User.id, User.username))
            user_names = {row.id: row.username for row in user_result}

            result = await db.execute(
                select(ChatLog).order_by(ChatLog.created_at.desc()).limit(limit)
            )
            for cl in result.scalars().all():
                activities.append({
                    "type": "chat", "role": cl.role,
                    "content": (cl.content or "")[:200],
                    "session_id": cl.session_id or "",
                    "msg_type": cl.msg_type or "",
                    "detail": (cl.content or "")[:200],
                    "timestamp": cl.created_at.isoformat() if cl.created_at else "",
                    "created_at": cl.created_at.isoformat() if cl.created_at else "",
                })

            result = await db.execute(
                select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
            )
            for al in result.scalars().all():
                activities.append({
                    "type": "audit",
                    "action": al.action.value if al.action else "",
                    "agent": al.agent or "",
                    "user_id": al.user_id or "",
                    "username": user_names.get(al.user_id or "", ""),
                    "session_id": al.session_id or "",
                    "input_summary": str(al.input_data or "")[:150],
                    "detail": str(al.input_data or "")[:150] or (al.action.value if al.action else ""),
                    "timestamp": al.created_at.isoformat() if al.created_at else "",
                    "created_at": al.created_at.isoformat() if al.created_at else "",
                })

        activities.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        sliced = activities[:limit]
        return {"activities": sliced, "activity": sliced, "total": len(activities)}
    except Exception as e:
        return {"activities": [], "activity": [], "total": 0, "error": str(e)}


# ── System Health ────────────────────────────────────────────────────────

@router.get("/health")
async def system_health(user: TokenData = Depends(require_admin)):
    import httpx
    import glob
    import os
    import psutil
    from config.settings import settings
    from llm.pool_manager import pool_manager

    # Check Kali
    kali_status = "unreachable"
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{settings.KALI_AGENT_URL}/health")
            if r.status_code == 200:
                kali_status = "online"
    except Exception:
        pass

    # Check Redis
    redis_status = "offline"
    try:
        if session_manager._redis:
            await session_manager._redis.ping()
            redis_status = "online"
    except Exception:
        pass

    db_connected = True
    users_total = 0
    users_active = 0
    sessions_total = 0
    sessions_active = 0
    findings_total = 0
    findings_critical = 0
    llm_active_keys = 0
    llm_provider = ""
    shells_total = 0

    try:
        async with async_session() as db:
            users_total = await db.scalar(select(func.count()).select_from(User)) or 0
            users_active = await db.scalar(
                select(func.count()).select_from(User).where(User.is_active.is_(True))
            ) or 0
            sessions_total = await db.scalar(
                select(func.count()).select_from(PentestSession)
                .where(PentestSession.status != SessionStatus.ARCHIVED)
            ) or 0
            sessions_active = await db.scalar(
                select(func.count()).select_from(PentestSession)
                .where(PentestSession.status == SessionStatus.ACTIVE)
            ) or 0
            findings_total = await db.scalar(select(func.count()).select_from(Finding)) or 0
            findings_critical = await db.scalar(
                select(func.count()).select_from(Finding).where(Finding.severity == "critical")
            ) or 0
            llm_active_keys = await db.scalar(
                select(func.count()).select_from(UserAPIKey).where(UserAPIKey.is_active.is_(True))
            ) or 0
            llm_provider = await db.scalar(
                select(UserAPIKey.provider)
                .where(UserAPIKey.is_active.is_(True))
                .order_by(UserAPIKey.created_at.desc())
                .limit(1)
            ) or ""
    except Exception:
        db_connected = False

    # System metrics (Ubuntu host)
    cpu_pct = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    # Log file sizes
    log_patterns = ["/var/log/pentestai*.log", "/tmp/pentestai*.log",
                    "*.log", "logs/*.log"]
    log_info = {}
    error_count = 0
    for pattern in log_patterns:
        for path in glob.glob(pattern):
            try:
                size = os.path.getsize(path)
                log_info[os.path.basename(path)] = size
                # Count ERROR lines, skip user prompt lines
                with open(path, "r", errors="ignore") as f:
                    for line in f:
                        low = line.lower()
                        if "error" in low and "user" not in low and "prompt" not in low:
                            error_count += 1
            except Exception:
                pass

    try:
        from memory.attack_knowledge_base import attack_kb
        for session_id in getattr(attack_kb, "_sessions", {}):
            shells_total += len(attack_kb.get_full_summary(session_id).get("shells", []))
    except Exception:
        pass

    system_data = {
        "cpu_percent": round(cpu_pct, 1),
        "memory_percent": round(mem.percent, 1),
        "ram_used_mb": round(mem.used / 1024 / 1024),
        "ram_total_mb": round(mem.total / 1024 / 1024),
        "disk_total_gb": round(disk.total / 1024 / 1024 / 1024, 1),
        "disk_used_gb": round(disk.used / 1024 / 1024 / 1024, 1),
        "disk_free_gb": round(disk.free / 1024 / 1024 / 1024, 1),
        "disk_percent": round(disk.percent, 1),
    }

    return {
        "backend": "online",
        "version": settings.APP_VERSION,
        "system": system_data,
        "database": {"connected": db_connected, "status": "online" if db_connected else "offline"},
        "redis": {"connected": redis_status == "online", "status": redis_status},
        "kali": {
            "connected": kali_status == "online",
            "status": kali_status,
            "url": settings.KALI_AGENT_URL,
        },
        "llm": {
            "active": llm_active_keys > 0,
            "active_keys": llm_active_keys,
            "provider": llm_provider or getattr(pool_manager, "current_provider", "") or "—",
        },
        "users": {"total": users_total, "active": users_active},
        "sessions": {"total": sessions_total, "active": sessions_active, "shells": shells_total},
        "findings": {"total": findings_total, "critical": findings_critical},
        "kali_agent": kali_status,
        "kali_url": settings.KALI_AGENT_URL,
        "cpu_pct": system_data["cpu_percent"],
        "ram_used_mb": system_data["ram_used_mb"],
        "ram_total_mb": system_data["ram_total_mb"],
        "ram_pct": system_data["memory_percent"],
        "disk_total_gb": system_data["disk_total_gb"],
        "disk_used_gb": system_data["disk_used_gb"],
        "disk_free_gb": system_data["disk_free_gb"],
        "disk_pct": system_data["disk_percent"],
        "log_files": log_info,
        "backend_errors": error_count,
    }


# ── Solution: Real errors endpoint + online status fix ─────────────────

@router.get("/errors")
async def get_backend_errors(
    limit: int = 10,
    user: TokenData = Depends(require_admin)
):
    """Return last N real backend errors from structlog output."""
    import glob, os
    errors = []
    log_patterns = ["/var/log/pentestai*.log", "/tmp/pentestai*.log",
                    "*.log", "logs/*.log"]
    for pattern in log_patterns:
        for path in glob.glob(pattern):
            try:
                with open(path, "r", errors="ignore") as f:
                    for line in f:
                        low = line.lower()
                        if ("error" in low or "exception" in low or "traceback" in low) \
                                and "user" not in low and "prompt" not in low:
                            errors.append({
                                "message": line.strip()[:200],
                                "file": os.path.basename(path),
                                "timestamp": "",
                            })
            except Exception:
                pass
    errors = errors[-limit:]
    return {"errors": errors, "total": len(errors)}
