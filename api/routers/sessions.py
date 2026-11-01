"""
PentestAI v8 — Sessions Router
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from api.auth import get_current_user, TokenData
from api.session_access import get_accessible_session
from memory.session_manager import session_manager

router = APIRouter()


class NewSession(BaseModel):
    target: str
    name: Optional[str] = ""
    context_type: str = "internal_corporate"
    scope: Optional[dict] = None


@router.post("/new")
async def create_session(body: NewSession, user: TokenData = Depends(get_current_user)):
    result = await session_manager.create_session(
        user.user_id, body.target, body.name, body.context_type,
        body.scope or {"targets": [body.target], "exclusions": []})
    return result


@router.get("/list")
async def list_sessions(user: TokenData = Depends(get_current_user)):
    sessions = await session_manager.list_sessions(user.user_id)
    return {"sessions": sessions, "total": len(sessions)}


@router.get("/{session_id}")
async def get_session(session_id: str, user: TokenData = Depends(get_current_user)):
    return await get_accessible_session(session_id, user)


@router.delete("/{session_id}")
async def delete_session(session_id: str, user: TokenData = Depends(get_current_user)):
    await get_accessible_session(session_id, user)
    from memory.worker_jobs import worker_jobs
    from agents.autonomous_engine import autonomous_engine
    result = await worker_jobs.cancel_session(user.user_id, session_id)
    if result['pending']:
        raise HTTPException(409, "Worker cancellation is not confirmed; engagement was not archived")
    await autonomous_engine.detach_session(session_id)
    await session_manager.delete_session(session_id)
    return {"status": "deleted", "session_id": session_id}


@router.get("/{session_id}/restore")
async def restore_session(session_id: str, user: TokenData = Depends(get_current_user)):
    session = await get_accessible_session(session_id, user)
    logs = await session_manager.get_chat_logs(session_id)
    findings = await session_manager.get_findings_summary(session_id)
    counts = findings.get("counts", {})
    # Derive topbar stats from session data
    ports_count = session.get("ports_count", 0)
    vulns_count = (counts.get("critical", 0) + counts.get("high", 0) +
                   counts.get("medium", 0))
    shells_count = session.get("shells_count", 0)
    return {
        "session_id": session_id,
        "target": session.get("target", ""),
        "logs": logs,
        "findings": findings.get("findings", []),
        "total": findings.get("total", 0),
        "counts": counts,
        "phase": session.get("phase", "scope"),
        "tools_run": session.get("tools_run", []),
        "ports_count": ports_count,
        "vulns_count": vulns_count,
        "shells_count": shells_count,
    }


@router.patch("/{session_id}/phase")
async def update_phase(session_id: str, body: dict, user: TokenData = Depends(get_current_user)):
    await get_accessible_session(session_id, user)
    phase = body.get("phase", "")
    if phase:
        await session_manager.update_phase(session_id, phase)
    return {"status": "ok"}
