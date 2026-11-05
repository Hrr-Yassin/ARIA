"""
PentestAI v8 — Reports Router
"""
import re
import hashlib
import os
import stat
from memory.report_artifacts import find_report
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from typing import Optional

from api.auth import get_current_user, TokenData
from api.session_access import get_accessible_session
from agents.report_agent import report_agent
from config.settings import settings

router = APIRouter()


class ReportRequest(BaseModel):
    session_id: str
    turn_id: Optional[str] = None
    format: str = "html"   # html | markdown | latex | pdf


@router.post("/generate")
async def generate_report(body: ReportRequest, user: TokenData = Depends(get_current_user)):
    allowed = {"html", "markdown", "latex", "pdf"}
    if body.format not in allowed:
        raise HTTPException(400, f"Invalid format. Allowed: {', '.join(sorted(allowed))}")
    await get_accessible_session(body.session_id, user)
    try:
        result = await report_agent.generate_report(
            body.session_id, user.user_id, body.format, user.skill_level)
        from memory.session_manager import session_manager
        await session_manager.add_chat_log(body.session_id,'assistant',f"{body.format} report generated",'report',
            {'type':'report','filename':result['filename'],'format':body.format,'turn_id':body.turn_id})
        return {**result,'turn_id':body.turn_id}
    except Exception:
        raise HTTPException(500, "Report generation failed") from None


@router.get("/view/{session_id}")
async def view_html_report(session_id: str, user: TokenData = Depends(get_current_user)):
    """Serve HTML report inline."""
    await get_accessible_session(session_id, user)
    result = await report_agent.generate_report(
        session_id, user.user_id, "html", user.skill_level)
    if result.get("content"):
        return HTMLResponse(result["content"])
    raise HTTPException(500, "HTML report generation failed")


@router.get("/download/{filename}")
async def download_report(filename: str, user: TokenData = Depends(get_current_user)):
    if not re.fullmatch(r'pentest_report_[0-9a-f]{32}\.(pdf|md|tex|html)', filename):
        raise HTTPException(404, "Report not found")
    try:
        artifact = await find_report(filename)
    except Exception:
        raise HTTPException(503, "Report storage unavailable") from None
    if not artifact:
        raise HTTPException(404, "Report not found")
    await get_accessible_session(artifact['session_id'], user)
    # Open without following links and serve the validated descriptor's bytes.
    root = Path(settings.REPORT_OUTPUT_DIR).resolve()
    try:
        descriptor = os.open(root / filename, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as file:
            if not stat.S_ISREG(os.fstat(file.fileno()).st_mode) or os.fstat(file.fileno()).st_size > 20_000_000:
                raise OSError()
            content = file.read(20_000_001)
        if hashlib.sha256(content).hexdigest() != artifact['sha256']:
            raise OSError()
    except (OSError, KeyError):
        raise HTTPException(404, "Report not found") from None
    types = {'.pdf': 'application/pdf', '.md': 'text/markdown', '.tex': 'application/x-latex', '.html': 'text/html'}
    return Response(content, media_type=types[Path(filename).suffix], headers={
        'Content-Disposition': f'attachment; filename="{filename}"', 'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'})
