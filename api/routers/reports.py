"""
PentestAI v8 — Reports Router
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional

from api.auth import get_current_user, TokenData
from api.session_access import get_accessible_session
from agents.report_agent import report_agent
from config.settings import settings

router = APIRouter()


class ReportRequest(BaseModel):
    session_id: str
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
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Report generation failed: {e}")


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
async def download_report(filename: str):
    """Download a generated report file (no auth — filename is unique enough)."""
    # Validate filename: pentest_report_<anything_safe>_YYYYMMDD_HHMMSS.<ext>
    if not re.match(r'^pentest_report_[\w\-]+_\d{8}_\d{6}\.(pdf|md|tex|html)$', filename):
        raise HTTPException(400, "Invalid filename")

    filepath = Path(settings.REPORT_OUTPUT_DIR) / filename
    if not filepath.exists():
        raise HTTPException(404, "Report file not found — it may have been cleaned up")

    media_types = {
        ".pdf":  "application/pdf",
        ".md":   "text/markdown",
        ".tex":  "application/x-latex",
        ".html": "text/html",
    }
    mt = media_types.get(filepath.suffix, "application/octet-stream")
    return FileResponse(str(filepath), filename=filename, media_type=mt)
