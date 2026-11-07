"""Program research, explicit owner activation, and private candidate ranking."""
import asyncio
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from api.auth import TokenData, get_current_user
from memory.program_policy import (
    ProgramImport, PolicyReview, ProgramFit, program_policies, program_catalog, save_program_fit,
)
from security.program_fetch import fetch_policy


router = APIRouter()


@router.get('/{session_id}/history')
async def policy_history(session_id: str, user: TokenData = Depends(get_current_user)):
    return {'history': await program_policies.history(session_id, user.user_id),
            'policy': await program_policies.status(session_id, user.user_id),
            'discovery_authorizes_testing': False}


@router.post('/{session_id}/import-text')
async def import_policy(session_id: str, body: ProgramImport, user: TokenData = Depends(get_current_user)):
    result = await program_policies.import_text(session_id, user.user_id, body)
    await suspend_execution(session_id, user.user_id, result)
    return result


@router.post('/{session_id}/{snapshot_id}/review')
async def review_policy(session_id: str, snapshot_id: str, body: PolicyReview,
                        user: TokenData = Depends(get_current_user)):
    result = await program_policies.review(session_id, user.user_id, snapshot_id, body)
    await suspend_execution(session_id, user.user_id, result)
    return result


class PageImport(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=200)
    source_url: str = Field(max_length=2048)
    program_type: Literal['paid_bounty', 'disclosure_only', 'unknown'] = 'unknown'


class Activation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    review_id: str
    confirm: bool = False


@router.get('/catalog')
async def catalog(user: TokenData = Depends(get_current_user)):
    return {'programs': await program_catalog(user.user_id), 'discovery_authorizes_testing': False}


@router.post('/{session_id}/import-page')
async def import_page(session_id: str, body: PageImport, user: TokenData = Depends(get_current_user)):
    # Authorize BEFORE fetching; a caller cannot use another owner's engagement for egress.
    await program_policies.history(session_id, user.user_id)
    try:
        checked = ProgramImport(name=body.name, source_url=body.source_url, text='pending', program_type=body.program_type)
        fetched = await fetch_policy(checked.source_url)
    except (ValueError, OSError, TimeoutError, EOFError, asyncio.LimitOverrunError):
        raise HTTPException(422, 'Public policy retrieval failed; use manual text import for authenticated or unsupported pages') from None
    checked.text = fetched['text']
    checked.retrieved_at = datetime.now(timezone.utc)
    result = await program_policies.import_text(session_id, user.user_id, checked, fetched=fetched)
    await suspend_execution(session_id, user.user_id, result)
    return result


@router.post('/{session_id}/{snapshot_id}/activate')
async def activate_policy(session_id: str, snapshot_id: str, body: Activation,
                          user: TokenData = Depends(get_current_user)):
    if not body.confirm:
        raise HTTPException(422, 'Explicit owner confirmation is required')
    return await program_policies.activate(session_id, user.user_id, snapshot_id, body.review_id)


@router.post('/{session_id}/{snapshot_id}/fit')
async def assess_program(session_id: str, snapshot_id: str, body: ProgramFit,
                         user: TokenData = Depends(get_current_user)):
    return await save_program_fit(session_id, user.user_id, snapshot_id, body)


async def suspend_execution(session_id: str, owner_id: str, snapshot: dict) -> None:
    if snapshot.get('execution_suspended'):
        from memory.worker_jobs import worker_jobs
        from memory.web_actions import web_actions
        await worker_jobs.cancel_session(owner_id, session_id)
        await web_actions.cancel_all(session_id, owner_id)
