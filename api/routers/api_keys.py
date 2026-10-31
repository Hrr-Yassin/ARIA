"""
PentestAI v8 — API Keys Router
Per-user API key management with encryption.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import select, delete

from api.auth import get_current_user, TokenData
from memory.database_models import UserAPIKey, async_session
from llm.pool_manager import pool_manager

router = APIRouter()


class AddKeyRequest(BaseModel):
    provider: str  # groq, gemini, openrouter
    api_key: str
    label: Optional[str] = ""
    requests_limit: Optional[int] = 30


class UpdateKeyRequest(BaseModel):
    is_active: Optional[bool] = None
    requests_limit: Optional[int] = None
    label: Optional[str] = None


@router.get("/")
async def list_keys(user: TokenData = Depends(get_current_user)):
    """List all API keys for current user (keys are masked)."""
    async with async_session() as db:
        result = await db.execute(
            select(UserAPIKey).where(UserAPIKey.user_id == user.user_id)
        )
        keys = result.scalars().all()

    masked = []
    for k in keys:
        decrypted = pool_manager.decrypt_key(k.encrypted_key)
        mask = decrypted[:8] + "..." + decrypted[-4:] if len(decrypted) > 12 else "***"
        masked.append({
            "id": k.id,
            "provider": k.provider,
            "label": k.label,
            "masked_key": mask,
            "is_active": k.is_active,
            "requests_used": k.requests_used,
            "requests_limit": k.requests_limit,
            "last_error": k.last_error,
            "created_at": k.created_at.isoformat() if k.created_at else "",
        })

    # Add pool status
    pool_status = pool_manager.get_status(user.user_id)
    return {"keys": masked, "pool_status": pool_status}


@router.post("/")
async def add_key(body: AddKeyRequest, user: TokenData = Depends(get_current_user)):
    """Add a new API key."""
    if body.provider not in ("groq", "gemini", "openrouter"):
        raise HTTPException(400, "Provider must be groq, gemini, or openrouter")

    encrypted = pool_manager.encrypt_key(body.api_key)

    async with async_session() as db:
        key = UserAPIKey(
            user_id=user.user_id,
            provider=body.provider,
            encrypted_key=encrypted,
            label=body.label or f"{body.provider} key",
            requests_limit=body.requests_limit or 30,
        )
        db.add(key)
        await db.commit()
        await db.refresh(key)

    # Reload pool
    async with async_session() as db:
        result = await db.execute(
            select(UserAPIKey).where(UserAPIKey.user_id == user.user_id)
        )
        all_keys = result.scalars().all()
        pool_manager.load_user_keys(user.user_id, all_keys)

    return {"status": "added", "key_id": key.id, "provider": body.provider}


@router.delete("/{key_id}")
async def remove_key(key_id: str, user: TokenData = Depends(get_current_user)):
    """Remove an API key."""
    async with async_session() as db:
        result = await db.execute(
            select(UserAPIKey).where(
                UserAPIKey.id == key_id,
                UserAPIKey.user_id == user.user_id,
            )
        )
        key = result.scalar_one_or_none()
        if not key:
            raise HTTPException(404, "Key not found")
        await db.delete(key)
        await db.commit()

    # Reload pool
    async with async_session() as db:
        result = await db.execute(
            select(UserAPIKey).where(UserAPIKey.user_id == user.user_id)
        )
        all_keys = result.scalars().all()
        pool_manager.load_user_keys(user.user_id, all_keys)

    return {"status": "removed", "key_id": key_id}


@router.patch("/{key_id}")
async def update_key(key_id: str, body: UpdateKeyRequest,
                     user: TokenData = Depends(get_current_user)):
    """Update key settings."""
    async with async_session() as db:
        result = await db.execute(
            select(UserAPIKey).where(
                UserAPIKey.id == key_id,
                UserAPIKey.user_id == user.user_id,
            )
        )
        key = result.scalar_one_or_none()
        if not key:
            raise HTTPException(404, "Key not found")
        if body.is_active is not None:
            key.is_active = body.is_active
        if body.requests_limit is not None:
            key.requests_limit = body.requests_limit
        if body.label is not None:
            key.label = body.label
        await db.commit()

    return {"status": "updated", "key_id": key_id}
