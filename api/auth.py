"""
PentestAI v8 — Authentication & Authorization
JWT-based auth with admin/pentester roles and 3 skill levels.
"""
import hashlib
import asyncio
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import settings
from memory.database_models import User, UserRole, SkillLevel, async_session

security = HTTPBearer(auto_error=False)

from security.credentials import hash_password, verify_password, auth_revision, revoke_credentials


# ── JWT ──────────────────────────────────────────────────────────────────

def create_token(user_id: str, username: str, role: str, skill_level: str, auth_revision: int = 0) -> str:
    payload = {
        "sub": user_id,
        "rev": auth_revision,
        "username": username,
        "role": role,
        "skill_level": skill_level,
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM],
                          options={"require": ["exp", "iat", "sub", "rev"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Models ───────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=1024)

class LoginResponse(BaseModel):
    token: str
    user_id: str
    username: str
    role: str
    skill_level: str
    display_name: str

class TokenData(BaseModel):
    user_id: str
    username: str
    role: str
    skill_level: str
    auth_revision: int = 0


# ── Dependencies ─────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> TokenData:
    """Extract and validate JWT from Authorization header or cookie."""
    token = None

    # Try Authorization header first
    if credentials:
        token = credentials.credentials

    # Fallback to cookie
    if not token:
        token = request.cookies.get("pentestai_token")

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    if not credentials and request.method not in {"GET", "HEAD"}:
        raise HTTPException(401, "Bearer authentication required for state changes")
    return await authenticate_socket_token(token)


def token_identity(token: str) -> TokenData:
    try:
        payload = decode_token(token)
        return TokenData(user_id=payload["sub"], username=payload["username"],
                         role=payload["role"], skill_level=payload.get("skill_level", "intermediate"),
                         auth_revision=payload["rev"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(401, "Invalid token") from None


async def current_identity(user_id: str, revision: Optional[int] = None) -> TokenData:
    try:
        async with async_session() as db:
            user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
            if not user or not user.is_active or (revision is not None and auth_revision(user) != revision):
                raise HTTPException(401, "Account or credentials are unavailable")
            return TokenData(user_id=user.id, username=user.username, role=user.role.value,
                             skill_level=user.skill_level.value, auth_revision=auth_revision(user))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "Authentication storage unavailable") from None


async def authenticate_socket_token(token: str) -> TokenData:
    identity = token_identity(token)
    return await current_identity(identity.user_id, identity.auth_revision)


async def require_admin(user: TokenData = Depends(get_current_user)) -> TokenData:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def authenticate_user(username: str, password: str) -> Optional[User]:
    """Verify credentials and return user."""
    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == username).with_for_update())
        user = result.scalar_one_or_none()
        if user and user.is_active and await asyncio.to_thread(verify_password, password, user.password_hash):
            if not user.password_hash.startswith("pbkdf2_sha256$"):
                user.password_hash = await asyncio.to_thread(hash_password, password)
            user.last_login = datetime.utcnow()
            await db.commit()
            return user
    return None


# Solution 11 — Skill Level: always read from DB, not JWT
async def get_skill_level_from_db(user_id: str) -> str:
    """Re-read skill_level from DB on every request — not from cached JWT."""
    from sqlalchemy import select
    async with async_session() as db:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if user:
            return user.skill_level.value
    return "intermediate"
