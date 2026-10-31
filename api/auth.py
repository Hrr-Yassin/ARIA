"""
PentestAI v8 — Authentication & Authorization
JWT-based auth with admin/pentester roles and 3 skill levels.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import settings
from memory.database_models import User, UserRole, SkillLevel, async_session

security = HTTPBearer(auto_error=False)

# ── Password hashing (SHA-256 + salt — no bcrypt dependency needed) ──────

def hash_password(password: str, salt: str = "") -> str:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"{salt}${hashed}"

def verify_password(password: str, stored: str) -> bool:
    if "$" not in stored:
        return False
    salt, hashed = stored.split("$", 1)
    return hash_password(password, salt).split("$", 1)[1] == hashed


# ── JWT ──────────────────────────────────────────────────────────────────

def create_token(user_id: str, username: str, role: str, skill_level: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "skill_level": skill_level,
        "exp": datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ── Models ───────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

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

    # Fallback to query param (for WebSocket)
    if not token:
        token = request.query_params.get("token")

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_token(token)
    return TokenData(
        user_id=payload["sub"],
        username=payload["username"],
        role=payload["role"],
        skill_level=payload.get("skill_level", "intermediate"),
    )

async def require_admin(user: TokenData = Depends(get_current_user)) -> TokenData:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# ── Default users seeding ────────────────────────────────────────────────

DEFAULT_USERS = [
    {
        "username": "myth",
        "password": "Myth04$$",
        "role": UserRole.ADMIN,
        "skill_level": SkillLevel.EXPERT,
        "display_name": "Administrator",
    },
    {
        "username": "hacker",
        "password": "hacker$$",
        "role": UserRole.PENTESTER,
        "skill_level": SkillLevel.INTERMEDIATE,
        "display_name": "Pentester",
    },
]

async def seed_default_users():
    """Create default users if they don't exist."""
    async with async_session() as db:
        for u in DEFAULT_USERS:
            result = await db.execute(select(User).where(User.username == u["username"]))
            existing = result.scalar_one_or_none()
            if not existing:
                user = User(
                    username=u["username"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"],
                    skill_level=u["skill_level"],
                    display_name=u["display_name"],
                )
                db.add(user)
        await db.commit()


async def authenticate_user(username: str, password: str) -> Optional[User]:
    """Verify credentials and return user."""
    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user and verify_password(password, user.password_hash) and user.is_active:
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
