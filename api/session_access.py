"""
Shared session access helpers for user-scoped routes.
"""
from fastapi import HTTPException

from api.auth import TokenData
from memory.session_manager import session_manager


async def get_accessible_session(session_id: str, user: TokenData) -> dict:
    session = await session_manager.get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")

    owner_id = session.get("user_id")
    if user.role != "admin" and owner_id and owner_id != user.user_id:
        raise HTTPException(403, "Session access denied")

    return session
