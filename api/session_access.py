"""
Shared session access helpers for user-scoped routes.
"""
from fastapi import HTTPException

from api.auth import TokenData
from memory.session_manager import session_manager


async def get_accessible_session(session_id: str, user: TokenData) -> dict:
    session = await session_manager.get_session(session_id, authoritative=True)
    if not session:
        raise HTTPException(404, "Session not found")

    owner_id = session.get("user_id")
    if not isinstance(owner_id, str) or not owner_id or (user.role != "admin" and owner_id != user.user_id):
        raise HTTPException(403, "Session access denied")

    from llm.engagement_budget import engagement_context
    engagement_context.set({'session_id': session_id, 'owner': user.user_id})
    return session
