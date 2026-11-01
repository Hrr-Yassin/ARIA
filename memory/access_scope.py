"""Authoritative private-memory visibility; no process-global owner cache."""
from sqlalchemy import select
from memory.database_models import User, PentestSession, SessionStatus, async_session


async def owned_session_ids(user_id: str) -> set[str]:
    if not user_id:
        return set()
    async with async_session() as db:
        user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if not user or not user.is_active:
            return set()
        rows = await db.execute(select(PentestSession.id).where(
            PentestSession.user_id == user_id, PentestSession.status != SessionStatus.ARCHIVED))
        return set(rows.scalars().all())
