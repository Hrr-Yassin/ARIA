"""Persistent report-to-engagement mapping; filenames are never capabilities."""
from sqlalchemy import select
from memory.database_models import DecisionLog, async_session


async def register_report(session_id, owner_id, filename, content_hash):
    async with async_session() as db:
        db.add(DecisionLog(session_id=session_id, user_id=owner_id,
            decision_type='report_artifact', metadata_={'filename': filename, 'sha256': content_hash}))
        await db.commit()


async def find_report(filename):
    async with async_session() as db:
        row = (await db.execute(select(DecisionLog).where(
            DecisionLog.decision_type == 'report_artifact',
            DecisionLog.metadata_['filename'].as_string() == filename))).scalar_one_or_none()
        return {'session_id': row.session_id, **row.metadata_} if row else None
