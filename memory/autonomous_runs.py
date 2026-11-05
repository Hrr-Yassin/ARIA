"""Required persistence for run state; storage failure prevents further dispatch."""
from datetime import datetime
from sqlalchemy import select
from memory.database_models import AutonomousRun, async_session
from security.redaction import redact

TERMINAL = {"completed", "blocked", "failed"}


class RunStore:
    async def save(self, snapshot):
        async with async_session() as db:
            row = await db.get(AutonomousRun, snapshot["run_id"])
            if row is None:
                row = AutonomousRun(id=snapshot["run_id"], session_id=snapshot["session_id"])
                db.add(row)
            row.state = snapshot["run_state"]
            transitions = list((row.snapshot or {}).get("transitions", []))
            if not transitions or transitions[-1]["state"] != snapshot["run_state"]:
                transitions.append({"state": snapshot["run_state"], "reason_code": snapshot.get("reason_code", ""),
                    "timestamp": datetime.utcnow().isoformat()})
            row.snapshot = redact({**snapshot, "transitions": transitions})
            row.updated_at = datetime.utcnow()
            await db.commit()

    async def latest(self, session_id):
        async with async_session() as db:
            row = (await db.execute(select(AutonomousRun).where(
                AutonomousRun.session_id == session_id).order_by(
                AutonomousRun.updated_at.desc(), AutonomousRun.id.desc()).limit(1))).scalar_one_or_none()
            return row.snapshot if row else {"active": False}

    async def recover(self):
        async with async_session() as db:
            rows = (await db.execute(select(AutonomousRun).where(
                AutonomousRun.state.notin_(TERMINAL)).with_for_update())).scalars().all()
            for row in rows:
                row.state = "blocked"
                row.snapshot = {**row.snapshot, "active": False, "run_state": "blocked",
                    "reason_code": "restart_reconciliation", "waiting_approval": False,
                    "pending_action_id": None,
                    "reason": "Server restarted. Inspect durable worker jobs before starting another run; no command was replayed."}
                row.updated_at = datetime.utcnow()
            await db.commit()


run_store = RunStore()
