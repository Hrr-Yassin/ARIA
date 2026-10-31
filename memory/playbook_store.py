"""
PentestAI v10 — Playbook Store
==============================

Persists successful attack paths to PostgreSQL and surfaces them as SUGGESTIONS
to the AttackPlannerAgent. Crucially, the playbook store does NOT auto-execute
anything — it just provides the LLM with "here's what worked last time on a
similar service so you can propose it to the human."

Academic-brief mapping: aligns with "produire un rapport de pentest structuré
et professionnel" — past successful paths become reference material. The
human pentester always validates before any exploit step is taken.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

import structlog
from sqlalchemy import select, update

log = structlog.get_logger("playbook_store")


@dataclass
class PlaybookModel:
    id: str
    service: str
    version_pattern: str
    goal_type: str
    steps: List[dict]
    success_rate: float
    avg_time_seconds: int
    last_used: str
    tags: List[str] = field(default_factory=list)
    success_count: int = 0
    failure_count: int = 0


class PlaybookStore:
    """
    DB-backed playbook persistence with in-memory cache.

    Usage:
        store = PlaybookStore()
        pb = await store.get_best_playbook("vsftpd", "2.3.4", "initial_access")
        await store.save_successful_path(session_id, user_id, ...)
    """

    def __init__(self):
        self._cache: dict[str, PlaybookModel] = {}
        self._cache_loaded = False

    # ────────────────────────────────────────────────────────────────────
    #  Public API
    # ────────────────────────────────────────────────────────────────────

    async def save_successful_path(self, session_id: str, user_id: str,
                                    service: str, version: str,
                                    goal_type: str, steps: List[dict],
                                    time_to_success: int,
                                    tags: Optional[List[str]] = None) -> Optional[PlaybookModel]:
        """
        Persist a confirmed successful exploit chain.

        `steps` must be a list of dicts like:
           [{"order": 1, "tool": "nmap", "command": "...", "purpose": "..."}]
        """
        from memory.database_models import async_session, Playbook  # noqa: PLC0415

        pb_id = str(uuid.uuid4())
        version_pattern = self._make_version_pattern(version)
        tags_list = tags or self._auto_tags(service, steps)

        payload = {
            "service": service,
            "version_pattern": version_pattern,
            "goal_type": goal_type,
            "steps": steps,
            "success_rate": 1.0,
            "avg_time_seconds": time_to_success,
            "tags": tags_list,
            "success_count": 1,
            "failure_count": 0,
        }
        try:
            async with async_session() as db:
                row = Playbook(
                    id=pb_id,
                    user_id=user_id,
                    session_id=session_id,
                    name=f"{service} {version} → {goal_type}",
                    target_profile=service,
                    phases=payload,
                    created_at=datetime.utcnow(),
                )
                db.add(row)
                await db.commit()
        except Exception as exc:  # noqa: BLE001
            log.warning("Playbook save failed", error=str(exc))
            return None

        model = PlaybookModel(
            id=pb_id, service=service, version_pattern=version_pattern,
            goal_type=goal_type, steps=steps,
            success_rate=1.0, avg_time_seconds=time_to_success,
            last_used=datetime.utcnow().isoformat(), tags=tags_list,
            success_count=1,
        )
        self._cache[pb_id] = model
        log.info("Playbook saved",
                 pb_id=pb_id, service=service, steps=len(steps),
                 time_seconds=time_to_success)
        return model

    async def get_best_playbook(self, service: str, version: str = "",
                                 goal_type: str = "") -> Optional[PlaybookModel]:
        """Return the highest-success-rate playbook matching this target."""
        await self._load_cache()
        candidates = []
        needle = f"{service} {version}".lower().strip()

        for pb in self._cache.values():
            if goal_type and pb.goal_type != goal_type:
                continue
            if pb.service.lower() not in needle:
                continue
            score = pb.success_rate
            # Version pattern bonus
            if pb.version_pattern:
                try:
                    import re as _re
                    if _re.search(pb.version_pattern, needle, _re.I):
                        score += 0.2
                except Exception:  # noqa: BLE001
                    pass
            # Need reasonable reliability
            if pb.success_count == 0:
                continue
            total = pb.success_count + pb.failure_count
            if total >= 3 and pb.success_rate < 0.5:
                continue
            candidates.append((score, pb))

        if not candidates:
            return None
        candidates.sort(key=lambda c: -c[0])
        best = candidates[0][1]
        if candidates[0][0] < 0.7:
            # Not confident enough — still return but caller can check success_rate
            pass
        return best

    async def get_similar_playbooks(self, services_list: List[str],
                                     limit: int = 5) -> List[PlaybookModel]:
        """Return playbooks that match ANY of the provided services."""
        await self._load_cache()
        needles = [s.lower() for s in services_list if s]
        matches = []
        for pb in self._cache.values():
            if any(pb.service.lower() in n or n in pb.service.lower() for n in needles):
                matches.append(pb)
        matches.sort(key=lambda p: -p.success_rate)
        return matches[:limit]

    async def increment_success(self, playbook_id: str):
        await self._increment(playbook_id, success=True)

    async def increment_failure(self, playbook_id: str):
        await self._increment(playbook_id, success=False)

    async def list_all(self, user_id: Optional[str] = None,
                        limit: int = 50) -> List[PlaybookModel]:
        """Return all playbooks (for the Intel-panel Playbooks tab)."""
        await self._load_cache()
        items = list(self._cache.values())
        items.sort(key=lambda p: p.last_used, reverse=True)
        return items[:limit]

    # ────────────────────────────────────────────────────────────────────
    #  Prompt rendering
    # ────────────────────────────────────────────────────────────────────

    def render_for_prompt(self, pb: PlaybookModel) -> str:
        """Render a playbook as a PROVEN PLAYBOOK block for the planner prompt."""
        if not pb:
            return ""
        lines = [
            "PROVEN PLAYBOOK FOR THIS TARGET (suggestion only — human must approve):",
            f"  Service: {pb.service}  |  Goal: {pb.goal_type}  |  "
            f"Success rate: {pb.success_rate:.0%}  "
            f"(wins: {pb.success_count}, losses: {pb.failure_count})",
        ]
        for i, step in enumerate(pb.steps[:8], 1):
            cmd = step.get("command", step.get("action", ""))[:140]
            purpose = step.get("purpose", "")[:80]
            lines.append(f"    {i}. {cmd}" + (f"   # {purpose}" if purpose else ""))
        lines.append("  ^ Treat as informed baseline, not binding plan. Adapt to current evidence.")
        return "\n".join(lines)

    # ────────────────────────────────────────────────────────────────────
    #  Private
    # ────────────────────────────────────────────────────────────────────

    async def _load_cache(self, force: bool = False):
        if self._cache_loaded and not force:
            return
        try:
            from memory.database_models import async_session, Playbook  # noqa: PLC0415
            async with async_session() as db:
                stmt = select(Playbook).limit(1000)
                rows = (await db.execute(stmt)).scalars().all()
                for row in rows:
                    phases = row.phases if isinstance(row.phases, dict) else {}
                    self._cache[row.id] = PlaybookModel(
                        id=row.id,
                        service=phases.get("service", row.target_profile or ""),
                        version_pattern=phases.get("version_pattern", ""),
                        goal_type=phases.get("goal_type", ""),
                        steps=phases.get("steps", []),
                        success_rate=float(phases.get("success_rate", 0.0)),
                        avg_time_seconds=int(phases.get("avg_time_seconds", 0)),
                        last_used=row.created_at.isoformat() if row.created_at else "",
                        tags=phases.get("tags", []),
                        success_count=int(phases.get("success_count", 0)),
                        failure_count=int(phases.get("failure_count", 0)),
                    )
                self._cache_loaded = True
                log.info("Playbook cache loaded", count=len(self._cache))
        except Exception as exc:  # noqa: BLE001
            log.debug("Playbook cache load failed (ok if DB empty)", error=str(exc))
            self._cache_loaded = True

    async def _increment(self, playbook_id: str, success: bool):
        pb = self._cache.get(playbook_id)
        if not pb:
            return
        if success:
            pb.success_count += 1
        else:
            pb.failure_count += 1
        total = pb.success_count + pb.failure_count
        pb.success_rate = pb.success_count / total if total else 0.0
        pb.last_used = datetime.utcnow().isoformat()
        # Persist
        try:
            from memory.database_models import async_session, Playbook  # noqa: PLC0415
            async with async_session() as db:
                stmt = select(Playbook).where(Playbook.id == playbook_id)
                row = (await db.execute(stmt)).scalar_one_or_none()
                if row is not None:
                    phases = dict(row.phases) if isinstance(row.phases, dict) else {}
                    phases.update({
                        "success_count": pb.success_count,
                        "failure_count": pb.failure_count,
                        "success_rate": pb.success_rate,
                    })
                    row.phases = phases
                    await db.commit()
        except Exception as exc:  # noqa: BLE001
            log.debug("Playbook increment persist failed", error=str(exc))

    @staticmethod
    def _make_version_pattern(version: str) -> str:
        """Turn '2.3.4' into regex '2\\.3\\.[0-9]+' to match minor-version drift."""
        if not version:
            return ""
        parts = version.strip().split(".")
        if len(parts) < 2:
            return re.escape(version)
        # Keep major.minor, wildcard patch
        import re
        base = re.escape(".".join(parts[:2]))
        return f"{base}(\\.\\d+)?"

    @staticmethod
    def _auto_tags(service: str, steps: list) -> List[str]:
        tags = [service.split()[0].lower()] if service else []
        commands = " ".join(s.get("command", "") for s in steps).lower()
        if "msfconsole" in commands:
            tags.append("metasploit")
        if "hydra" in commands:
            tags.append("brute-force")
        if "nikto" in commands or "nuclei" in commands:
            tags.append("web")
        if "smb" in commands or "samba" in commands:
            tags.append("smb")
        return list(dict.fromkeys(tags))  # dedupe preserve order


# Singleton
playbook_store = PlaybookStore()
