"""
PentestAI v9 — Command Hash Registry
Solution 1: Programmatic deduplication of executed commands per session.
SHA-256 based — independent of LLM, 100% reliable.
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, Optional
import structlog

log = structlog.get_logger("command_registry")


@dataclass
class CommandEntry:
    command: str
    cmd_hash: str
    result_summary: str
    stdout: str
    status: str          # "success" | "failed" | "running" | "killed"
    executed_at: float = field(default_factory=time.time)
    execution_time_ms: int = 0
    agent: str = ""
    phase: str = ""


class CommandRegistry:
    """
    Tracks every command executed per session by SHA-256 hash.
    Prevents re-execution of identical commands (Solution 1).
    Also serves as data source for Command History Viewer (Solution 6).
    """

    def __init__(self):
        # session_id -> {hash -> CommandEntry}
        self._registry: Dict[str, Dict[str, CommandEntry]] = {}

    def _hash(self, command: str) -> str:
        return hashlib.sha256(command.strip().encode()).hexdigest()[:16]

    def _ensure_session(self, session_id: str):
        if session_id not in self._registry:
            self._registry[session_id] = {}

    def is_duplicate(self, session_id: str, command: str) -> bool:
        self._ensure_session(session_id)
        h = self._hash(command)
        return h in self._registry[session_id]

    def get_previous_result(self, session_id: str, command: str) -> Optional[CommandEntry]:
        self._ensure_session(session_id)
        h = self._hash(command)
        return self._registry[session_id].get(h)

    def register(self, session_id: str, command: str, stdout: str,
                 status: str = "success", execution_time_ms: int = 0,
                 agent: str = "", phase: str = "") -> CommandEntry:
        self._ensure_session(session_id)
        h = self._hash(command)
        lines = [l for l in stdout.strip().splitlines() if l.strip()]
        summary = lines[0][:120] if lines else ""
        entry = CommandEntry(
            command=command, cmd_hash=h,
            result_summary=summary, stdout=stdout,
            status=status, execution_time_ms=execution_time_ms,
            agent=agent, phase=phase,
        )
        self._registry[session_id][h] = entry
        log.info("Command registered", session=session_id, hash=h,
                 status=status, cmd=command[:60])
        return entry

    def get_history(self, session_id: str,
                    filter_status: str = None,
                    filter_agent: str = None) -> list:
        self._ensure_session(session_id)
        entries = list(self._registry[session_id].values())
        entries.sort(key=lambda e: e.executed_at)
        if filter_status:
            entries = [e for e in entries if e.status == filter_status]
        if filter_agent:
            entries = [e for e in entries if e.agent == filter_agent]
        return entries

    def get_failed(self, session_id: str) -> list:
        return self.get_history(session_id, filter_status="failed")

    def mark_killed(self, session_id: str, command: str):
        self._ensure_session(session_id)
        h = self._hash(command)
        if h in self._registry[session_id]:
            self._registry[session_id][h].status = "killed"

    def clear_session(self, session_id: str):
        self._registry.pop(session_id, None)

    def summary(self, session_id: str) -> dict:
        self._ensure_session(session_id)
        entries = list(self._registry[session_id].values())
        return {
            "total": len(entries),
            "success": sum(1 for e in entries if e.status == "success"),
            "failed": sum(1 for e in entries if e.status == "failed"),
            "running": sum(1 for e in entries if e.status == "running"),
        }


command_registry = CommandRegistry()
