"""
PentestAI v9 — Command Lifecycle Manager
Solution 3: Kill mechanism + async timeout guard for all Kali Agent calls.
Prevents infinite background execution.
"""
import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional
import structlog
import httpx

from config.settings import settings
from memory.command_registry import command_registry
from memory.execution_authorization import execution_authorization
from memory.worker_jobs import worker_jobs

log = structlog.get_logger("lifecycle")

COMMAND_TIMEOUT = 300       # 5 min default
LLM_TIMEOUT     = 60        # 1 min for LLM calls
MAX_CONCURRENT  = 5         # per session


@dataclass
class RunningTask:
    task_id: str
    session_id: str
    command: str
    started_at: float = field(default_factory=time.time)
    task: Optional[asyncio.Task] = field(default=None, repr=False)


class CommandLifecycleManager:
    """
    Wraps every Kali Agent call with:
    - asyncio.wait_for timeout (Solution 3a)
    - per-session kill endpoint (Solution 3b)
    - duplicate check via CommandRegistry (Solution 1)
    """

    def __init__(self):
        self._running: Dict[str, Dict[str, RunningTask]] = {}   # session -> task_id -> task

    def _ensure(self, session_id: str):
        if session_id not in self._running:
            self._running[session_id] = {}

    # ── Execute ──────────────────────────────────────────────────────────

    async def execute(self, session_id: str, command: str,
                      target: str = "", agent: str = "",
                      phase: str = "", timeout: int = COMMAND_TIMEOUT,
                      force: bool = False, user_id: str = "", action_id: str = "") -> dict:
        """
        Execute a command on the Kali Agent with full lifecycle control.
        Returns {stdout, stderr, exit_code, execution_time_ms, status, cached}
        """
        self._ensure(session_id)

        # Concurrent limit
        if len(self._running[session_id]) >= MAX_CONCURRENT:
            return {"stdout": "", "stderr": "Max concurrent commands reached",
                    "exit_code": -1, "status": "rejected", "cached": False}

        task_id = str(uuid.uuid4())[:8]
        t0 = time.time()

        # Register as running
        command_registry.register(
            session_id, command, stdout="",
            status="running", agent=agent, phase=phase
        )

        async def _call():
            return await execution_authorization.execute(
                user_id, session_id, command, action_id=action_id,
                timeout=min(timeout, settings.AUTONOMOUS_STEP_TIMEOUT_SECONDS),
            )

        task = asyncio.create_task(_call())
        rt = RunningTask(task_id=task_id, session_id=session_id,
                         command=command, task=task)
        self._running[session_id][task_id] = rt

        try:
            result = await asyncio.wait_for(task, timeout=timeout)
            elapsed = int((time.time() - t0) * 1000)
            stdout  = result.get("stdout", "")
            status  = "success" if result.get("exit_code", 0) == 0 else "failed"

            command_registry.register(
                session_id, command, stdout=stdout,
                status=status, execution_time_ms=elapsed,
                agent=agent, phase=phase,
            )
            return {**result, "execution_time_ms": elapsed,
                    "status": status, "cached": False}

        except asyncio.TimeoutError:
            task.cancel()
            elapsed = int((time.time() - t0) * 1000)
            command_registry.register(
                session_id, command, stdout="[TIMEOUT]",
                status="failed", execution_time_ms=elapsed,
                agent=agent, phase=phase,
            )
            log.warning("Command timed out", session=session_id,
                        cmd=command[:60], timeout=timeout)
            return {"stdout": "", "stderr": f"Command timed out after {timeout}s",
                    "exit_code": -1, "execution_time_ms": elapsed,
                    "status": "timeout", "cached": False}

        except asyncio.CancelledError:
            elapsed = int((time.time() - t0) * 1000)
            cancellation = await worker_jobs.cancel_session(user_id, session_id)
            if cancellation["cancelled"] and not cancellation["pending"]:
                command_registry.mark_killed(session_id, command)
            return {"stdout": "", "stderr": "Request interrupted; inspect durable worker status",
                    "exit_code": -1, "execution_time_ms": elapsed,
                    "status": "cancellation_pending" if cancellation["pending"] else "cancelled" if cancellation["cancelled"] else "interrupted", "cached": False}

        except Exception as e:
            elapsed = int((time.time() - t0) * 1000)
            command_registry.register(
                session_id, command, stdout="",
                status="failed", execution_time_ms=elapsed,
                agent=agent, phase=phase,
            )
            log.error("Command failed", session=session_id, error=str(e))
            return {"stdout": "", "stderr": str(e),
                    "exit_code": -1, "execution_time_ms": elapsed,
                    "status": "failed", "cached": False}

        finally:
            self._running[session_id].pop(task_id, None)

    # ── Kill ─────────────────────────────────────────────────────────────

    async def kill_all(self, session_id: str, user_id: str = "") -> dict:
        result = await worker_jobs.cancel_session(user_id, session_id)
        if not result['pending']:
            tasks = [rt.task for rt in self._running.get(session_id, {}).values() if rt.task and not rt.task.done()]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return result

    async def kill_one(self, session_id: str, task_id: str, user_id: str = "") -> dict:
        # Cancellation scope is the engagement, not an untrusted local task ID.
        if task_id not in self._running.get(session_id, {}):
            return {"cancelled": 0, "pending": 0, "jobs": []}
        return await self.kill_all(session_id, user_id=user_id)

    def get_running(self, session_id: str) -> list:
        self._ensure(session_id)
        now = time.time()
        return [
            {"task_id": rt.task_id, "command": rt.command,
             "elapsed_s": round(now - rt.started_at)}
            for rt in self._running[session_id].values()
            if not rt.task.done()
        ]

    # ── LLM wrapper ──────────────────────────────────────────────────────

    async def call_llm(self, coro, timeout: int = LLM_TIMEOUT):
        """Wrap any LLM coroutine with timeout guard."""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            log.warning("LLM call timed out", timeout=timeout)
            return None


lifecycle = CommandLifecycleManager()
