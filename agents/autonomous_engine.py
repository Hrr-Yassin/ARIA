"""
PentestAI v10 — Autonomous Execution Engine
===========================================

The central new component of v10. Implements the full cycle:

    plan → auto_execute(green/orange) → structured_parse → kb_update → re_plan → …

CRITICAL ACADEMIC-BRIEF ALIGNMENT:
    The project brief states: "L'exploitation assistée par l'IA mais validée
    par l'humain" and "Toute action critique doit être explicitement validée
    par l'humain".

    This engine HARD-BLOCKS on any risk_color == "red" step. The loop emits a
    [WAITING_APPROVAL] event and awaits a human decision via
    `provide_approval_decision()`. Nothing bypasses this gate.

    The AUTO_RISK_THRESHOLD setting further restricts auto-execution:
        - "green_only"   → only green auto-runs
        - "green_orange" → green + orange auto-run (default; brief-aligned)

Every autonomous step writes a DecisionLog row for complete traceability —
the jury can replay exactly which decisions were AI-made vs human-validated.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncGenerator, Dict, List, Optional, Any

import httpx
import structlog

from config.settings import settings
from config.tools_registry import TOOL_AGENT_MAP
from memory.attack_knowledge_base import attack_kb
from memory.parsers import dispatch_parser

log = structlog.get_logger("autonomous_engine")


# ─────────────────────────────────────────────────────────────────────────────
#  Data shapes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ApprovalRequest:
    """A pending red-risk step waiting for human decision."""
    action_id: str
    session_id: str
    step_number: int
    command: str
    tool: str
    risk_color: str
    purpose: str
    created_at: float = field(default_factory=time.time)
    decision: Optional[str] = None      # None | "approve" | "reject" | "modify"
    modified_command: str = ""


@dataclass
class AutoActivityEvent:
    """Event streamed over WebSocket for each autonomous step."""
    type: str = "auto_activity"
    step: int = 0
    action: str = ""
    tool: str = ""
    risk_color: str = "green"
    status: str = "running"             # running | done | failed | waiting_approval
    output_preview: str = ""
    kb_updates: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "step": self.step,
            "action": self.action,
            "tool": self.tool,
            "risk_color": self.risk_color,
            "status": self.status,
            "output_preview": self.output_preview,
            "kb_updates": self.kb_updates,
            "timestamp": self.timestamp,
            **self.extra,
        }


@dataclass
class SessionRunState:
    """Per-session autonomous run state."""
    session_id: str
    user_id: str
    goal: str
    target: str
    skill_level: str
    started_at: float = field(default_factory=time.time)
    steps_taken: int = 0
    active: bool = True
    current_phase: str = "recon"
    pending_approval: Optional[ApprovalRequest] = None
    stop_requested: bool = False
    event_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    activity_log: List[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
#  AutonomousEngine
# ─────────────────────────────────────────────────────────────────────────────
class AutonomousEngine:
    """
    Drives the autonomous cycle for a single session.

    Usage:
        engine = AutonomousEngine()
        # Start
        asyncio.create_task(engine.autonomous_cycle(session_id, user_id, ...))
        # Stream activity
        async for event in engine.stream_events(session_id):
            await websocket.send_json(event)
        # Stop
        engine.request_stop(session_id)
    """

    MAX_STEPS = settings.AUTONOMOUS_MAX_STEPS
    STEP_TIMEOUT = settings.AUTONOMOUS_STEP_TIMEOUT_SECONDS
    STEP_DELAY = settings.AUTONOMOUS_STEP_DELAY_SECONDS

    def __init__(self):
        self._runs: Dict[str, SessionRunState] = {}
        # Queue of pending approvals per session
        self._approvals: Dict[str, Dict[str, ApprovalRequest]] = {}

    # ────────────────────────────────────────────────────────────────────
    #  Public API — lifecycle
    # ────────────────────────────────────────────────────────────────────

    async def start(self, session_id: str, user_id: str,
                    goal: str = "initial_access",
                    target: str = "",
                    skill_level: str = "intermediate") -> dict:
        """Create a run state and kick off the loop in a background task."""
        if session_id in self._runs and self._runs[session_id].active:
            return {"status": "already_running",
                    "steps_taken": self._runs[session_id].steps_taken}

        state = SessionRunState(
            session_id=session_id, user_id=user_id,
            goal=goal, target=target, skill_level=skill_level,
        )
        self._runs[session_id] = state
        self._approvals[session_id] = {}

        # Subscribe to KB replan events for adaptive behaviour
        attack_kb.register_replan_callback(session_id, self._on_replan_event)

        # Write audit record
        await self._write_decision_log(
            state, decision_type="autonomous_start",
            reasoning=f"Autonomous cycle started toward goal: {goal}",
            action_taken="engine.start()", risk_color="info",
        )

        # Kick off the loop
        asyncio.create_task(self._run_loop(state))

        log.info("autonomous cycle started",
                 session=session_id, goal=goal, target=target)
        return {
            "status": "started", "session_id": session_id,
            "goal": goal, "target": target, "max_steps": self.MAX_STEPS,
        }

    def request_stop(self, session_id: str) -> dict:
        """Request graceful stop — finishes any in-flight step then exits."""
        state = self._runs.get(session_id)
        if not state:
            return {"status": "not_running"}
        state.stop_requested = True
        state.active = False
        attack_kb.unregister_replan_callback(session_id)
        log.info("autonomous stop requested", session=session_id)
        return {"status": "stopping", "steps_taken": state.steps_taken}

    def get_status(self, session_id: str) -> dict:
        state = self._runs.get(session_id)
        if not state:
            return {"active": False}
        return {
            "active": state.active,
            "steps_taken": state.steps_taken,
            "max_steps": self.MAX_STEPS,
            "current_phase": state.current_phase,
            "goal": state.goal,
            "target": state.target,
            "started_at": state.started_at,
            "elapsed_seconds": int(time.time() - state.started_at),
            "waiting_approval": state.pending_approval is not None,
            "pending_action_id": state.pending_approval.action_id
                                  if state.pending_approval else None,
            "stop_requested": state.stop_requested,
            "activity_tail": state.activity_log[-10:],
        }

    # ────────────────────────────────────────────────────────────────────
    #  Public API — WebSocket streaming
    # ────────────────────────────────────────────────────────────────────

    async def stream_events(self, session_id: str) -> AsyncGenerator[dict, None]:
        """
        Async generator of events to stream over WebSocket. Emits a snapshot
        of recent activity, then streams live events until the run ends.
        """
        state = self._runs.get(session_id)
        if not state:
            yield {"type": "error", "message": "autonomous run not found"}
            return

        # Replay the tail so late subscribers have context
        for ev in state.activity_log[-10:]:
            yield ev

        # Live stream
        while state.active or not state.event_queue.empty():
            try:
                event = await asyncio.wait_for(state.event_queue.get(), timeout=1.0)
                yield event
            except asyncio.TimeoutError:
                continue

    # ────────────────────────────────────────────────────────────────────
    #  Public API — human approval handling
    # ────────────────────────────────────────────────────────────────────

    def get_pending_approvals(self, session_id: str) -> List[dict]:
        """List pending red-risk approvals for a session."""
        queue = self._approvals.get(session_id, {})
        return [
            {"action_id": a.action_id, "command": a.command,
             "tool": a.tool, "risk_color": a.risk_color,
             "purpose": a.purpose, "step_number": a.step_number,
             "created_at": a.created_at,
             "waiting_seconds": int(time.time() - a.created_at)}
            for a in queue.values() if a.decision is None
        ]

    async def provide_approval_decision(self, session_id: str, action_id: str,
                                         decision: str,
                                         modified_command: str = "") -> dict:
        """
        Called by the API when the human responds to an approval request.

        `decision`: one of "approve" | "reject" | "modify"
        """
        if decision not in ("approve", "reject", "modify"):
            return {"status": "error", "message": "invalid decision"}

        queue = self._approvals.get(session_id, {})
        req = queue.get(action_id)
        if not req:
            return {"status": "error", "message": "approval request not found"}
        if req.decision is not None:
            return {"status": "error", "message": "already decided"}

        req.decision = decision
        if decision == "modify":
            req.modified_command = modified_command

        # Write decision-log entry for traceability
        state = self._runs.get(session_id)
        if state:
            await self._write_decision_log(
                state, decision_type="approval_decision",
                reasoning=f"Human decided: {decision}",
                action_taken=req.command if decision != "modify" else modified_command,
                risk_color=req.risk_color,
                human_involved=True, human_decision=decision,
            )

        log.info("approval decided", session=session_id,
                 action=action_id, decision=decision)
        return {"status": "recorded", "decision": decision}

    # ────────────────────────────────────────────────────────────────────
    #  Main loop
    # ────────────────────────────────────────────────────────────────────

    async def _run_loop(self, state: SessionRunState):
        """The actual autonomous loop. Runs as a background task."""
        try:
            while state.active and state.steps_taken < self.MAX_STEPS:
                if state.stop_requested:
                    break

                # 1) Check if goal achieved
                achieved, reason = await self._check_goal_achieved(state)
                if achieved:
                    await self._emit(state, AutoActivityEvent(
                        type="goal_achieved", step=state.steps_taken,
                        action=reason, status="done",
                    ))
                    attack_kb.mark_goal_achieved(state.session_id, state.goal, reason)
                    break

                # 2) Ask the orchestrator/planner for the next step
                next_step = await self._plan_next_step(state)
                if not next_step:
                    await self._emit(state, AutoActivityEvent(
                        type="auto_complete", step=state.steps_taken,
                        action="No further actions proposed — ending cycle",
                        status="done",
                    ))
                    break

                state.steps_taken += 1
                state.current_phase = next_step.get("phase", state.current_phase)

                risk = (next_step.get("risk_color") or "orange").lower()
                command = next_step.get("command", "")
                tool = next_step.get("tool", "").lower()
                purpose = next_step.get("purpose", "")
                action_id = next_step.get("action_id") or str(uuid.uuid4())

                # 3) Risk gate — decide auto vs approval
                threshold = settings.AUTO_RISK_THRESHOLD
                auto_ok = (
                    (threshold == "green_only" and risk == "green")
                    or (threshold == "green_orange" and risk in ("green", "orange"))
                )

                if not auto_ok:
                    # HARD STOP — requires human approval (academic brief req't)
                    req = ApprovalRequest(
                        action_id=action_id,
                        session_id=state.session_id,
                        step_number=state.steps_taken,
                        command=command, tool=tool,
                        risk_color=risk, purpose=purpose,
                    )
                    self._approvals[state.session_id][action_id] = req
                    state.pending_approval = req

                    await self._emit(state, AutoActivityEvent(
                        type="waiting_approval",
                        step=state.steps_taken,
                        action=f"Step {state.steps_taken}: {command}",
                        tool=tool, risk_color=risk,
                        status="waiting_approval",
                        extra={"action_id": action_id,
                               "purpose": purpose,
                               "reason": ("Risk level requires explicit "
                                          "human validation per project scope.")},
                    ))
                    await self._write_decision_log(
                        state, decision_type="await_approval",
                        reasoning=f"Step {state.steps_taken} at {risk} risk requires approval",
                        action_taken=f"blocked: {command}",
                        risk_color=risk,
                        human_involved=True, human_decision="pending",
                    )

                    # Wait for decision (or stop)
                    decision = await self._wait_for_approval(state, req)
                    state.pending_approval = None

                    if decision == "reject" or state.stop_requested:
                        await self._emit(state, AutoActivityEvent(
                            type="auto_activity",
                            step=state.steps_taken,
                            action=f"Step {state.steps_taken} REJECTED by human",
                            tool=tool, risk_color=risk, status="failed",
                        ))
                        # Feed the rejection back into planning context
                        attack_kb.log_event(
                            state.session_id, "human_rejected_step",
                            "autonomous_engine",
                            f"Human rejected: {command[:120]}",
                        )
                        await asyncio.sleep(self.STEP_DELAY)
                        continue
                    if decision == "modify":
                        command = req.modified_command or command
                    # decision == "approve" → fall through to execute

                # 4) Execute the step
                await self._emit(state, AutoActivityEvent(
                    step=state.steps_taken,
                    action=f"Running {command[:140]}",
                    tool=tool, risk_color=risk, status="running",
                    extra={"purpose": purpose, "action_id": action_id},
                ))

                stdout, stderr, success = await self._execute_command(
                    state, tool, command,
                )

                # 5) Parse output deterministically → KB
                parse_result = dispatch_parser(
                    state.session_id, tool, command,
                    stdout or stderr, state.target,
                )

                output_preview = (stdout or stderr or "")[:300].replace("\n", " ")
                await self._emit(state, AutoActivityEvent(
                    step=state.steps_taken,
                    action=f"{'✓' if success else '✗'} {tool} "
                           f"{'done' if success else 'failed'}",
                    tool=tool, risk_color=risk,
                    status="done" if success else "failed",
                    output_preview=output_preview,
                    kb_updates=parse_result.events[:10],
                    extra={"action_id": action_id,
                           "ports_added": len(parse_result.ports_added),
                           "vulns_added": len(parse_result.vulns_added),
                           "creds_added": len(parse_result.creds_added),
                           "shells_added": len(parse_result.shells_added)},
                ))

                # 6) Decision log
                await self._write_decision_log(
                    state,
                    decision_type="auto_execute" if auto_ok else "approved_execute",
                    reasoning=purpose or f"Autonomous step {state.steps_taken}",
                    action_taken=command,
                    risk_color=risk,
                    observation=output_preview,
                    human_involved=not auto_ok,
                    human_decision="approve" if not auto_ok else "none",
                )

                # Rate-limit between steps
                await asyncio.sleep(self.STEP_DELAY)

            # Loop ended
            if state.steps_taken >= self.MAX_STEPS:
                await self._emit(state, AutoActivityEvent(
                    type="auto_complete",
                    step=state.steps_taken,
                    action=f"Max steps ({self.MAX_STEPS}) reached — pausing",
                    status="done",
                ))
        except Exception as exc:  # noqa: BLE001
            log.exception("autonomous loop crashed",
                          session=state.session_id, error=str(exc))
            await self._emit(state, AutoActivityEvent(
                type="auto_error", step=state.steps_taken,
                action=f"Loop error: {str(exc)[:200]}", status="failed",
            ))
        finally:
            state.active = False
            attack_kb.unregister_replan_callback(state.session_id)
            await self._write_decision_log(
                state, decision_type="autonomous_stop",
                reasoning=f"Cycle ended after {state.steps_taken} steps",
                action_taken="engine._run_loop exit",
                risk_color="info",
            )
            log.info("autonomous cycle ended",
                     session=state.session_id, steps=state.steps_taken)

    # ────────────────────────────────────────────────────────────────────
    #  Planning / goal checking
    # ────────────────────────────────────────────────────────────────────

    async def _plan_next_step(self, state: SessionRunState) -> Optional[dict]:
        """
        Ask the orchestrator agent for the next single best action.
        Imports are deferred to avoid import cycles.
        """
        from agents.orchestrator_agent import orchestrator_agent  # noqa: PLC0415

        open_ports = []
        host = attack_kb.get_host(state.session_id, state.target)
        if host:
            open_ports = [
                {"port": p, "service": d.get("service", ""),
                 "version": d.get("version", "")}
                for p, d in host.ports.items() if d.get("state") == "open"
            ]

        recent_events = attack_kb.get_timeline(state.session_id, limit=10)
        history_str = [
            {"role": "system", "content": f"[{e['event']}] {e['detail']}"}
            for e in recent_events
        ]

        try:
            resp = await orchestrator_agent.process(
                session_id=state.session_id, user_id=state.user_id,
                input_data={
                    "user_input": (f"[AUTO-MODE step {state.steps_taken+1}] "
                                   f"Goal: {state.goal}. Propose next single best "
                                   f"action. Tag it with risk_color so the loop "
                                   f"knows if human approval is needed."),
                    "target": state.target,
                    "chat_history": history_str,
                    "tools_run": [e["event"] for e in recent_events
                                  if "_parsed" in e["event"]],
                    "open_ports": open_ports,
                },
                skill_level=state.skill_level,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("planner failed in auto-loop",
                        session=state.session_id, error=str(exc))
            return None

        commands = resp.get("commands") or []
        if not commands:
            return None
        return commands[0]

    async def _check_goal_achieved(self, state: SessionRunState) -> tuple[bool, str]:
        """
        Check if the goal is achieved based on KB state. Returns (achieved, reason).
        """
        summary = attack_kb.get_full_summary(state.session_id)
        shells = summary.get("shells", [])
        creds = summary.get("credentials", [])

        goal = state.goal.lower()
        if goal == "initial_access":
            if shells:
                return True, f"Shell obtained on {shells[0].get('host', state.target)}"
        elif goal == "dump_creds":
            if creds:
                return True, f"Credential extracted: {creds[0].get('user', '?')}"
        elif goal == "privilege_escalation":
            rooted = any(s.get("privilege") in ("root", "SYSTEM", "admin")
                         for s in shells)
            if rooted:
                return True, "Privileged shell obtained"
        elif goal == "full_compromise":
            rooted = any(s.get("privilege") in ("root", "SYSTEM", "admin")
                         for s in shells)
            if rooted and creds:
                return True, "Full compromise: root shell + credentials"
        return False, ""

    async def _on_replan_event(self, event: dict):
        """
        Called by attack_kb when a trigger fires (critical_vuln_found, etc.).
        We just emit it so the frontend can show a plan-updated toast; the
        next iteration of the loop will naturally pick up the new KB state.
        """
        session_id = None
        for sid, state in self._runs.items():
            if state.active:
                # We assume at most one active run per session
                if event.get("host") == state.target:
                    session_id = sid
                    break
        if not session_id:
            return
        state = self._runs[session_id]
        await self._emit(state, {
            "type": "plan_updated",
            "trigger": event.get("trigger"),
            "host": event.get("host"),
            "detail": event.get("detail"),
            "urgency": event.get("urgency", "normal"),
            "timestamp": datetime.utcnow().isoformat(),
        })

    # ────────────────────────────────────────────────────────────────────
    #  Command execution (via Kali agent)
    # ────────────────────────────────────────────────────────────────────

    async def _execute_command(self, state: SessionRunState,
                                tool: str, command: str) -> tuple[str, str, bool]:
        """
        Execute a command via the Kali agent. Returns (stdout, stderr, success).
        Falls back to a clear error message if the Kali agent is unreachable.
        """
        url = f"{settings.KALI_AGENT_URL}/execute"
        headers = {"Authorization": f"Bearer {settings.KALI_AGENT_TOKEN}"}
        payload = {
            "command": command, "timeout": self.STEP_TIMEOUT,
            "session_id": state.session_id,
        }
        try:
            async with httpx.AsyncClient(timeout=self.STEP_TIMEOUT + 5) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return (
                        data.get("stdout", ""),
                        data.get("stderr", ""),
                        data.get("exit_code", 0) == 0,
                    )
                return "", f"Kali agent {resp.status_code}: {resp.text[:200]}", False
        except Exception as exc:  # noqa: BLE001
            log.warning("kali agent unreachable",
                        session=state.session_id, error=str(exc))
            return "", f"Kali agent unreachable: {exc}", False

    # ────────────────────────────────────────────────────────────────────
    #  Approval waiting
    # ────────────────────────────────────────────────────────────────────

    async def _wait_for_approval(self, state: SessionRunState,
                                  req: ApprovalRequest) -> str:
        """Block until human responds (or stop is requested)."""
        while req.decision is None and not state.stop_requested:
            await asyncio.sleep(0.5)
        return req.decision or "reject"

    # ────────────────────────────────────────────────────────────────────
    #  Event emission
    # ────────────────────────────────────────────────────────────────────

    async def _emit(self, state: SessionRunState,
                     event: "AutoActivityEvent | dict"):
        """Push an event into the stream queue + tail buffer."""
        ev_dict = event.to_dict() if isinstance(event, AutoActivityEvent) else event
        state.activity_log.append(ev_dict)
        # Keep tail bounded
        if len(state.activity_log) > 200:
            state.activity_log = state.activity_log[-200:]
        try:
            await state.event_queue.put(ev_dict)
        except Exception as exc:  # noqa: BLE001
            log.debug("emit failed", error=str(exc))

    # ────────────────────────────────────────────────────────────────────
    #  Decision-log persistence
    # ────────────────────────────────────────────────────────────────────

    async def _write_decision_log(self, state: SessionRunState, *,
                                    decision_type: str,
                                    reasoning: str = "",
                                    action_taken: str = "",
                                    risk_color: str = "",
                                    observation: str = "",
                                    human_involved: bool = False,
                                    human_decision: str = "none"):
        """Write a DecisionLog row (best-effort — DB failure is non-fatal)."""
        if not settings.DECISION_LOG_ENABLED:
            return
        try:
            from memory.database_models import (  # noqa: PLC0415
                async_session, DecisionLog,
            )
            async with async_session() as db:
                row = DecisionLog(
                    session_id=state.session_id,
                    user_id=state.user_id,
                    step_number=state.steps_taken,
                    decision_type=decision_type,
                    agent="autonomous_engine",
                    reasoning=reasoning[:2000],
                    action_taken=action_taken[:2000],
                    risk_color=risk_color,
                    human_involved=human_involved,
                    human_decision=human_decision,
                    observation=observation[:2000],
                    metadata_={"goal": state.goal, "target": state.target},
                )
                db.add(row)
                await db.commit()
        except Exception as exc:  # noqa: BLE001
            log.debug("decision_log write failed", error=str(exc))


# Singleton
autonomous_engine = AutonomousEngine()
