"""
PentestAI v9 — Coordinator (Brain) Agent
Decides which agent to invoke, prevents redundancy, avoids unnecessary steps.
Acts as intelligent dispatcher between all specialized agents.
"""
import re
from agents.base_agent import BaseAgent
from memory.attack_knowledge_base import attack_kb

SYSTEM = """You are the COORDINATOR for supervised evidence analysis.
Select one existing specialist and give a concise public reason. Routing grants no
execution authority. Preserve the original objective, scope and recorded evidence.
Available review roles: planner (prerequisites and bounded plan), recon (requested
observations), scan (authorized TCP observations), vuln (conditional applicability),
web_intel (saved HTTP/auth/session evidence), correlation (contradictions, alternatives
and independent controls), report (evidence-attributed reports).
The post role is blocked; exploitation and post-access execution are unavailable.
Reviewing saved HTTP or code evidence does not require a new port scan. Do not repeat
completed observations, escalate from a public page, or treat agent agreement as
confirmation. Missing evidence or unsupported requests must be explained.
Output JSON with selected_agent, reason, skip_if and next_after; no private reasoning."""


class CoordinatorAgent(BaseAgent):
    agent_name = "coordinator"
    agent_role = "Coordinator — Intelligent Agent Dispatcher"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return SYSTEM

    async def decide_next_agent(self, session_id: str, user_id: str,
                                 user_input: str, target: str,
                                 current_phase: str = "scope",
                                 tools_run: list = None,
                                 skill_level: str = "intermediate") -> dict:
        """
        Core decision: which agent handles this input?
        Returns: {agent, reason, priority_commands, skip_reason}
        """
        kb_ctx = attack_kb.get_agent_context_string(session_id)
        kb_summary = attack_kb.get_full_summary(session_id)
        mode = attack_kb.get_attack_mode(session_id)
        mode_settings = attack_kb.get_mode_settings(session_id)
        current_goal = attack_kb.get_current_goal(session_id)

        hosts = kb_summary.get("hosts", [])
        shells = kb_summary.get("shells", [])
        creds = kb_summary.get("credentials", [])
        tools_done = tools_run or []

        # Fast-path heuristic decisions (no LLM needed for clear cases)
        fast_decision = self._fast_decide(
            user_input, hosts, shells, creds, tools_done, mode, current_phase)
        if fast_decision:
            attack_kb.log_event(session_id, "coordinator_decision", "coordinator",
                                f"→ {fast_decision['agent']} (fast path: {fast_decision['reason']})")
            return fast_decision

        # LLM-based decision for ambiguous cases
        prompt = f"""USER REQUEST: "{user_input}"
TARGET: {target}
CURRENT PHASE: {current_phase}
ATTACK MODE: {mode.upper()} ({mode_settings.get('description','')})
CURRENT GOAL: {current_goal.goal_type if current_goal else 'none set'}

KNOWLEDGE BASE STATE:
{kb_ctx}

HOSTS DISCOVERED: {len(hosts)} | SHELLS ACTIVE: {len(shells)} | CREDS FOUND: {len(creds)}
TOOLS ALREADY RUN: {', '.join(tools_done) if tools_done else 'none'}

AVAILABLE REVIEW AGENTS: planner, recon, scan, vuln, web_intel, correlation, report

Decision rules:
- Don't re-run tools already done on same target unless new info exists
- Post-access and exploitation roles are unavailable; select prerequisite review, not execution
- If user explicitly asks for report → report
- If user sets a goal → planner
- If contradictions in findings → correlation
- Bug bounty mode: never send to post agent without explicit permission
- Attack mode cannot expand capabilities or the original objective

JSON:
{{
  "selected_agent": "agent_name",
  "reason": "why this agent",
  "skip_if": "condition when this decision should be overridden",
  "opsec_note": "OPSEC consideration for this step (empty if lab mode)",
  "next_after": "which agent logically follows this one"
}}"""

        result = await self.query_llm(user_id, prompt, self.get_system_prompt(skill_level))
        if result.get("success"):
            parsed = self.parse_json(result["content"])
            if parsed and parsed.get("selected_agent"):
                agent_name = parsed["selected_agent"]
                reason = parsed.get("reason", "")
                attack_kb.log_event(session_id, "coordinator_decision", "coordinator",
                                    f"→ {agent_name} (LLM: {reason[:80]})")
                return {
                    "agent": agent_name,
                    "reason": reason,
                    "opsec_note": parsed.get("opsec_note", ""),
                    "next_after": parsed.get("next_after", ""),
                    "skip_if": parsed.get("skip_if", ""),
                }

        # Ultimate fallback
        return self._fallback_decide(user_input, hosts, current_phase)

    def _fast_decide(self, user_input: str, hosts: list, shells: list,
                     creds: list, tools_done: list, mode: str, phase: str) -> dict | None:
        """Rule-based fast decisions — no LLM needed."""
        lower = user_input.lower()
        import re
        is_url = bool(re.search(r'https?://|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', user_input) and
                      not re.match(r'^\d{1,3}(\.\d{1,3}){3}', user_input.strip()))

        # Explicit report request
        if any(w in lower for w in ["report", "generate report", "export"]):
            return {"agent": "report", "reason": "User explicitly requested report"}

        # Saved HTTP analysis does not require active discovery.
        if any(word in lower for word in ('review', 'interpret', 'analyze', 'analyse')) and any(
                word in lower for word in ('http', 'cookie', 'bearer', 'session management', 'cors')):
            return {'agent': 'web_intel', 'reason': 'Review the supplied HTTP evidence and its limitations'}

        # Explicit goal setting
        if any(p in lower for p in ["goal:", "set goal", "attack goal", "objective:",
                                     "get shell", "dump cred", "pivot to", "escalate"]):
            return {"agent": "planner", "reason": "User defining attack goal"}

        # Solution 17: Bug bounty + URL → web_intel first
        if mode == "bug_bounty" and is_url and "web_intel" not in tools_done:
            return {"agent": "web_intel",
                    "reason": "Bug bounty mode + URL target: passive web analysis first"}

        # URL target (any mode) → web_intel before aggressive scan
        if is_url and "web_intel" not in tools_done and phase in ("scope", "reconnaissance"):
            return {"agent": "web_intel",
                    "reason": "URL target detected: web intel analysis before scanning"}

        # Post-exploitation actions (only if shell exists)
        post_keywords = ["privesc", "priv esc", "escalat", "hashdump", "credential dump",
                         "mimikatz", "persistence", "lateral", "pivot", "loot", "post exploit",
                         "meterpreter sessions", "active session"]
        if any(k in lower for k in post_keywords):
            if shells:
                return {"agent": "post", "reason": f"Post-exploitation requested, {len(shells)} shell(s) active"}
            else:
                return None  # Let LLM decide

        # No ports known → must scan first
        if not hosts or all(h.get("port_count", 0) == 0 for h in hosts):
            if any(w in lower for w in ["exploit", "vuln", "cve", "attack"]):
                return {"agent": "scan",
                        "reason": "Cannot exploit without port data — scanning first"}

        # Correlation explicitly requested
        if any(w in lower for w in ["correlat", "kill chain", "chain", "combine", "cross"]):
            return {"agent": "correlation", "reason": "Cross-correlation explicitly requested"}

        # Bug bounty mode — block post-exploitation
        if mode == "bug_bounty" and any(k in lower for k in post_keywords):
            return {"agent": "vuln",
                    "reason": "Bug bounty mode: post-exploitation restricted, switching to vuln assessment"}

        return None

    def _fallback_decide(self, user_input: str, hosts: list, phase: str) -> dict:
        lower = user_input.lower()
        if not hosts:
            return {"agent": "scan", "reason": "No hosts discovered yet"}
        if any(w in lower for w in ["scan", "port", "nmap"]):
            return {"agent": "scan", "reason": "Scan keywords in request"}
        if any(w in lower for w in ["recon", "whois", "dns", "subdomain"]):
            return {"agent": "recon", "reason": "Recon keywords in request"}
        if any(w in lower for w in ["vuln", "cve", "exploit", "nuclei"]):
            return {"agent": "vuln", "reason": "Vulnerability keywords in request"}
        return {"agent": "scan", "reason": "Default: scan to gather data"}

    async def delegate_task(self, session_id: str, user_id: str, task_id: str,
                            request_id: str, skill_level: str = 'intermediate') -> dict:
        """Delegate a durable task and collect its typed reviewable result."""
        from orchestrator.team_coordinator import team_coordinator
        return await team_coordinator.run(session_id, user_id, task_id, request_id, skill_level)

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        """Standard agent process interface."""
        decision = await self.decide_next_agent(
            session_id=session_id,
            user_id=user_id,
            user_input=input_data.get("user_input", ""),
            target=input_data.get("target", ""),
            current_phase=input_data.get("current_phase", "scope"),
            tools_run=input_data.get("tools_run", []),
            skill_level=skill_level,
        )
        return {
            "type": "coordination",
            "selected_agent": decision.get("agent", "scan"),
            "reason": decision.get("reason", ""),
            "opsec_note": decision.get("opsec_note", ""),
            "next_after": decision.get("next_after", ""),
        }


coordinator_agent = CoordinatorAgent()
