"""
PentestAI v9 — Coordinator (Brain) Agent
Decides which agent to invoke, prevents redundancy, avoids unnecessary steps.
Acts as intelligent dispatcher between all specialized agents.
"""
import re
from agents.base_agent import BaseAgent
from memory.attack_knowledge_base import attack_kb

SYSTEM = """You are the COORDINATOR (Brain) of a multi-agent penetration testing platform.

Your sole job: decide which specialist agent to invoke next, and why.

Available agents:
- planner    → Set/update attack goal, build step-by-step attack path
- recon      → OSINT, DNS, subdomain enum, tech fingerprinting (passive/active)
- scan       → Port scanning, service detection, version fingerprinting
- vuln       → CVE mapping, exploit validation, exploitability assessment
- exploit    → Orchestrator handles exploitation planning
- post       → Post-exploitation: privesc, credential dump, lateral movement, persistence
- web_intel  → Passive HTTP analysis, endpoint scoring, auth detection (bug_bounty + URL targets)
- correlation → Cross-reference all findings, build kill chains, detect false positives
- report     → Generate pentest report

DECISION LOGIC:
1. If no ports known → scan first (never skip to exploit)
2. If goal not set → planner first
3. If ports known but no vulns → vuln agent
4. If vuln confirmed + shell exists → post agent
5. If multiple contradicting findings → correlation agent
6. Never call the same agent twice for same data (check KB)
7. In red_team mode → prefer slow/stealthy options
8. In bug_bounty mode → ALWAYS use web_intel first if target is URL/domain
9. If target is URL/domain → web_intel before scan
10. Never suggest destructive actions in bug_bounty mode

OUTPUT: Single word agent name + brief reason. Valid JSON only."""


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

AVAILABLE AGENTS: planner, recon, scan, vuln, post, correlation, report

Decision rules:
- Don't re-run tools already done on same target unless new info exists
- If shells exist + user asks about credentials → post agent
- If user explicitly asks for report → report
- If user sets a goal → planner
- If contradictions in findings → correlation
- Bug bounty mode: never send to post agent without explicit permission
- Red team mode: prefer slower/stealthier approach, add OPSEC notes

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
