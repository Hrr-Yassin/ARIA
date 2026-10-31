"""
PentestAI v8 — Agent 6: Correlation & Kill Chain
Cross-references all agent results, builds kill chains, validates exploitability.
"""
from agents.base_agent import BaseAgent
from memory.knowledge_cache import knowledge_cache
from memory.vector_store import vector_store

SYSTEM = """You are the CORRELATION & KILL CHAIN agent in a multi-agent pentest platform.
Your role: cross-reference results from ALL agents, build attack chains, verify exploitability.

You receive data from ALL other agents and:
1. Cross-correlate findings (e.g., Apache version from headers + nmap + nuclei)
2. Build realistic kill chains (step-by-step exploitation paths)
3. Verify if a vulnerability is ACTUALLY exploitable on THIS specific target
4. Detect false positives and hallucinated attack paths
5. Identify attack surface gaps (what hasn't been tested)

Example: Agent 3 finds Apache 2.4.49 on port 80, Agent 4 finds CVE-2021-41773.
You verify: Is mod_cgi enabled? Is the path traversal actually reachable?
Then build: port scan → version detect → CVE match → path traversal → RCE kill chain.

RULES:
- Never assume — always check evidence from other agents
- Confidence scoring: how sure are we this chain works?
- Identify missing validations needed before exploitation
- Output kill chains as ordered steps with prerequisites

{skill_instruction}
RESPOND: Valid JSON only."""


class CorrelationAgent(BaseAgent):
    agent_name = "correlation"
    agent_role = "Correlation & Kill Chain — Cross-Agent Intelligence"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return SYSTEM.format(skill_instruction=self.get_skill_instruction(skill_level))

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        """Analyze all collected data and build correlations."""
        target = input_data.get("target", "")

        # Gather ALL intelligence from all agents
        all_intel = vector_store.get_all(session_id)
        findings_by_agent = {}
        for entry in all_intel:
            agent = entry.get("agent", "unknown")
            findings_by_agent.setdefault(agent, []).append(entry["content"][:200])

        cached = knowledge_cache.get_all_for_session(session_id)
        open_ports = knowledge_cache.get_open_ports(session_id, target)
        techs = knowledge_cache.get_technologies(session_id)

        # Build comprehensive intel summary
        intel_sections = []
        for agent, items in findings_by_agent.items():
            intel_sections.append(f"[{agent.upper()}]")
            for item in items[:5]:
                intel_sections.append(f"  - {item}")

        ports_str = "\n".join(
            f"  {p['port']}/{p['service']}: {p['version']}" for p in open_ports
        ) if open_ports else "  No ports discovered"

        tech_str = ", ".join(f"{k}: {v}" for k, v in techs.items() if v) or "Unknown"

        prompt = f"""TARGET: {target}

DISCOVERED SERVICES:
{ports_str}

TECHNOLOGY STACK: {tech_str}

ALL AGENT INTELLIGENCE:
{chr(10).join(intel_sections) if intel_sections else 'No data yet.'}

TOOLS RUN: {', '.join(set(e.get('tool','') for e in cached)) or 'none'}

Perform cross-correlation analysis:
1. What patterns emerge from combining all agents' data?
2. Are there vulnerabilities that multiple agents confirm?
3. What realistic kill chains can be built?
4. What are the false positives? (claims not supported by evidence)
5. What gaps exist in our testing coverage?

JSON:
{{
  "correlations": [
    {{
      "finding": "what was correlated",
      "agents_involved": ["recon", "scan", "vuln"],
      "evidence": "combined evidence from multiple sources",
      "confidence": 0.9,
      "significance": "why this matters"
    }}
  ],
  "kill_chains": [
    {{
      "name": "attack chain name",
      "target_service": "service:port",
      "steps": [
        {{
          "step": 1,
          "action": "what to do",
          "prerequisite": "what must be true",
          "tool": "tool to use",
          "command": "exact command",
          "expected_result": "what success looks like"
        }}
      ],
      "overall_confidence": 0.85,
      "missing_validations": ["what needs checking"],
      "impact": "what attacker gains"
    }}
  ],
  "false_positives": ["findings that lack supporting evidence"],
  "coverage_gaps": ["areas not yet tested"],
  "suggested_response": "summary for pentester",
  "risk_reassessment": "updated risk view based on correlations"
}}"""

        result = await self.query_llm(user_id, prompt, self.get_system_prompt(skill_level))
        if result.get("success"):
            parsed = self.parse_json(result["content"])
            if parsed:
                # Store correlations in shared memory
                for corr in parsed.get("correlations", []):
                    self.store_discovery(
                        session_id,
                        f"Correlation: {corr.get('finding', '')} "
                        f"(agents: {', '.join(corr.get('agents_involved', []))}, "
                        f"confidence: {corr.get('confidence', 0)})",
                        corr, "correlation",
                    )
                for kc in parsed.get("kill_chains", []):
                    self.store_discovery(
                        session_id,
                        f"Kill Chain: {kc.get('name', '')} → {kc.get('impact', '')} "
                        f"(confidence: {kc.get('overall_confidence', 0)})",
                        kc, "kill_chain",
                    )

                return {
                    "type": "correlation",
                    "correlations": parsed.get("correlations", []),
                    "kill_chains": parsed.get("kill_chains", []),
                    "false_positives": parsed.get("false_positives", []),
                    "coverage_gaps": parsed.get("coverage_gaps", []),
                    "suggested_reply": parsed.get("suggested_response", ""),
                    "risk_reassessment": parsed.get("risk_reassessment", ""),
                }

        return {
            "type": "correlation",
            "correlations": [],
            "kill_chains": [],
            "suggested_reply": "Insufficient data for correlation. Run more scans first.",
        }


correlation_agent = CorrelationAgent()
