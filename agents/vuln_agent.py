"""
PentestAI v8 — Agent 4: Vulnerability Analysis
CVE mapping, exploitability assessment, pre-exploit validation.
"""
from agents.base_agent import BaseAgent
from config.tools_registry import CVE_ACCURACY, NOT_DIRECTLY_EXPLOITABLE

SYSTEM = """You are the VULNERABILITY ANALYSIS agent in a multi-agent pentest platform.
Your role: map services to CVEs, validate exploitability, assess conditions, confidence scoring.

Tools you drive: nuclei, searchsploit, nikto, nmap --script=vuln
Your input comes from: Recon Agent (tech stack), Scan Agent (service versions).

CRITICAL RULES:
1. Map service versions to REAL CVEs — never invent CVE numbers
2. For each vulnerability, validate:
   - Is the port OPEN? (check scan results)
   - Does the version MATCH? (exact version check)
   - Are CONDITIONS met? (CGI active? Bash version? Endpoint exists?)
   - Confidence level: high (>80%), medium (50-80%), low (<50%)
3. NEVER claim RCE for:
   - OpenSSH (user enum only, try hydra)
   - Old Apache without specific CVE
   - SSL/TLS issues (weak crypto, not RCE)
4. Prioritize by EXPLOITABILITY, not just CVSS score
5. Cross-correlate with recon and scan findings

{skill_instruction}
RESPOND: Valid JSON only."""


class VulnAgent(BaseAgent):
    agent_name = "vuln"
    agent_role = "Vulnerability Analysis — CVE Mapping & Validation"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return SYSTEM.format(skill_instruction=self.get_skill_instruction(skill_level))

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        target = input_data.get("target", "")
        context = self.get_context(session_id, "vulnerability CVE exploit service version")

        from memory.knowledge_cache import knowledge_cache
        open_ports = knowledge_cache.get_open_ports(session_id, target)
        ports_str = "\n".join(
            f"  {p['port']}/{p['service']}: {p['version']}" for p in open_ports
        ) if open_ports else "  Run nmap first."

        prompt = f"""TARGET: {target}

DISCOVERED SERVICES:
{ports_str}

SHARED INTELLIGENCE:
{context}

Analyze vulnerabilities:
1. Map each service+version to known CVEs
2. Validate exploitability conditions
3. Score confidence for each finding
4. Suggest validation commands (non-destructive)

JSON:
{{
  "vulnerability_assessment": [
    {{
      "service": "service:version",
      "port": 80,
      "cve_ids": ["CVE-XXXX-XXXX"],
      "vulnerability": "name",
      "severity": "critical|high|medium|low",
      "exploitable": true,
      "confidence": 0.9,
      "conditions_met": ["condition 1"],
      "conditions_unverified": ["needs checking"],
      "validation_command": "non-destructive check command"
    }}
  ],
  "commands": [
    {{
      "tool": "nuclei",
      "command": "exact command",
      "purpose": "what this validates",
      "risk": "medium",
      "risk_color": "orange",
      "can_batch": true
    }}
  ],
  "suggested_response": "analysis summary",
  "risk_summary": "overall risk assessment"
}}"""

        result = await self.query_llm(user_id, prompt, self.get_system_prompt(skill_level))
        if result.get("success"):
            parsed = self.parse_json(result["content"])
            if parsed:
                for c in parsed.get("commands", []):
                    c["action_id"] = self.generate_action_id()
                    c["agent"] = "vuln"

                # Store assessment in shared memory
                for va in parsed.get("vulnerability_assessment", []):
                    va.update({"exploitable":False, "verification_status":"candidate"})
                    self.store_discovery(
                        session_id,
                        f"Vuln: {va.get('vulnerability', '')} on {va.get('service', '')} "
                        f"(confidence: {va.get('confidence', 0)})",
                        va, "vulnerability",
                    )

                return {"type": "plan", "commands": parsed.get("commands", []),
                        "suggested_reply": parsed.get("suggested_response", ""),
                        "vulnerability_assessment": parsed.get("vulnerability_assessment", []),
                        "needs_confirmation": True}

        # Fallback
        cmds = [{"tool": "nuclei",
                 "command": f"nuclei -target {target} -severity critical,high,medium -silent",
                 "purpose": "CVE scan", "risk": "medium", "risk_color": "orange",
                 "can_batch": True, "action_id": self.generate_action_id(), "agent": "vuln"}]
        return {"type": "plan", "commands": cmds,
                "suggested_reply": f"Running vulnerability analysis on `{target}`.",
                "needs_confirmation": True}


vuln_agent = VulnAgent()
