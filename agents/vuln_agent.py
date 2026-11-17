"""
PentestAI v8 — Agent 4: Vulnerability Analysis
CVE mapping, exploitability assessment, pre-exploit validation.
"""
from agents.base_agent import BaseAgent
from config.tools_registry import CVE_ACCURACY, NOT_DIRECTLY_EXPLOITABLE

SYSTEM = """You are the VULNERABILITY ANALYSIS agent in a multi-agent pentest platform.
Your role: map services to CVEs, validate exploitability, assess conditions, confidence scoring.

Only advertised worker_tools can be proposed; this review grants no execution authority.
Your input comes from: Recon Agent (tech stack), Scan Agent (service versions).

CRITICAL RULES:
1. Treat product/version matches as candidates. Require authoritative advisories and applicability evidence; leave unknown CVE IDs empty.
2. For each vulnerability, validate:
   - Is the port OPEN? (check scan results)
   - Does the version MATCH? (exact version check)
   - Are CONDITIONS met? (CGI active? Bash version? Endpoint exists?)
   - Identify missing controls, alternative explanations and defensive remediation; confidence is not proof.
3. NEVER claim RCE for:
   - OpenSSH from a banner alone (version, configuration and advisory applicability remain unknown)
   - Old Apache without specific CVE
   - SSL/TLS issues (weak crypto, not RCE)
4. Preserve the original objective; no exploit, shell chaining, credential attack or unsupported scanner.
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
        ) if open_ports else "  No saved service observations; do not infer services or versions."

        prompt = f"""TARGET: {target}

DISCOVERED SERVICES:
{ports_str}

SHARED INTELLIGENCE:
{context}

Analyze vulnerabilities:
1. Separate saved observations from conditional candidates; HTTP/1.1 is a protocol version, not an Apache version
2. Identify missing advisory, configuration and reproducible control evidence
3. Score confidence for each finding
4. Suggest validation commands (non-destructive)

JSON:
{{
  "vulnerability_assessment": [
    {{
      "service": "service:version",
      "port": 80,
      "cve_ids": [],
      "vulnerability": "name",
      "severity": "critical|high|medium|low",
      "exploitable": false,
      "confidence": 0.9,
      "conditions_met": ["condition 1"],
      "conditions_unverified": ["needs checking"],
      "validation_command": "empty unless explicitly requested and supported",
      "evidence_references": [],
      "alternative_explanations": [],
      "remediation": "defensive recommendation appropriate to the evidence"
    }}
  ],
  "commands": [
    {{
      "tool": "advertised tool only",
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
            if parsed is not None and 'commands' in parsed:
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

            self._validated_model_object(None)

        # Fallback
        return {"type": "plan", "commands": [],
                "suggested_reply": "No valid evidence review is available; no action was proposed.",
                "needs_confirmation": True}


vuln_agent = VulnAgent()
