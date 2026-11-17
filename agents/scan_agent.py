"""
PentestAI v8 — Agent 3: Scan & Enumeration
Service detection, version fingerprinting, attack surface mapping.
"""
from agents.base_agent import BaseAgent

SYSTEM = """You are the SCAN & ENUMERATION agent in a multi-agent pentest platform.
Your role: port scanning, service detection, version fingerprinting, creating structured service maps.

Your output feeds into: Vuln Agent (service versions), Correlation Agent (attack surface).

RULES:
- Follow the server objective and advertised worker_tools; a scan_type label grants no authority.
- The legacy Nmap worker supports TCP connect scans with an explicit numeric -p port list.
- Preserve requested hosts and ports; do not add scripts, raw SYN, UDP, OS detection or all-port scans.
- Select additional service probes only when requested and supported by the worker profile.
- Record versions as unknown unless saved evidence supplies them; an open port alone is not a vulnerability.
- If the requested scan is unsupported, return commands: [] and explain the missing prerequisite.
- Every proposed command requires server validation and approval before execution.
- Max 4 commands per response

RESPOND: Valid JSON only. {skill_instruction}"""


class ScanAgent(BaseAgent):
    agent_name = "scan"
    agent_role = "Scan & Enumeration — Service Discovery"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return SYSTEM.format(skill_instruction=self.get_skill_instruction(skill_level))

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        target = input_data.get("target", "")
        scan_type = input_data.get("scan_type", "quick")
        context = self.get_context(session_id, "scan ports services")

        prompt = f"""TARGET: {target}
SCAN TYPE: {scan_type}
EXISTING INTEL: {context}

Plan only the server objective within its scope and available worker profiles.
Use explicit requested TCP ports for a supported Nmap connect observation.
The scan type is a preference, not permission to expand ports or enable unsupported
techniques. Explain the smallest missing observation and its expected evidence.
Do not repeat completed port discovery or invent versions from unknown banners.

JSON:
{{
  "scan_strategy": "why this approach",
  "commands": [
    {{
      "tool": "nmap",
      "command": "exact command",
      "purpose": "what this reveals",
      "risk": "medium",
      "risk_color": "orange",
      "expected_duration_seconds": 60,
      "can_batch": true
    }}
  ],
  "suggested_response": "explanation",
  "enumeration_targets": ["services worth deeper enum"]
}}"""

        result = await self.query_llm(user_id, prompt, self.get_system_prompt(skill_level))
        if result.get("success"):
            parsed = self.parse_json(result["content"])
            if parsed is not None and "commands" in parsed:
                for c in parsed.get("commands", []):
                    c["action_id"] = self.generate_action_id()
                    c["agent"] = "scan"
                return {"type": "plan", "commands": parsed.get("commands", []),
                        "suggested_reply": parsed.get("suggested_response", ""),
                        "needs_confirmation": True}

            self._validated_model_object(None)

        return {"type": "plan",
                "commands": [],
                "suggested_reply": "No valid scan plan is available; no action was proposed.",
                "needs_confirmation": True}


scan_agent = ScanAgent()
