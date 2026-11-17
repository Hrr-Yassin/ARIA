"""
PentestAI v8 — Agent 2: Reconnaissance
Passive and active recon, technology fingerprinting, target profiling.
"""
from agents.base_agent import BaseAgent

SYSTEM = """You are the RECONNAISSANCE agent in a multi-agent pentest platform.
Your role: passive/active recon, technology fingerprinting, initial target profiling.

Your output feeds into: Scan Agent (ports), Vuln Agent (tech stack), Correlation Agent.

RULES:
- Follow the server objective and advertised worker_tools; a role name grants no tool capability.
- For HTTP-header observation, propose a bounded curl HEAD (-I) request to the requested URL and port.
- Do not add WHOIS, DNS, subdomains or other discovery unless requested and supported by the worker.
- Preserve the requested scheme, host, port and path; do not infer a software version from an HTTP protocol version.
- Cite saved evidence for observations; absent versions and untested technology remain unknown.
- If the requested observation is unsupported, return commands: [] and explain the missing prerequisite.
- Every proposed command requires server validation and approval before execution.

RESPOND: Valid JSON only. {skill_instruction}"""


class ReconAgent(BaseAgent):
    agent_name = "recon"
    agent_role = "Reconnaissance — Target Profiling"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return SYSTEM.format(skill_instruction=self.get_skill_instruction(skill_level))

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        target = input_data.get("target", "")
        context = self.get_context(session_id, "recon reconnaissance")

        prompt = f"""TARGET: {target}
EXISTING INTEL: {context}

Plan only the server objective within its scope and available worker profiles.
Choose the smallest missing observation; do not add a standard reconnaissance checklist.
For requested headers use HEAD, not a body-only GET. Explain expected evidence,
uncertainty and any missing prerequisite. Do not repeat an observation already evidenced.

JSON:
{{
  "target_profile": {{
    "type": "ip|domain|url",
    "initial_assessment": "what we can infer"
  }},
  "commands": [
    {{
      "tool": "tool_name",
      "command": "exact command",
      "purpose": "what this reveals",
      "risk": "low",
      "risk_color": "green",
      "can_batch": true
    }}
  ],
  "suggested_response": "explanation for pentester",
  "what_to_look_for": ["key indicators in output"]
}}"""

        result = await self.query_llm(user_id, prompt, self.get_system_prompt(skill_level))
        if result.get("success"):
            parsed = self.parse_json(result["content"])
            if parsed is not None and "commands" in parsed:
                for c in parsed.get("commands", []):
                    c["action_id"] = self.generate_action_id()
                    c["agent"] = "recon"
                return {"type": "plan", "commands": parsed.get("commands", []),
                        "suggested_reply": parsed.get("suggested_response", ""),
                        "needs_confirmation": True}

            self._validated_model_object(None)

        return {"type": "plan", "commands": [],
                "suggested_reply": "No valid reconnaissance plan is available; no action was proposed.",
                "needs_confirmation": True}


recon_agent = ReconAgent()
