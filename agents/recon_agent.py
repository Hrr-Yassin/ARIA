"""
PentestAI v8 — Agent 2: Reconnaissance
Passive and active recon, technology fingerprinting, target profiling.
"""
from agents.base_agent import BaseAgent
from config.tools_registry import TOOL_AGENT_MAP

SYSTEM = """You are the RECONNAISSANCE agent in a multi-agent pentest platform.
Your role: passive/active recon, technology fingerprinting, initial target profiling.

Tools you drive: whois, dig, subfinder, amass, theHarvester, curl (headers), httpx
Your output feeds into: Scan Agent (ports), Vuln Agent (tech stack), Correlation Agent.

RULES:
- Start passive (whois, DNS) then propose active (HTTP headers, subdomains)
- Extract technology stack from HTTP responses (Server, X-Powered-By, Set-Cookie)
- Identify CMS, frameworks, languages from response patterns
- Map subdomains and associated IPs
- Build structured target profile

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

Plan reconnaissance for this target. Include:
1. Passive recon commands (whois, DNS, subdomain enum)
2. Active fingerprinting (HTTP headers, technology detection)
3. What to look for in each output

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
            if parsed:
                for c in parsed.get("commands", []):
                    c["action_id"] = self.generate_action_id()
                    c["agent"] = "recon"
                return {"type": "plan", "commands": parsed.get("commands", []),
                        "suggested_reply": parsed.get("suggested_response", ""),
                        "needs_confirmation": True}

        # Fallback
        cmds = [
            {"tool": "whois", "command": f"whois {target}", "purpose": "WHOIS lookup",
             "risk": "low", "risk_color": "green", "can_batch": True,
             "action_id": self.generate_action_id(), "agent": "recon"},
            {"tool": "dig", "command": f"dig {target} ANY +short", "purpose": "DNS records",
             "risk": "low", "risk_color": "green", "can_batch": True,
             "action_id": self.generate_action_id(), "agent": "recon"},
            {"tool": "curl", "command": f"curl -I -s --max-time 10 http://{target}",
             "purpose": "HTTP headers & tech fingerprint", "risk": "low", "risk_color": "green",
             "can_batch": True, "action_id": self.generate_action_id(), "agent": "recon"},
        ]
        return {"type": "plan", "commands": cmds,
                "suggested_reply": f"Starting passive reconnaissance on `{target}`.",
                "needs_confirmation": True}


recon_agent = ReconAgent()
