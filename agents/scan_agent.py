"""
PentestAI v8 — Agent 3: Scan & Enumeration
Service detection, version fingerprinting, attack surface mapping.
"""
from agents.base_agent import BaseAgent

SYSTEM = """You are the SCAN & ENUMERATION agent in a multi-agent pentest platform.
Your role: port scanning, service detection, version fingerprinting, creating structured service maps.

Tools you drive: nmap, masscan, rustscan, gobuster, ffuf, enum4linux, smbclient
Your output feeds into: Vuln Agent (service versions), Correlation Agent (attack surface).

RULES:
- Adapt scan parameters based on context (stealth vs aggressive)
- Extract exact version numbers for every service
- Enumerate: SMB shares, FTP anonymous, NFS exports, web directories
- Create structured service map
- Don't just list ports — identify what's interesting and why
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

        scan_configs = {
            "quick": f"nmap -sS -sV -sC --top-ports 1000 -T4 {target}",
            "full": f"nmap -sS -sV -sC -p- -T4 {target}",
            "stealth": f"nmap -sS -sV -T2 --top-ports 100 {target}",
            "udp": f"nmap -sU -sV --top-ports 50 -T4 {target}",
        }

        prompt = f"""TARGET: {target}
SCAN TYPE: {scan_type}
EXISTING INTEL: {context}

Plan {scan_type} scanning. Consider:
1. What scan technique is best for this context?
2. What services should we enumerate further?
3. What specific scripts or flags add value?

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
            if parsed:
                for c in parsed.get("commands", []):
                    c["action_id"] = self.generate_action_id()
                    c["agent"] = "scan"
                return {"type": "plan", "commands": parsed.get("commands", []),
                        "suggested_reply": parsed.get("suggested_response", ""),
                        "needs_confirmation": True}

        cmd = scan_configs.get(scan_type, scan_configs["quick"])
        return {"type": "plan",
                "commands": [{"tool": "nmap", "command": cmd, "purpose": f"{scan_type} port scan",
                              "risk": "medium", "risk_color": "orange", "can_batch": True,
                              "action_id": self.generate_action_id(), "agent": "scan"}],
                "suggested_reply": f"Running **{scan_type}** scan on `{target}`.",
                "needs_confirmation": True}


scan_agent = ScanAgent()
