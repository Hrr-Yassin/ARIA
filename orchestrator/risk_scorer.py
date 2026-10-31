"""
PentestAI v8 — Risk Scorer
GREEN (auto-execute) / ORANGE (notify) / RED (require validation)
"""

# Tool risk classification
TOOL_RISK = {
    # GREEN - passive, no impact
    "whois": "green", "dig": "green", "host": "green", "curl": "green",
    "wget": "green", "ping": "green", "searchsploit": "green",
    # ORANGE - active scanning, detectable
    "nmap": "orange", "masscan": "orange", "rustscan": "orange",
    "nuclei": "orange", "nikto": "orange", "gobuster": "orange",
    "ffuf": "orange", "dirb": "orange", "wpscan": "orange",
    "enum4linux": "orange", "smbclient": "orange", "nbtscan": "orange",
    "subfinder": "green", "amass": "green", "theHarvester": "green",
    # RED - exploitation, destructive potential
    "msfconsole": "red", "msfvenom": "red", "sqlmap": "red",
    "hydra": "red", "john": "red", "hashcat": "red",
    "crackmapexec": "red",
}


def classify_risk(tool: str, command: str = "") -> str:
    """Classify command risk level."""
    tool_lower = tool.lower()
    base_risk = TOOL_RISK.get(tool_lower, "orange")

    # Override based on command content
    cmd_lower = command.lower()
    if any(w in cmd_lower for w in ["exploit", "run", "payload", "reverse", "shell"]):
        return "red"
    if any(w in cmd_lower for w in ["--batch", "--force", "brute", "fuzz"]):
        return "red" if base_risk != "green" else "orange"
    if any(w in cmd_lower for w in ["-I", "--head", "-s", "passive"]):
        return "green"

    return base_risk


def should_auto_execute(risk_color: str, user_preferences: dict = None) -> bool:
    """Determine if a command should auto-execute based on risk."""
    if user_preferences:
        threshold = user_preferences.get("auto_execute_threshold", "green")
        levels = {"green": 0, "orange": 1, "red": 2}
        return levels.get(risk_color, 2) <= levels.get(threshold, 0)
    return risk_color == "green"
