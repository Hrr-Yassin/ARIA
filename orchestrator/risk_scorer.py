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
    import shlex
    try:
        argv = shlex.split(command)
    except ValueError:
        return "red"
    if not argv or argv[0] != tool:
        return "red"
    base_risk = TOOL_RISK.get(tool.lower(), "red")
    if base_risk == "red":
        return "red"
    if tool == "curl":
        if any(flag in argv for flag in ("-X", "--request", "-d", "--data", "--data-raw")):
            return "red"
        return "green" if any(flag in argv for flag in ("-I", "-sI", "-Is", "--head")) else "orange"
    return base_risk


def should_auto_execute(risk_color: str, user_preferences: dict = None) -> bool:
    """Determine if a command should auto-execute based on risk."""
    if user_preferences:
        threshold = user_preferences.get("auto_execute_threshold", "green")
        levels = {"green": 0, "orange": 1, "red": 2}
        return levels.get(risk_color, 2) <= levels.get(threshold, 0)
    return risk_color == "green"
