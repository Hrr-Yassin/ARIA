"""
PentestAI v9 — Workflow Engine
Manages OWASP/PTES methodology phases, attack modes, progress tracking.
"""
from typing import Optional
from config.tools_registry import PENTEST_PHASES


PHASE_TOOLS = {
    "scope":                  [],
    "reconnaissance":         ["whois", "dig", "subfinder", "amass", "theHarvester", "curl"],
    "scanning":               ["nmap", "masscan", "rustscan", "gobuster", "ffuf", "enum4linux"],
    "vulnerability_analysis": ["nuclei", "searchsploit", "nikto", "wpscan"],
    "exploitation":           ["msfconsole", "sqlmap", "hydra"],
    "post_exploitation":      ["msfconsole", "mimikatz", "linpeas", "winpeas", "crackmapexec"],
    "reporting":              [],
}

PHASE_AGENTS = {
    "scope":                  "coordinator",
    "reconnaissance":         "recon",
    "scanning":               "scan",
    "vulnerability_analysis": "vuln",
    "exploitation":           "orchestrator",
    "post_exploitation":      "post",
    "reporting":              "report",
}

# Tools that transition phases when they complete
PHASE_TRANSITIONS = {
    "nmap":          ("scanning",               "vulnerability_analysis"),
    "masscan":       ("scanning",               "vulnerability_analysis"),
    "rustscan":      ("scanning",               "vulnerability_analysis"),
    "nuclei":        ("vulnerability_analysis", "exploitation"),
    "searchsploit":  ("vulnerability_analysis", "exploitation"),
    "msfconsole":    ("exploitation",           "post_exploitation"),
    "hydra":         ("exploitation",           "post_exploitation"),
    "sqlmap":        ("exploitation",           "post_exploitation"),
    "linpeas":       ("post_exploitation",      "reporting"),
    "winpeas":       ("post_exploitation",      "reporting"),
}

# Mode-based scan flags
MODE_SCAN_FLAGS = {
    "lab":        {"nmap": "-T4 --open", "timing": "T4", "masscan_rate": "10000"},
    "red_team":   {"nmap": "-T2 --open --randomize-hosts", "timing": "T2", "masscan_rate": "1000"},
    "bug_bounty": {"nmap": "-T3 --open", "timing": "T3", "masscan_rate": "5000"},
}


class WorkflowEngine:
    """Tracks pentest phases and guides methodology adherence."""

    def get_current_phase_info(self, phase: str, tools_run: list) -> dict:
        idx = PENTEST_PHASES.index(phase) if phase in PENTEST_PHASES else 0
        phase_tools = PHASE_TOOLS.get(phase, [])
        tools_done = [t for t in tools_run if t in phase_tools]
        progress = (len(tools_done) / max(len(phase_tools), 1)) * 100 if phase_tools else 0

        return {
            "current_phase":    phase,
            "phase_index":      idx,
            "total_phases":     len(PENTEST_PHASES),
            "phase_progress":   round(progress),
            "tools_expected":   phase_tools,
            "tools_completed":  tools_done,
            "tools_remaining":  [t for t in phase_tools if t not in tools_run],
            "responsible_agent": PHASE_AGENTS.get(phase, "orchestrator"),
            "next_phase":       PENTEST_PHASES[idx + 1] if idx + 1 < len(PENTEST_PHASES) else None,
        }

    def get_overall_progress(self, phase: str, tools_run: list) -> dict:
        total_tools = sum(len(v) for v in PHASE_TOOLS.values())
        done_tools = len([t for t in tools_run if any(t in tv for tv in PHASE_TOOLS.values())])
        phase_idx = PENTEST_PHASES.index(phase) if phase in PENTEST_PHASES else 0
        phase_pct = round((phase_idx / max(len(PENTEST_PHASES) - 1, 1)) * 100)
        tool_pct = round((done_tools / max(total_tools, 1)) * 100)
        return {
            "phase_pct":         phase_pct,
            "tools_coverage_pct": tool_pct,
            "overall_pct":       round((phase_pct + tool_pct) / 2),
        }

    def suggest_next_phase(self, current_phase: str, tools_run: list,
                           has_shell: bool = False, has_findings: bool = False) -> Optional[str]:
        """Suggest phase advancement based on state."""
        idx = PENTEST_PHASES.index(current_phase) if current_phase in PENTEST_PHASES else 0
        phase_tools = PHASE_TOOLS.get(current_phase, [])
        done = [t for t in tools_run if t in phase_tools]

        # Phase-specific advancement logic
        if current_phase == "scanning" and len(done) >= 1:
            return "vulnerability_analysis"
        if current_phase == "vulnerability_analysis" and has_findings:
            return "exploitation"
        if current_phase == "exploitation" and has_shell:
            return "post_exploitation"
        if current_phase == "post_exploitation" and len(done) >= 2:
            return "reporting"

        # Generic: advance when most phase tools done
        if phase_tools and len(done) >= max(len(phase_tools) // 2, 1):
            next_idx = idx + 1
            if next_idx < len(PENTEST_PHASES):
                return PENTEST_PHASES[next_idx]

        return None

    def get_tool_phase_transition(self, tool: str) -> Optional[tuple]:
        """Returns (from_phase, to_phase) if this tool triggers a phase change."""
        return PHASE_TRANSITIONS.get(tool.lower())

    def get_mode_scan_flags(self, attack_mode: str = "lab") -> dict:
        return MODE_SCAN_FLAGS.get(attack_mode, MODE_SCAN_FLAGS["lab"])

    def get_phase_opsec_notes(self, phase: str, attack_mode: str) -> list:
        if attack_mode != "red_team":
            return []
        notes = {
            "reconnaissance": [
                "Use passive recon before active — avoid DNS bruteforce that triggers alerts",
                "Space requests over time — don't enumerate subdomains too fast",
            ],
            "scanning": [
                "Use -T2 timing to avoid IDS/IPS detection",
                "Add --randomize-hosts to avoid sequential scan patterns",
                "Consider -D decoy1,decoy2,ME for nmap decoy scanning",
                "Scan from a pivot host if available to hide attacker IP",
            ],
            "exploitation": [
                "Use stageless payloads to reduce network signatures",
                "Prefer HTTPS C2 to blend with legitimate traffic",
                "Avoid Metasploit's default port 4444 — use 443 or 80",
                "Test payload on localhost first to ensure no crashes",
            ],
            "post_exploitation": [
                "Clear bash/cmd history after credential operations",
                "Use memory-only tools (Cobalt Strike, Empire) where possible",
                "Remove dropped files after use",
                "Avoid touching disk-based AV/EDR monitored paths",
            ],
        }
        return notes.get(phase, [])


workflow_engine = WorkflowEngine()
