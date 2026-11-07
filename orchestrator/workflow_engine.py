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

    @staticmethod
    def evidence_readiness(phase: str, ledger: dict | None) -> dict:
        """Count declared questions, while requiring reviewed tasks for readiness."""
        if not isinstance(ledger, dict):
            return {'state': 'unknown', 'questions_total': 0, 'questions_tested': 0, 'percent': 0}
        tasks = [t for t in ledger.get('tasks', []) if t.get('phase') == phase and t.get('state') != 'cancelled']
        if not tasks or any(not t.get('security_questions') for t in tasks):
            return {'state': 'unknown', 'questions_total': 0, 'questions_tested': 0, 'percent': 0}
        keys = {key for task in tasks for key in task['security_questions']}
        coverage = {item.get('key'): item for item in ledger.get('coverage', [])}
        evidence = {item.get('id') for item in ledger.get('evidence', [])}
        def tested(key):
            record = coverage.get(key, {})
            refs = record.get('evidence_references') or []
            return record.get('status') == 'tested' and bool(refs) and all(ref in evidence for ref in refs)
        done = sum(tested(key) for key in keys)
        def reviewed(task):
            if task.get('state') != 'completed' or not task.get('reviewed_by'):
                return False
            snapshot = {item.get('key'): item for item in task.get('completion_review', [])}
            for key in task['security_questions']:
                saved, current = snapshot.get(key, {}), coverage.get(key, {})
                if not saved.get('ready') or any(saved.get(field) != current.get(field)
                    for field in ('question', 'feature', 'evidence_references')):
                    return False
            return True
        ready = done == len(keys) and all(reviewed(t) for t in tasks)
        return {'state': 'ready' if ready else 'not_ready', 'questions_total': len(keys),
                'questions_tested': done, 'percent': round(100 * done / len(keys))}

    def get_current_phase_info(self, phase: str, tools_run: list, ledger: dict | None = None) -> dict:
        idx = PENTEST_PHASES.index(phase) if phase in PENTEST_PHASES else 0
        phase_tools = PHASE_TOOLS.get(phase, [])
        readiness = self.evidence_readiness(phase, ledger)
        return {
            'current_phase': phase, 'phase_index': idx, 'total_phases': len(PENTEST_PHASES),
            'phase_progress': readiness['percent'], 'readiness': readiness,
            'tools_expected': phase_tools, 'tools_completed': [t for t in tools_run if t in phase_tools],
            'tools_remaining': [t for t in phase_tools if t not in tools_run],
            'responsible_agent': PHASE_AGENTS.get(phase, 'orchestrator'),
            'next_phase': PENTEST_PHASES[idx + 1] if idx + 1 < len(PENTEST_PHASES) else None,
        }

    def get_overall_progress(self, phase: str, tools_run: list, ledger: dict | None = None) -> dict:
        readiness = self.evidence_readiness(phase, ledger)
        # Legacy numeric keys remain present; their basis is now declared questions.
        return {'phase_pct': readiness['percent'], 'tools_coverage_pct': readiness['percent'],
                'overall_pct': readiness['percent'], 'basis': 'current_phase_security_questions',
                'readiness': readiness}

    def suggest_next_phase(self, current_phase: str, tools_run: list,
                           has_shell: bool = False, has_findings: bool = False) -> Optional[str]:
        """Automatic advancement is disabled; a human reviews readiness."""
        return None

    def get_tool_phase_transition(self, tool: str) -> Optional[tuple]:
        return None

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
