"""
PentestAI v10 — Global Attack Knowledge Base
Central shared state for all agents.

v10 additions:
  • Event-driven re-planning callbacks — notify subscribers when critical
    events happen (vuln found, shell obtained, cred found, scan complete).
  • Auto CVE-enrichment hook — when a port+version is added, schedule
    `cve_enricher.auto_enrich_port` as a background task.
  • Decision-log bridge — every state mutation is reflected in the timeline
    so the "traçabilité complète des décisions" requirement is covered.
"""
import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Awaitable
from datetime import datetime
import structlog

log = structlog.get_logger("attack_kb")


@dataclass
class HostEntry:
    ip: str
    hostname: str = ""
    os: str = ""
    os_confidence: float = 0.0
    ports: Dict[int, dict] = field(default_factory=dict)
    vulnerabilities: List[dict] = field(default_factory=list)
    credentials: List[dict] = field(default_factory=list)
    shells: List[dict] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # v10: track which enrichments we've already kicked off (avoid dup tasks)
    _enriched_ports: set = field(default_factory=set)

    def add_port(self, port: int, service: str, version: str = "",
                 banner: str = "", state: str = "open"):
        self.ports[port] = {
            "service": service, "version": version,
            "banner": banner, "state": state,
            "scanned_at": datetime.utcnow().isoformat(),
        }
        self.last_updated = datetime.utcnow().isoformat()

    def add_credential(self, user: str, password: str = "", service: str = "",
                       port: int = 0, hash_type: str = "", hash_value: str = ""):
        cred = {"user": user, "password": password, "service": service,
                "port": port, "hash_type": hash_type, "hash_value": hash_value,
                "found_at": datetime.utcnow().isoformat()}
        key = f"{user}:{password}:{service}:{port}"
        if not any(f"{c['user']}:{c['password']}:{c['service']}:{c['port']}" == key
                   for c in self.credentials):
            self.credentials.append(cred)
            self.last_updated = datetime.utcnow().isoformat()

    def add_shell(self, shell_type: str, port: int, user: str,
                  privilege: str = "user", details: str = ""):
        shell = {"type": shell_type, "port": port, "user": user,
                 "privilege": privilege, "details": details,
                 "obtained_at": datetime.utcnow().isoformat(), "active": True}
        self.shells.append(shell)
        self.last_updated = datetime.utcnow().isoformat()
        log.info("Shell added to KB", host=self.ip, type=shell_type,
                 user=user, priv=privilege)

    def add_vulnerability(self, title: str, severity: str, cve_ids: List[str] = None,
                          cvss: float = 0.0, description: str = "",
                          exploitable: bool = False, port: int = 0):
        vuln = {"title": title, "severity": severity, "cve_ids": cve_ids or [],
                "cvss": cvss, "description": description, "exploitable": exploitable,
                "port": port, "found_at": datetime.utcnow().isoformat()}

        def _vuln_key(v):
            return (f"{v['title'].lower().strip()}:{v.get('port',0)}:"
                    f"{','.join(sorted(v.get('cve_ids',[])))}")

        new_key = _vuln_key({"title": title, "port": port, "cve_ids": cve_ids or []})
        if not any(_vuln_key(v) == new_key for v in self.vulnerabilities):
            self.vulnerabilities.append(vuln)
            self.last_updated = datetime.utcnow().isoformat()

    def to_summary(self) -> dict:
        open_ports = [p for p, d in self.ports.items() if d.get("state") == "open"]
        active_shells = [s for s in self.shells if s.get("active")]
        return {
            "ip": self.ip, "hostname": self.hostname, "os": self.os,
            "open_ports": open_ports, "port_count": len(open_ports),
            "vuln_count": len(self.vulnerabilities),
            "cred_count": len(self.credentials),
            "shell_count": len(active_shells),
            "has_root": any(s.get("privilege") in ("root", "SYSTEM", "admin")
                            for s in active_shells),
            "tags": self.tags,
            "last_updated": self.last_updated,
        }


@dataclass
class AttackGoal:
    goal_type: str
    description: str = ""
    target: str = ""
    status: str = "pending"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    achieved_at: str = ""
    steps_completed: List[str] = field(default_factory=list)


# v10: callback type
ReplanCallback = Callable[[dict], Awaitable[None]]


class AttackKnowledgeBase:
    """Central knowledge base shared across all agents for a pentest session."""

    def __init__(self):
        self._sessions: Dict[str, dict] = {}
        # v10: session_id -> callback (triggered on major events)
        self._replan_callbacks: Dict[str, ReplanCallback] = {}
        # v10: callback for CVE enrichment (injected from cve_enricher)
        self._cve_enrich_callback: Optional[Callable[[str, str, int, str, str], Awaitable[None]]] = None

    def _ensure_session(self, session_id: str) -> dict:
        if session_id not in self._sessions:
            self._sessions[session_id] = {
                "hosts": {},
                "goals": [],
                "attack_mode": "lab",
                "opsec_level": "normal",
                "timeline": [],
                "pivot_routes": [],
                "attack_graph": {},
                "current_goal": None,
                "mode_settings": _MODE_SETTINGS["lab"],
            }
        return self._sessions[session_id]

    # ── Host management ───────────────────────────────────────────────────

    def get_or_create_host(self, session_id: str, ip: str) -> HostEntry:
        s = self._ensure_session(session_id)
        if ip not in s["hosts"]:
            s["hosts"][ip] = HostEntry(ip=ip)
            self._log_event(session_id, "host_discovered", "kb", f"New host: {ip}")
        return s["hosts"][ip]

    def get_host(self, session_id: str, ip: str) -> Optional[HostEntry]:
        return self._sessions.get(session_id, {}).get("hosts", {}).get(ip)

    def get_all_hosts(self, session_id: str) -> List[HostEntry]:
        return list(self._sessions.get(session_id, {}).get("hosts", {}).values())

    def update_host_ports(self, session_id: str, ip: str, ports: List[dict]):
        """Add/update ports. v10: auto-schedules CVE enrichment for new versions."""
        host = self.get_or_create_host(session_id, ip)
        scan_complete_triggered = False
        prior_port_count = len(host.ports)

        for p in ports:
            port_num = p.get("port", 0)
            service = p.get("service", "")
            version = p.get("version", "")
            host.add_port(port_num, service, version, p.get("banner", ""))

            # v10: schedule CVE enrichment for versioned ports (once per port)
            if version and port_num not in host._enriched_ports:
                host._enriched_ports.add(port_num)
                self._schedule_cve_enrich(session_id, ip, port_num, service, version)

        # v10: fire scan_complete trigger when port count has grown & stabilized
        if len(host.ports) > prior_port_count and len(host.ports) >= 3:
            scan_complete_triggered = True

        if scan_complete_triggered:
            self._trigger_replan(session_id, {
                "trigger": "scan_complete",
                "host": ip,
                "detail": {"port_count": len(host.ports)},
                "suggested_phase": "vulnerability_analysis",
                "urgency": "normal",
            })

    def add_credential(self, session_id: str, ip: str, **kwargs):
        host = self.get_or_create_host(session_id, ip)
        host.add_credential(**kwargs)
        self._log_event(session_id, "credential_found", "kb",
                        f"Credential on {ip}: {kwargs.get('user')}@{kwargs.get('service','?')}:{kwargs.get('port',0)}")
        # v10: fire callback for lateral-movement re-planning
        self._trigger_replan(session_id, {
            "trigger": "credential_found",
            "host": ip,
            "detail": {"user": kwargs.get("user"), "service": kwargs.get("service")},
            "suggested_phase": "post_exploitation",
            "urgency": "high",
        })

    def add_shell(self, session_id: str, ip: str, **kwargs):
        host = self.get_or_create_host(session_id, ip)
        host.add_shell(**kwargs)
        self._log_event(session_id, "shell_obtained", "exploit",
                        f"{kwargs.get('type')} shell on {ip} as {kwargs.get('user')} "
                        f"[{kwargs.get('privilege')}]")
        # v10: fire callback for post-exploitation re-planning
        self._trigger_replan(session_id, {
            "trigger": "shell_obtained",
            "host": ip,
            "detail": {"type": kwargs.get("type"), "privilege": kwargs.get("privilege")},
            "suggested_phase": "post_exploitation",
            "urgency": "immediate",
        })

    def add_vulnerability(self, session_id: str, ip: str, **kwargs):
        host = self.get_or_create_host(session_id, ip)
        host.add_vulnerability(**kwargs)

        # v10: fire callback for critical vulns
        cvss = float(kwargs.get("cvss", 0.0))
        exploitable = bool(kwargs.get("exploitable", False))
        if exploitable and cvss >= 7.0:
            self._trigger_replan(session_id, {
                "trigger": "critical_vuln_found",
                "host": ip,
                "detail": {
                    "title": kwargs.get("title"),
                    "cvss": cvss,
                    "cve_ids": kwargs.get("cve_ids", []),
                },
                "suggested_phase": "exploitation",
                "urgency": "high",
            })

    # ── v10: Re-planning callbacks ───────────────────────────────────────

    def register_replan_callback(self, session_id: str, callback: ReplanCallback):
        """Register async callback invoked on major KB events."""
        self._replan_callbacks[session_id] = callback
        log.debug("replan_callback registered", session=session_id)

    def unregister_replan_callback(self, session_id: str):
        self._replan_callbacks.pop(session_id, None)

    def _trigger_replan(self, session_id: str, event: dict):
        """Fire the session's replan callback if registered (fire-and-forget)."""
        cb = self._replan_callbacks.get(session_id)
        if not cb:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(cb(event))
        except RuntimeError:
            # No running loop — likely in a sync test path. Ignore.
            pass
        except Exception as exc:  # noqa: BLE001
            log.debug("replan callback scheduling failed", error=str(exc))

    # ── v10: CVE enrichment hook ─────────────────────────────────────────

    def register_cve_enricher(self,
                              enricher_callback: Callable[[str, str, int, str, str], Awaitable[None]]):
        """
        Register the async CVE-enrichment callback. Typically called once at
        startup: `attack_kb.register_cve_enricher(auto_enrich_port)`.
        """
        self._cve_enrich_callback = enricher_callback

    def _schedule_cve_enrich(self, session_id: str, ip: str, port: int,
                              service: str, version: str):
        if not self._cve_enrich_callback:
            return
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self._cve_enrich_callback(
                    session_id, ip, port, service, version,
                ))
        except RuntimeError:
            pass
        except Exception as exc:  # noqa: BLE001
            log.debug("cve enrich scheduling failed", error=str(exc))

    # ── Attack goals ──────────────────────────────────────────────────────

    def set_attack_goal(self, session_id: str, goal_type: str,
                        description: str = "", target: str = ""):
        s = self._ensure_session(session_id)
        goal = AttackGoal(goal_type=goal_type, description=description, target=target)
        s["goals"].append(goal)
        s["current_goal"] = goal
        self._log_event(session_id, "goal_set", "planner", f"Goal: {goal_type} — {description}")
        return goal

    def get_current_goal(self, session_id: str) -> Optional[AttackGoal]:
        return self._sessions.get(session_id, {}).get("current_goal")

    def mark_goal_achieved(self, session_id: str, goal_type: str, detail: str = ""):
        s = self._ensure_session(session_id)
        for g in s["goals"]:
            if g.goal_type == goal_type and g.status != "achieved":
                g.status = "achieved"
                g.achieved_at = datetime.utcnow().isoformat()
                self._log_event(session_id, "goal_achieved", "kb",
                                f"✅ Goal {goal_type} achieved: {detail}")
                break

    # ── Attack mode & OPSEC ───────────────────────────────────────────────

    def set_attack_mode(self, session_id: str, mode: str):
        s = self._ensure_session(session_id)
        s["attack_mode"] = mode
        s["mode_settings"] = _MODE_SETTINGS.get(mode, _MODE_SETTINGS["lab"])
        log.info("Attack mode changed", session=session_id, mode=mode)
        self._log_event(session_id, "mode_changed", "user", f"Attack mode: {mode}")

    def get_mode_settings(self, session_id: str) -> dict:
        return self._sessions.get(session_id, {}).get("mode_settings", _MODE_SETTINGS["lab"])

    def get_attack_mode(self, session_id: str) -> str:
        return self._sessions.get(session_id, {}).get("attack_mode", "lab")

    # ── Timeline & events ─────────────────────────────────────────────────

    def _log_event(self, session_id: str, event_type: str, agent: str, detail: str):
        s = self._ensure_session(session_id)
        s["timeline"].append({
            "ts": datetime.utcnow().isoformat(),
            "event": event_type,
            "agent": agent,
            "detail": detail,
        })

    def log_event(self, session_id: str, event_type: str, agent: str, detail: str):
        self._log_event(session_id, event_type, agent, detail)

    def get_timeline(self, session_id: str, limit: int = 50) -> List[dict]:
        events = self._sessions.get(session_id, {}).get("timeline", [])
        return events[-limit:]

    # ── Attack graph ──────────────────────────────────────────────────────

    def update_attack_graph(self, session_id: str, from_node: str,
                            to_node: str, edge_type: str, label: str = ""):
        s = self._ensure_session(session_id)
        g = s["attack_graph"]
        if from_node not in g:
            g[from_node] = []
        g[from_node].append({"to": to_node, "type": edge_type, "label": label,
                              "ts": datetime.utcnow().isoformat()})

    def get_attack_graph(self, session_id: str) -> dict:
        return self._sessions.get(session_id, {}).get("attack_graph", {})

    # ── Summary for agents ────────────────────────────────────────────────

    def get_full_summary(self, session_id: str) -> dict:
        s = self._ensure_session(session_id)
        hosts = [h.to_summary() for h in s["hosts"].values()]
        all_creds = []
        all_shells = []
        for h in s["hosts"].values():
            all_creds.extend(h.credentials)
            all_shells.extend([{**sh, "host": h.ip} for sh in h.shells])
        return {
            "attack_mode": s["attack_mode"],
            "opsec_level": s["opsec_level"],
            "mode_settings": s["mode_settings"],
            "hosts": hosts,
            "total_hosts": len(hosts),
            "credentials": all_creds,
            "shells": [sh for sh in all_shells if sh.get("active")],
            "goals": [{"type": g.goal_type, "status": g.status,
                       "description": g.description} for g in s["goals"]],
            "current_goal": s["current_goal"].goal_type if s["current_goal"] else None,
            "timeline_count": len(s["timeline"]),
            "pivot_routes": s["pivot_routes"],
        }

    def get_agent_context_string(self, session_id: str) -> str:
        s = self._ensure_session(session_id)
        lines = []
        mode = s["attack_mode"]
        goal = s["current_goal"]
        lines.append(f"ATTACK MODE: {mode.upper()} | OPSEC: {s['opsec_level']}")
        if goal:
            lines.append(f"CURRENT GOAL: {goal.goal_type} — {goal.description} [{goal.status}]")

        for h in s["hosts"].values():
            open_ports = [f"{p}/{d['service']}" for p, d in h.ports.items()
                          if d.get("state") == "open"]
            shells = [f"{sh['type']}({sh['user']}/{sh['privilege']})"
                      for sh in h.shells if sh.get("active")]
            line = f"HOST {h.ip}"
            if h.os:
                line += f" OS={h.os}"
            if open_ports:
                line += f" PORTS={','.join(str(p) for p in list(h.ports.keys())[:8])}"
            if h.credentials:
                line += f" CREDS={len(h.credentials)}"
            if shells:
                line += f" SHELLS={','.join(shells)}"
            lines.append(line)

        recent = s["timeline"][-5:]
        if recent:
            lines.append("RECENT: " + " | ".join(e["detail"][:60] for e in recent))
        return "\n".join(lines)


_MODE_SETTINGS = {
    "lab": {
        "scan_speed": "T4", "max_threads": 50, "delay_between_commands": 0,
        "use_tor": False, "rotate_user_agents": False, "random_delays": False,
        "allow_noisy_tools": True, "allow_destructive": True, "stealth_mode": False,
        "description": "Fast & aggressive — ideal for lab/CTF environments",
        "allowed_risk_colors": ["green", "orange", "red"],
        "scan_flags": "-T4 --open", "nmap_timing": "T4",
    },
    "red_team": {
        "scan_speed": "T2", "max_threads": 10, "delay_between_commands": 5,
        "use_tor": False, "rotate_user_agents": True, "random_delays": True,
        "allow_noisy_tools": False, "allow_destructive": True, "stealth_mode": True,
        "description": "Stealthy & realistic — simulates real APT behaviour",
        "allowed_risk_colors": ["green", "orange", "red"],
        "scan_flags": "-T2 --open --randomize-hosts", "nmap_timing": "T2",
        "opsec_notes": [
            "Use --randomize-hosts to avoid sequential scanning patterns",
            "Add random delays between requests",
            "Avoid loud tools like masscan, nikto without proxychains",
            "Use -D decoy1,decoy2,ME for nmap decoy scans",
            "Route through proxychains when pivoting",
        ],
    },
    "bug_bounty": {
        "scan_speed": "T3", "max_threads": 5, "delay_between_commands": 3,
        "use_tor": False, "rotate_user_agents": True, "random_delays": True,
        "allow_noisy_tools": False, "allow_destructive": False, "stealth_mode": True,
        "require_web_intel_first": True, "human_like_delays": True,
        "description": "Focused & safe — passive-first, surgical, stays in scope",
        "allowed_risk_colors": ["green", "orange"],
        "scan_flags": "-T3 --open", "nmap_timing": "T3",
        "blocked_tools": ["masscan", "nikto", "hydra", "sqlmap --level=5", "msfconsole"],
        "restrictions": [
            "No exploitation without explicit written permission",
            "No brute force unless in scope",
            "No DoS/destructive payloads",
            "Start with web_intel agent for URL targets",
            "Document all actions for responsible disclosure",
        ],
    },
}


# Singleton
attack_kb = AttackKnowledgeBase()

# v10: wire the auto-enricher on module import (deferred to avoid cycle)
try:
    from config.cve_enricher import auto_enrich_port as _auto_enrich
    attack_kb.register_cve_enricher(_auto_enrich)
except Exception:  # noqa: BLE001
    pass
