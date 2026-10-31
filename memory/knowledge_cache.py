"""
PentestAI v8 — Knowledge Cache
Redis-backed cache for scan results, open ports, and cross-agent correlation.
Prevents duplicate scans and enables shared intelligence across agents.
"""
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

import structlog

log = structlog.get_logger(__name__)


class KnowledgeCache:
    """In-memory + Redis cache for scan results and discoveries."""

    def __init__(self):
        self._redis = None
        self._local: Dict[str, Dict] = {}  # session_id -> {tool:target:subtype -> data}

    async def initialize_redis(self, redis_client):
        self._redis = redis_client

    def _key(self, session_id: str, tool: str, target: str, subtype: str = "") -> str:
        return f"cache:{session_id}:{tool}:{target}:{subtype}".rstrip(":")

    def store(self, session_id: str, tool: str, target: str, command: str,
              raw_output: str, analysis: dict, subtype: str = ""):
        """Store scan result in cache."""
        key = self._key(session_id, tool, target, subtype)
        entry = {
            "tool": tool,
            "target": target,
            "command": command,
            "raw_output": raw_output[:10000],
            "analysis": analysis,
            "subtype": subtype,
            "timestamp": datetime.utcnow().isoformat(),
            "ts": time.time(),
        }
        self._local.setdefault(session_id, {})[key] = entry

    def has(self, session_id: str, tool: str, target: str, subtype: str = "") -> bool:
        key = self._key(session_id, tool, target, subtype)
        return key in self._local.get(session_id, {})

    def get(self, session_id: str, tool: str, target: str, subtype: str = "") -> Optional[dict]:
        key = self._key(session_id, tool, target, subtype)
        return self._local.get(session_id, {}).get(key)

    def get_all_for_session(self, session_id: str) -> list:
        return list(self._local.get(session_id, {}).values())

    def get_open_ports(self, session_id: str, target: str = "") -> list:
        """Extract open ports from cached nmap results."""
        ports = []
        seen = set()
        for entry in self._local.get(session_id, {}).values():
            if entry.get("tool") not in ("nmap", "masscan", "rustscan"):
                continue
            analysis = entry.get("analysis", {})
            verbose = analysis.get("verbose", {})
            for svc in verbose.get("services_detected", []):
                if svc not in seen:
                    seen.add(svc)

            # Parse from findings
            for f in analysis.get("findings", []):
                title = f.get("title", "")
                evidence = f.get("evidence", "")
                # Extract port from evidence line
                import re
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", evidence)
                if m:
                    port_data = {"port": int(m.group(1)), "service": m.group(2), "version": m.group(3).strip()}
                    key = (port_data["port"], port_data["service"])
                    if key not in seen:
                        seen.add(key)
                        ports.append(port_data)

        return ports

    def get_findings_summary(self, session_id: str) -> dict:
        """Aggregate all findings from cache."""
        all_findings = []
        seen_titles = set()

        for entry in self._local.get(session_id, {}).values():
            analysis = entry.get("analysis", {})
            for f in analysis.get("findings", []):
                title_key = f.get("title", "").lower()[:50]
                if title_key not in seen_titles:
                    seen_titles.add(title_key)
                    all_findings.append(f)

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda x: sev_order.get(x.get("severity", "info"), 5))

        counts = {}
        for f in all_findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1

        return {"findings": all_findings, "counts": counts, "total": len(all_findings)}

    def get_session_context_summary(self, session_id: str) -> str:
        """Build concise context summary for LLM prompts."""
        entries = self.get_all_for_session(session_id)
        if not entries:
            return "No scans performed yet."

        lines = []
        for e in entries[-5:]:  # Last 5 results
            tool = e.get("tool", "")
            analysis = e.get("analysis", {})
            summary = analysis.get("summary", analysis.get("chat_message", ""))
            if summary:
                lines.append(f"[{tool}] {summary[:200]}")

        return "\n".join(lines) if lines else "No significant results yet."

    def get_technologies(self, session_id: str) -> dict:
        """Extract detected technologies from all cached results."""
        techs = {"web_server": "", "os": "", "languages": [], "frameworks": [], "cms": ""}

        for entry in self._local.get(session_id, {}).values():
            analysis = entry.get("analysis", {})
            for f in analysis.get("findings", []):
                desc = f.get("description", "").lower()
                title = f.get("title", "").lower()
                if "apache" in desc or "apache" in title:
                    techs["web_server"] = "Apache"
                elif "nginx" in desc:
                    techs["web_server"] = "Nginx"
                elif "iis" in desc:
                    techs["web_server"] = "IIS"
                if "php" in desc:
                    if "PHP" not in techs["languages"]:
                        techs["languages"].append("PHP")
                if "wordpress" in desc:
                    techs["cms"] = "WordPress"
                if "linux" in desc:
                    techs["os"] = "Linux"
                elif "windows" in desc:
                    techs["os"] = "Windows"

        return techs

    def clear_session(self, session_id: str):
        self._local.pop(session_id, None)


knowledge_cache = KnowledgeCache()
