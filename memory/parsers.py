"""
PentestAI v10 — Structured Output Parsers
==========================================

Deterministic, zero-LLM extraction of structured intelligence from pentest tool
stdout/stderr. Every parser:

  1. Commits its findings directly to the shared `attack_kb`.
  2. Returns a `ParseResult` carrying human-readable event strings.
  3. Fails gracefully — unexpected formats never raise, they return an empty
     ParseResult so the LLM analysis pass can still run on the raw text.

The orchestrator calls `dispatch_parser()` at the start of every `analyze_output()`
invocation, BEFORE the LLM sees the output. The `events` field is then injected
into the LLM prompt as "PRE-PARSED FACTS" so the model never has to re-extract
what we already know with regex-level certainty.

Academic-brief mapping: this module provides the "traçabilité complète des
décisions" requirement — every parsed fact is timestamped and auditable
(via `attack_kb._log_event`) with no AI in the loop.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Dict, Optional

import structlog

from memory.attack_knowledge_base import attack_kb

log = structlog.get_logger("parsers")


# ═════════════════════════════════════════════════════════════════════════════
#  ParseResult — uniform return type
# ═════════════════════════════════════════════════════════════════════════════
@dataclass
class ParseResult:
    """Uniform output of every parser."""
    tool: str = ""
    hosts_updated: List[str] = field(default_factory=list)
    ports_added: List[dict] = field(default_factory=list)
    vulns_added: List[dict] = field(default_factory=list)
    creds_added: List[dict] = field(default_factory=list)
    shells_added: List[dict] = field(default_factory=list)
    events: List[str] = field(default_factory=list)  # human-readable summary lines

    def is_empty(self) -> bool:
        return not any([self.hosts_updated, self.ports_added, self.vulns_added,
                        self.creds_added, self.shells_added, self.events])

    def summary_block(self) -> str:
        """Render as a PRE-PARSED FACTS block for LLM prompts."""
        if self.is_empty():
            return ""
        lines = [f"PRE-PARSED FACTS (from {self.tool}, extracted deterministically):"]
        for e in self.events[:20]:
            lines.append(f"  • {e}")
        return "\n".join(lines)

    def extend(self, other: "ParseResult") -> "ParseResult":
        self.hosts_updated.extend(other.hosts_updated)
        self.ports_added.extend(other.ports_added)
        self.vulns_added.extend(other.vulns_added)
        self.creds_added.extend(other.creds_added)
        self.shells_added.extend(other.shells_added)
        self.events.extend(other.events)
        return self


# ═════════════════════════════════════════════════════════════════════════════
#  NMAP PARSERS
# ═════════════════════════════════════════════════════════════════════════════
def parse_nmap_xml(session_id: str, xml_str: str, target: str = "") -> ParseResult:
    """
    Parse nmap -oX output. Most reliable nmap parser — handles full details.
    """
    result = ParseResult(tool="nmap")
    if not xml_str or "<nmaprun" not in xml_str:
        return result

    try:
        # XML sometimes has a DTD header before <?xml — strip anything before
        idx = xml_str.find("<?xml")
        if idx > 0:
            xml_str = xml_str[idx:]
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        log.debug("nmap xml parse error", error=str(exc))
        return result

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # IP
        ip = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr", "")
                break
        if not ip:
            ip = target
        if not ip:
            continue

        # Hostname
        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        host = attack_kb.get_or_create_host(session_id, ip)
        if hostname and not host.hostname:
            host.hostname = hostname

        # OS detection
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                host.os = match.get("name", "")
                try:
                    host.os_confidence = float(match.get("accuracy", "0")) / 100.0
                except ValueError:
                    pass
                result.events.append(
                    f"OS detected on {ip}: {host.os} ({int(host.os_confidence*100)}%)"
                )

        # Ports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                st = port_el.find("state")
                if st is None or st.get("state") != "open":
                    continue
                try:
                    port_num = int(port_el.get("portid", "0"))
                except ValueError:
                    continue
                svc_el = port_el.find("service")
                service = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
                version_bits = []
                if svc_el is not None:
                    for key in ("product", "version", "extrainfo"):
                        v = svc_el.get(key)
                        if v:
                            version_bits.append(v)
                version = " ".join(version_bits)
                banner = svc_el.get("banner", "") if svc_el is not None else ""

                host.add_port(port_num, service, version, banner, "open")
                result.ports_added.append({
                    "ip": ip, "port": port_num, "service": service, "version": version,
                })
                result.events.append(
                    f"Port {port_num}/tcp open on {ip}: {service}"
                    + (f" ({version})" if version else "")
                )

        result.hosts_updated.append(ip)
        attack_kb.log_event(session_id, "nmap_parsed", "parsers",
                            f"Nmap XML ingested for {ip}: "
                            f"{len(result.ports_added)} port(s)")

    return result


def parse_nmap_greppable(session_id: str, gnmap_str: str, target: str = "") -> ParseResult:
    """
    Parse nmap -oG output. Less detailed than XML but often easier to produce.
    Line format: Host: <ip> (<name>) Ports: <port>/<state>/<proto>//<svc>//<ver>/, ...
    """
    result = ParseResult(tool="nmap")
    if not gnmap_str:
        return result

    for line in gnmap_str.splitlines():
        m = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)\s+Ports:\s+(.+?)(?:\s+Ignored|$)", line)
        if not m:
            continue
        ip = m.group(1)
        hostname = m.group(2)
        port_blob = m.group(3)

        host = attack_kb.get_or_create_host(session_id, ip)
        if hostname and not host.hostname:
            host.hostname = hostname

        for pblob in port_blob.split(","):
            parts = pblob.strip().split("/")
            # port/state/proto//svc//ver
            if len(parts) < 7:
                continue
            try:
                port_num = int(parts[0])
            except ValueError:
                continue
            state = parts[1]
            service = parts[4] or "unknown"
            version = parts[6].replace("|", " ").strip() if len(parts) > 6 else ""
            if state != "open":
                continue
            host.add_port(port_num, service, version, "", "open")
            result.ports_added.append({
                "ip": ip, "port": port_num, "service": service, "version": version,
            })
            result.events.append(
                f"Port {port_num}/tcp open on {ip}: {service}"
                + (f" ({version})" if version else "")
            )
        result.hosts_updated.append(ip)

    if result.hosts_updated:
        attack_kb.log_event(session_id, "nmap_parsed", "parsers",
                            f"Nmap -oG ingested: {len(result.hosts_updated)} host(s)")
    return result


def parse_nmap_stdout(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse regular nmap stdout. Heuristic — only used when XML/gnmap unavailable.
    Captures standard table format:
        PORT     STATE SERVICE    VERSION
        21/tcp   open  ftp        vsftpd 2.3.4
    """
    result = ParseResult(tool="nmap")
    if not stdout:
        return result

    # Find target IP in output; "Nmap scan report for 192.168.1.10"
    current_ip = target
    ip_match = re.search(r"Nmap scan report for (?:\S+\s+\()?(\d+\.\d+\.\d+\.\d+)\)?", stdout)
    if ip_match:
        current_ip = ip_match.group(1)

    if not current_ip:
        return result

    host = attack_kb.get_or_create_host(session_id, current_ip)

    # Port table rows
    port_re = re.compile(
        r"^(\d{1,5})/(tcp|udp)\s+(open|open\|filtered)\s+(\S+)(?:\s+(.+?))?$",
        re.MULTILINE,
    )
    for m in port_re.finditer(stdout):
        try:
            port_num = int(m.group(1))
        except ValueError:
            continue
        service = m.group(4)
        version = (m.group(5) or "").strip()
        # Strip trailing garbage like "syn-ack ttl 64"
        version = re.sub(r"\s+(syn-ack|reset ttl).*$", "", version).strip()
        host.add_port(port_num, service, version, "", "open")
        result.ports_added.append({
            "ip": current_ip, "port": port_num,
            "service": service, "version": version,
        })
        result.events.append(
            f"Port {port_num}/tcp open on {current_ip}: {service}"
            + (f" ({version})" if version else "")
        )

    # OS guess line
    os_m = re.search(r"OS details?:\s+([^\n]+)", stdout)
    if os_m:
        host.os = os_m.group(1).strip()
        result.events.append(f"OS detected on {current_ip}: {host.os}")

    if result.ports_added:
        result.hosts_updated.append(current_ip)
        attack_kb.log_event(session_id, "nmap_parsed", "parsers",
                            f"Nmap stdout ingested for {current_ip}: "
                            f"{len(result.ports_added)} port(s)")
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  METASPLOIT PARSER
# ═════════════════════════════════════════════════════════════════════════════
# Track failed exploits per session (module signature) — mirrors orchestrator pattern.
_msf_failed: Dict[str, set] = {}


def parse_msf_stdout(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse msfconsole stdout. Detects:
      - "[*] Meterpreter session N opened (attacker:port -> target:port)" → add_shell(meterpreter)
      - "[*] Command shell session N opened ..."                          → add_shell(shell)
      - "[-] Exploit failed ..."                                           → track failure
      - "[+] ... - Login Successful: user:pass" (aux scanners)             → add_credential
    """
    result = ParseResult(tool="msfconsole")
    if not stdout:
        return result

    target_ip = target or _first_ipv4(stdout) or ""

    # Sessions opened
    sess_re = re.compile(
        r"\[\*\]\s+(Meterpreter|Command shell)\s+session\s+\d+\s+opened\s+"
        r"\((?P<lhost>[\w.:]+)\s*->\s*(?P<rhost>[\w.:]+)\)",
        re.IGNORECASE,
    )
    for m in sess_re.finditer(stdout):
        shell_type = "meterpreter" if m.group(1).lower().startswith("meterp") else "shell"
        rhost = m.group("rhost").split(":")[0]
        rport_str = m.group("rhost").split(":")[-1] if ":" in m.group("rhost") else "0"
        try:
            rport = int(rport_str)
        except ValueError:
            rport = 0
        attack_kb.add_shell(
            session_id, rhost,
            type=shell_type, port=rport, user="unknown", privilege="user",
            details="obtained via msfconsole",
        )
        result.shells_added.append({
            "ip": rhost, "type": shell_type, "port": rport,
        })
        result.events.append(f"🎯 {shell_type.upper()} shell OPENED on {rhost}:{rport}")

    # MSF auxiliary login successes (ssh_login, ftp_login, smb_login, etc.)
    # Format: "[+] 192.168.1.10:22 - Success: 'root:toor'"
    login_re = re.compile(
        r"\[\+\]\s+(?P<ip>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)\s+-\s+"
        r"(?:Login\s+)?Success(?:ful)?:?\s*['\"]?(?P<user>[^:'\"]+):(?P<pass>[^'\"]+)['\"]?",
        re.IGNORECASE,
    )
    for m in login_re.finditer(stdout):
        ip = m.group("ip")
        try:
            port = int(m.group("port"))
        except ValueError:
            port = 0
        user = m.group("user").strip()
        pwd = m.group("pass").strip()
        attack_kb.add_credential(
            session_id, ip, user=user, password=pwd,
            service=_port_to_service(port), port=port,
        )
        result.creds_added.append({"ip": ip, "user": user, "port": port})
        result.events.append(f"🔑 Credential found: {user}:{pwd} on {ip}:{port}")

    # Failures — track signature so orchestrator can avoid re-running
    fail_re = re.compile(
        r"\[-\]\s+(?:Exploit(?:s)?\s+failed|Failed|No session was created|"
        r"The target is not (?:vulnerable|exploitable))",
        re.IGNORECASE,
    )
    if fail_re.search(stdout):
        # Extract the module used for tracking
        mod_m = re.search(r"use\s+(\S+)|msf\w*\s+\S+\s+(\S+)\s*>", stdout)
        mod_sig = mod_m.group(1) if mod_m and mod_m.group(1) else "unknown"
        _msf_failed.setdefault(session_id, set()).add(mod_sig)
        result.events.append(
            f"❌ MSF module failed: {mod_sig} on {target_ip or 'target'}"
        )
        attack_kb.log_event(session_id, "exploit_failed", "parsers",
                            f"MSF module failed: {mod_sig}")

    if result.shells_added or result.creds_added:
        attack_kb.log_event(session_id, "msf_parsed", "parsers",
                            f"MSF: +{len(result.shells_added)} shell(s), "
                            f"+{len(result.creds_added)} cred(s)")
    return result


def get_failed_msf_modules(session_id: str) -> set:
    """Public accessor for orchestrator's anti-loop logic."""
    return _msf_failed.get(session_id, set())


# ═════════════════════════════════════════════════════════════════════════════
#  HYDRA PARSER
# ═════════════════════════════════════════════════════════════════════════════
def parse_hydra_output(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse hydra output. Success line format:
      [PORT][SERVICE] host: IP   login: USER   password: PASS
    """
    result = ParseResult(tool="hydra")
    if not stdout:
        return result

    # Canonical success line
    hit_re = re.compile(
        r"\[(?P<port>\d+)\]\[(?P<svc>\w+)\]\s+host:\s+(?P<ip>\S+)\s+"
        r"login:\s+(?P<user>\S+)\s+password:\s+(?P<pass>\S+)",
    )
    for m in hit_re.finditer(stdout):
        try:
            port = int(m.group("port"))
        except ValueError:
            port = 0
        ip = m.group("ip")
        svc = m.group("svc")
        user = m.group("user")
        pwd = m.group("pass")
        attack_kb.add_credential(
            session_id, ip, user=user, password=pwd, service=svc, port=port,
        )
        result.creds_added.append(
            {"ip": ip, "user": user, "password": pwd, "service": svc, "port": port}
        )
        result.events.append(f"🔑 Hydra success: {user}:{pwd} on {ip}:{port}/{svc}")

    # Summary line: "1 of 1 target successfully completed, N valid passwords found"
    summary = re.search(r"(\d+)\s+valid\s+password", stdout)
    if summary and int(summary.group(1)) > 0 and not result.creds_added:
        result.events.append(f"Hydra reports {summary.group(1)} valid passwords (format unrecognized)")

    if result.creds_added:
        attack_kb.log_event(session_id, "hydra_parsed", "parsers",
                            f"Hydra: +{len(result.creds_added)} credential(s)")
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  NIKTO PARSER
# ═════════════════════════════════════════════════════════════════════════════
def parse_nikto_output(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse nikto output. Finding lines start with "+ "; OSVDB/CVE refs inline.
    """
    result = ParseResult(tool="nikto")
    if not stdout:
        return result

    target_ip = target or _first_ipv4(stdout) or ""
    # Nikto target line: "+ Target IP: 192.168.1.10"  or "- Target: http://..."
    tgt_m = re.search(r"Target IP:\s+(\d+\.\d+\.\d+\.\d+)", stdout)
    if tgt_m:
        target_ip = tgt_m.group(1)

    if not target_ip:
        return result

    port = 80
    port_m = re.search(r"Target Port:\s+(\d+)", stdout)
    if port_m:
        try:
            port = int(port_m.group(1))
        except ValueError:
            pass

    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()
        # Skip header metadata lines ("Start Time:", "Target Hostname:", ...)
        if re.match(r"(Start Time|Target Hostname|Target IP|Target Port|"
                    r"Server:|Hosts tested|End Time):", body):
            continue

        # Extract CVE/OSVDB refs
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", body, re.IGNORECASE)
        # Severity heuristic — nikto doesn't give CVSS; infer from keywords
        severity = "low"
        lower = body.lower()
        if any(k in lower for k in ("rce", "remote code", "sql injection",
                                    "command execution", "arbitrary file", "shell")):
            severity = "high"
        elif any(k in lower for k in ("xss", "clickjack", "disclosure",
                                       "directory traversal", "admin login")):
            severity = "medium"

        title = body[:160]
        attack_kb.add_vulnerability(
            session_id, target_ip,
            title=f"[nikto] {title}",
            severity=severity,
            cve_ids=[c.upper() for c in cves],
            cvss=0.0,
            description=body,
            exploitable=severity == "high",
            port=port,
        )
        result.vulns_added.append({
            "ip": target_ip, "title": title, "severity": severity,
            "cve_ids": cves, "port": port,
        })
        result.events.append(f"🔍 Nikto [{severity}] on {target_ip}:{port} — {title[:100]}")

    if result.vulns_added:
        result.hosts_updated.append(target_ip)
        attack_kb.log_event(session_id, "nikto_parsed", "parsers",
                            f"Nikto: +{len(result.vulns_added)} finding(s)")
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  NUCLEI PARSER
# ═════════════════════════════════════════════════════════════════════════════
def parse_nuclei_output(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse nuclei output. Line format:
      [template-id] [protocol] [severity] URL [matcher]
    Severities: info | low | medium | high | critical
    """
    result = ParseResult(tool="nuclei")
    if not stdout:
        return result

    severity_cvss = {
        "info": 0.0, "low": 3.5, "medium": 5.5, "high": 7.8, "critical": 9.5,
    }

    nuc_re = re.compile(
        r"\[(?P<tpl>[^\]]+)\]\s+"
        r"\[(?P<proto>[^\]]+)\]\s+"
        r"\[(?P<sev>info|low|medium|high|critical)\]\s+"
        r"(?P<url>\S+)",
        re.IGNORECASE,
    )

    for m in nuc_re.finditer(stdout):
        tpl = m.group("tpl")
        sev = m.group("sev").lower()
        url = m.group("url")

        # Extract IP + port from URL
        ip = _first_ipv4(url) or target or ""
        if not ip:
            continue
        port_m = re.search(r":(\d{2,5})", url)
        port = int(port_m.group(1)) if port_m else (443 if url.startswith("https") else 80)

        # CVE inside template id (e.g. "CVE-2021-44228")
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", tpl, re.IGNORECASE)

        title = f"[nuclei] {tpl}"
        attack_kb.add_vulnerability(
            session_id, ip,
            title=title,
            severity=sev,
            cve_ids=[c.upper() for c in cves],
            cvss=severity_cvss[sev],
            description=f"Template {tpl} matched on {url}",
            exploitable=sev in ("high", "critical"),
            port=port,
        )
        result.vulns_added.append({
            "ip": ip, "title": tpl, "severity": sev,
            "cve_ids": cves, "port": port,
        })
        result.events.append(f"🎯 Nuclei [{sev}] {tpl} on {ip}:{port}")

    if result.vulns_added:
        attack_kb.log_event(session_id, "nuclei_parsed", "parsers",
                            f"Nuclei: +{len(result.vulns_added)} finding(s)")
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  GOBUSTER PARSER
# ═════════════════════════════════════════════════════════════════════════════
def parse_gobuster_output(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse gobuster output. Line format varies by mode:
      dir mode : "/admin                 (Status: 301) [Size: 315]"
      dns mode : "Found: admin.example.com"
      vhost    : "Found: admin.example.com (Status: 200) [Size: 1234]"
    """
    result = ParseResult(tool="gobuster")
    if not stdout:
        return result

    target_ip = target or _first_ipv4(stdout) or ""

    # Dir-mode
    dir_re = re.compile(
        r"^\s*(/\S+)\s+\(Status:\s+(\d{3})\)(?:\s+\[Size:\s+(\d+)\])?",
        re.MULTILINE,
    )
    interesting_paths = []
    for m in dir_re.finditer(stdout):
        path, status, size = m.group(1), m.group(2), m.group(3) or "?"
        interesting_paths.append((path, status, size))

    if interesting_paths and target_ip:
        # Add as one enumeration finding (summary) not one per path
        sample = [f"{p} ({s})" for p, s, _ in interesting_paths[:5]]
        summary = f"Gobuster discovered {len(interesting_paths)} paths: " + ", ".join(sample)
        if len(interesting_paths) > 5:
            summary += f" ...+{len(interesting_paths)-5} more"
        attack_kb.add_vulnerability(
            session_id, target_ip,
            title="[gobuster] Directory/file enumeration",
            severity="info",
            cve_ids=[],
            cvss=0.0,
            description=summary,
            exploitable=False,
            port=80,
        )
        result.vulns_added.append({
            "ip": target_ip, "title": "Gobuster paths", "severity": "info",
            "count": len(interesting_paths),
        })
        for p, s, _ in interesting_paths[:10]:
            result.events.append(f"📁 Path: {p} [{s}] on {target_ip}")

    # DNS / vhost mode
    dns_re = re.compile(r"Found:\s+(\S+?)(?:\s+\(Status:|\s*$)", re.MULTILINE)
    for m in dns_re.finditer(stdout):
        subdomain = m.group(1)
        result.events.append(f"🌐 Subdomain/vhost discovered: {subdomain}")

    if result.events:
        attack_kb.log_event(session_id, "gobuster_parsed", "parsers",
                            f"Gobuster: {len(result.events)} discoveries")
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  ENUM4LINUX PARSER
# ═════════════════════════════════════════════════════════════════════════════
def parse_enum4linux_output(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse enum4linux / enum4linux-ng output. Extracts: users, shares, OS info,
    workgroup/domain, RID range hits.
    """
    result = ParseResult(tool="enum4linux")
    if not stdout:
        return result

    target_ip = target or _first_ipv4(stdout) or ""
    if not target_ip:
        return result

    host = attack_kb.get_or_create_host(session_id, target_ip)

    # OS / platform
    os_m = re.search(r"(?:OS|Platform)[:=]\s+([^\r\n]+)", stdout)
    if os_m and not host.os:
        host.os = os_m.group(1).strip()[:80]
        result.events.append(f"SMB OS detected on {target_ip}: {host.os}")

    # Workgroup / domain
    wg_m = re.search(r"(?:Workgroup|Domain)[:=]\s+(\S+)", stdout)
    if wg_m:
        result.events.append(f"SMB domain/workgroup: {wg_m.group(1)}")

    # Users (various formats from enum4linux / ng)
    users: set = set()
    for m in re.finditer(r"user:\[(?P<u>[^\]]+)\]", stdout):
        users.add(m.group("u"))
    for m in re.finditer(r"index:\s*0x[0-9a-fA-F]+\s+RID:\s*0x[0-9a-fA-F]+\s+\w+:\s*(\S+)", stdout):
        users.add(m.group(1))

    for u in list(users)[:30]:
        # Stash user as a "discovered credential template" (no password yet)
        attack_kb.add_credential(
            session_id, target_ip,
            user=u, password="", service="smb", port=445,
        )
        result.creds_added.append({"ip": target_ip, "user": u, "port": 445})
    if users:
        result.events.append(
            f"👤 SMB users discovered on {target_ip}: {len(users)} ({', '.join(list(users)[:5])}…)"
        )

    # Shares
    share_re = re.compile(
        r"^\s*(\S+)\s+(Disk|IPC|Printer)\s+(.*)$", re.MULTILINE | re.IGNORECASE
    )
    shares = []
    for m in share_re.finditer(stdout):
        shares.append(m.group(1))
    if shares:
        result.events.append(f"📂 SMB shares on {target_ip}: {', '.join(shares[:10])}")
        attack_kb.add_vulnerability(
            session_id, target_ip,
            title="[smb] Enumerable shares",
            severity="low",
            cve_ids=[],
            cvss=0.0,
            description=f"Shares visible: {', '.join(shares)}",
            exploitable=False,
            port=445,
        )
        result.vulns_added.append({"ip": target_ip, "title": "SMB shares", "shares": shares})

    # Null session / guest access
    if re.search(r"Server allows sessions using username ''", stdout) or \
       re.search(r"Anonymous (?:login|access) allowed", stdout, re.IGNORECASE):
        attack_kb.add_vulnerability(
            session_id, target_ip,
            title="[smb] Null / anonymous session allowed",
            severity="medium",
            cve_ids=[],
            cvss=5.0,
            description="SMB accepts anonymous (null) sessions — enables enumeration.",
            exploitable=True,
            port=445,
        )
        result.vulns_added.append({
            "ip": target_ip, "title": "SMB null session", "severity": "medium",
        })
        result.events.append(f"⚠️  SMB null session allowed on {target_ip}")

    if result.events:
        result.hosts_updated.append(target_ip)
        attack_kb.log_event(session_id, "enum4linux_parsed", "parsers",
                            f"enum4linux: {len(result.events)} finding(s)")
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  SEARCHSPLOIT PARSER — opportunistic
# ═════════════════════════════════════════════════════════════════════════════
def parse_searchsploit_output(session_id: str, stdout: str, target: str = "") -> ParseResult:
    """
    Parse searchsploit output. Doesn't mutate KB directly (no target association
    with a specific exploit yet) but emits events so the LLM sees what's available.
    """
    result = ParseResult(tool="searchsploit")
    if not stdout:
        return result

    # Table rows: "Exploit Title | Path"
    row_re = re.compile(r"^\s*(?P<title>[^|]{5,120}?)\s+\|\s+(?P<path>\S+\.\w+)\s*$", re.MULTILINE)
    hits = []
    for m in row_re.finditer(stdout):
        hits.append((m.group("title").strip(), m.group("path").strip()))
    if hits:
        result.events.append(f"🔎 searchsploit: {len(hits)} exploit(s) found")
        for title, path in hits[:6]:
            result.events.append(f"   • {title} → {path}")
    return result


# ═════════════════════════════════════════════════════════════════════════════
#  DISPATCHER
# ═════════════════════════════════════════════════════════════════════════════
# Maps tool keyword → parser function. Order matters: check more-specific first.
_PARSER_DISPATCH = [
    ("nmap",          "_nmap_dispatch"),     # special — pick XML/gnmap/stdout
    ("msfconsole",    parse_msf_stdout),
    ("msfvenom",      parse_msf_stdout),
    ("hydra",         parse_hydra_output),
    ("nikto",         parse_nikto_output),
    ("nuclei",        parse_nuclei_output),
    ("gobuster",      parse_gobuster_output),
    ("ffuf",          parse_gobuster_output),  # similar format
    ("dirb",          parse_gobuster_output),
    ("enum4linux",    parse_enum4linux_output),
    ("searchsploit",  parse_searchsploit_output),
]


def _nmap_dispatch(session_id: str, output: str, target: str) -> ParseResult:
    """Pick the best nmap parser based on output shape."""
    if not output:
        return ParseResult(tool="nmap")
    stripped = output.lstrip()
    if stripped.startswith("<?xml") or "<nmaprun" in output[:500]:
        return parse_nmap_xml(session_id, output, target)
    if re.search(r"^Host:\s+\d", output, re.MULTILINE):
        return parse_nmap_greppable(session_id, output, target)
    return parse_nmap_stdout(session_id, output, target)


def dispatch_parser(session_id: str, tool: str, command: str,
                    output: str, target: str = "") -> ParseResult:
    """
    Main entry point used by the orchestrator. Picks the right parser based on
    tool name (or command string), runs it, returns ParseResult.

    Always returns a valid ParseResult — errors are swallowed and logged.
    """
    if not output:
        return ParseResult(tool=tool or "unknown")

    # Prefer explicit tool, fall back to scanning the command
    needle = (tool or command or "").lower()
    try:
        for key, parser in _PARSER_DISPATCH:
            if key in needle:
                if parser == "_nmap_dispatch":
                    return _nmap_dispatch(session_id, output, target)
                return parser(session_id, output, target)
    except Exception as exc:  # noqa: BLE001
        log.warning("parser crashed — returning empty result",
                    tool=tool, error=str(exc))
        return ParseResult(tool=tool or "unknown")

    # No match — return empty (LLM will still analyze raw output)
    return ParseResult(tool=tool or "unknown")


# ═════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═════════════════════════════════════════════════════════════════════════════
def _first_ipv4(text: str) -> Optional[str]:
    m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
    return m.group(1) if m else None


def _port_to_service(port: int) -> str:
    """Rough mapping used when MSF didn't label the service."""
    return {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "smb",
        143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
        5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
        27017: "mongo",
    }.get(port, "unknown")
