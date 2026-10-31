"""
PentestAI v9 — Scope Validator (Enhanced)
Solution 12: Strict, mandatory scope enforcement per session.
Anti-bypass: normalizes commands before validation.
"""
import re
import ipaddress

DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\s+/",r"\bmkfs\b",r"\bdd\s+if=",r"\bshutdown\b",
    r"\breboot\b",r"\bDROP\s+(TABLE|DATABASE)\b",r"\bDELETE\s+FROM\b",
    r"\b>/dev/sd[a-z]\b",r":\(\)\{.*\}",
]

IP_RE     = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE    = re.compile(r"https?://([^\s/]+)")

BUG_BOUNTY_BLOCKED = ["masscan","hydra ","sqlmap --level=5","nikto -C all"]


def _normalize(command: str) -> str:
    cmd = command.strip()
    cmd = re.sub(r'\x1b\[[0-9;]*[mGKH]', '', cmd)
    cmd = re.sub(r'\s+', ' ', cmd)
    cmd = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), cmd)
    return cmd


def _extract_targets(command: str) -> set:
    targets = set()
    targets.update(IP_RE.findall(command))
    for m in URL_RE.finditer(command):
        targets.add(m.group(1))
    for m in DOMAIN_RE.finditer(command):
        t = m.group()
        if t not in {"localhost","example.com"} and not t.endswith(".sh"):
            targets.add(t)
    return targets


def validate_scope(command: str, scope: dict) -> dict:
    violations = []
    normalized = _normalize(command)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, normalized, re.I):
            violations.append(f"Dangerous pattern: {pattern}")
    mode = scope.get("mode", "lab")
    if mode == "bug_bounty":
        for b in BUG_BOUNTY_BLOCKED:
            if b in normalized.lower():
                violations.append(f"Tool blocked in bug_bounty: {b}")
    allowed_targets = set(scope.get("targets", []))
    exclusions      = set(scope.get("exclusions", []))
    safe            = {"127.0.0.1","0.0.0.0","localhost","::1"}
    cmd_targets     = _extract_targets(normalized)
    if allowed_targets and cmd_targets:
        for t in cmd_targets:
            if t in safe or t in exclusions:
                continue
            in_scope = False
            for allowed in allowed_targets:
                try:
                    net = ipaddress.ip_network(allowed, strict=False)
                    if ipaddress.ip_address(t) in net:
                        in_scope = True; break
                except ValueError:
                    if t == allowed or t.endswith("."+allowed):
                        in_scope = True; break
            if not in_scope:
                violations.append(f"Out-of-scope target: {t}")
    for excl in exclusions:
        if excl in normalized:
            violations.append(f"Excluded target: {excl}")
    return {
        "valid": len(violations) == 0,
        "reason": "; ".join(violations) if violations else "OK",
        "violations": violations,
        "normalized_command": normalized,
    }


def scope_is_defined(scope: dict) -> bool:
    return bool(scope and scope.get("targets"))
