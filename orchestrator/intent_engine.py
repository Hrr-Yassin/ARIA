"""
PentestAI v9 — Intent Engine
Fast regex-based intent classifier. Routes unknown queries to LLM.
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Intent(str, Enum):
    NEW_TARGET   = "new_target"
    SCAN         = "scan"
    RECON        = "recon"
    VULN         = "vuln"
    WEB          = "web"
    EXPLOIT      = "exploit"
    SQLMAP       = "sqlmap"
    REPORT       = "report"
    STATUS       = "status"
    FINDINGS     = "findings"
    CORRELATE    = "correlate"
    QUERY        = "query"
    # New v9 intents
    SET_GOAL     = "set_goal"
    POST_EXPLOIT = "post_exploit"
    SET_MODE     = "set_mode"
    SESSIONS     = "sessions"


@dataclass
class IntentResult:
    intent: Intent
    confidence: float
    target: Optional[str] = None
    subtype: Optional[str] = None
    raw_input: str = ""
    entities: Dict[str, Any] = field(default_factory=dict)
    suggested_reply: str = ""
    needs_confirmation: bool = True
    group_commands: bool = False


IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE    = re.compile(r"https?://\S+")
CVE_RE    = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

PATTERNS = {
    Intent.NEW_TARGET: [
        r"\b(new|add|create|start|register)\b.*(target|host|ip|machine|box|server)",
        r"\b(target|host|ip|machine)\b.*(is|=|:)\s*[\d.]+",
        r"^(scan|test|pentest|hack|check|attack|assess|analyser|scanner)\s+[\d.]+",
        r"^[\d.]+\s*$",
        r"^https?://",
        r"\b(nouvelle.cible|définir.cible|cible.est)\b",
    ],
    Intent.SET_GOAL: [
        r"\b(set.?goal|attack.?goal|objective|mission|goal\s*:)\b",
        r"\b(get|gain|obtain).*(shell|access|initial.access|foothold)\b",
        r"\b(dump|extract|steal|harvest).*(cred|password|hash|secret)\b",
        r"\b(pivot|move|lateral|traverse).*(network|subnet|internal|host)\b",
        r"\b(escalate|privesc|privilege|become.root|get.root|root.the)\b",
        r"\b(persist|maintain.access|backdoor|establish.persistence)\b",
        r"\b(full.compromise|pwn|own.the|complete.takeover)\b",
    ],
    Intent.POST_EXPLOIT: [
        r"\b(post.?exploit|post.?pwn|after.access|after.shell)\b",
        r"\b(privesc|priv.esc|privilege.escal)\b",
        r"\b(hashdump|mimikatz|credential.dump|dump.cred|dump.hash)\b",
        r"\b(lateral.mov|pass.the.hash|pth|smb.relay)\b",
        r"\b(persist|crontab.backdoor|authorized_keys|schtask.malware)\b",
        r"\b(loot|pillage|plunder|enum.local|local.enum)\b",
        r"\b(meterpreter.session|shell.session|active.session)\b",
    ],
    Intent.SET_MODE: [
        r"\b(set.?mode|attack.?mode|switch.?to|enable)\b.*(lab|red.?team|bug.?bounty|stealth)",
        r"\b(lab.mode|red.?team.mode|bug.?bounty.mode)\b",
        r"\b(stealth.?mode|opsec.?mode|quiet.?mode|aggressive.?mode)\b",
    ],
    Intent.SESSIONS: [
        r"\b(sessions?|active.shells?|meterpreter.sessions?|open.shells?)\b",
        r"\b(list.sessions?|show.sessions?|my.shells?)\b",
        r"\b(session.management|manage.sessions?)\b",
    ],
    Intent.SCAN: [
        r"\b(scan|nmap|port|open.port|service|version|detect)\b",
        r"\b(what|which|show).*(port|service|running|open)\b",
        r"\b(enumerate|discover|find).*(port|service|host)\b",
        r"\b(scanner|analyser|balayage|quels?.*(port|service))\b",
    ],
    Intent.RECON: [
        r"\b(recon|whois|dns|subdomain|amass|subfinder|theHarvester)\b",
        r"\b(passive.recon|active.recon|osint|intelligence)\b",
        r"\b(fingerprint|tech.stack|headers|cms.detect)\b",
        r"\b(reconnaissance|ricognizione|recognición)\b",
    ],
    Intent.VULN: [
        r"\b(vuln|cve|exploit.check|nuclei|nikto|searchsploit)\b",
        r"\b(vulnerabilit|weakness|security.flaw|security.issue)\b",
        r"\b(validate.exploit|check.exploit|exploit.works)\b",
    ],
    Intent.WEB: [
        r"\b(web|http|gobuster|ffuf|dirb|directory)\b",
        r"\b(web.scan|web.test|web.app|web.vuln|wpscan)\b",
        r"\b(burp|injection|xss|csrf|lfi|rfi|idor)\b",
    ],
    Intent.EXPLOIT: [
        r"\b(exploit|msfconsole|metasploit|payload|shell|reverse)\b",
        r"\b(use.module|run.exploit|launch.attack|try.exploit)\b",
        r"\b(sploiter|exploiter|ausnutzen|aprovechar)\b",
    ],
    Intent.SQLMAP: [
        r"\b(sqlmap|sql.inject|sqli|database.dump|db.extract)\b",
    ],
    Intent.CORRELATE: [
        r"\b(correlat|kill.chain|attack.chain|combine|cross.ref|chain)\b",
        r"\b(summarize.all|analyze.all|full.analysis)\b",
    ],
    Intent.REPORT: [
        r"\b(report|generate.report|export|pdf|markdown|latex)\b",
        r"\b(rapport|informe|relazione|bericht)\b",
    ],
    Intent.FINDINGS: [
        r"\b(finding|show.finding|list.vuln|list.find|what.found|results)\b",
        r"\b(resultats|résultats|hallazgos|Ergebnisse)\b",
    ],
    Intent.STATUS: [
        r"\b(status|progress|where.are.we|phase|summary|overview)\b",
        r"\b(état|état.avancement|progreso|stand)\b",
    ],
}

GOAL_TYPE_MAP = {
    r"(get|gain|initial).*(shell|access|foothold)": "initial_access",
    r"dump.*(cred|password|hash)": "dump_creds",
    r"(pivot|lateral|move).*(network|subnet|internal)": "pivot",
    r"(persist|maintain|backdoor)": "persistence",
    r"(privesc|escalate|root|become.admin)": "privilege_escalation",
    r"(full.compromise|pwn|own|takeover)": "full_compromise",
}

MODE_MAP = {
    r"lab": "lab",
    r"red.?team": "red_team",
    r"bug.?bounty": "bug_bounty",
    r"stealth": "red_team",
    r"aggressive": "lab",
}

POST_TYPE_MAP = {
    r"(priv.?esc|escalat|sudo|root)": "privesc",
    r"(cred|hash|dump|mimikatz|shadow|sam)": "dump_creds",
    r"(lateral|pivot|pass.the.hash|move)": "lateral",
    r"(persist|backdoor|crontab|schtask)": "persist",
    r"(session|shell|meterpreter)": "situational_awareness",
}


class IntentEngine:
    def parse(self, text: str, current_target: str = "") -> IntentResult:
        lower = text.lower().strip()

        # Extract entities
        ip_m    = IP_RE.search(text)
        url_m   = URL_RE.search(text)
        domain_m = DOMAIN_RE.search(text)
        cve_m   = CVE_RE.search(text)

        detected_target = (
            url_m.group() if url_m else
            ip_m.group() if ip_m else
            (domain_m.group() if domain_m and "." in domain_m.group() else None)
        ) or current_target

        entities: Dict[str, Any] = {}
        if cve_m:
            entities["cve"] = cve_m.group()
        if ip_m:
            entities["ip"] = ip_m.group()

        # Detect scan type
        if "full" in lower or "-p-" in lower or "all port" in lower:
            entities["scan_type"] = "full"
        elif "stealth" in lower or "-T1" in lower or "-T2" in lower:
            entities["scan_type"] = "stealth"
        elif "udp" in lower:
            entities["scan_type"] = "udp"
        else:
            entities["scan_type"] = "quick"

        # Score each intent
        scores: Dict[Intent, float] = {}
        for intent, patterns in PATTERNS.items():
            score = 0.0
            for pat in patterns:
                if re.search(pat, lower):
                    score += 1.0
            if score > 0:
                scores[intent] = score / len(patterns)

        if not scores:
            return IntentResult(intent=Intent.QUERY, confidence=0.5,
                                target=detected_target, raw_input=text, entities=entities)

        best = max(scores, key=scores.get)
        confidence = min(scores[best] * 2, 1.0)

        # Special handling for new intents
        if best == Intent.SET_GOAL:
            goal_type = "initial_access"
            for pat, gtype in GOAL_TYPE_MAP.items():
                if re.search(pat, lower):
                    goal_type = gtype
                    break
            entities["goal_type"] = goal_type
            return IntentResult(
                intent=Intent.SET_GOAL, confidence=confidence,
                target=detected_target, raw_input=text, entities=entities,
                suggested_reply=f"Setting attack goal: **{goal_type.replace('_', ' ')}**",
                needs_confirmation=False,
            )

        if best == Intent.SET_MODE:
            mode = "lab"
            for pat, m in MODE_MAP.items():
                if re.search(pat, lower):
                    mode = m
                    break
            entities["attack_mode"] = mode
            return IntentResult(
                intent=Intent.SET_MODE, confidence=confidence,
                target=detected_target, raw_input=text, entities=entities,
                suggested_reply=f"Switching to **{mode.replace('_', ' ').title()}** mode",
                needs_confirmation=False,
            )

        if best == Intent.POST_EXPLOIT:
            post_type = "auto"
            for pat, pt in POST_TYPE_MAP.items():
                if re.search(pat, lower):
                    post_type = pt
                    break
            entities["post_type"] = post_type
            return IntentResult(
                intent=Intent.POST_EXPLOIT, confidence=confidence,
                target=detected_target, raw_input=text, entities=entities,
                needs_confirmation=True,
            )

        # NEW_TARGET: only if there's an actual target detected
        if best == Intent.NEW_TARGET and not detected_target:
            if current_target:
                best = Intent.QUERY
                confidence = 0.4
            else:
                best = Intent.QUERY

        return IntentResult(
            intent=best, confidence=confidence,
            target=detected_target, raw_input=text, entities=entities,
            needs_confirmation=best in (Intent.EXPLOIT, Intent.SQLMAP, Intent.VULN),
        )


intent_engine = IntentEngine()
