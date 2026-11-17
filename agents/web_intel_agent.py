"""
PentestAI v9 — Web Intel Agent
Solution 17: Intelligent web pentesting agent for bug bounty mode.
Passive-first, human-like behavior, HTTP analysis, auth detection.
Solution 16: Smart HTTP analysis, endpoint scoring, auth fingerprinting.
"""
import re
from agents.base_agent import BaseAgent
from memory.attack_knowledge_base import attack_kb

SYSTEM = """You are the WEB INTEL agent, reviewing authorized recorded HTTP evidence.
Analyze saved traffic before proposing any additional observation.

YOUR CAPABILITIES:
1. Passive HTTP analysis (headers, cookies, tokens, endpoints from traffic)
2. Technology fingerprinting without active scanning
3. Auth mechanism detection: JWT, OAuth, Basic, API Key, Session
4. Endpoint and parameter review priority from names only, never a vulnerability probability
5. Smart test sequencing — one target at a time, with reasoning before action

OPERATING RULES:
- ALWAYS explain your reasoning before suggesting any test
- ALWAYS start passive (observe, analyze) before active testing
- NEVER suggest automated mass-scanning tools (no nikto -C all, no ffuf wordlists)
- ONE endpoint at a time — no parallel testing
- Proposals require the original objective, server scope, capability checks and human approvals.
- Do not route public-page observations directly to exploitation or claim absent services.
- List missing controls, plausible alternative explanations and defensive remediation.

UNVALIDATED REVIEW PRIORITIES (1-10; names alone do not establish risk or likelihood):
- IDOR on user IDs: 9
- JWT alg:none / weak secret: 9
- SQLi in search/filter params: 8
- SSRF in URL params: 8
- OAuth redirect_uri: 8
- XSS in reflected params: 6
- Missing security headers: 3
- Information disclosure: 4

AUTH DETECTION PATTERNS:
- Authorization: Bearer → Bearer scheme; opaque or JWT token format remains unverified
- Authorization: Basic → Basic auth (check default creds)
- Set-Cookie: session → Session (check flags: Secure, HttpOnly, SameSite)
- X-API-Key / api_key param → API Key (check rate limit bypass)
- OAuth2 flow detected → check state param, redirect_uri, PKCE

OUTPUT: Valid JSON only. Include a brief evidence-linked public_rationale before suggestions;do not request or disclose private chain-of-thought.
"""


class WebIntelAgent(BaseAgent):
    agent_name = "web_intel"
    agent_role = "Web Intel — Passive HTTP Analyst"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return SYSTEM

    async def analyze_http_traffic(self, session_id: str, user_id: str,
                                    http_data: dict,
                                    skill_level: str = "intermediate") -> dict:
        """
        Analyze intercepted HTTP traffic passively.
        Detects: auth type, endpoints, vuln-prone params, tech stack.
        """
        target = http_data.get("url", "")
        headers = http_data.get("headers", {})
        params  = http_data.get("params", {})
        body    = http_data.get("body", "")
        cookies = http_data.get("cookies", {})

        # Fast-path: detect auth type without LLM
        auth_type = self._detect_auth(headers, cookies)
        tech_stack = self._detect_tech(headers, body)
        vuln_params = self._score_params(params, body)

        # Update KB
        kb_ctx = attack_kb.get_agent_context_string(session_id)

        prompt = f"""TARGET URL: {target}
HTTP HEADERS: {headers}
PARAMETERS: {params}
COOKIES: {cookies}
BODY SNIPPET: {str(body)[:500]}
DETECTED AUTH: {auth_type}
TECH STACK: {tech_stack}
VULN-PRONE PARAMS (scored): {vuln_params}
KB CONTEXT: {kb_ctx}

Analyze this HTTP traffic passively. Output JSON:
{{
  "public_rationale": "Brief evidence-linked explanation; no private reasoning.",
  "auth_type": "bearer|basic|apikey|session|unknown|none",
  "auth_findings": [],
  "endpoint_score": 0-10,
  "vuln_hypothesis": "conditional candidate only, or insufficient evidence",
  "suggested_test": "missing recorded control evidence; empty when no further action is justified",
  "passive_findings": [],
  "next_step": "what to do next",
  "limitations": ["missing evidence and alternative explanations"]
}}"""

        result = await self.call_llm(
            session_id=session_id, user_id=user_id,
            prompt=prompt, skill_level=skill_level
        )

        # Log to KB
        attack_kb.log_event(session_id, "web_intel_analysis", "web_intel",
                            f"Analyzed {target} → auth:{auth_type} score:{vuln_params}")
        return result or {}

    async def process(self, session_id: str, user_id: str,
                      input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        if 'recorded_evidence_ids' in input_data:
            from memory.burp_community import get_evidence
            from security.evidence_analysis import review_http
            ids = input_data['recorded_evidence_ids']
            if not isinstance(ids,list) or len(ids)>20 or any(not isinstance(ref,str) or not 1<=len(ref)<=100 for ref in ids):
                return {'commands':[], 'rejections':[{'code':'invalid_evidence_selection','detail':'Select at most20owned evidence IDs'}]}
            interpretations=[]
            for ref in dict.fromkeys(ids):
                data=await get_evidence(session_id,ref)
                interpretations.append(review_http(data['summary'],ref))
            return {'type':'analysis','agent':'web_intel','commands':[], 'interpretations':interpretations,
                    'analysis_kind':'deterministic_recorded_http_review','model_calls':0,
                    'suggested_reply':f'Reviewed{len(interpretations)}recorded HTTP observations. Status, auth and scanner hints do not confirm vulnerabilities; inspect missing controls and remediation.',
                    'confirmed_vulnerabilities':[]}
        user_input = input_data.get("user_input", "")
        target     = input_data.get("target", "")
        http_data  = input_data.get("http_data", {})
        kb_ctx     = attack_kb.get_agent_context_string(session_id)
        mode       = attack_kb.get_attack_mode(session_id)

        prompt = f"""USER REQUEST: {user_input}
TARGET: {target}
MODE: {mode.upper()} (bug bounty — passive first, surgical, no noise)
HTTP DATA: {http_data}
KB STATE: {kb_ctx}

Respond as WEB INTEL agent. Output JSON:
{{
  "public_rationale": "Brief evidence-linked explanation;no private reasoning.",
  "agent": "web_intel",
  "phase": "reconnaissance|vulnerability_analysis|report",
  "passive_steps": [],
  "active_steps": [],
  "commands": [],
  "findings": [],
  "auth_analysis": {{}},
  "next_agent": "vuln|correlation|report",
  "opsec_notes": "..."
}}"""

        return await self.call_llm(
            session_id=session_id, user_id=user_id,
            prompt=prompt, skill_level=skill_level
        ) or {}

    # ── Fast-path helpers (no LLM) ────────────────────────────────────

    def _detect_auth(self, headers: dict, cookies: dict) -> str:
        h = {str(k).lower(): v for k, v in headers.items()}
        auth = h.get("authorization", "")
        if not isinstance(auth, str):
            return "unknown"
        if auth.strip():
            parts = auth.strip().split(None, 1)
            if len(parts) != 2 or not parts[1].strip():
                return "unknown"
            scheme = parts[0].lower()
            return scheme if scheme in {"bearer", "basic"} else "unknown"
        if "x-api-key" in h or "api-key" in h:
            return "apikey"
        if cookies:
            ck = " ".join(cookies.keys()).lower()
            if any(w in ck for w in ["session", "sess", "token", "auth"]):
                return "session"
        return "none"

    def _detect_tech(self, headers: dict, body: str) -> list:
        found = []
        h = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        # Advertised product hints only. Unrelated prose is not a fingerprint.
        server = h.get('server', '')
        for tech, pattern in (('nginx', r'\bnginx\b'), ('apache', r'\bapache\b'),
                              ('iis', r'\bmicrosoft-iis\b')):
            if re.search(pattern, server):
                found.append(tech)
        powered = h.get('x-powered-by', '')
        for tech in ('php', 'express'):
            if re.search(r'\b' + tech + r'\b', powered):
                found.append(tech)
        if any(key.startswith('x-aspnet') for key in h):
            found.append('asp.net')
        if re.search(r'''(?:src|href)\s*=\s*["'][^"']*/wp-content/''', str(body), re.I):
            found.append('wordpress')
        return found

    def _score_params(self, params: dict, body: str) -> dict:
        high_risk = ["id", "user_id", "uid", "file", "path", "url", "redirect",
                     "callback", "next", "return", "query", "search", "filter",
                     "order", "sort", "page", "token", "key", "secret"]
        scored = {}
        all_params = list(params.keys()) + re.findall(r'"(\w+)":', str(body))
        for p in all_params:
            pl = p.lower()
            score = 0
            if pl in high_risk:
                score = 8
            elif any(h in pl for h in ["id", "url", "file", "key"]):
                score = 6
            elif any(h in pl for h in ["name", "search", "query"]):
                score = 5
            else:
                score = 2
            if score >= 5:
                scored[p] = score
        return dict(sorted(scored.items(), key=lambda x: -x[1])[:10])


web_intel_agent = WebIntelAgent()
