"""
PentestAI v9 — Web Intel Agent
Solution 17: Intelligent web pentesting agent for bug bounty mode.
Passive-first, human-like behavior, HTTP analysis, auth detection.
Solution 16: Smart HTTP analysis, endpoint scoring, auth fingerprinting.
"""
import re
from agents.base_agent import BaseAgent
from memory.attack_knowledge_base import attack_kb

SYSTEM = """You are the WEB INTEL agent — a senior web application security researcher.
You operate in Bug Bounty mode: passive-first, surgical, human-like. Never noisy.

YOUR CAPABILITIES:
1. Passive HTTP analysis (headers, cookies, tokens, endpoints from traffic)
2. Technology fingerprinting without active scanning
3. Auth mechanism detection: JWT, OAuth, Basic, API Key, Session
4. Endpoint and parameter scoring by vulnerability probability
5. Smart test sequencing — one target at a time, with reasoning before action

OPERATING RULES:
- ALWAYS explain your reasoning before suggesting any test
- ALWAYS start passive (observe, analyze) before active testing
- NEVER suggest automated mass-scanning tools (no nikto -C all, no ffuf wordlists)
- ONE endpoint at a time — no parallel testing
- Random delays between requests (simulate human browsing)
- Suggest manual PoC first, automated tool only as fallback

VULNERABILITY PRIORITY SCORING (1-10):
- IDOR on user IDs: 9
- JWT alg:none / weak secret: 9
- SQLi in search/filter params: 8
- SSRF in URL params: 8
- OAuth redirect_uri: 8
- XSS in reflected params: 6
- Missing security headers: 3
- Information disclosure: 4

AUTH DETECTION PATTERNS:
- Authorization: Bearer → JWT (decode, check alg, exp, claims)
- Authorization: Basic → Basic auth (check default creds)
- Set-Cookie: session → Session (check flags: Secure, HttpOnly, SameSite)
- X-API-Key / api_key param → API Key (check rate limit bypass)
- OAuth2 flow detected → check state param, redirect_uri, PKCE

OUTPUT: Valid JSON only. Include reasoning_chain before any suggestion.
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
  "reasoning_chain": "step by step analysis",
  "auth_type": "jwt|oauth|basic|apikey|session|none",
  "auth_findings": [],
  "endpoint_score": 0-10,
  "vuln_hypothesis": "most likely vulnerability and why",
  "suggested_test": "exact manual test to perform first",
  "passive_findings": [],
  "next_step": "what to do next",
  "opsec_notes": "how to stay stealthy"
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
  "reasoning_chain": "...",
  "agent": "web_intel",
  "phase": "reconnaissance|vulnerability_analysis|exploitation",
  "passive_steps": [],
  "active_steps": [],
  "commands": [],
  "findings": [],
  "auth_analysis": {{}},
  "next_agent": "vuln|exploit|report",
  "opsec_notes": "..."
}}"""

        return await self.call_llm(
            session_id=session_id, user_id=user_id,
            prompt=prompt, skill_level=skill_level
        ) or {}

    # ── Fast-path helpers (no LLM) ────────────────────────────────────

    def _detect_auth(self, headers: dict, cookies: dict) -> str:
        h = {k.lower(): v for k, v in headers.items()}
        auth = h.get("authorization", "")
        if auth.lower().startswith("bearer"):
            return "jwt"
        if auth.lower().startswith("basic"):
            return "basic"
        if "x-api-key" in h or "api-key" in h:
            return "apikey"
        if cookies:
            ck = " ".join(cookies.keys()).lower()
            if any(w in ck for w in ["session", "sess", "token", "auth"]):
                return "session"
        if "oauth" in str(h).lower() or "client_id" in str(h).lower():
            return "oauth"
        return "none"

    def _detect_tech(self, headers: dict, body: str) -> list:
        found = []
        h = str(headers).lower()
        b = str(body).lower()
        tech_sigs = {
            "nginx": "nginx", "apache": "apache", "iis": "iis",
            "php": "x-powered-by: php", "asp.net": "x-aspnet",
            "django": "csrftoken", "rails": "x-runtime",
            "express": "x-powered-by: express", "wordpress": "wp-content",
            "laravel": "laravel_session",
        }
        for tech, sig in tech_sigs.items():
            if sig in h or sig in b:
                found.append(tech)
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
