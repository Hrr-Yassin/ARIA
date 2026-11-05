"""
PentestAI v10 — Attack Planner Agent
Builds goal-driven, step-by-step attack paths.

v10 additions:
  • Playbook lookup — at the start of process(), query the playbook store for
    historical paths matching the target's services. Render as "HISTORICAL PLAYBOOK"
    suggestion block in the prompt. Human still approves every red-risk step.
  • Smart LLM routing — uses task_type="attack_planning" (tier 3, best model).
  • Semantic similar-case retrieval — cross-session pattern recognition.
"""
from agents.base_agent import BaseAgent
from memory.attack_knowledge_base import attack_kb
from memory.playbook_store import playbook_store

GOAL_TEMPLATES = {
    "discovery": {"description":"Assess configured services with bounded observations", "phases":["recon","scan"], "success_criteria":"Durable TCP port and HTTP observations within scope", "typical_path":"Bounded connect scan then HTTP observation; no access claim"},
    "initial_access": {
        "description": "Gain first shell or foothold on the target",
        "phases": ["recon", "scan", "vuln", "exploit"],
        "success_criteria": "Obtain any interactive shell on target",
        "typical_path": "Port scan → service enum → exploit weak service → shell",
    },
    "dump_creds": {
        "description": "Extract credentials (hashes, plaintext, tokens)",
        "phases": ["scan", "exploit", "post_exploitation"],
        "success_criteria": "Obtain at least one valid credential set",
        "typical_path": "Initial access → hashdump/mimikatz/grep configs → crack offline",
    },
    "pivot": {
        "description": "Move laterally from current foothold to new host/subnet",
        "phases": ["post_exploitation", "scan", "exploit"],
        "success_criteria": "Successfully reach and interact with an internal host",
        "typical_path": "Shell → route add/proxychains setup → scan internal range → exploit internal service",
    },
    "persistence": {
        "description": "Establish a mechanism to regain access after reboot/disconnect",
        "phases": ["post_exploitation"],
        "success_criteria": "Persistence mechanism survives reboot or session loss",
        "typical_path": "Shell → crontab/schtasks/registry run key/service install",
    },
    "privilege_escalation": {
        "description": "Elevate from user to root/SYSTEM",
        "phases": ["post_exploitation"],
        "success_criteria": "Obtain root or SYSTEM privilege",
        "typical_path": "Low-priv shell → sudo misconfig/SUID/kernel exploit/token steal → root",
    },
    "full_compromise": {
        "description": "Complete takeover: access, credentials, pivot, persistence",
        "phases": ["recon", "scan", "vuln", "exploit", "post_exploitation"],
        "success_criteria": "Root/SYSTEM on primary target + lateral movement + persistence",
        "typical_path": "Full PTES pipeline from recon to persistence",
    },
}

SYSTEM = """You are the ATTACK PLANNER agent — a senior red team operator.
Your job: translate a high-level attack GOAL into a concrete, ordered attack plan.

You receive:
- The attack goal (e.g. "get initial access", "dump credentials")
- Current knowledge base state (known hosts, ports, shells, credentials)
- Attack mode (lab / red_team / bug_bounty)
- OPTIONALLY: a HISTORICAL PLAYBOOK suggestion from past engagements on similar targets
- OPTIONALLY: SIMILAR CASES from semantic memory

You output a prioritized, step-by-step attack path with:
1. Which services/ports are the best attack surface for the goal
2. Exact sequence of steps (validate → exploit → post-exploit)
3. Fallback options if primary path fails
4. OPSEC considerations based on attack mode
5. Success criteria for each step

RULES:
- Never suggest exploiting something not yet scanned
- For red_team mode: include stealth techniques (slow scan, delays, decoys)
- For bug_bounty mode: exclude destructive or out-of-scope actions
- Always provide VALIDATE step before EXPLOIT step
- Include confidence score for each path
- If a HISTORICAL PLAYBOOK is provided, revalidate its applicability and prerequisites against
  actual current evidence. NEVER blindly copy — justify deviations.
- Any exploit step (RCE, remote shell, brute-force login, unsafe write) MUST be
  tagged risk_color: "red" — the supervisor loop will block these pending
  explicit human approval.

RESPOND: Valid JSON only. No markdown fences."""


class AttackPlannerAgent(BaseAgent):
    agent_name = "planner"
    agent_role = "Attack Planner — Goal-Driven Path Builder"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return SYSTEM

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        goal_type = input_data.get("goal_type", "discovery")
        target = input_data.get("target", "")
        custom_desc = input_data.get("description", "")

        kb_summary = attack_kb.get_full_summary(session_id)
        kb_context = attack_kb.get_agent_context_string(session_id)
        mode_settings = attack_kb.get_mode_settings(session_id)
        mode = attack_kb.get_attack_mode(session_id)

        goal_template = GOAL_TEMPLATES.get(goal_type)
        if goal_template is None:
            return {"commands":[],"goal_type":goal_type,"suggested_reply":"Blocked: requested goal has no supported template","rejections":[{"code":"unsupported_goal","detail":"Requested goal was preserved; no fallback goal was selected"}]}
        goal_desc = custom_desc or goal_template["description"]

        attack_kb.set_attack_goal(session_id, goal_type, goal_desc, target)

        # Build hosts context
        hosts_ctx = ""
        all_services = []
        for h in kb_summary.get("hosts", []):
            ports_str = ", ".join(str(p) for p in h.get("open_ports", []))
            hosts_ctx += (f"\n  HOST {h['ip']}: {h['port_count']} ports [{ports_str}] "
                         f"| vulns={h['vuln_count']} creds={h['cred_count']} shells={h['shell_count']}")
            # Gather services for playbook lookup
            host_entry = attack_kb.get_host(session_id, h["ip"])
            if host_entry:
                for _p, pd in host_entry.ports.items():
                    svc = pd.get("service", "")
                    ver = pd.get("version", "")
                    if svc:
                        all_services.append(f"{svc} {ver}".strip())

        existing_shells = kb_summary.get("shells", [])
        existing_creds = kb_summary.get("credentials", [])

        # ── v10: Playbook lookup ────────────────────────────────────────
        playbook_block = ""
        matched_playbook = None
        for svc_str in all_services[:6]:
            parts = svc_str.split(maxsplit=1)
            svc = parts[0] if parts else ""
            ver = parts[1] if len(parts) > 1 else ""
            if svc:
                pb = await playbook_store.get_best_playbook(svc, ver, goal_type, user_id=user_id)
                if pb and pb.success_rate >= 0.7:
                    matched_playbook = pb
                    playbook_block = "\n\n" + playbook_store.render_for_prompt(pb)
                    break

        # ── v10: Similar cases from vector store ────────────────────────
        similar_block = ""
        try:
            similar_block = await self.get_similar_cases(
                query=f"attack plan for {goal_type} on services: {', '.join(all_services[:5])}",
                top_k=3, exclude_session=session_id, user_id=user_id,
            )
            if similar_block:
                similar_block = "\n\n" + similar_block
        except Exception:  # noqa: BLE001
            pass

        prompt = f"""ATTACK GOAL: {goal_type.upper()}
DESCRIPTION: {goal_desc}
TARGET: {target}
ATTACK MODE: {mode.upper()} ({mode_settings.get('description','')})
OPSEC: {'STEALTH REQUIRED' if mode_settings.get('stealth_mode') else 'Normal'}

CURRENT KNOWLEDGE BASE:
{kb_context}

KNOWN HOSTS:{hosts_ctx if hosts_ctx else ' None yet — need reconnaissance first'}

EXISTING SHELLS: {len(existing_shells)} active
KNOWN CREDENTIALS: {len(existing_creds)} sets

GOAL TEMPLATE:
- Typical path: {goal_template['typical_path']}
- Success criteria: {goal_template['success_criteria']}

SCAN TIMING: {mode_settings.get('nmap_timing','T4')}
ALLOW NOISY TOOLS: {mode_settings.get('allow_noisy_tools', True)}
ALLOW DESTRUCTIVE: {mode_settings.get('allow_destructive', True)}
{playbook_block}{similar_block}

Build a complete attack plan for this goal:
1. Analyze current KB state — what do we already know?
2. What is missing that we need before we can achieve the goal?
3. Build ordered attack steps specific to what was found
4. If a playbook was provided, consider it but adapt to current evidence
5. For each step: include fallback if it fails
6. TAG EVERY EXPLOIT STEP risk_color=\"red\" so the human must approve it

JSON:
{{
  "goal_type": "{goal_type}",
  "goal_description": "{goal_desc}",
  "attack_mode": "{mode}",
  "readiness": "ready|needs_more_recon|blocked",
  "readiness_reason": "why ready or not",
  "used_playbook": {str(matched_playbook is not None).lower()},
  "estimated_steps": 5,
  "primary_path": [
    {{
      "step": 1,
      "phase": "scan|recon|vuln|exploit|post_exploitation",
      "action": "what to do — specific to what we know",
      "tool": "tool_name",
      "command": "exact shell command with real target/IP",
      "purpose": "what this achieves toward the goal",
      "success_criteria": "what success looks like",
      "risk_color": "green|orange|red",
      "opsec_note": "OPSEC consideration for this step",
      "fallback": "what to do if this fails"
    }}
  ],
  "fallback_paths": [
    {{"name": "...", "trigger": "...", "steps": ["...", "..."]}}
  ],
  "opsec_warnings": ["warning1 if red_team mode"],
  "success_criteria": "overall goal completion definition",
  "confidence": 0.8,
  "suggested_response": "conversational plan summary for the pentester"
}}"""

        # v10: use best model for planning
        result = await self.query_llm_smart(
            user_id, prompt, self.get_system_prompt(skill_level),
            task_type="attack_planning",
        )
        if result.get("success"):
            parsed = self.parse_json(result["content"])
            if parsed:
                commands = []
                for step in parsed.get("primary_path", [])[:6]:
                    if step.get("command"):
                        commands.append({
                            "tool": step.get("tool", ""),
                            "command": step["command"],
                            "purpose": f"[Step {step.get('step','')}] {step.get('action','')}",
                            "risk_color": step.get("risk_color", "orange"),
                            "risk": step.get("risk_color", "medium"),
                            "action_id": self.generate_action_id(),
                            "agent": "planner",
                            "step": step.get("step", 0),
                            "phase": step.get("phase", ""),
                            "opsec_note": step.get("opsec_note", ""),
                            "fallback": step.get("fallback", ""),
                            "can_batch": step.get("risk_color", "orange") == "green",
                        })

                attack_kb.log_event(
                    session_id, "plan_created", "planner",
                    f"Plan for {goal_type}: {len(commands)} steps, "
                    f"readiness={parsed.get('readiness')}, "
                    f"playbook={'yes' if matched_playbook else 'no'}")

                return {
                    "type": "attack_plan",
                    "goal_type": goal_type,
                    "goal_description": goal_desc,
                    "attack_mode": mode,
                    "readiness": parsed.get("readiness", "unknown"),
                    "readiness_reason": parsed.get("readiness_reason", ""),
                    "primary_path": parsed.get("primary_path", []),
                    "fallback_paths": parsed.get("fallback_paths", []),
                    "opsec_warnings": parsed.get("opsec_warnings", []),
                    "success_criteria": parsed.get("success_criteria", ""),
                    "confidence": parsed.get("confidence", 0.5),
                    "used_playbook": matched_playbook.id if matched_playbook else None,
                    "commands": commands,
                    "suggested_reply": parsed.get("suggested_response", ""),
                    "needs_confirmation": True,
                }

        return self._fallback_plan(session_id, goal_type, target, mode, mode_settings)

    def _fallback_plan(self, session_id: str, goal_type: str, target: str,
                       mode: str, mode_settings: dict) -> dict:
        timing = mode_settings.get("nmap_timing", "T4")
        is_stealth = mode_settings.get("stealth_mode", False)
        commands = []

        if goal_type in ("initial_access", "full_compromise"):
            commands = [
                {"tool": "nmap",
                 "command": f"nmap -sS -sV -sC --top-ports 1000 -{timing} {target}",
                 "purpose": "[Step 1] Service discovery for attack surface mapping",
                 "risk_color": "orange", "risk": "medium",
                 "action_id": self.generate_action_id(), "agent": "planner",
                 "can_batch": False},
                {"tool": "nuclei",
                 "command": f"nuclei -target {target} -severity critical,high -silent",
                 "purpose": "[Step 2] CVE scan on discovered services",
                 "risk_color": "orange", "risk": "medium",
                 "action_id": self.generate_action_id(), "agent": "planner",
                 "can_batch": False},
            ]
            if is_stealth:
                commands[0]["command"] += " --randomize-hosts"
                commands[0]["purpose"] += " (stealth: randomized)"
        elif goal_type == "dump_creds":
            commands = [
                {"tool": "msfconsole",
                 "purpose": "[Step 1] Post-exploitation credential dump",
                 "command": f"msfconsole -q -x 'use post/multi/recon/local_exploit_suggester; exit'",
                 "risk_color": "red", "risk": "high",
                 "action_id": self.generate_action_id(), "agent": "planner",
                 "can_batch": False},
            ]

        return {
            "type": "attack_plan",
            "goal_type": goal_type, "attack_mode": mode,
            "readiness": "needs_more_recon",
            "readiness_reason": "LLM unavailable — using template plan",
            "commands": commands,
            "suggested_reply": f"⚠️ Using template plan for **{goal_type}**. "
                                f"Run recon first for an AI-optimized path.",
            "needs_confirmation": True,
            "confidence": 0.4,
        }


attack_planner_agent = AttackPlannerAgent()
