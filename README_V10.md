# PentestAI v10 — Upgrade Overlay

Academic Proof-of-Concept: **collaborative pentesting between human and AI agents** (as specified in the project brief *"PoC de pentesting collaboratif Humain – Agents IA"*).

## What v10 adds on top of v9

| # | Feature | New files | Modified files |
|---|---------|-----------|----------------|
| 1 | **Autonomous Execution Engine** — plan→exec→parse→KB→replan loop with **blocking human approval** on red-risk steps | `agents/autonomous_engine.py` | — |
| 2 | **ReAct reasoning loop** in the Orchestrator — thought/action/observation trace shown in UI | — | `agents/orchestrator_agent.py` |
| 3 | **Structured output parsers** — nmap/msf/hydra/nikto/nuclei/gobuster/enum4linux outputs parsed into the KB **before** the LLM sees them | `memory/parsers.py` | `agents/orchestrator_agent.py` |
| 4 | **Live CVE enrichment** via NVD API (+ fallback) — replaces the static CVE dict | `config/cve_enricher.py` | `config/tools_registry.py`, `memory/attack_knowledge_base.py` |
| 5 | **Adaptive re-planning callbacks** — critical vuln / shell / credential / scan-complete events trigger automatic replan | — | `memory/attack_knowledge_base.py` |
| 6 | **Semantic vector store** — `sentence-transformers` with graceful keyword fallback; cross-session similar-case retrieval | — | `memory/vector_store.py` |
| 7 | **Tiered LLM routing** — cheap model for analysis, best model for exploit reasoning, deterministic code for intent classification | — | `llm/pool_manager.py`, `agents/base_agent.py` |
| 8 | **Playbook store** — DB-backed successful attack paths surfaced as *suggestions* (human still approves) | `memory/playbook_store.py` | `memory/database_models.py`, `agents/attack_planner_agent.py` |
| 9 | **Decision Log** — every autonomous step, LLM call, and approval is timestamped and queryable via API/UI (satisfies the brief's *"traçabilité complète des décisions"*) | — | `memory/database_models.py`, `api/routers/pentest.py` |
| 10 | **Tactical Terminal frontend** — full redesign with 3-panel layout, AUTO button, live activity log, Intel panel, Decision Log tab, approval banner | — | `web/index.html`, `web/static/styles/index.css`, `web/static/scripts/app.js` |

## Academic brief alignment

The project brief from your school lists six mandatory requirements. Each is covered:

| Requirement (FR) | Where it's implemented |
|------------------|------------------------|
| Un agent orchestrateur | `agents/orchestrator_agent.py` — coordinates recon→scan→vuln→exploit→report phases |
| Des agents spécialisés | `agents/recon_agent.py`, `scan_agent.py`, `vuln_agent.py`, `report_agent.py`, `attack_planner_agent.py` |
| Interaction explicite avec le pentester humain | Approval banner + `/autonomous/approve` endpoint, blocking gate on red-risk steps |
| Traçabilité complète des décisions | `DecisionLog` table + `/decision-log` endpoint + Decisions tab in Intel panel |
| L'exploitation assistée par l'IA mais validée par l'humain | `autonomous_engine.py` — HARD STOP on `risk_color == "red"` until user responds |
| Associe services à CVE, priorise, justifie | `config/cve_enricher.py` (live NVD + fallback) |

## Installation

**Quickest path:**

```bash
# 1. Unzip the overlay next to your existing pentest-fixed directory
unzip pentest-v10-batch-1.zip

# 2. Run the overlay installer pointing at your v9 project
chmod +x pentest-v10-batch-1/apply_v10_overlay.sh
./pentest-v10-batch-1/apply_v10_overlay.sh /path/to/pentest-fixed

# 3. Migrate the database (adds decision_logs table)
cd /path/to/pentest-fixed
python -c "import asyncio; from memory.database_models import init_db; asyncio.run(init_db())"

# 4. Restart
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

The installer backs up every v9 file it replaces into `backup_v9_<timestamp>/` so you can roll back.

## Configuration

New `.env` keys (all optional — sensible defaults):

```bash
# CVE enrichment (free NVD account — higher rate limit)
NVD_API_KEY=

# Autonomous engine limits
AUTONOMOUS_MAX_STEPS=12
AUTONOMOUS_STEP_DELAY_SECONDS=1.5

# Risk threshold: "green_only" | "green_orange" (default, matches brief)
AUTO_RISK_THRESHOLD=green_orange

# Traceability toggle (keep on for the jury)
DECISION_LOG_ENABLED=true
```

## How AUTO mode behaves (the important part)

When the user clicks **AUTO** on the header:

1. Engine starts → emits `auto_activity` events over WebSocket
2. For each step, the orchestrator proposes the next single best command
3. Risk gate:
   - `green` or `orange` → executes immediately, output parsed into KB
   - `red` → emits `waiting_approval`, **loop pauses**, approval banner appears
4. User clicks **Approve / Modify / Reject** in the banner
5. Decision is recorded in `DecisionLog`, loop resumes
6. If a critical finding is added (CVSS ≥ 7 + exploitable), replan fires automatically

Max 12 steps per cycle by default. At any time, the user can click AUTO again to stop. All decisions — AI-made or human-made — appear in the **Decisions** tab for the jury.

## Files delivered

```
pentest-v10-batch-1/
├── README_V10.md                          ← this file
├── apply_v10_overlay.sh                   ← installer
├── requirements.txt                        ← + sentence-transformers, numpy
├── agents/
│   ├── autonomous_engine.py               ★ NEW
│   ├── orchestrator_agent.py              ← rewritten (ReAct, parsers, smart LLM)
│   ├── attack_planner_agent.py            ← rewritten (playbooks, smart LLM)
│   └── base_agent.py                      ← rewritten (query_llm_smart)
├── api/routers/
│   └── pentest_v10_additions.py           ★ NEW (spliced into pentest.py by installer)
├── config/
│   ├── cve_enricher.py                    ★ NEW
│   ├── settings.py                        ← rewritten (v10 keys)
│   └── tools_registry.py                  ← rewritten (dynamic CVE shim)
├── llm/
│   └── pool_manager.py                    ← rewritten (tiered routing)
├── memory/
│   ├── parsers.py                         ★ NEW
│   ├── playbook_store.py                  ★ NEW
│   ├── vector_store.py                    ← rewritten (semantic + keyword fallback)
│   ├── attack_knowledge_base.py           ← rewritten (replan callbacks, CVE hooks)
│   └── database_models.py                 ← rewritten (DecisionLog, Playbook v10)
└── web/
    ├── index.html                         ← rewritten (Tactical Terminal)
    └── static/
        ├── scripts/app.js                 ← rewritten
        └── styles/index.css               ← rewritten
```

## Notes for the demo

- The **Decision Log** tab is your strongest demo evidence of *traçabilité*. Show the jury that every AI decision and every human approval is recorded with timestamps and reasoning.
- The **approval banner** is the *interaction explicite*. Demo a red-risk step being blocked and resolved by you.
- The **playbook store** is shown in the Playbooks tab. Even if empty on day one, explain that it learns over sessions.
- The **ReAct reasoning chain** (collapsible in any AI message) shows the agent's thought process — strong evidence of justified decisions.

## Safety posture

Consistent with the brief's "validée par l'humain" requirement, the engine ships with:
- `AUTO_RISK_THRESHOLD=green_orange` default (never auto-executes red)
- Red-risk commands are always routed through the blocking approval queue
- Rate limits between steps (1.5s) and max-steps-per-cycle (12)
- All commands still pass through the existing v9 scope-validation middleware

Rollback: to return to v9, restore the files from the `backup_v9_*` directory created by the installer.
