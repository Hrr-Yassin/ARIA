# PentestAI — Orchestrator v11 Build Spec
### Target audience: coding agent (Codex / VSCode agent) continuing this repo
### Scope of this document: architecture + step-by-step build plan only. No exploit payloads, no scope-bypass logic, no evasion techniques. Every phase below treats **scope enforcement as a hard gate**, not a prompt instruction — this is what makes autonomous bug-bounty testing legitimate instead of unauthorized access.

---

## 0. Ground rule that overrides everything else in this file

A bug-bounty program's published scope (in-scope assets, out-of-scope assets, allowed test types, rate limits, disallowed actions like DoS/social engineering/physical) **is the entire legal basis for testing**. The orchestrator must therefore treat scope as a *compiled, enforced allow-list checked in code*, not as context text handed to an LLM and trusted. Every phase below assumes this. If a future contributor (human or agent) proposes removing or weakening the scope gate to "make the agent more autonomous," that is a correctness bug, not a feature — flag it and stop.

---

## 1. Findings from reviewing `orchestrator.py` (v10) that shape this spec

| Gap in v10 | Why it matters for v11's goal | Fix direction |
|---|---|---|
| `engagement_scope` is prompt context only, never code-enforced | An LLM hallucination or prompt-injected finding could propose a command against an out-of-scope host | New `scope_manager` module validates every `AssessmentCommand`/`action` against a compiled scope object *before* it reaches `execution_authorization` |
| `_failed_exploits` is in-process, module-level state | Breaks under multiple workers/sessions, lost on restart — unacceptable for a long-running autonomous loop | Move all session state into the existing `memory/` layer (session-scoped, persisted) |
| `_validate_commands` only checks `nmap/nuclei/gobuster` dedup + MSF module names | Any other tool string passes through with only loose checks | Centralize *all* command validation in one `risk_gate` module with a declared schema per tool |
| LLM-failure fallback (`_default_commands`) still returns active (orange) commands | Autonomous mode should fail closed, not fail active, when reasoning is unavailable | Fallback path returns zero commands + a "planner unavailable" status in autonomous mode |
| `store_discovery` is a knowledge-base write, not an audit log | No tamper-evident record of "what was proposed vs. approved vs. executed" for later disclosure/report | Add an append-only `audit_log` sink, separate from the vector/knowledge store |

---

## 2. Target directory layout

Add a new top-level `orchestrator/` package. It wraps and calls the existing `agents/`, `memory/`, `config/` modules — it does not duplicate their logic.

```
orchestrator/
  __init__.py
  core.py                  # OrchestratorEngine — top-level loop, owns the state machine
  state_machine.py         # Phase enum + transition rules (Scope → Recon → Scan → Enum → Validate → Report)
  scope_manager.py         # Compiles program scope, exposes is_in_scope(), hard-fails anything ambiguous
  bounty_platform/
    __init__.py
    base_connector.py      # Abstract connector interface
    hackerone_connector.py # Pulls program scope + rules of engagement via API
    bugcrowd_connector.py  # Same, for Bugcrowd
    manual_connector.py    # Loads scope from a local signed YAML/JSON for programs without API access
  agent_registry.py        # Maps phase -> which existing agents/* to invoke, with capability declarations
  planner.py                # Wraps OrchestratorAgent.process / _bounded_assessment_plan, adds scope pre-filter
  risk_gate.py              # Single choke point: every command passes through here before execution_authorization
  audit_log.py              # Append-only, hash-chained record of proposed/approved/executed/result
  rate_limiter.py           # Per-target and per-program request-rate controls (respects program's stated limits)
  report_generator.py       # Turns audit_log + findings into a submission-ready report draft (human reviews before sending)
  config/
    scope_schema.json       # JSON schema a program's scope must validate against
    risk_policy.yaml         # Declares which actions are auto-green / require approval / are always-forbidden
  tests/
    test_scope_manager.py
    test_risk_gate.py
    test_state_machine.py
```

Design rule: **no module outside `scope_manager.py` and `risk_gate.py` may call `execution_authorization.execute` directly.** That funnel is what makes the scope guarantee auditable in one place.

---

## 3. Build phases (each phase = one PR-sized unit of work)

### Phase 0 — Repo scaffolding
- Create the directory tree above with empty modules + docstrings describing each file's single responsibility.
- Add `orchestrator/config/scope_schema.json` (JSON Schema) with required fields: `program_id`, `in_scope` (list of host/wildcard/app-id patterns + asset type), `out_of_scope` (same shape), `allowed_test_types` (enum: passive, active-scan, auth-testing, etc.), `disallowed_actions` (enum: dos, social-engineering, physical, destructive), `rate_limit` (requests/sec or similar, optional), `program_notes` (free text, stored but never auto-interpreted as permission).
- Acceptance: schema validates against 2-3 real program scope exports you hand-transcribe for testing (don't scrape live platforms yet).

### Phase 1 — `scope_manager.py`
- `ScopeManager.load(source: BountyPlatformConnector) -> CompiledScope`
- `CompiledScope.is_in_scope(asset: str, action_type: str) -> ScopeDecision` where `ScopeDecision` is `{allowed: bool, reason: str, matched_rule: str|None}`.
- Matching must be **conservative by default**: ambiguous matches (e.g., a subdomain not explicitly listed under a wildcard, or an IP with no stated ownership) resolve to `allowed=False`. Never "allow unless explicitly forbidden."
- Any `disallowed_actions` entry (dos, social-engineering, physical, destructive) hard-blocks regardless of asset match.
- Unit tests: exact-match host, wildcard subdomain, out-of-scope override beats in-scope wildcard, unlisted asset → denied, disallowed action type → denied even for in-scope asset.
- Acceptance: 100% of test cases pass; no network calls in this module (pure logic over a loaded scope object).

### Phase 2 — `bounty_platform/` connectors
- `base_connector.py` defines `BountyPlatformConnector.fetch_program_scope(program_id) -> dict` (raw, pre-validation).
- Implement `manual_connector.py` first (reads a local signed/reviewed YAML) — this is the safe default and what you should use while developing everything else.
- Only after `manual_connector` and `scope_manager` are fully tested, implement `hackerone_connector.py` / `bugcrowd_connector.py` using their official APIs with stored API credentials, read-only scope endpoints.
- Every connector output is run through `scope_schema.json` validation before being handed to `scope_manager.load()`. Reject and halt on schema failure — do not "best-effort" parse an ambiguous scope document.
- Acceptance: connector returns raw dict; a separate adapter function maps platform-specific field names to the internal schema; adapter is unit-tested against saved fixture responses (no live calls in CI).

### Phase 3 — `state_machine.py`
- Reuse the existing phase ordering from `orchestrator.py`'s system prompt (`Recon → Scan → Enumerate → Vuln Validate → Exploit (if validated) → Report`) but make it an explicit enum + transition table instead of prompt text, with a new leading phase: `SCOPE_LOAD` (must complete before `RECON` can start).
- `StateMachine.can_transition(current, proposed) -> bool`; illegal transitions (e.g., jumping to exploit-equivalent "Validate" without a completed scan phase) are rejected in code, mirroring the "NEVER skip phases" rule that's currently only enforced by prompt instruction.
- Acceptance: property test that no sequence of calls can reach `EXPLOIT_VALIDATED` phase without passing through `SCOPE_LOAD → RECON → SCAN → ENUMERATE`.

### Phase 4 — `risk_gate.py`
- Single function: `risk_gate.submit(action: ProposedAction) -> GateResult`.
- Pipeline inside `submit`: (1) schema-validate the action against `risk_policy.yaml` for that tool, (2) call `scope_manager.is_in_scope`, (3) check `rate_limiter`, (4) classify risk color per existing `risk_color` convention, (5) if red → require explicit human approval via the existing `execution_authorization.propose`, else pass to execute.
- This replaces/wraps the current `_validate_commands` logic — port its MSF-module validation and command-dedup logic in here rather than deleting it.
- Acceptance: a fuzz test feeding malformed/boundary actions (missing target, target outside scope, tool not in policy) confirms none reach `execution_authorization.execute`.

### Phase 5 — `audit_log.py`
- Append-only log: each entry `{timestamp, session_id, action_proposed, scope_decision, risk_color, approval_status, approver (if human), execution_result_summary, hash_prev}` — hash-chain each entry to the previous one so the log is tamper-evident.
- This is what turns into your eventual bug-bounty **submission evidence trail** — treat it as a first-class artifact, not a debug log.
- Acceptance: log survives process restart (persisted to disk/DB via existing `memory/` layer), chain-verification function detects any inserted/modified/deleted entry.

### Phase 6 — `agent_registry.py` + `planner.py`
- `agent_registry.py`: declarative map of `phase -> [agent_name, capability_tags]`, reading from the existing `agents/` package (orchestrator, recon, scan, exploit-equivalent, report agents) without changing their internals yet.
- `planner.py`: thin wrapper around the existing `OrchestratorAgent.process()` / `_bounded_assessment_plan()` that (a) injects the current `CompiledScope` into the prompt as context **and** (b) pipes every returned command through `risk_gate.submit()` before anything else touches it. This is the fix for Gap #1 in the table above — scope becomes enforced, not just described.
- Acceptance: integration test where the planner is fed a scenario with an out-of-scope target in the conversation history; resulting commands against that target are rejected by `risk_gate`, and the audit log records the rejection with reason `out_of_scope`.

### Phase 7 — `core.py` (`OrchestratorEngine`)
- Owns the loop: `load_scope → state_machine.start → planner.propose → risk_gate.submit → (if approved) execute via existing executor → analyze_output (existing OrchestratorAgent.analyze_output) → update state → repeat until phase=REPORT or max_steps/time budget hit`.
- Hard stop conditions (fail closed, not open): scope load failure, repeated risk_gate rejections past a threshold, LLM planner unavailable, time/step budget exceeded.
- This is the file that makes the system "autonomous" — keep it as a thin coordinator; all actual judgment calls live in the modules above so they stay independently testable.
- Acceptance: a full dry-run against the `manual_connector` fixture program completes `SCOPE_LOAD → RECON → SCAN` with zero actions outside the fixture's declared scope, verified via `audit_log` chain inspection.

### Phase 8 — `report_generator.py`
- Converts a session's `audit_log` + stored findings into a **draft** report (markdown) in the target platform's typical submission structure (summary, steps to reproduce, impact, evidence references). Mark it explicitly as a draft requiring human review before submission — do not wire this to any auto-submit capability.
- Acceptance: given a fixture session's audit log + findings, output is deterministic and includes only in-scope, risk-gate-approved actions.

### Phase 9 — Observability
- Structured logging (reuse existing `structlog` usage) for every `risk_gate` decision and state transition.
- A minimal metrics counter (actions proposed / approved / rejected-by-scope / rejected-by-risk / executed) per session, surfaced for the human operator dashboard.

---

## 4. What stays manual / human-in-the-loop by design (do not automate these)

- Final approval of any `red`-classified action (this already exists via `execution_authorization` — keep it).
- Submission of any report to the bug-bounty platform.
- Interpretation of ambiguous scope language (e.g., "subdomains of X are in scope except staging environments" where "staging" isn't machine-identifiable) — route these to a human-review queue instead of guessing.
- Initial onboarding of a new program via `hackerone_connector`/`bugcrowd_connector` — require a human to confirm the parsed scope matches the program page before the engine is allowed to run against it.

---

## 5. Suggested build order for the coding agent

1. Phase 0 → 1 → 2 (manual connector only) → 3, with full unit test coverage before touching `core.py`.
2. Phase 4 → 5, since risk_gate and audit_log are the safety backbone everything else depends on.
3. Phase 6 → 7 wiring, run only against `manual_connector` fixtures in a sandboxed/lab target (e.g., Metasploitable2, as v10 already assumes) — not a live bug-bounty program — until the full scope→execute→audit chain is proven.
4. Only after that: Phase 2's live `hackerone_connector`/`bugcrowd_connector`, Phase 8, Phase 9.
5. Live-program use follows, with the human-review gates from Section 4 kept in place.
