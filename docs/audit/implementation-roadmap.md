# ARIA — Phase B Gap Analysis and Prioritized Implementation Roadmap

Audit date: 2026-11-13. Branch `autonoms_pentesters`, HEAD `2fd16db72406a41fc7370537b80d4cb7f7d71bac`.

Phase B evaluates ARIA against the practical competencies of experienced security researchers. Each capability row states what ARIA **actually does** (verified), what is **simulated/planned**, what a **senior engineer would additionally do**, the **architectural gap**, the **smallest safe improvement**, how to **measure** improvement, and estimated effort. No maturity scores are assigned without a rubric; where a label is used, the rubric is stated inline.

## Capability gap analysis (Phase B)

### B1. Attack-surface understanding
- **Does**: open ports/services from nmap receipts become structured KB facts (`memory/parsers.py`, `knowledge_store.py`); planner sees open ports; CVE enrichment annotates service banners (`config/cve_enricher.py`, wired at `memory/attack_knowledge_base.py:565-566`) but "Enrichment only annotates; never triggers exploits".
- **Simulated/planned**: the legacy `_build_attack_surface` and `_is_metasploitable` heuristics; SERVICE_ATTACK_STRATEGY tables (`tools_registry.py:228-261`).
- **Senior would also**: infer application topology (components, trust boundaries, data flows), rank targets by business value, plan coverage by exposure — not just open ports.
- **Gap**: attack-surface model is port/version-centric; application map exists but is human-populated and not connected to run planning.
- **Smallest safe improvement**: feed the (owner-populated) application-map object inventory into the bounded planner prompt as optional context, read-only.
- **Measure**: planner proposals citing application objects in a fixture scenario (offline test); no new execution paths.
- **Effort**: S (1–2 days incl. tests).

### B2. Web application architecture analysis
- **Does**: `web_intel` fast-path auth/tech detection (`agents/web_intel_agent.py:146-199`); deterministic parsers for curl output; Burp import → sealed application map with identities/objects/workflows/permissions.
- **Simulated/planned**: review-only specialist roles reasoning over saved captures.
- **Senior would also**: map routes, state, sessions, roles end-to-end; identify where validation happens (client vs server).
- **Gap**: analysis is evidence-bound but only over saved HTTP captures; no active route discovery beyond a single curl per step.
- **Smallest safe improvement**: enable the specialist review phase to consume multiple cataloged captures per object (already coded; needs lab fixture coverage).
- **Measure**: review tasks created from multi-capture objects in `tests/test_specialist_*`.
- **Effort**: S.

### B3. API and authorization testing
- **Does**: authorization review over recorded objects/permissions with identity switching (`application_map.py` authorization-review), human-controlled; `aria-http` replays with controlled identities (feature-gated OFF here).
- **Simulated/planned**: `authorization:` specialist candidates depend on ≥2 researcher-controlled identities and ≥2 evidence captures — machinery exists, rarely exercised without the authenticated worker.
- **Senior would also**: enumerate endpoints, test every role×object×verb cell, distinguish missing authz from broken authz.
- **Gap**: the IDOR/BOLA machinery is lab-only, feature-gated, and has no real-container HTTP-runner scenario.
- **Smallest safe improvement**: add a real-container `aria-http` scenario to `integration/test_worker.py` (GET replay + budget + expiry) before relying on the capability anywhere.
- **Measure**: the new scenario passes with the built image; offline tests unchanged.
- **Effort**: S–M.

### B4. Authentication and session reasoning
- **Does**: passive detection fast-paths; review templates for authentication specialty; no active credential attacks (hydra adapter exists API-side but worker rejects it).
- **Simulated/planned**: `authentication:http-response` review candidates.
- **Senior would also**: test session fixation, token lifecycle, logout invalidation, multi-factor gaps on lab apps.
- **Gap**: no active authentication testing capability; the lab's controlled identities are the only session material.
- **Smallest safe improvement**: none without a new tool profile — record as blocked; do not add tools without Phase C adapter discipline.
- **Measure**: n/a (blocked).
- **Effort**: M (later, via typed adapter).

### B5. Business-logic vulnerability investigation
- **Does**: business-logic review template over recorded workflows (`specialist_integration.py:310-329`); correlation specialist.
- **Simulated/planned**: workflow invariants are human-recorded.
- **Senior would also**: model invariants, test state transitions, race conditions, negative amounts, cross-entity flows.
- **Gap**: no active multi-step workflow testing; single-request worker.
- **Smallest safe improvement**: encode workflow invariant checks as review questions (already templated); extend benchmark cases to business-logic fixtures.
- **Measure**: benchmark cases with workflow ground truth.
- **Effort**: M.

### B6. Input validation and injection analysis
- **Does**: input-validation review template; deterministic JSON/HTTP parsers; no active injection testing (curl only).
- **Simulated/planned**: `input_validation:` candidates from captured objects.
- **Senior would also**: fuzz parameters, test parser differentials, encoding bypasses on lab apps.
- **Gap**: no active fuzzing/injection capability; a scanner match would be an observation only (correctly).
- **Smallest safe improvement**: none without a new tool profile — blocked; requires the typed-adapter slice first.
- **Measure**: n/a.
- **Effort**: M–L (later).

### B7. Cloud and IAM security analysis
- **Does**: nothing. No cloud adapters, no IAM enumeration, no Kubernetes/container-orchestration tooling.
- **Simulated/planned**: nothing.
- **Senior would also**: review IAM policies, assume-role chains, storage exposure, log configs.
- **Gap**: absent; out of the current lab boundary (Fedora/Kali + one target VM).
- **Smallest safe improvement**: none — record as out of scope; do not fabricate capability.
- **Measure**: n/a.
- **Effort**: L (a later engagement profile entirely).

### B8. Evidence correlation and uncertainty handling
- **Does (strong)**: bounded owner-bound observations with hashes; untrusted-data framing on evidence in prompts; specialist context separates `confirmed_evidence` (worker receipts) from hypotheses/observations (`specialist_integration.py:677-765`); verification state machine rejects non-fresh sources.
- **Simulated/planned**: vector-store similarity (feature-gated).
- **Senior would also**: cross-finding causal chains with explicit confidence intervals.
- **Gap**: uncertainty is binary (verified/unverified); no numeric confidence or alternative-explanation ledger per hypothesis (decision-log text exists but is unstructured).
- **Smallest safe improvement**: add structured `alternative_explanations` field to specialist result contract (pydantic), populate from templates, show in planner context.
- **Measure**: contract tests + planner-context fixture.
- **Effort**: S.

### B9. Adaptive hypothesis generation
- **Does**: planner sees validation feedback, executed commands, open ports, specialist context; anti-loop dedup by command digest; rejection feedback loops (3 corrective attempts).
- **Simulated/planned**: `react_loop` exists but is not wired into the main flow.
- **Senior would also**: maintain explicit hypothesis list with status (untested/testing/disconfirmed/confirmed), retest on new evidence.
- **Gap**: hypotheses live in team ledger + decision log text, but the run planner has no first-class hypothesis ledger to plan against.
- **Smallest safe improvement**: expose the team-ledger hypothesis list (already in `planner_context`) as explicit "unconfirmed hypotheses" block in the bounded planner prompt (it is present; strengthen test coverage asserting it appears).
- **Measure**: offline planner fixture asserts the block.
- **Effort**: XS–S.

### B10. Independent reproduction and false-positive rejection
- **Does (strong for humans)**: verification ledger requires fresh-source reproduction, negative controls, content verification, human signoff — all enforced in code.
- **Simulated/planned**: none autonomous — by design.
- **Senior would also**: same, plus retest cadence for non-reproducible findings.
- **Gap**: no autonomous reproduction — the system can never "confirm" a finding; retest/outcome tracking exists for reports (Phase 6) but is disconnected from verification.
- **Smallest safe improvement**: link report retest/outcome records to verification findings (read-only view), keeping reproduction human-driven.
- **Measure**: view test with fixture data.
- **Effort**: S.

### B11. Reporting quality and remediation analysis
- **Does (strong)**: reviewed-report drafts with evidence manifests, sha256 artifacts, outcomes and retests (`professional_reports.py`, Phase 6 routes); report_agent assembles from verified data.
- **Simulated/planned**: —.
- **Senior would also**: tailor remediation to stack, provide fix validation steps.
- **Gap**: remediation text quality depends on the model; no structured remediation→retest link per finding (retest records exist).
- **Smallest safe improvement**: bind retest records to finding ids (schema already supports via outcomes; add validation).
- **Measure**: route/store tests.
- **Effort**: S.

### B12. Campaign continuity and research efficiency
- **Does (strong)**: durable checkpoints, replay guards, lease-based supervisor, retry backoff, budgets, fences, recovery — the best-evidenced area (SPEC-10…15).
- **Simulated/planned**: real 8×5 soak (accelerated harnesses only).
- **Senior would also**: operate continuously with human review queues.
- **Gap**: no measured multi-hour production run; per-call latency/cost not stored; no prompt caching.
- **Smallest safe improvement**: (a) store latency + settlement in model_attempt; (b) schedule a real 8-hour supervised lab soak when the lab is available (record as blocker until then).
- **Measure**: (a) unit test; (b) soak report artifact.
- **Effort**: (a) XS; (b) operational, 1 day supervised.

## Rubric note

The labels above use this rubric: **S/XS** ≈ hours–2 days; **M** ≈ 3–10 days; **L** ≈ multi-week; each improvement is "safe" only if it adds no execution authority, weakens no boundary, and ships with regression tests. Anything labeled blocked/out-of-scope is a capability admission, not a plan.

## Phase I — prioritized ranking

Rank = Impact (research capability) × Evidence of necessity (verified gap) × Feasibility × (1/Risk) × (1/Cost). Top candidates, verified gaps only:

| # | Slice | Evidence (file:line) | Impact | Risk | Cost | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | **Worker image missing `orchestrator/program_scope.py`** — program-policy jobs would 500 on an image-only service deployment while `/capabilities` advertises `program_policy_version: 1` | `worker/service.py:44-56`, `worker/Dockerfile`, `worker/app.py:129` | M (reliability of program-policy enforcement) | minimal | XS | defect fix + admission guard + regression test |
| 1 | **Typed adapter dispatch slice (Phase C)**: wire the declarative registry's `TCPConnect`/`HTTPObservation` request validation into the existing jobs-v1 dispatch so agents submit typed operations (curl/nmap only), with structured receipts and failure classification — before any new tool | `config/security_tool_registry.py:269-341`, `worker/policy.py:38-62`, `memory/worker_jobs.py:337-448` | **H** (foundation for every future tool, evidence schemas, and the "senior team" claims) | low–med | M | the single coherent slice that improves real capability; strictly no new tools |
| 2 | Authorization-surface alignment: apply `_campaign_owner` semantics to `autonomous/*` routes; decide explicitly whether admin override is intended there and log it; add Origin check to `ws_chat` | `api/routers/pentest.py:1252-1270,1314-1321`, `memory/execution_authorization.py:155-167`, `pentest.py:576-578` | M (security consistency) | minimal | XS | audit-decision first: record the intended policy, then code |
| 3 | Repair the 5 failing offline tests (harness patch scope) | §8 of architecture-review | M (evidence hygiene — every later slice depends on green regressions) | minimal | XS | do before slice 1 |
| 4 | Phase E quick wins: stable-prefix + `cache_control` on OpenRouter/Gemini adapters; persist latency/cache metadata in `model_attempt` | `llm/pool_manager.py`, `llm/gemini_client.py`, `llm/openrouter_client.py` | M (cost per 8×5) | low | S–M | never claim caching without provider usage metadata |
| 5 | Real-container `aria-http` scenario in `integration/test_worker.py` (B3) | `integration/test_worker.py` | M | low | S–M | unblocks authenticated testing claims |
| 6 | Structured alternative-explanations field (B8) + planner hypothesis block test (B9) | `agents/result_contract.py`, `specialist_integration.py:730-749` | M | minimal | S | |
| 7 | Real 8-hour supervised lab soak (B12b) | — | H (the 8×5 goal itself) | low (supervised) | operational | **blocked**: requires lab availability + human supervision; do not claim from simulations |
| 8 | Benchmark measured arms (Phase H) | `evaluation/benchmark.py:135-162` | H | low | operational | **blocked**: requires participants/protocol; not this session |

**Session decision (2026-11-13)**: slices 0 and 3 are the smallest, safest, evidence-backed changes and are prerequisites for every later slice (they repair the shipped artifact set and the regression signal). They are implemented in this session as the first approved improvement; slice 1 (typed dispatch) is the first major slice and is **proposed, not started** — it needs review of the acceptance criteria below.

### Acceptance criteria for slice 1 (typed dispatch, proposed)

1. Problem: agents emit free-form command strings; the new registry validates typed requests but has no dispatch path (`structured_dispatch_not_implemented`).
2. Files: `config/security_tool_registry.py`, `memory/worker_jobs.py` (or a new `orchestrator/typed_dispatch.py`), `api/routers/pentest.py`, tests.
3. Architecture: typed request → registry validation (offline) → canonical command via existing `validate_worker_command` → **same** proposal/approval/execute gate → same jobs-v1 worker → structured receipt mapped into the existing `ToolResult` envelope. No new tools, no new authorization, no new network paths.
4. Acceptance: (a) offline tests for validation+canonicalization roundtrip; (b) all 475 existing tests green; (c) a `phase`-style isolated worker script proves one typed nmap and one typed curl end-to-end; (d) registry catalog reports the dispatch path as available **only** when it is.
5. Rollout: merge only after review; do not start slice 2 until slice 1 is validated.

## Blocked items (recorded, not bypassed)

- Real 8-hour soak: requires the lab worker + Metasploitable VM + human supervision window.
- Benchmark measured arms: requires a human researcher, a single-assistant arm, and a retained protocol.
- Any new tool beyond curl/nmap/aria-http: requires slice 1 first, then per-tool image/version/schema review (Phase C discipline).
- Kali/Fedora host changes: no approval in this session; untouched.
