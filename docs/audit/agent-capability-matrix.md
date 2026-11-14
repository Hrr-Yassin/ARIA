# ARIA — Agent Capability Matrix (Phase A audit)

Audit date: 2026-11-13. Branch `autonoms_pentesters`, HEAD `2fd16db72406a41fc7370537b80d4cb7f7d71bac`.

Legend — **Implemented**: traceable to executing code. **Tested**: regression coverage exists (see acceptance-matrix). **Planned-only**: named in config/docs but no execution path. **Simulated**: exercised only with fakes/harnesses. **Unavailable**: no code.

## 1. Agent inventory (all agents are in-process classes, not processes)

| Agent | Class/file | Responsibilities actually implemented | Instantiation | Communication |
| --- | --- | --- | --- | --- |
| Orchestrator (planner) | `OrchestratorAgent`, `agents/orchestrator_agent.py` | Two modes: (a) `_bounded_assessment_plan` for the autonomous loop — strict JSON contract, one command, server-revalidated; (b) legacy interactive planning with attack-surface/context assembly. Output analysis (`analyze_output`) runs deterministic parsers BEFORE the LLM and downgrades known-inaccurate CVE claims (`_validate_analysis`) | Singleton `orchestrator_agent` (:877); invoked by engine (`autonomous_engine.py:1193`) and API flow (`pentest.py`) | No direct agent-to-agent calls; writes KB/vector store; reads evidence context |
| Coordinator | `CoordinatorAgent`, `agents/coordinator_agent.py` | `decide_next_agent` — routes interactive input to a specialist role; legacy orchestration bookkeeping | Singleton; invoked from `pentest.py` | Calls specialist `.process()` in-process |
| Recon | `ReconAgent`, `agents/recon_agent.py` | LLM role: passive recon suggestions | Via coordinator or team ledger (`ROLE_BY_SPECIALTY` does not use it) | Returns `AgentResult` contract |
| Scan | `ScanAgent`, `agents/scan_agent.py` | LLM role: scan suggestions | Via coordinator | Returns contract |
| Vuln | `VulnAgent`, `agents/vuln_agent.py` | LLM role: vulnerability analysis; used as `input_validation` specialist in SPEC-13 (`specialist_integration.py:52`) | Via team coordinator | Reads only task evidence inputs; review-only objective |
| Web Intel | `WebIntelAgent`, `agents/web_intel_agent.py` | LLM role: passive HTTP/auth analysis with deterministic fast-paths (`_detect_auth`, `_detect_tech`, `_score_params`); used as exposure/authentication/authorization specialist | Via team coordinator | Review-only; no target traffic |
| Correlation | `CorrelationAgent`, `agents/correlation_agent.py` | LLM role: cross-finding correlation; used as business_logic specialist | Via team coordinator | Review-only |
| Report | `ReportAgent`, `agents/report_agent.py` | Report generation with `worker_evidence_manifest` provenance | Via report routes | Reads findings/evidence |
| Post-exploitation | `PostExploitationAgent`, `agents/post_exploitation_agent.py` | **Hard-stubbed**: `base_agent.py:107-108` returns "Post-access work requires verified access…" before any model call | Via coordinator | None |
| Attack planner | `AttackPlannerAgent`, `agents/attack_planner_agent.py` | Planner alternative role (legacy) | Via coordinator | Returns contract |
| Autonomous engine | `AutonomousEngine`, `agents/autonomous_engine.py` | The bounded run loop: plan → authorize → execute → parse → persist; checkpoint restore; approval queue; WebSocket streaming | Singleton `autonomous_engine` (:1681); background asyncio task per session | Subscribes to KB replan events (`_on_replan_event`); emits event queue |
| Campaign supervisor | `CampaignSupervisor`, `orchestrator/campaign_supervisor.py` | Durable scheduler/lease-holder; never calls a model; never creates authorization | Singleton (:1073); one loop per API process | Drives engine via start/restore/stop; reads campaign store |
| Team coordinator | `TeamCoordinator`, `orchestrator/team_coordinator.py` | Durable task claim → specialist dispatch → collect; duplicate-proof; never dispatches tools | Singleton (:139) | In-process specialist calls with task evidence inputs |
| Specialist integration | `SpecialistIntegration`, `orchestrator/specialist_integration.py` | Deterministic candidate selection + task ensure + bounded run of review-only investigations | Singleton (:768) | Team store ledger as the message bus |

**Agent-to-agent communication = the durable team-task ledger.** There is no message-passing runtime, no swarm, no autonomous sub-agent spawning. "Collaboration" is: evidence → candidate selection → immutable task rows → coordinator dispatches exactly one specialist per task → result collected as an unverified contract → human review.

## 2. Capability matrix

### 2.1 What is real (traceable + tested)

| Capability | Where | Test evidence (offline suite, 470/475 passing at audit) |
| --- | --- | --- |
| Bounded planning loop (≤12 steps, ≤ MAX_MODEL_CALLS model calls, 1.5 s step delay) | `autonomous_engine.py:890-1182` | `tests/test_checkpoints.py`, `test_execution.py` |
| Command allowlist policy (15 tokenized tools API-side; 2 worker-side) | `orchestrator/execution_policy.py:24-205`, `worker/policy.py:38-62` | `tests/test_execution.py`, `test_p1_workers.py`, `test_worker_server.py` |
| Red-risk human approval hard-block (approve/reject/modify; modify re-validated) | `autonomous_engine.py:952-1015`, `execution_authorization.py:155-167` | `tests/test_execution.py` |
| Durable single-use authorizations (CAS before worker contact) | `execution_authorization.py:169-228` | `tests/test_execution.py`, `test_p1_workers.py` |
| Evidence-backed observations (worker receipt required to persist) | `knowledge_store.py`, `autonomous_engine.py:1062-1093` | `tests/test_knowledge_store.py`, `test_context_integrity.py` |
| Checkpoint/restore with replay guards | `autonomous_engine.py:516-800` | `tests/test_checkpoints.py` |
| Campaign scheduling/leases/retry/pause/resume/cancel | `campaign_supervisor.py`, `campaign_store.py` | `tests/test_campaigns.py`, `test_endurance.py` |
| Specialist review tasks (deterministic, duplicate-proof, lease-gated) | `specialist_integration.py`, `team_coordinator.py` | `tests/test_specialist_*.py` (4 files) |
| Model accounting (reservations, settlement, budgets, stop states) | `engagement_budget.py` | `tests/test_engagement_budget.py` (2 errors observed — see §3) |
| Worker isolation (container flags, firewall, privilege drop, deadline kill) | `worker/runtime.py`, `worker/policy.py`, `worker/container_entry.py` | opt-in real-container suite `integration/test_worker.py` (not re-run here; CI job exists) |
| Human finding-verification state machine with positive/negative controls | `finding_verification.py` | `tests/test_finding_verification.py` |
| Reports with evidence manifest + sha256 artifact download | `report_agent.py`, `professional_reports.py`, `api/routers/reports.py` | `tests/test_professional_reports.py`, `test_report_provenance.py` |
| WebSocket live run streaming with origin check + per-event re-auth | `pentest.py:1496-1547` | `tests/test_user_flow.py` (per agent report) |

### 2.2 What is simulated / planned-only / unavailable

| Item | Status | Evidence |
| --- | --- | --- |
| Tools beyond curl/nmap/aria-http (hydra, sqlmap, nuclei, msfconsole, …) | **Unavailable via worker** — adapters exist but jobs worker rejects | `worker/policy.py:41-42`; matrix in architecture-review §5.1 |
| Structured typed tool dispatch (new manifest registry) | **Planned-only** — `structured_dispatch_not_implemented`, no POST route | `security_tool_registry.py:316`, `api/routers/tool_registry.py` |
| Exploitation goals | **Unavailable** — `unsupported_goal` at start | `autonomous_engine.py:304-307` |
| Post-exploitation | **Stubbed** | `base_agent.py:107-108` |
| Browser automation in worker container | **Not implemented** (API-side Playwright renderer only; feature-gated OFF) | `orchestrator/browser_mapping.py`, `settings.BROWSER_MAPPING_ENABLED=False` |
| Eight-hour endurance | **Simulated only** (accelerated harnesses); no wall-clock soak | `docs/spec15-endurance-status.md` |
| Prompt caching | **Not implemented** | grep across `llm/` |
| Cross-session learning ("playbook" auto-save) | **Not implemented** in main flow; vector-store similarity is read-only context injection | `base_agent.py:246-256`, `docs/p2-status.md` ENG-10 |
| ReAct loop | **Implemented but not wired** into the main workflow (`react_loop` experimental) | `orchestrator_agent.py:464-588`, docstring :466 |
| Automatic phase advancement | **Disabled by design** (human review required) | `workflow_engine.py:104-107` |
| Scientific benchmark comparison (human vs single assistant vs ARIA) | **Measured arms missing**; only a deterministic component baseline exists | `evaluation/benchmark.py:135-162`, `docs/phase7-benchmark-status.md` |

## 3. Test-suite health observed at audit

`python -m unittest discover -s tests -t . -q` → 475 tests, **470 passed / 5 failed** on 2026-11-13:

- `tests.test_llm_models.ModelTests.test_gemini_task_routing_honors_configured_model` (ERROR)
- `tests.test_engagement_budget.EngagementBudgets.test_storage_failure_prevents_physical_call_and_failover_counts` (ERROR)
- `tests.test_p1_credentials.CredentialTests.test_model_boundary_redacts_and_key_disable_takes_effect` (FAIL)
- `tests.test_p1_credentials.CredentialTests.test_provider_quota_reservation_prevents_concurrent_overuse` (FAIL)
- `tests.test_planner_readiness.PlannerReadiness.test_no_key_preflight_is_read_only` (FAIL)

Observed root cause: a test-harness socket mock (`AssertionError: Network disabled in tests`) fires inside LLM-client paths those tests do not patch — a harness interaction, pre-existing on this branch. No production code was changed during this audit. Recorded for the roadmap (low-risk fix: align the harness patch scope).

## 4. Ownership/lifecycle of tasks

| Entity | Owner | Lifecycle | Where |
| --- | --- | --- | --- |
| Run state | engine singleton, per session in-process | planning → executing → awaiting_approval → completed/blocked/failed | `autonomous_engine.py` |
| Durable run checkpoint | `autonomous_runs` row (session-scoped) | written before dispatch; restore-validated | `memory/autonomous_runs.py` |
| Campaign | `autonomous_campaigns` row + supervisor lease | scheduled → starting → running → pausing → paused/cancelled/completed/failed | `campaign_store.py`, `campaign_supervisor.py` |
| Specialist task | team ledger immutable events | queued → running → awaiting_review → completed/failed/blocked (human resolves) | `memory/team_tasks.py` |
| Worker job | worker PostgreSQL ledger (fingerprint-bound) | queued → running → succeeded/failed/cancelled | `worker/store.py`, `worker/service.py` |
| Execution authorization | DecisionLog `execution_authorization` row | pending/authorized → approved/rejected → consumed | `execution_authorization.py` |
| Finding (verification) | team ledger `verification_findings` | observation → … → reportable (human transitions only) | `finding_verification.py` |

## 5. Scheduling, ownership, lifecycle — summary for the audit

- One API process required (`--workers 1`) because run state, approval queues and KB are process-local (`docs/aria-phase-a-architecture.md:35`).
- The supervisor is the only scheduler; it never extends per-run step/model limits; per-tick it re-verifies every safety binding (§3 of execution-paths).
- Expired approvals (600 s) and scope/auth changes invalidate proposals deterministically (`execution_authorization.py:147-153`).
- Unresolved worker cancellation fences the engagement (`worker_blocked`); agents cannot clear the fence (`worker-contract.md` API-side recovery, verified in `worker_jobs.py`).
