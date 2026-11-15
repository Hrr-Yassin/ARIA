# ARIA reliability implementation plan

Active phase: **07 — Operational visibility and remaining live/measurement gaps**. Continue independent Phase05 compatibility feedback and Phase06 measurement while the two-hour synthetic endurance run remains active. Requirements are stable; update status only with evidence. All requirements are mandatory. Endurance durations retain individual outcomes.

Allowed statuses: NOT_STARTED, IN_PROGRESS, IMPLEMENTED, VERIFIED, FAILED, BLOCKED, NOT_TESTED.

## Phase 00 — Establish the real baseline

### P00-01: Repository integrity
- Status: VERIFIED
- Problem: Establish branch, local/remote HEAD, dirty changes and running revision.
- Expected behavior: Preserved changes and explicit running-revision confidence.
- Affected components: Git; service metadata.
- Dependencies: none.
- Implementation approach: Read-only Git/service inspection; preserve initial patch and hashes.
- Verification method: Compare remote branch; retain dirty provenance; inspect process revision.
- Acceptance criteria: Preserved changes and explicit running-revision confidence.
- Evidence / limitations: HEAD and fresh read-only remote HEAD match 1efbab4c6afd110a08b961fc3010562b130c84db. Initial six owner modifications preserved in patch/hashes. Original PID225979 remains active. X-ARIA-Build e5da773393398091 exactly matches reconstructed HEAD plus initial owner engine patch (plain HEAD fd83a48ba1c4dad8). Baseline-build-candidates and live-build-observation JSON establish startup source fingerprint; excludes frontend/worker bytes and is not a signed attestation. New reliability code is tested separately and is not loaded by that process.

### P00-02: Previous acceptance findings
- Status: VERIFIED
- Problem: Reconcile reported blockers, cancelled ports, failed review, bounded success and timings.
- Expected behavior: Reported observations distinguished from reproduced behavior.
- Affected components: reports; agents; tests.
- Dependencies: P00-01.
- Implementation approach: Read sanitized evidence; reproduce review and port defects offline.
- Verification method: Historical claim-to-artifact mapping and deterministic regressions.
- Acceptance criteria: Reported observations distinguished from reproduced behavior.
- Evidence / limitations: docs/operational-reliability-baseline.md; private historical-reconciliation.json (7/7 and 44/44 hashes); phase00-focused.log (123 tests passed). Historical behavior remains distinct from fresh offline reproduction.

### P00-03: Architecture inventory
- Status: VERIFIED
- Problem: Identify actual ownership, call paths and evidence maturity.
- Expected behavior: Every requested component classified by source/runtime/test/live evidence.
- Affected components: api; agents; orchestrator; memory; llm; worker; web.
- Dependencies: P00-01.
- Implementation approach: Trace entry points, stores, authorization and event paths.
- Verification method: Source-linked diagram and component evidence matrix.
- Acceptance criteria: Every requested component classified by source/runtime/test/live evidence.
- Evidence / limitations: docs/operational-reliability-baseline.md actual call graph and component evidence matrix; source entry points inspected; full baseline 659 tests. Live use explicitly limited to historical observed paths.

## Phase 01 — Mission objectives and state correctness

### P01-01: Objective preservation
- Status: VERIFIED
- Problem: Preserve original user objective across browser, API, persistence and restart.
- Expected behavior: No silent replacement, truncation or cross-session leakage.
- Affected components: web; api; agents; memory.
- Dependencies: P00-03.
- Implementation approach: Trace objective provenance and add deterministic isolation/restart tests.
- Verification method: Exact objective retention and stale/truncation regression cases.
- Acceptance criteria: No silent replacement, truncation or cross-session leakage.
- Evidence / limitations: Browser frontend exact objective/empty/oversize contracts; tests/test_access.py objective forwarding and two-session isolation; tests/test_context_integrity.py planner/grounding/scope tests; tests/test_checkpoints.py exact objective restart/owner/stale tests. All pass in fresh cycle1 full suite. Visible acceptance remains separate P07-02/P08-03; internal whitespace normalization and explicit truncation flag retained.

### P01-02: Completion semantics
- Status: VERIFIED
- Problem: Distinguish phase completion, pending work and truthful mission terminals.
- Expected behavior: All specified states accurately describe work; no forced extra execution.
- Affected components: agents; memory; web.
- Dependencies: P01-01.
- Implementation approach: Inspect bounded stop criteria; persist explicit reasons and pending state.
- Verification method: Synthetic phase/mission/blocked/budget/cancel/failure/pause cases.
- Acceptance criteria: All specified states accurately describe work; no forced extra execution.
- Evidence / limitations: Added deterministic cancellation-during-approval race reproduction: approval-stop-race-before.log 1test/1failure. Corrected stop priority before rejection. Focused approval-stop-race-after.log 57tests/1.815s and approval-timing-after.log 62tests/1.819s passed. Current full cycle10 724tests/35.381s and real SQL58tests/48.191s passed. Cancellation retains completed evidence and does not impersonate a human decision; bounded objective completion remains distinct from pending work.

### P01-03: State consistency
- Status: VERIFIED
- Problem: Preserve consistent state under concurrency, duplicates and restart.
- Expected behavior: All defined transition tests pass with reconstruction evidence.
- Affected components: agents; memory; api; web.
- Dependencies: P01-02.
- Implementation approach: Define valid transitions and atomic/idempotent persistence.
- Verification method: Synthetic normal/cancel/concurrent/duplicate/invalid/restart/stale/owner tests.
- Acceptance criteria: All defined transition tests pass with reconstruction evidence.
- Evidence / limitations: tests/test_checkpoint_fencing.py, test_checkpoints.py, test_mission_continuity.py; integration/test_checkpoint_postgres.py and test_mission_state_postgres.py; frontend event-order/gap contracts. Three original SQL failures retained in sql-6622b39fc92f; six-suite post-fix SQL 41 tests in 27.917s (sql-281b453aaa69); full cycle5 offline 701 tests in 34.221s pass. Explicit revision/generation/terminal/owner fences and fresh-process reconstruction verified. Does not prove distributed multi-Uvicorn-worker operation (one process remains required).

## Phase 02 — LLM reliability

### P02-01: Structured response contracts
- Status: VERIFIED
- Problem: Strictly validate all relevant untrusted model responses.
- Expected behavior: Invalid outputs rejected without weakening strict schema.
- Affected components: agents/base_agent.py; agents/orchestrator_agent.py; agents/autonomous_engine.py; llm.
- Dependencies: P00-02.
- Implementation approach: Inventory contracts and failure categories including historical typo.
- Verification method: Invalid JSON, fields, types, empty/truncated, timeout, transport, unknown usage tests.
- Acceptance criteria: Invalid outputs rejected without weakening strict schema.
- Evidence / limitations: docs/operational-reliability-model-contracts.md; strict plan/review and AgentResult contracts, generic parser shape contract, schema context reset, malformed/empty/truncated/type/field/timeout/transport/unknown-usage fixtures. Cycle2 full 679 and cycle3 full 689 tests passed; real SQL review journal checks pass. This verifies software contracts, not model expertise or timing.

### P02-02: Failure containment
- Status: VERIFIED
- Problem: Preserve completed work, evidence and accounting on provider/model failures.
- Expected behavior: Failures remain truthful and recoverable within authorization/budget.
- Affected components: agents; llm; memory.
- Dependencies: P02-01.
- Implementation approach: Bound handling and persist exact safe failure reason.
- Verification method: Fault injection; no duplicate dispatch, leakage or uncontrolled retries.
- Acceptance criteria: Failures remain truthful and recoverable within authorization/budget.
- Evidence / limitations: docs/operational-reliability-model-contracts.md; model_response_failures/local_model_reliability/mission_continuity/engagement_budget suites and integration/test_review_recovery_postgres.py. Invalid/empty/truncated/schema/transport/timeout/storage/unknown-usage/denial faults preserve completed evidence, stop or retain exact safe blocker, reset accounting context and never requery unknown review outcomes. Current SQL42 includes actual hard child-process exit and replay of exact saved response; cycle6 full708 pass. Does not validate provider reasoning quality or imply paid-provider availability.

### P02-03: Latency and token accounting
- Status: VERIFIED
- Problem: Separate construction, provider attempts, validation, processing, tokens and costs.
- Expected behavior: Missing usage unavailable; no conflated mission/model latency.
- Affected components: llm; agents; observability.
- Dependencies: P02-01.
- Implementation approach: Measure offline fixtures and inspect physical call accounting.
- Verification method: Attempt/retry/token/unknown-usage timing assertions.
- Acceptance criteria: Missing usage unavailable; no conflated mission/model latency.
- Evidence / limitations: llm/request_metrics.py, four provider clients, pool/accounting attempt ledger and review event timings. Construction, observed HTTP attempt, transport processing, pool invocation, strict review validation, result preparation and projection persistence have separate monotonic measurements. Strict input/output counts, conservative reservation totals, server logical-request/attempt IDs, retry grouping and provider-reported charges preserve unavailable values. Offline713 tests pass; targeted29 provider/accounting tests and18 measured-fixture checks pass; SQL10 recovery/accounting/mission tests plus dedicated twelve-operation correlation assertions pass. No paid-provider latency/billing claim; HTTP attempts do not imply provider-confirmed inference. Cross-layer API/queue/WS/browser integration remains P06.

## Phase 03 — Coordination of existing agents

### P03-01: Runtime ownership
- Status: VERIFIED
- Problem: Identify real responsibility and completion contracts per task.
- Expected behavior: Distinct actual work distinguished from named abstractions.
- Affected components: agents; orchestrator; memory/team_tasks.py.
- Dependencies: P00-03.
- Implementation approach: Trace task input/output/dependencies/evidence.
- Verification method: Source-linked ownership inventory plus runtime fixtures.
- Acceptance criteria: Distinct actual work distinguished from named abstractions.
- Evidence / limitations: docs/operational-reliability-coordination.md component input/output/state/dependency/evidence/completion inventory; actual six specialist roles invoked in SQL twelve-operation benchmark, report path distinct and model-free. Shared fixture responses do not demonstrate independent specialist expertise; historical live path used orchestrator planner/reviewer only.

### P03-02: Coordination correctness
- Status: VERIFIED
- Problem: Prevent duplicates and preserve dependencies, attribution and cancellation.
- Expected behavior: All specified coordination properties demonstrated.
- Affected components: agents; memory/team_tasks.py.
- Dependencies: P03-01.
- Implementation approach: Use harmless cooperative workloads.
- Verification method: Deterministic ordering/ownership/conflict/cancel/isolation tests.
- Acceptance criteria: All specified coordination properties demonstrated.
- Evidence / limitations: test_team_tasks/specialist_integration/specialist_hardening/research and real SQL mission/benchmark checks cover identity, dependencies, ownership, attribution, duplicate claim, cancellation, stale-revision conflicts, result fencing and isolated errors. Current SQL42 and offline708 pass. No tool dispatch added to coordinator; no worker privilege change.

### P03-03: Communication overhead
- Status: VERIFIED
- Problem: Measure messages, bytes, DB work, context and coordination latency.
- Expected behavior: Integrity preserved; optimization only with measured bottleneck.
- Affected components: agents; memory; observability.
- Dependencies: P03-02.
- Implementation approach: Profile comparable synthetic workloads before optimizing.
- Verification method: Retain reproducible raw measurements.
- Acceptance criteria: Integrity preserved; optimization only with measured bottleneck.
- Evidence / limitations: docs/operational-reliability-coordination.md and per-operation benchmark JSON retain actual request/result message counts, serialized inputs/outputs, SQL statement counts/bytes/wall durations, repeated context bytes and coordination latency. Baseline sql-f3b8a2b5eb4a: 22 agent messages, 877 SQL statements, 33137 model-input bytes, 4437 repeated context bytes. No unprofiled optimization or causal speedup claimed. Large-ledger performance remains unmeasured.

## Phase 04 — Memory, persistence and recovery

### P04-01: Data integrity
- Status: VERIFIED
- Problem: Preserve tasks, evidence, revisions, ownership and atomic transitions.
- Expected behavior: True mission state reconstructable with accurate references.
- Affected components: memory/research.py; memory/team_tasks.py; memory/autonomous_runs.py; memory/database_models.py.
- Dependencies: P01-03.
- Implementation approach: Inspect and test authoritative stores.
- Verification method: Disposable database persistence/idempotency/ownership tests.
- Acceptance criteria: True mission state reconstructable with accurate references.
- Evidence / limitations: docs/operational-reliability-coordination.md and state.md; engagement/row-locked checkpoints, atomic task events and exact-response journal. Current SQL42 checks revisions, ownership, duplicate writes/claims, receipt binding, state reconstruction, evidence hashes and accepted-review projection. Offline708 adds stale context and task cancellation/result fences. Verification is for defined synthetic contracts, not arbitrary database corruption or production-scale stress.

### P04-02: Restart recovery
- Status: VERIFIED
- Problem: Retain completed/pending/cancelled work and uncertain outcomes.
- Expected behavior: No uncertain sensitive replay or cancelled resurrection.
- Affected components: memory; api; orchestrator.
- Dependencies: P04-01.
- Implementation approach: Interrupt/restart synthetic workload against disposable DB.
- Verification method: Process interruption and reconciliation evidence.
- Acceptance criteria: No uncertain sensitive replay or cancelled resurrection.
- Evidence / limitations: Actual child-process exit after committed review ingestion in integration/test_review_recovery_postgres.py; saved encrypted response reused without new provider call. Mission/task/checkpoint PostgreSQL cases reconstruct completed/pending/cancelled work in fresh interpreter and fence previous writer generations. Unknown worker outcomes remain unresolved/cancelled until reconciliation; no automatic sensitive replay. Current SQL42 pass; no actual Kali interruption performed.

### P04-03: Memory quality
- Status: VERIFIED
- Problem: Measure context size, redundant/stale information and evidence provenance.
- Expected behavior: Observations, hypotheses, verified and human-reviewed findings remain distinct.
- Affected components: memory; agents.
- Dependencies: P04-01.
- Implementation approach: Inspect evidence/hypothesis boundaries and context construction.
- Verification method: Synthetic provenance and size/staleness checks.
- Acceptance criteria: Observations, hypotheses, verified and human-reviewed findings remain distinct.
- Evidence / limitations: docs/operational-reliability-coordination.md; context-size/repeated-byte benchmark, research scope/model/evidence digest checks, maximum three current related hypotheses with omitted-stale count, recorded-state versus proposed counts and independent verification gates. Original HEAD coordinator stale-context leakage reproduced (1 failing test); corrected focused73 and full708 pass; current SQL42 pass. No claim of large-graph memory/performance optimization.

## Phase 05 — Authorization and blocked-state management

### P05-01: Authorization and blocker correctness
- Status: VERIFIED
- Problem: Explain scope/approval/expiry/budget/worker incompatibility before runnable state.
- Expected behavior: No bypass or privilege expansion; safe exact reason and operator action.
- Affected components: security; orchestrator; worker interfaces; web.
- Dependencies: P00-02; P01-02.
- Implementation approach: Trace shared gates; test requested-port incompatibility with mocks.
- Verification method: Cross-path scope, expired approval, budget and unavailable capability tests.
- Acceptance criteria: No bypass or privilege expansion; safe exact reason and operator action.
- Evidence / limitations: Shared authorization/scope/expiry/one-use/budget gates retain existing fixtures. New pure planner and central WorkerJobs pre-dispatch checks reject advertised network/TCP-port mismatches before submit; missing metadata is unavailable. Focused65, full cycle10 724 and SQL58 pass. Explicitly owner-approved metadata-only Kali update applied; authenticated GET confirms unchanged 192.168.77.20/32 and TCP21/22/80/139/445. No target operation occurred. Restored planning lacks cached constraint metadata, so compatibility remains unavailable until the central fresh-capabilities check; it cannot bypass final admission.

## Phase 06 — Performance and observability

### P06-01: Baseline and correlation
- Status: IN_PROGRESS
- Problem: Measure thirteen requested API-to-render timing layers honestly.
- Expected behavior: Unavailable layers explicit; justified thresholds and comparable workloads.
- Affected components: api; agents; llm; worker; memory; websocket; web.
- Dependencies: P00-03.
- Implementation approach: Use correlation IDs and monotonic durations; document clock boundaries.
- Verification method: Reproducible timings, mean/median/max, adequate-sample p95, failures/retries/resources.
- Acceptance criteria: Unavailable layers explicit; justified thresholds and comparable workloads.
- Evidence / limitations: pending current-program verification.

## Phase 07 — Graphical interface and operational visibility

### P07-01: Operational dashboard
- Status: VERIFIED
- Problem: Expose real objective, phase, tasks, attribution, blockers, evidence, model, budget and worker health.
- Expected behavior: No fabricated progress or activity; explicit blocker details.
- Affected components: web; api; events.
- Dependencies: P01-03; P06-01.
- Implementation approach: Improve existing UI with accurate persisted/event state.
- Verification method: Frontend contracts and sanitized visible screenshots.
- Acceptance criteria: No fabricated progress or activity; explicit blocker details.
- Evidence / limitations: Current existing dashboard exposes exact objective, bounded/current mission states, real task/agent ownership, pending/blocked work, durable event identities, independently reviewed evidence, precise budget charges, worker health and unavailable metrics. Failed refresh retires stale success. Frontend/dashboard/failed-refresh/budget Node contracts pass. Source-attested visible-bd35eb400560: 8 graphical checks, sandboxed Chromium, zero page errors, 5 sanitized screenshots; overview inspected. Single fixture DOM49.6ms/frame-opportunity94.3ms; unavailable measurements remain explicit. Deployed owner acceptance remains separate P08-03.

### P07-02: Visible UI acceptance
- Status: VERIFIED
- Problem: Validate actual graphical login and navigation in sandboxed Chromium.
- Expected behavior: Graphical acceptance demonstrated or BLOCKED with exact prerequisite.
- Affected components: integration; Fedora desktop; web.
- Dependencies: P07-01.
- Implementation approach: Use Playwright headless=False without credential traces or API substitutions.
- Verification method: Visible browser assertions and sanitized screenshots.
- Acceptance criteria: Graphical acceptance demonstrated or BLOCKED with exact prerequisite.
- Evidence / limitations: integration/reliability_visible.py; visible-5ff08228f4a3/result.json and subsequent visible-80581393fe82 settled screenshots/catalog navigation. Real Fedora graphical Chromium156.0.8078.4, headless=False, chromium_sandbox=True; real application login, session selection, start, reload, dashboard link and evidence tab. No API interaction substitution/route mocks/traces; source unchanged during runs; exact objective, all12 tasks, worker blocker, unavailable readiness and zero page errors. Fresh synthetic PostgreSQL deployment, separate from original owner service and P08-03 live acceptance.

## Phase 08 — Controlled validation and endurance

### P08-01: Regression validation
- Status: VERIFIED
- Problem: Run relevant existing suites and focused corrected-defect tests.
- Expected behavior: Failures not hidden; required relevant checks pass.
- Affected components: tests; integration; web.
- Dependencies: corrected requirements.
- Implementation approach: Run Python, frontend contracts, JS syntax, integration and whitespace checks.
- Verification method: Retain actual output/counts/revision.
- Acceptance criteria: Failures not hidden; required relevant checks pass.
- Evidence / limitations: Current cycle10: 724offline Python tests in35.381s, wrapper38.094s; complete relevant ten-suite disposable PostgreSQL58tests in48.191s, wrapper50.971s (sql-eb02b547597a). Frontend, dashboard, failed-refresh and budget-button Node contracts; app/dashboard JS syntax and Git whitespace pass. Focused62 cancellation/approval/request-boundary tests pass. Source manifest cycle10-source-manifest.json. Original failed experiments retained; later implementation changes require renewed relevant checks.

### P08-02: Twelve-operation engineering benchmark
- Status: VERIFIED
- Problem: Account for twelve harmless operation lifecycles including faults and recovery.
- Expected behavior: Evidence covers state, coordination, model, persistence, cancellation and recovery.
- Affected components: integration; synthetic adapters; memory.
- Dependencies: P03-02; P04-02; P02-02.
- Implementation approach: Deterministic model/worker fixtures and lifecycle ledger.
- Verification method: Twelve operations; no lost/duplicate/unauthorized jobs or false terminals.
- Acceptance criteria: Evidence covers state, coordination, model, persistence, cancellation and recovery.
- Evidence / limitations: integration/reliability_workload.py and test_reliability_workload_postgres.py. sql-f3b8a2b5eb4a and combined seven-suite sql-5b9eeefeda87: all 12 lifecycle records, 9 completed/2 cancelled/1 blocked as injected, 12 simulated runtime starts, zero lost/duplicate/unauthorized dispatch, 12 preapproval denials, one duplicate-authorization and one dependency denial, two owner denials, six actual specialist roles. Real SQL; model/worker/owner fixtures; no target/provider/tool execution. Hard process crash recovery has separate review-journal evidence; benchmark recovery is before model dispatch. Workload remains truthfully blocked, not falsely mission-completed.

### P08-03: Visible laboratory acceptance
- Status: NOT_STARTED
- Problem: Repeat only authorized bounded non-destructive discovery on 192.168.77.20.
- Expected behavior: Objective/limit/blocker stop; distinct from synthetic twelve operations.
- Affected components: visible Chromium; existing worker; existing provider budget.
- Dependencies: P07-02; P05-01.
- Implementation approach: Use real graphical workflow, unguided decisions and existing approvals.
- Verification method: Sanitized UI, receipts and budget/timing evidence.
- Acceptance criteria: Objective/limit/blocker stop; distinct from synthetic twelve operations.
- Evidence / limitations: pending current-program verification.

### P08-04: Progressive endurance
- Status: IN_PROGRESS
- Problem: Demonstrate only feasible completed synthetic durations.
- Expected behavior: Each duration individually evidenced; unfinished durations NOT_TESTED.
- Affected components: integration; disposable DB; observability.
- Dependencies: P08-02.
- Implementation approach: Attempt 15m,30m,1h,2h,4h,8h progressively within resources.
- Verification method: Availability, CPU/RAM/growth, DB connections, throughput, loss/duplicate/recovery/accounting.
- Acceptance criteria: Each duration individually evidenced; unfinished durations NOT_TESTED.
- Evidence / limitations: 15m VERIFIED: endurance-3d8e73d8ef16, 900.0019s, 360 operations, 180 readiness samples, zero failures/lost/duplicate/unauthorized dispatch. 30m VERIFIED: endurance-d31a0e3f21b1, 1800.0010s, 720 operations, 360 readiness samples, same zero counters, RSS growth 15408 KiB, max 6 DB connections. ASGI/disposable SQL only; deployed network/browser availability not covered. 1h VERIFIED: endurance-d1aef3ed96de,3600.001140s,1440operations,719readiness/zero failures,RSS+17740KiB,max7DBconnections. 2h IN_PROGRESS in endurance-7acf4dc15d40 (session44869/PID577934);4h/8h NOT_TESTED. No extrapolation.

## Phase 09 — Final audit

### P09-01: Evidence-backed final audit
- Status: IN_PROGRESS
- Problem: Audit every requirement and component without inflated readiness claims.
- Expected behavior: All required report sections and requirement evidence; complete only if mandatory requirements VERIFIED.
- Affected components: reports; GOALS.md; PLANS.md; PROGRESS.md.
- Dependencies: P00-P08.
- Implementation approach: Generate graphical HTML, JSON acceptance matrix and CSV metrics from evidence.
- Verification method: Cross-check references, revision, defects, changes, limitations and statuses.
- Acceptance criteria: All required report sections and requirement evidence; complete only if mandatory requirements VERIFIED.
- Evidence / limitations: pending current-program verification.
