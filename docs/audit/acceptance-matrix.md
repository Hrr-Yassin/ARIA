# ARIA — Acceptance Matrix (Phase A audit)

Audit date: 2026-11-13. Branch `autonoms_pentesters`, HEAD `2fd16db72406a41fc7370537b80d4cb7f7d71bac`.

Purpose: record, per claimed capability, the acceptance evidence that exists today. Statuses: **ACCEPTED** (evidence re-executed in this audit), **EVIDENCED** (regression/integration coverage exists in the tree but not re-run here), **PARTIAL** (some evidence, gaps listed), **NOT DEMONSTRATED**.

## 1. Offline regression suite (re-executed in this audit)

Command: `.venv/bin/python -m unittest discover -s tests -t . -q`
Result: **475 tests — 470 passed, 3 failures, 2 errors** (16.4 s), 2026-11-13.

Failing (all pre-existing, harness-related — a socket mock raises `AssertionError: Network disabled in tests` inside LLM-client paths not patched by those tests):

| Test | Observed mode |
| --- | --- |
| `tests.test_llm_models.ModelTests.test_gemini_task_routing_honors_configured_model` | ERROR |
| `tests.test_engagement_budget.EngagementBudgets.test_storage_failure_prevents_physical_call_and_failover_counts` | ERROR |
| `tests.test_p1_credentials.CredentialTests.test_model_boundary_redacts_and_key_disable_takes_effect` | FAIL |
| `tests.test_p1_credentials.CredentialTests.test_provider_quota_reservation_prevents_concurrent_overuse` | FAIL |
| `tests.test_planner_readiness.PlannerReadiness.test_no_key_preflight_is_read_only` | FAIL |

## 2. Coverage of production modules (from the static coverage map of this audit)

Legend: **strong** = dedicated direct tests; **thin** = indirect or fixture-only; **none** = no direct test file.

| Module | Direct coverage | Notes |
| --- | --- | --- |
| `agents/autonomous_engine.py` | strong (15 test files + 2 integration suites) | most-exercised agent module |
| `agents/orchestrator_agent.py` | strong | planner mocked in most; real process only with mocked LLM |
| `agents/{recon,scan,vuln,correlation,attack_planner,post_exploitation}_agent.py` | thin | fixture-driven via `test_specialist_fixtures.py` |
| `agents/base_agent.py` | thin | `test_planner_capability_boundary.py` only |
| `orchestrator/campaign_supervisor.py`, `campaign_store.py` | strong | offline + Postgres + endurance harness |
| `orchestrator/specialist_integration.py` | strong | 5 test files + 2 Postgres suites |
| `orchestrator/team_coordinator.py` | strong | |
| `orchestrator/execution_policy.py`, `risk_scorer.py`, `workflow_engine.py` | strong | |
| `orchestrator/intent_engine.py` | **none direct** | only indirect via router |
| `orchestrator/program_scope.py` | **none direct** | only indirect via `execution_policy.py:88` |
| `orchestrator/browser_mapping.py` | thin | integration `phase3_mapping.py` only |
| `memory/execution_authorization.py` | strong | 16 test files |
| `memory/knowledge_store.py`, `evidence_context.py`, `team_tasks.py`, `application_map.py`, `finding_verification.py`, `professional_reports.py`, `program_policy.py`, `session_manager.py`, `worker_jobs.py` | strong | |
| `memory/parsers.py` | **none direct** | patched in some tests; exercised indirectly |
| `memory/command_registry.py`, `report_artifacts.py` | **none direct** | indirect only |
| `worker/service.py`, `policy.py`, `http_profile.py`, `runtime.py` | strong offline | real containers only in `integration/test_worker.py` + phase labs |
| `worker/container_entry.py` | **none** | container entrypoint (validated via `integration/test_worker.py` scenarios) |
| `worker/http_runner.py` | thin | `test_specialist_profiles.py`; no real-container HTTP-runner scenario |
| `llm/pool_manager.py`, `engagement_budget.py`, `validation_budget.py`, `local_client.py`, `gemini_client.py` | strong | Gemini via MockTransport |
| `llm/groq_client.py`, `openrouter_client.py` | **none** | always mocked through the factory — real provider HTTP is unverified offline |
| `api/routers/pentest.py`, `sessions.py`, `reports.py`, `admin.py`, `application_map.py`, `burp.py`, `programs.py`, `team.py`, `tool_registry.py` | strong | |
| `api/routers/api_keys.py` | **none functional** | only blanket-401 route check + frontend stub |
| `api/bootstrap_admin.py`, `api/rotate_provider_keys.py` | **none** | CLI-only, untested |
| `config/security_tool_registry.py`, `cve_enricher.py`, `settings.py` | strong | |
| `config/tools_registry.py` | **none direct** | legacy planning table, indirect everywhere |

## 3. Integration suites (in-tree; NOT re-run in this audit — require disposable services)

| Suite | Services | Gate |
| --- | --- | --- |
| `integration/test_campaign_postgres.py`, `test_campaign_execution_postgres.py`, `test_checkpoint_postgres.py`, `test_knowledge_store_postgres.py`, `test_observability_postgres.py`, `test_specialist_postgres.py`, `test_endurance_postgres.py` | disposable PostgreSQL (`*_test` DB) | `ARIA_INTEGRATION=1` |
| `integration/test_services.py` | PostgreSQL + Redis (db 15) | `ARIA_INTEGRATION=1` |
| `integration/test_worker.py` | real Docker/Podman containers + private network | `ARIA_WORKER_INTEGRATION=1` |
| `integration/test_community_connector.py` | real JVM replay fixture | — |
| Phase-lab scripts `phase0…phase7`, `live_validation`, browser scripts | real browser/LLM/worker/targets (lab VM 192.168.77.20) | per-phase gates |
| CI (`.github/workflows/ci.yml`) | offline + Postgres/Redis + Docker worker build | push/PR |

## 4. Capability → acceptance evidence matrix

| Capability (claim) | Status | Evidence |
| --- | --- | --- |
| Command allowlist policy; unknown syntax rejected | ACCEPTED | `tests/test_execution.py` etc. passed in this audit run |
| Red-risk human approval hard-block | ACCEPTED | passed offline suite |
| Durable single-use authorizations; CAS before dispatch | ACCEPTED | passed offline suite |
| Worker isolation (container flags, firewall, privilege drop) | EVIDENCED | `integration/test_worker.py` scenarios (not re-run; CI job exists) |
| Curl + Nmap TCP execution end-to-end | EVIDENCED | worker container suite + documented Kali lab receipts (`docs/kali-worker-deployment.md`) |
| Authenticated HTTP (`aria-http`) | PARTIAL | offline unit tests only; no real-container HTTP-runner scenario |
| Evidence-backed knowledge observations | ACCEPTED | `test_knowledge_store.py`, `test_context_integrity.py` passed |
| Checkpoint restore with replay guards | ACCEPTED | `test_checkpoints.py` passed |
| Campaign schedule/lease/retry/pause/cancel | ACCEPTED | `test_campaigns.py` passed |
| Specialist review tasks (SPEC-13) | ACCEPTED | specialist suites passed |
| Model accounting reservations/settlement | PARTIAL | logic covered by `test_engagement_budget.py`, but 2 tests in that area currently ERROR in this environment |
| Human finding verification with controls | ACCEPTED | `test_finding_verification.py` passed |
| Report generation + sha256 artifact download | ACCEPTED | `test_professional_reports.py` passed |
| WebSocket live run streaming (origin check, re-auth) | ACCEPTED | offline suite passed |
| Eight-hour 5-day operation | NOT DEMONSTRATED | only accelerated synthetic harness + wall-clock soak with synthetic engine/worker (`integration/endurance_soak.py`); no production soak |
| Scientific benchmark (3 arms) | NOT DEMONSTRATED | only deterministic component baseline (`evaluation/benchmark.py`); measured arms missing |
| Structured typed tool dispatch (new registry) | NOT DEMONSTRATED | catalog-only, `enabled=False`, no POST route |
| Exploitation / post-exploitation | NOT DEMONSTRATED | blocked at start (`unsupported_goal`); post agent stubbed |
| Prompt caching | NOT DEMONSTRATED | not implemented |
| Program-policy enforcement by worker image | PARTIAL | enforced by service on full checkout; **missing module in shipped image** (architecture-review §5.2) |

## 5. Acceptance criteria for the next engineering slice (to be filled when Phase I begins)

The first slice proposal (see `implementation-roadmap.md`) must state, before implementation:

1. Observed problem with file:line.
2. Files to change.
3. Proposed architecture.
4. Acceptance tests (offline; integration where applicable).
5. Validation commands and expected results.
6. Regression scope (which existing suites must stay green).
7. Limitations and follow-ups.
