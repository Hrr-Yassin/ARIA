# ARIA / pentest-ai — Technical and Security Review

Review date: 2026-11-01. Baseline: `e03d0d9afa564c62034aa037f3ef7cc4da940e6a` (`main`, initial project upload). Scope: the tracked backend, frontend, configuration, persistence, provider adapters, and installation scripts. This is a source-based engineering review with targeted local verification, not a completed penetration test or a guarantee that every defect has been discovered.

## Executive assessment

The project has a credible academic concept: specialist agents, deterministic output parsing, goal-driven investigation, and visible human decisions. Its modular directories and existing SQL models provide a useful starting point.

The main engineering risk is an incomplete v9-to-v10 integration. Frontend contracts do not match backend routes or authentication storage; eight session checks reverse their parameters; event callbacks do not reliably bind to their originating session; and some advertised features have no workflow caller. Security policy is distributed across prompts, browser confirmation, and several execution paths rather than enforced at one boundary.

**Assessment: suitable for continued isolated prototype development; not ready for exposed deployment or an autonomous security evaluation using sensitive data.** Documentation cleanup does not fix the issues below.

Severity describes potential impact in the affected deployment. “Confirmed” means demonstrated by source or a bounded local check; it does not mean a remote exploit was attempted. “Conditional” means additional access or environmental behavior is required.

## Findings register

| ID | Severity / priority | Finding | Primary evidence |
| --- | --- | --- | --- |
| SEC-01 | High / P0 | File-serving path is not confined to `web/` | `api/main.py:catch_all` |
| SEC-02 | High / P0 | Autonomous event stream accepts unauthenticated readers | `api/routers/pentest.py:autonomous_websocket` |
| SEC-03 | Critical potential / P0 | Execution has no universal scope and approval boundary | `execute_on_kali`, `ws_chat`, `AutonomousEngine._execute_command` |
| SEC-04 | High / P0 | Model-supplied risk tags govern autonomous authorization | `AutonomousEngine._run_loop`, `OrchestratorAgent._validate_commands` |
| SEC-05 | High / P0 | Demonstration credentials and fallback signing/worker secrets | `api/auth.py`, `config/settings.py`, `setup.sh` |
| SEC-06 | High / P0 | Provider encryption key is generated temporarily and logged | `llm/pool_manager.py:LLMPoolManager.__init__`, `decrypt_key` |
| SEC-07 | High / P1 | Cross-user retrieval/playbook isolation is absent | `memory/vector_store.py:search_similar`, `memory/playbook_store.py:list_all` |
| SEC-08 | High / P1 | Report downloads have no authentication or owner check | `api/routers/reports.py:download_report` |
| SEC-09 | Medium / P1 | Cache/status routes omit session ownership validation | `api/routers/pentest.py:get_cache`, `get_status` |
| SEC-10 | Medium / P1 | Disabled users and role changes do not invalidate JWT access | `api/auth.py:get_current_user`, `require_admin` |
| SEC-11 | Medium / P1 | Password storage uses fast SHA-256 | `api/auth.py:hash_password`, `verify_password` |
| SEC-12 | High potential / P1 | Untrusted evidence influences prompts; sensitive data can reach providers | `agents/base_agent.py`, `agents/web_intel_agent.py`, orchestrator prompts |
| SEC-13 | Medium / P1 | Policy heuristics miss targets and misclassify commands | `api/middleware/scope_validator.py`, `orchestrator/risk_scorer.py` |
| SEC-14 | High conditional / P1 | Pickle deserialization trusts Redis embedding bytes | `memory/vector_store.py:load` |
| SEC-15 | Medium / P1 | Transport, token storage, origins and resource controls need hardening | `config/settings.py`, `web/static/scripts/`, `api/main.py` |
| SEC-16 | High / P1 | Tool-result ingestion can mutate another user's session | `api/routers/pentest.py:analyze_tool_results` |
| ENG-01 | Blocker / P0 | Browser/API contracts disagree | `web/static/scripts/app.js`, `login.js`, `api/main.py` |
| ENG-02 | Blocker / P0 | Eight v10 session checks reverse arguments; wrong session type access | `api/routers/pentest.py`, `api/session_access.py` |
| ENG-03 | Medium / P1 | Replan events can be delivered to the wrong session | `agents/autonomous_engine.py:_on_replan_event` |
| ENG-04 | High / P1 | Web Intel invokes an absent base-class method | `agents/web_intel_agent.py`, `agents/base_agent.py` |
| ENG-05 | High / P1 | Stop/restart, cancellation and event delivery are not durable | `agents/autonomous_engine.py`, `memory/command_lifecycle.py` |
| ENG-06 | High / P1 | Decision logging fails open and loses decision detail | `agents/autonomous_engine.py:_write_decision_log`, `_run_loop` |
| ENG-07 | Medium / P1 | Cache and database session representations differ | `memory/session_manager.py:create_session`, `get_session` |
| ENG-08 | Medium / P1 | Partial persistence and missing lifecycle wiring | `memory/attack_knowledge_base.py`, `vector_store.py`, `api/main.py` |
| ENG-09 | Medium / P2 | Playbook persistence and matching have latent defects | `memory/playbook_store.py` |
| ENG-10 | Medium / P2 | Advertised ReAct/playbook learning is not integrated | ReAct/playbook caller search |
| ENG-11 | Medium / P1 | Execution clients use incompatible authentication conventions | `api/routers/pentest.py`, `autonomous_engine.py`, `command_lifecycle.py` |
| ENG-12 | Medium / P1 | No versioned migrations, test suite or CI configuration | `memory/database_models.py:init_db`, repository inventory |
| ENG-13 | Medium / P2 | Dependency and deployment reproducibility are incomplete | `requirements.txt`, `setup.sh`, application metadata |
| ENG-14 | High / P1 | CVE candidates can be promoted to exploitable without applicability validation | `config/cve_enricher.py:_nvd_search`, `auto_enrich_port` |
| ENG-15 | Medium / P2 | Synchronous model loading/encoding can block the API event loop | `memory/vector_store.py:_Embedder`, `VectorStore.add`, `search_similar` |

## Security analysis and remediation

### SEC-01 — Unconfined file serving

`catch_all` joins a request-derived path to `WEB_DIR` and checks only existence and file type. A parent-relative path can resolve to the repository configuration or `.env`. The local path probe confirms traversal outside the web root; actual HTTP reachability depends on URL normalization by the server/proxy.

**Fix:** remove arbitrary file serving and use explicit static mounts plus a deliberate SPA fallback. If a path resolver remains, resolve both paths, reject anything outside the web root, and account for symlinks. **Acceptance:** encoded traversal and symlink cases cannot return repository files or secrets through the real ASGI stack and deployment proxy.

### SEC-02 — Autonomous WebSocket disclosure

`autonomous_websocket` accepts a connection and checks a token only when supplied. With no token it streams the requested session's events. With a token it reads `user_id`, although issued JWTs identify the user in `sub`; the extracted value is unused and ownership is never checked. The documented first-message authentication is not implemented.

**Fix:** require valid authentication and a live authorized user, check session access before streaming, and validate the WebSocket origin. **Acceptance:** missing/invalid credentials and another user's session are rejected; authorized users receive only their allowed session events.

### SEC-03 — Inconsistent execution authorization

The REST proxy permits an absent `session_id` and validates scope only when the returned scope is truthy. The chat `run_commands` branch checks ownership when a session is supplied but directly forwards commands without scope validation. The autonomous engine sends commands directly to the worker without validating scope. Browser confirmation is not a server authorization control, and the chat execution branch does not verify a persisted approval.

Consequently, an authenticated user can reach paths that do not establish engagement scope or critical-action approval. This has critical potential impact because the operation is remote command execution by design; actual worker privileges and network reach are external and unverified.

**Fix:** require an engagement on every job; implement one deny-by-default command service used by all callers; authorize immutable proposals and enforce scope again at the worker. Prefer structured argument vectors and reviewed tool adapters to unrestricted shell strings. **Acceptance:** direct REST/socket calls, omitted sessions, chained commands, modified approvals and autonomous proposals cannot bypass the same policy checks.

### SEC-04 — Risk tags are not an authorization boundary

The autonomous loop uses `next_step.risk_color`, defaulting to orange. The orchestrator command validator checks some Metasploit details but does not independently enforce risk classification. A model can therefore mislabel a critical action as green/orange and cause it to run without approval. Retrieved content can influence this decision.

**Fix:** classify tool behavior and arguments on the server, allow risk only to increase relative to tool policy, reject unknown commands, and require approval for critical side effects. Revalidate a human-modified command. **Acceptance:** a deliberately mislabelled critical proposal still blocks before dispatch.

### SEC-05 — Predictable initial access and secrets

Startup seeds hardcoded demonstration accounts. Settings also supply known signing and worker-token defaults. `setup.sh` generates a signing secret for its normal fresh-install path, but direct startup can retain the default; the worker-token default remains predictable. Do not repeat these credentials in new operational documentation.

**Fix:** refuse insecure signing/worker defaults outside explicit test mode, bootstrap an administrator using deployment-provided credentials, and disable automatic demo seeding. Rotate any deployed copies. **Acceptance:** a fresh non-test deployment cannot start with known credentials or default secrets.

### SEC-06 — Encryption-key lifecycle failure

Missing or invalid `FERNET_KEY` causes generation of a temporary encryption key, including logging the key. Persisted provider keys then cannot be decrypted after restart with another temporary key. `decrypt_key` returns the original ciphertext on `InvalidToken`, concealing configuration errors and potentially sending ciphertext as a provider credential.

**Fix:** require a persistent valid key, remove secret logging, fail decryption explicitly, and support controlled rotation with a key identifier. **Acceptance:** encrypted keys survive restart; invalid configuration fails clearly; logs contain no key material.

### SEC-07 — Cross-engagement information isolation

Semantic and keyword retrieval search all process-local sessions and only offer `exclude_session`, not an owner/access filter. Base-agent retrieval injects matching content into another investigation's prompts. Playbook listing accepts `user_id` but ignores it, and its cache loads unfiltered database rows. The broken v10 routes currently mask some direct exposure, but the storage/retrieval design is independently unsafe for multiple users.

**Fix:** retain tenant/user and engagement ownership in every stored entry and filter before ranking, caching, rendering, or model submission. Separate private playbooks from explicitly published sanitized templates. **Acceptance:** two-user tests show no private cross-user retrieval, including keyword fallback and cache reload.

### SEC-08/09 — Report and session-view access gaps

Report download intentionally has no authentication; a filename acts as a bearer capability without expiry or explicit sharing. Cache/status routes authenticate the caller but do not check ownership. Filename validation limits traversal in the report route but does not authorize access.

**Fix:** map reports to sessions and enforce session authorization on all views/downloads; if sharing is required, use scoped expiring grants. **Acceptance:** another user cannot read status, cache metadata, reports or report content even when IDs/filenames are known.

### SEC-10/11 — Account lifecycle and passwords

`get_current_user` trusts JWT role and identity claims without checking whether the database user remains active. `require_admin` trusts the token role. Disabling an account or changing privileges therefore does not promptly revoke existing access. Password hashing uses a salted single SHA-256 pass and ordinary string comparison; it is fast for offline guessing after a database leak.

**Fix:** validate active user and authorization state, add token revocation/versioning, and migrate password hashes to a password-specific adaptive scheme with a supported library. Add login throttling and security events. **Acceptance:** disabled/demoted users lose access promptly, and old hashes upgrade after successful authentication.

### SEC-12 — Model trust and engagement-data handling

Tool outputs, banners, retrieved cases and HTTP traffic are concatenated into prompts. Web Intel includes headers, cookies, parameters and body snippets, which can contain credentials. No common redaction, provider-consent policy, or structured untrusted-data boundary is visible. A prompt instruction is insufficient to constrain execution.

**Fix:** centralize redaction and outbound-data policy, retain evidence references rather than unrestricted secrets, mark observations as untrusted, validate model output against strict schemas, and keep authorization outside the model. **Acceptance:** seeded secrets do not reach a mocked provider; adversarial observations cannot change command policy.

### SEC-13 — Scope and risk heuristic weaknesses

The scope validator permits an empty allowlist and performs no target check when extraction finds no target. Its regex approach omits IPv6 and cannot safely interpret shell expansion, target files or dynamic resolution. Domain suffix matching implicitly allows subdomains. Exclusions use substring matching, and URLs with ports can be interpreted inconsistently.

The risk scorer lowercases the command then compares against `-I` (which cannot match after lowercasing), while `-s` is treated as a green indicator even for active scans such as `nmap -sV`. Tool identity and actual shell behavior are not bound together.

**Fix:** represent targets and permitted networks explicitly, validate tool-specific arguments, define subdomain/DNS policy, reject unresolved/unparsed cases, and test negative cases. **Acceptance:** CIDR, IPv6, exclusions, domain boundaries and active-scan flags have declared, verified behavior.

### SEC-14/15 — Infrastructure and defense in depth

Embedding load uses `pickle.loads` on Redis data. If an attacker can modify those values and the loader is invoked, deserialization can execute code. The loader is not currently wired into startup, so this is a conditional latent issue. Use a non-executable array format and validate shape/type/size.

Defaults allow all CORS origins with credentials, bind the API to all interfaces, and use HTTP for the worker. Frontend tokens are held in local storage and autonomous socket URLs contain a token; TLS, origin policy, token leakage prevention and server-side request limits are not established. These are deployment/design risks, not proof of a particular cross-origin exploit. Define exact origins, transport authentication/encryption, a consistent browser-session strategy, input/output limits, throttles and model/tool budgets. Run the backend and worker with distinct least-privileged identities.

### SEC-16 — Unauthorized evidence mutation

`analyze_tool_results` authenticates the caller but never calls `get_accessible_session` before updating tools, findings, chat and shared investigation memory for the supplied session ID. A different authenticated user who knows an ID can inject purported evidence into that engagement, potentially influencing later plans and reports.

**Fix:** check session ownership before any mutation; bind accepted tool results to an authorized worker job and verify its provenance rather than trusting client-supplied command/output fields. **Acceptance:** cross-user ingestion is denied before state changes, and fabricated or replayed results cannot overwrite trusted job evidence.

## Engineering and reliability analysis

### ENG-01 — Frontend/backend contract drift

| Contract | Frontend | Backend |
| --- | --- | --- |
| Stored authentication token | Login stores `pentestai_token`; main app reads `auth_token` | Expects a valid bearer token or supported fallback |
| Session listing | `/api/sessions/list` | `/api/session/list` |
| Session creation | `/api/sessions/create`, expects `id` | `/api/session/new`, returns `session_id` |
| Session identity / phase | Reads `s.id`, `s.current_phase` | Returns `session_id`, `phase` |
| User input | `/api/pentest/v8/input` | `/api/v8/input` |
| Manual execution | `/api/pentest/kali/execute` | `/api/kali/execute` |
| Tool output | `/api/pentest/tool-results` | `/api/tool-results` |
| Provider key management | `/api/api-keys/list`, `/add` | `/api/keys/` with GET/POST |

Unknown GET API paths can fall through to the HTML SPA response, masking route errors as successful HTTP responses. **Fix:** standardize one API schema, derive frontend types/client calls from it, and make unknown `/api/*` return JSON 404. Test login → session creation → plan → result → report through the browser.

### ENG-02 — Broken v10 session access

Eight calls in `api/routers/pentest.py` pass `(user, session_id)` to a helper defined as `(session_id, user)`. Baseline lines: 1062, 1079, 1088, 1099, 1109, 1176, 1215 and 1246. These affect autonomous lifecycle/approvals, decision logs, playbooks and KB snapshots. The start route additionally reads `sess.target`, although the helper returns a dictionary.

**Fix:** use explicit keyword arguments and a typed session DTO; use the correct target field. Validate `max_steps` and actually apply it: the request currently declares it but the engine uses its configured class limit instead. Test every v10 route with owner, non-owner and administrator identities.

### ENG-03/04 — Runtime interface errors

`_on_replan_event` searches all active runs and selects the first whose target equals `event.host`, rather than using the session that registered the callback. Two concurrent engagements against the same host can receive the wrong update, including event details. Bind the callback to its session/run ID and test two active runs with the same target. Timeline records themselves use `event`, matching the planner's history lookup; this interface was checked and is not reported as a defect.

Web Intel calls `self.call_llm`, which is absent from the current base class; available methods are `query_llm` and `query_llm_smart`. Reconcile the method signature and response parsing, then test both Web Intel entry points with a mocked provider.

### ENG-05 — Stop/restart races and incomplete cancellation

The engine launches an untracked background task. Stop immediately marks the run inactive but does not cancel or await that task; a new start can replace session state while an old command/planning operation remains in flight. The old loop's cleanup can unregister the new run's callback. Recheck stop immediately before execution and track each run by immutable run ID.

Cancelling the lifecycle manager's HTTP coroutine does not establish that a remote process has stopped. Moreover, the principal REST/chat/autonomous paths call HTTP directly rather than using the lifecycle manager. A single event queue distributes events among readers rather than broadcasting to all subscribers. In-memory runs/approvals vanish on restart and split across API workers.

**Fix:** durable run/job states, owned task handles, idempotency keys, remote cancellation acknowledgment, per-subscriber fan-out and bounded retention. Test stop during planning, execution and approval; immediate restart; two subscribers; process restart and duplicate job delivery.

### ENG-06 — Audit completeness is not guaranteed

Decision writes are best-effort and swallowed at debug level. Commands can execute while audit storage fails. An approved modified command is later logged as `approve` in the execution record, and the approval helper records the initiating run user rather than explicitly receiving the actual approver identity. Several manual paths use other audit/chat records rather than one linked command lifecycle.

**Fix:** require durable authorization events before critical dispatch; preserve actor, decision, modified command digest, policy version, job/result IDs and failure status. Use an explicit degraded mode when persistence fails. Do not claim tamper evidence or complete decision traceability without implementing and testing it.

### ENG-07/08 — Inconsistent state and persistence

The initial Redis session written by `create_session` omits `scope`, `session_id`, `status`, and `context_type`, unlike the database reconstruction path. A newly created cached session can therefore lack scope, weakening the REST proxy's conditional check. Define one serialized session representation and validate cached data.

Attack KB state and much shared memory are process-local. Vector `persist`/`load` methods exist but have no application lifecycle caller; keyword-only entries are skipped by vector persistence because entries without embeddings are ignored. Archiving a session does not visibly purge every associated in-memory run/cache. Implement a clear source of truth, rehydration strategy, retention policy and lifecycle cleanup. Test Redis loss and cold restart with and without embeddings.

### ENG-09/10 — Playbooks and claimed learning are incomplete

`_make_version_pattern` references `re` before a local `import re` when a version has fewer than two components; Python treats `re` as local throughout the method and raises `UnboundLocalError`. `_load_cache` marks loading complete even after a database error, suppressing future retry. Patch-level wildcard matching can suggest paths outside the exact vulnerable version; suggestions must retain and revalidate prerequisites.

No runtime caller of `save_successful_path` or `react_loop` was found in the tracked code. The autonomous engine uses `orchestrator_agent.process`, not the standalone ReAct loop. Successful runs therefore do not currently establish automatic playbook learning or integrated ReAct traces. Wire these features with evidence-backed success checks or narrow the claims; do not delete their modules merely because integration is unfinished.

### ENG-11 — External worker contract is unspecified

Manual REST/chat uses a JSON `token`, the autonomous engine uses `Authorization: Bearer`, and the lifecycle manager uses `X-Token`. Payloads also differ. Since the worker is absent, compatibility and process isolation cannot be verified. Define one client, request/response schema, authentication mechanism, job IDs, timeout semantics and cancellation API. Validate it against a mock first and a controlled worker later.

### ENG-12/13 — Delivery and operations

- No tracked automated test suite or CI workflow was present at the baseline. Syntax validity does not catch the contract, authorization and state errors above. Add focused unit tests, API/socket authorization tests, browser integration and controlled worker contract tests.
- `init_db` uses `create_all`; it creates absent tables but does not provide ordered upgrades of existing schemas. Introduce versioned migrations and test upgrade/rollback behavior with a restored database.
- Requirements mix exact old pins with unbounded lower limits and optional-heavy embedding packages in the main install. No lockfile, declared Python support matrix, license file or repeatable deployment manifest is present. Do not infer dependency CVEs from version age; run a current advisory scan separately.
- A temporary install under the review host's Python 3.14 failed building the pinned native dependencies (`asyncpg` and `pydantic-core`, including a PyO3 version-support error). The core review dependency subset installed under Python 3.11. Declare and enforce a supported Python version rather than assuming the system interpreter is compatible.
- `setup.sh` performs global installation, suppresses several failures, embeds database/demo settings, and creates a root service. Replace with an unprivileged service, explicit prerequisites, dedicated environment and verified startup/readiness.
- Runtime metadata still advertises v8/v9 in places while settings say v10. Health always returns `ok` without dependency readiness. Standardize version reporting, structured logs, correlation IDs and readiness probes.
- Provider quotas and key state are cached per process; key PATCH updates the database without visibly reloading the live pool. Verify immediate disable/limit changes and persist usage consistently before evaluating cost or rate-limit behavior.

### ENG-14/15 — Evidence quality and embedding performance

The NVD search keeps a CVE whose description mentions the service even if the supplied version is absent. `auto_enrich_port` then sets `exploitable` from a known module mapping and score threshold alone. That does not verify affected version ranges, configuration or prerequisites. Preserve these as candidate matches, evaluate applicability from structured affected-product data and target evidence, and require an independent validation step before exploitation. The module docstring advertises CIRCL fallback, but current service/detail methods use NVD followed by static data; the CIRCL constant is not an implemented fallback path.

Sentence-transformer loading and encoding happen synchronously from methods used by async request workflows. The first request may download/load the model, and subsequent encoding can stall other API work. Move initialization and inference to a bounded executor/worker, apply input limits, and benchmark concurrent requests in semantic and fallback modes. No throughput numbers were measured in this review.

## Remediation order and completion gates

1. **P0 — Restore a safe usable vertical slice:** unify browser/auth/API contracts; repair session/event interfaces; close arbitrary file access and socket disclosure; require real secrets; centralize execution scope/risk/approval enforcement. Gate: two-user negative authorization tests and one mocked end-to-end session pass.
2. **P1 — Make execution and evidence reliable:** durable authorization/job state, remote cancellation, worker contract, data isolation, encryption lifecycle, account revocation, redaction and audit persistence. Gate: restart, concurrency, audit-storage outage and adversarial-observation tests pass without unauthorized or duplicate execution.
3. **P2 — Prepare the academic evaluation:** migrations, reproducible environment, CI, bounded resource usage, evidence-grounded playbook learning, ReAct integration if retained, and the experimental protocol in `README.md`. Gate: repeated controlled runs with complete traces and published limitations.

## Verification and limitations

Checks performed include Git remote/revision comparison, tracked-file inventory, Python AST parsing, JavaScript syntax validation, shell syntax validation, import/export and base-agent method inspection, route/client comparison, and bounded probes of traversal, WebSocket authentication, scope/risk behavior and interface failures. Additional check results are recorded below after validation.

| Local check | Result |
| --- | --- |
| Python syntax | All 49 tracked Python source files parsed successfully |
| JavaScript / shell syntax | All three JavaScript files and retained `setup.sh` passed syntax checks |
| Core dependency subset / backend import | Installed in a temporary Python 3.11 environment; backend import succeeded |
| Liveness via ASGI transport, without startup lifespan | HTTP 200, version `10.0.0`; this did not connect to PostgreSQL or establish readiness |
| Encoded parent traversal via ASGI transport | Returned `config/settings.py` source outside `web/`; no secret file was requested |
| Frontend session-list URL | HTTP 200 with HTML, confirming fallback masks the missing API route |
| v10 status with a valid signed test identity and mocked session lookup | HTTP 500, confirming the argument/interface failure without a database |
| Autonomous socket handler with a mocked event source and no token | Received the private-session test event |
| `nmap -sV` risk / empty scope | Classified green / permitted a remote target |
| Single-component playbook version | Raised `UnboundLocalError` |
| Web Intel method interface | `call_llm` is absent |
| Two active runs against the same target | Callback selected the first run, irrespective of event origin |
| Documentation / cleanup | Local Markdown links and code fences checked; removed files absent; `git diff --check` passed |

No commands were sent to a Kali worker, no target scanning/exploitation was performed, and no production data was accessed. A full PostgreSQL/Redis-backed startup, real browser workflow, worker compatibility, live model quality, dependency advisory scan and performance benchmark remain outside verified coverage. Installing temporary review dependencies is not equivalent to validating the full declared dependency set, especially the embedding stack.

## Repository cleanup in this change

Removed only `apply_v10_overlay.sh` and `README_V10.md`. The installer expects a separate v9 target and references an absent `api/routers/pentest_v10_additions.py`; this checkout already contains the merged route block. The old README describes applying that overlay and overstates several guarantees. The new root README documents the integrated repository and explicitly marks the proposed evaluation architecture.

Retained `setup.sh` as legacy installation reference, all source modules, HTML/CSS/JavaScript assets, requirements and package initializers. No evidence justifies deleting runtime components as part of this documentation cleanup. Git history retains the removed material. Runtime findings are documented, not silently repaired by this change.
