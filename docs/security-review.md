# Security remediation status

Historical validation checkpoint: counts and deployment statements below apply to
that recorded stage. See [the Phase 0 baseline](phase0-baseline.md) for the current
source inventory, schema head `0003`, and new validation results.

Worker follow-up: an initial curl/Nmap container worker is now included. See
[worker setup](worker-setup.md) and [executed validation](worker-validation.md).
Worker-absence statements below describe the earlier remediation checkpoint.

This document tracks the local P0/P1 remediation of the findings in
[`technical_revow.md`](../technical_revow.md). The original review remains a
baseline assessment, not a statement that every historical finding is still open.
No production deployment, real worker execution, model call, or security scan was
used to validate these changes. This document records local validation; publication status is tracked in Git history.

## Implemented groups

| Group | Findings | Implementation | Regression coverage |
| --- | --- | --- | --- |
| 1. File/API routing | SEC-01, part of ENG-01 | Removed request-derived file serving. Explicit UI pages and Starlette's confined static mount remain; unknown API paths return JSON 404. | `tests/test_routing.py`: encoded traversal, symlinks, unknown routes, valid UI/static assets. |
| 2. Secrets/bootstrap | SEC-05, SEC-06 | Required deployment-provided signing/worker/encryption secrets and database URL. Removed automatic demo seeding. Added interactive administrator bootstrap. Missing/invalid encryption keys and ciphertext fail explicitly without logging keys. Legacy installer now requires deliberate environment/database provisioning. | `tests/test_secrets.py`: absent/known-invalid configuration, persistent encryption, wrong keys/ciphertext, absence of automatic seeding. |
| 3. Session/socket/client integration | SEC-02, ENG-01, ENG-02 | Fixed eight session-helper calls and dictionary access, bypassed cached authorization metadata, denied absent ownership, authenticated/authorized event streams, validated origins, aligned frontend routes/token/session/key fields and top-level plans, honored bounded step limits. | `tests/test_access.py` and `tests/frontend_contracts.cjs`: owner/non-owner cases, invalid/expired/missing tokens, origin denial, login/session/plan/approval/socket contracts. |
| 4. Execution authorization | SEC-03, SEC-04; prerequisites from SEC-13 and ENG-06/07/11 | Shared server-derived risk/target policy and durable command-bound approvals cover REST, chat, autonomous execution, lifecycle execution and ReAct/custom executors. One worker transport uses bearer authentication. Authorization records commit before dispatch; claims are consumed once. | `tests/test_execution.py`, `tests/test_authorization_store.py`: all callers, denied dispatch, approved execution, modifications, scope changes, expiry, replay, races, storage failure, worker timeout and SQL transition behavior. |

The tool-result ingestion route also checks session ownership before changing
engagement state; this is a direct prerequisite for protecting the restored flow,
not a complete implementation of worker-result provenance (SEC-16).

## Files changed by group

- Group 1: `api/main.py`, `tests/__init__.py`, `tests/support.py`, `tests/test_routing.py`.
- Group 2: `config/settings.py`, `api/auth.py`, `api/main.py`, `api/bootstrap_admin.py`, `llm/pool_manager.py`, `setup.sh`, `tests/test_secrets.py`.
- Group 3: `api/auth.py`, `api/session_access.py`, `api/routers/pentest.py`, `agents/autonomous_engine.py`, `web/static/scripts/app.js`, `tests/test_access.py`, `tests/frontend_contracts.cjs`.
- Group 4: `orchestrator/execution_policy.py`, `orchestrator/risk_scorer.py`, `api/middleware/scope_validator.py`, `memory/execution_authorization.py`, `memory/session_manager.py`, `memory/command_lifecycle.py`, `api/routers/pentest.py`, `agents/autonomous_engine.py`, `agents/orchestrator_agent.py`, `web/static/scripts/app.js`, `tests/test_execution.py`, `tests/test_authorization_store.py`. Shared fixtures/access tests were updated for live socket authentication and DNS blocking.
- Status documentation: `README.md`, `technical_revow.md`, and this file.

## Execution policy

- Every dispatch requires an active database user and active engagement with known
  ownership. Administrator status comes from the database at this boundary.
- Scope is read from PostgreSQL, not a cached request, UI target, or model output.
  Empty scope, unparsed targets, excluded targets and unknown command syntax deny
  dispatch. Domains match explicitly; subdomains are not implicitly included.
- Reviewed adapters validate supported tool options and reconstruct shell arguments
  with `shlex.join`. Shell chaining, expansions, redirects, arbitrary interpreters,
  target files, unreviewed scripts/configs and HTTP redirect-following are blocked.
  Metasploit has a separate constrained module/statement adapter.
- Critical actions require explicit approval of the canonical command. A model or
  caller cannot downgrade risk or submit a boolean that acts as approval. Modified
  commands pass validation again and replace the authorization binding.
- Proposals expire after ten minutes and bind the requester, session, command,
  current ownership/scope and revision. PostgreSQL row locks and compare-and-set
  transitions prevent duplicate use. Audit-storage failure denies dispatch even
  when optional legacy decision logging is disabled.
- Claims commit before contacting the worker. After a timeout, the same claim is
  not replayed automatically. This prevents duplicate dispatch; it does **not**
  prove remote cancellation or exactly-once worker execution.
- The manual UI creates a proposal, displays server-required confirmation, records
  the decision and supplies the action ID on execution. API clients can use
  `POST /api/execution/proposals` and
  `POST /api/execution/{action_id}/decision` with the engagement ID.

The conservative adapter list intentionally blocks previously accepted arbitrary
shell commands and unsupported flags. It retains reviewed command forms for nmap,
curl, DNS/WHOIS lookups, nuclei, nikto, gobuster, hydra, sqlmap, enum4linux,
smbclient, searchsploit and Metasploit. Adding a tool/option requires an adapter and
negative regression tests; human approval does not bypass syntax/scope policy.

## Validation

Run with the project dependencies installed in Python 3.11:

```bash
python -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
node --check web/static/scripts/app.js
bash -n setup.sh
```

Tests generate ephemeral test-process secrets. Python fixtures block socket
connections and DNS resolution and disable embedding downloads. Workers, language
models and SQL/cache behavior are mocked; the transport-contract test uses
`httpx.MockTransport`. The Node scenarios execute the real frontend code in a VM
with fake DOM, storage, API and WebSocket implementations.

**P0 checkpoint:** 34 Python regression tests passed; the mocked Node login/session/plan/approval/rejection/socket scenarios passed; JavaScript and shell syntax, Python AST parsing (59 files), documentation links/fences and `git diff --check` passed. No known failures remain in these checks.

A real PostgreSQL concurrency run, full startup with PostgreSQL/Redis, browser
end-to-end testing, and compatibility with an external Kali server remain
unverified. The worker implementation is absent. It must adopt the shared bearer
contract; JSON-token and `X-Token` fallback authentication were removed to avoid
ambiguous downgrade behavior.

## Prioritized P1 implementation

| Group | Findings | Changes / regression coverage |
| --- | --- | --- |
| Private memory and report access | SEC-07/08/09/14, ENG-07/09 | Retrieval filters authoritative owned session IDs before ranking. Playbooks use fresh owner-scoped SQL snapshots and row-locked counters. Redis vector cache uses authenticated encrypted JSON v3, validates shape/size, restores keyword entries and ignores old pickle data. Reports have persistent session mappings, random unique names, owner checks, content hashes, no-follow reads and private filesystem permissions. Concurrent same-target exports do not overwrite each other. |
| Credentials and account lifecycle | SEC-10/11; SEC-06 rotation support | Passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations, constant-time verification and on-login legacy migration. HTTP and socket identity uses live database state. Credential revisions in existing user preferences persist logout/password/role/deactivation revocation across restarts. Login admission is atomic in Redis or bounded per-process memory when Redis is absent. Previous Fernet keys support controlled rotation; provider pools retain ciphertext, reload before calls and reserve quota atomically. |
| Outbound data and evidence | SEC-12/16, ENG-04/14 | Model/log boundaries redact structured credentials, authentication headers, cookies, private keys, URI credentials, JWTs and known provider/recovered secrets. Observations are labelled untrusted. Gemini credentials use a header instead of a query string. Worker uploads must match durable output/exit-status receipts; manual uploads remain available with an explicit manual evidence label. Reports distinguish unverified findings. Web Intel's missing interface is restored with session authorization. CVE search hits remain candidates rather than inferred exploitation proof. |
| Worker lifecycle and concurrency | ENG-03/05/06/08/11 | Durable job IDs/states, strict worker capabilities/receipts, acknowledged cancellation, deadline handling, restart reconciliation without resubmission, per-engagement admission locks/fences, expired pre-stop approvals, protected job diagnostics and cancellation before archival. Run tasks are tracked; concurrent start/stop is serialized, callbacks bind run/session IDs, and subscribers receive independent event queues. |

Primary files added for P1: `memory/access_scope.py`, `memory/report_artifacts.py`,
`memory/worker_jobs.py`, `security/credentials.py`, `security/encryption.py`,
`security/redaction.py`, `security/login_throttle.py`, `api/import_report.py`, and
`api/rotate_provider_keys.py`. Existing agents, auth/admin/report/session/pentest
routers, provider adapters, memory stores and frontend auth handling were updated.
Tests are in `tests/test_p1_isolation.py`, `tests/test_p1_credentials.py`,
`tests/test_p1_workers.py` and `tests/test_p1_agent_boundaries.py`, alongside the
retained P0 regressions and mocked Node scenarios.

**Current local results:** 72 Python tests pass. Mocked Node scenarios, Python AST,
JavaScript/shell syntax and whitespace checks pass. Earlier verification found one
legacy transport fixture passing `transport` twice; that fixture was corrected.
No remaining failures are known in the executed checks.

### Compatibility and operator steps

- Tokens issued before credential revisions were introduced are deliberately
  invalidated; users must sign in again. Existing legacy password hashes migrate
  after successful login. Historical demonstration passwords still need operator
  rotation; this change does not silently delete accounts or change their secrets.
- Keep the primary Fernet key persistent. To rotate, configure the new
  `FERNET_KEY` and JSON `FERNET_PREVIOUS_KEYS`, run
  `python -m api.rotate_provider_keys`, verify decryption, and retain old keys until
  encrypted cache records have expired or been rewritten. The command commits all
  provider-key updates together and prints only a count.
- Old report files are not automatically assigned to a user based on target names.
  After independently checking ownership, a trusted operator can run
  `python -m api.import_report --source /path/to/old-report.md --session-id <id>`.
  It preserves the original file, creates a private randomly named copy and records
  the engagement mapping. A filename collision cannot overwrite/delete an export.
- The default worker protocol is jobs-v1. Explicit legacy compatibility is
  retained, but cannot confirm remote termination. See
  [worker-contract.md](worker-contract.md) for deployment requirements and status
  semantics. No external worker server implementation was added or contacted.
- APIs that change state require Bearer authentication. HttpOnly cookies support
  protected read/download navigation. Browser sockets authenticate in the first
  message, not the URL. Revoked client tokens are cleared to avoid login loops.
- Login admission limits are shared/restart-safe with Redis; without Redis they
  are local to one API process and reset on restart. Provider quota reservations
  count attempted external calls, including failed attempts, conservatively.

## Remaining limitations / follow-up

These changes do not close every broader P1/P2 item in the historical review.
This document records the earlier P0/P1 pass; [p2-status.md](p2-status.md) supersedes
its historical installation, test-count and migration descriptions.

- A live PostgreSQL/Redis startup, PostgreSQL concurrency stress, browser end-to-end
  run and real worker/provider integration remain unverified. Tests use in-memory
  storage doubles, mocked SQL sessions, mock HTTP transports and a fake DOM.
- Critical authorization and job transitions are durable, but optional reasoning
  logs remain best-effort. Full attack-KB/run/approval-UI rehydration and complete
  decision-log coverage are not implemented. Vector cache restores when Redis is
  available; cache loss is not equivalent to restoring the whole investigation.
- Keep one API process until distributed autonomous-run ownership and full recovery
  are implemented. Jobs use PostgreSQL admission locks, but planning state and live
  subscribers are local. Local login throttling also assumes one process.
- Redaction is defense in depth, not a guarantee that arbitrary unlabelled secrets
  or personal data are detected. Source evidence/reports remain sensitive, and SQL,
  report volumes, backups, infrastructure logs and external-provider policies need
  deployment protection. Strict typed model schemas and explicit per-engagement
  external-data consent policy remain future work.
- Worker-side isolation, TLS deployment, DNS pinning, process-group termination and
  persistent worker idempotency require the external worker implementation. Unknown
  legacy outcomes cannot be resolved safely by guessing or replaying execution.
- P2 follow-up adds versioned migrations, CI, locked core dependencies, an
  unprivileged setup and bounded embedding inference; current results and limits
  are in [p2-status.md](p2-status.md). Dormant learning/ReAct claims are explicitly
  narrowed. Stricter CSP/browser-token storage, global request limits, complete CVE
  applicability, full recovery and real embedding performance remain open. The
  earlier P1 pass used existing JSON/ledger columns; migrations now also track
  the schema revision in `alembic_version`.


The subsequent reliability/specialist/Community work is recorded separately in
[the upgrade validation register](aria-upgrade-validation.md), including explicit
blocked and untested cases. Its staged implementation is not full release acceptance.
