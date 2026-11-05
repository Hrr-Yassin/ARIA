# Phase 0: engineering baseline

Date: 2026-11-05. Base commit: `37d6cb066654e4b00fa18adfe8f2ce3e0da50801`.
Validation applies to that revision plus the Phase 0 working-tree changes described
here. Local artifact metadata records a source-content hash. This is an engineering
baseline, not a production release or proof of specialist expertise.

## Capability inventory (BASE-01)

The [registered route inventory](phase0-route-inventory.csv) lists all 71 API
path/method registrations, including HTTP and WebSocket handlers. It was generated
from `api.main.app.routes`, rather than inferred from frontend buttons. The route
admission regression checks missing identity; it does not prove all route behavior.

| Area | Implemented | Validation level / unavailable behavior |
| --- | --- | --- |
| Identity and engagements | Login/logout, live identity checks, scope and ownership checks, session history | Offline regressions and synthetic service checks; infrastructure TLS and broad browser hardening remain separate work |
| Planning | Coordinator, orchestrator, planner, intent/phase engines | Mocked specialist fixtures; live general planning quality is not established |
| Specialists | Recon, scan, vulnerability, web intelligence, correlation, post-access, reporting | Entry points and typed candidate/action contracts exist; post-access execution is blocked; independent expert quality review remains pending |
| Execution authorization | SQL proposals, policy validation, command-bound decisions, single-use claims | Offline denial/replay/concurrency tests; Phase 0 adds a real-container trace with explicit approval |
| Worker | Authenticated jobs-v1, independent PostgreSQL ledger, constrained job containers | Existing real worker scenarios plus Phase 0 HTTP trace; external TCP/TLS worker deployment is outside this gate |
| Worker profiles | curl and bounded Nmap TCP forms | API adapter descriptions of other tools do not enable them on this worker; raw/UDP/NSE and arbitrary commands are unavailable |
| Reporting | HTML, Markdown, LaTeX, PDF generation and owner-bound downloads | Reports include worker ledger IDs/hashes and selected HTTP capture provenance; observations do not establish vulnerabilities |
| Memory/recovery | SQL evidence/history, encrypted optional Redis vectors, durable run snapshots, worker recovery | Recovery reconciles/cancels without replay; full attack-KB/planner rehydration and automatic investigation resumption are unavailable |
| Burp Community | Encrypted selected-capture import, connector APIs, Repeater handoff and request-bound web-action records | Feature-gated; the isolated Phase 0 lab disables it. Real desktop replay/mutation release acceptance is not established by this baseline |
| Learning | Private playbook lookup and counters | Automatic reviewed learning and main-workflow ReAct integration remain deferred |
| Providers | Per-user Groq, Gemini and OpenRouter adapters | No live provider calls in Phase 0; model identifiers and production availability are not validated here |

Relevant switches and limits:

| Setting | Code default | Meaning |
| --- | --- | --- |
| `DEBUG` | `false` | API documentation visibility; use an actual boolean string |
| `KALI_AGENT_URL` | empty | Worker must be configured separately; never infer reachability from configuration |
| `KALI_WORKER_PROTOCOL` | `jobs-v1` | Required durable transport; legacy mode lacks equivalent cancellation guarantees |
| `BURP_COMMUNITY_ENABLED` | `false` | Connector release gate; user binding and token configuration also apply |
| `AUTONOMOUS_MAX_STEPS` | `12` | Bounded autonomous run size |
| `AUTONOMOUS_STEP_TIMEOUT_SECONDS` | `120` | API execution timeout ceiling |
| `AUTO_RISK_THRESHOLD` | `green_orange` | Default autonomous approval threshold; server policy still applies |
| `DECISION_LOG_ENABLED` | `true` | Optional explanation logs; authorization persistence remains mandatory |
| `ARIA_EMBEDDING_MODEL_PATH` | unset | Optional local embedding model; the supported core uses keyword fallback |

`GET /api/capabilities` requires identity and returns supported profiles separately
from current worker reachability. Only the intersection of advertised tools and
this release's curl/Nmap profiles is shown as available. Failure or malformed
capabilities yield no available tools; transport errors and private URLs are hidden.
Settings shows online, not-configured, unreachable, and request-failure states.
This display is informational and does not grant execution permission.

## Schema and historical records (BASE-02)

| Revision | Responsibility |
| --- | --- |
| `0001` | Frozen v10 baseline; initial upgrade only on an empty database |
| `0002` | Durable autonomous-run snapshots |
| `0003` | Durable request-bound web-action approvals and outcomes |

The current startup requirement and migration head are **0003**. Historical P0,
P1, P2, worker, browser and upgrade registers retain their original test counts
and dates. Their results do not describe this entire source revision. Read this
file for Phase 0 evidence and those registers for their specifically stated checks.
No owner deployment was migrated or restarted as part of Phase 0.

## Isolated staging configuration (BASE-03)

Use Python 3.11, the installed hash-locked dependencies, a supported local container
runtime, and a previously built immutable worker image. For Podman:

```bash
podman build -f worker/Dockerfile -t aria-worker:test .
ARIA_PHASE0=1 WORKER_TEST_RUNTIME=podman DEBUG=false \
  .venv/bin/python -B -m integration.phase0_baseline
```

The runner creates a unique `aria-worker-test-*` private network and containers:
PostgreSQL 16.6, Redis 7.4.1 and harmless HTTP servers. Published database/cache
ports are random and bound to loopback. The existing worker fixture checks target
reachability before confinement. Only synthetic data and generated process-local
signing, encryption, worker, and account secrets are used.

Application databases are `aria_phase0_test`, `aria_restore_test`,
`aria_rollback_test`, and `aria_verify_restore_test` inside the newly created
PostgreSQL container; the worker uses `aria_worker_test`. Redis uses DB 15 in the
new Redis container. Names may repeat across runs because the containers are unique.
The application points to an ASGI worker transport, not an existing worker URL.
The Burp connector and optional embeddings are disabled; no provider keys are loaded.

The runner does not call `integration.stage_upgrade`, which reads the owner DB.
It does not edit `.env`, owner accounts, Redis DB 0, service units, or existing VMs.
Cleanup removes only its own containers/volumes/network. Reports, synthetic backup,
source manifest and sanitized results remain under ignored `.local-lab/phase0/`.
Review `services.log` and `result.json` for a failed run before retrying.

## Validation record (BASE-04)

Environment: Linux x86_64, CPython 3.11.17, Node 22.23.1; real-service acceptance
uses rootless Podman with PostgreSQL 16.6 and Redis 7.4.1. No public target or live
model is part of this baseline.

| Command | Result |
| --- | --- |
| `DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q` | Passed: 132 tests, 5.979 seconds |
| `node tests/frontend_contracts.cjs` | Passed |
| `node --check web/static/scripts/app.js` | Passed |
| `.venv/bin/python -m pip check` | Passed |
| `git diff --check` | Passed |
| `ARIA_WORKER_INTEGRATION=1 WORKER_TEST_RUNTIME=podman WORKER_TEST_IMAGE=<immutable image ID below> .venv/bin/python -B -m unittest integration.test_worker -v` | Passed: seven real-container tests, 83.332 seconds |
| `ARIA_PHASE0=1 WORKER_TEST_RUNTIME=podman DEBUG=false .venv/bin/python -B -m integration.phase0_baseline` | Passed: five service tests, backup/restore and approved action-to-report/restart trace |
| `DEBUG=false .local-lab/browser-venv/bin/python integration/browser_reliability.py` | Passed: ten checks including four capability states; no page errors |

The unchanged base suite passed **128 tests** outside the sandbox in 6.117 seconds.
A sandboxed run stalled on its first ASGI request; running the same suite outside
that sandbox completed. Tests retain their outbound socket/DNS mocks. The shell
also supplies an invalid ambient `DEBUG` string, so the command overrides it for
the test process only. No `.env` change is needed.

## Backup, migration and rollback checks (BASE-05)

The runner first executes `integration.test_services`: upgrade/check on an empty
DB; downgrade and synthetic legacy adoption; upgrade/check again; real SQL/cache
and recovery tests. Those destructive checks run only in its new container.

It then creates a synthetic database at `0001`, inserts a retained synthetic user,
and takes an actual custom-format `pg_dump`. It restores that backup into a separate
staging database, upgrades through `0002` and `0003`, runs `alembic check`, and
verifies the retained password-hash marker. Finally it restores the same backup
into another fresh DB and verifies revision `0001` and the marker, demonstrating
rollback through restore. The backup's SHA-256 is recorded in `result.json`.

For operational rollback, stop writes, preserve the failed database for inspection,
restore the verified pre-upgrade backup into a fresh database, point the matching
previous application revision at that restore, and verify schema/data/readiness
before reopening writes. Restoring a backup can lose post-backup writes; plan the
maintenance window accordingly. Do not use `alembic downgrade base` on owner data.

This proves the synthetic backup/restore procedure, not a backup/restore of owner
or customer data. No claim about owner schema adoption is made.

## Action-to-report trace and restart (BASE-06 / BASE-07)

The acceptance runner uses real synthetic SQL accounts and authenticated ASGI API
requests. It creates one engagement scoped to the private HTTP target on TCP 8080.
The trace requires explicit approval for a harmless HTTP HEAD observation and checks:

1. A SQL proposal records canonical command, scope digest, requester, expiry, and policy risk.
2. Dispatch without the required approval returns 403.
3. A decision records the approver and exact proposal; execution consumes it once.
4. The authenticated worker endpoint launches a real isolated curl job and saves its receipt in an independent SQL ledger.
5. ARIA verifies output hashes against its durable job record, saves tool-output history, and accepts the receipt through `/api/tool-results`. Interpretation is mocked; receipt verification and SQL/cache ingestion are real.
6. A Markdown report includes the owned job ID and output hashes, with zero vulnerability findings; owner download succeeds and another user is denied.
7. The worker controller and API lifespan are recreated using persisted SQL state. An unfinished run becomes blocked; saved history/report remain readable; consuming the old action again is denied; no job is resubmitted.

`result.json` links action ID, job ID, evidence ID, report filename/hash and output
hash. The HTTP response is an observation, not a vulnerability. Models are patched
to fail if called. ASGI transport exercises endpoint/authentication code but does
not validate external TCP/TLS transport. Restart recreation is not a host power-loss
or comprehensive crash-consistency test.

## Baseline fixes

The result-ingestion route called nonexistent
`workflow_engine.suggest_phase_transition`, causing otherwise valid tool results to
fail after interpretation. It now calls the existing `suggest_next_phase` interface
with an explicit finding-presence flag. An offline regression covers ingestion and
phase advancement; the real-worker trace also ingests its receipt with mocked
interpretation. This does not certify broader workflow coverage or live model quality.
Reports now include scoped worker-ledger receipt references even when an observation
produces zero findings. This closes the action-to-report provenance gap without
classifying successful HTTP responses as vulnerabilities.

## Capability UI evidence (BASE-08)

The Firefox fixture harness exercises the real Settings panel with synthetic online,
not-configured, unreachable and API-error responses. Screenshots and browser results
are saved in `.local-lab/reliability-browser/capabilities-*.png` and `report.json`.
API regressions additionally cover missing identity, malformed tool advertisements,
unsupported tools and suppression of private transport-error text.

## Acceptance decision

BASE-01 through BASE-08 are complete for the engineering baseline. The commands
above pass, including explicit approval, session/report isolation, migration and
synthetic backup/restore, saved history and restart no-replay checks. Phase 1 policy management and live vulnerability research are not
part of this implementation.

## Retained acceptance identifiers

The successful final run used source-manifest SHA-256
`80e0d4ce99236ab415e7f2ff80acb885bd47aea9a977792ca33f376cf0779c2e`
and worker image
`sha256:bb5f48b3d9a9ca41d4375ff50627db0ed0caeeee2d50f8f355c39a2925839e33`.
Its action/job ID was `7fec0b71-987b-4b37-9bfc-322939d79a94`; saved tool evidence
ID was `d27e02c0-f04a-455d-84f8-0545a1ff1feb`. The Markdown report hash was
`db1b32acec7f384aaf40b46546f2fd2538b1c733166e3b1481d677ec9e19d0d1`.
These are synthetic fixture identifiers, not customer records. The content manifest
covers Python, SQL, JSON and browser source assets; documentation-only completion
updates follow the run. Detailed local artifacts remain ignored and are not
published by this change.
