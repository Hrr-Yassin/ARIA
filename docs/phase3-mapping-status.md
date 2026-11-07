# Phase 3: authenticated application mapping

Implemented and validated on 2026-11-06 in the working tree based on `d278f45`;
no PR created. **Phase 3 is complete for the bounded, supervised lab profile below.**
This is implementation/acceptance evidence, not an owner deployment change or a
claim of production readiness, arbitrary authenticated browsing, or vulnerability
verification. Phase 4 remains separate work.

## What was actually realized

The first audit found saved-evidence mapping implemented and tested, plus browser
and authenticated-worker code that had not passed combined acceptance. The first
real worker run failed on its container working directory and private key mount;
both were fixed and verified. The first Community attempt timed out because its
lab VM was off. After verifying its isolated NIC/network, the target was started
for the bounded acceptance run and cleanly shut down afterward.

| Task | Implemented behavior and acceptance |
| --- | --- |
| WEB-01 | Controlled identities with explicit human ownership attestation, roles, opaque UUID handles, write-only encrypted authentication headers, object ownership records, expiry and revocation. Two distinct authenticated lab accounts tested |
| WEB-02 | Ephemeral Firefox contexts keyed by ARIA owner, engagement and application identity. Cookies/local storage remain separate; closing a context discards its state. Service workers/downloads/permissions disabled, WebSockets blocked, WebRTC/prefetch disabled. Browser HTTP is fulfilled by approved worker receipts, never native `route.continue_()` traffic |
| WEB-03 | Official Burp Community runtime loaded; real proxy capture, selected import/deduplication and Repeater staging passed. Scanner remains unavailable. The connector's deployment flag remains off by default |
| WEB-04 | Endpoint catalog from selected captures and reviewed worker/browser observations: method, origin/route, parameter names, identity/role, timestamps, hashes and evidence/job references. Planned requests remain separate from observations |
| WEB-05 | Human-recorded, evidence-linked before/after workflows for sharing, invitations, exports and account settings. These records do not execute state changes |
| WEB-06 | Expected allow/deny/unknown object permissions per identity/operation. Corrections append a record linked to the superseded human assertion |
| WEB-07 | Structured `aria-http` worker capability binds identity, capture/request, full encrypted request digest, current scope/principal and one-use approval. Independent worker network/port ceiling, shared admission limits, deadline, cancellation and restart reconciliation tested |
| WEB-08 | Private bounded originals plus response comparison using status, content type and JSON content or byte digests. Object key order normalized; array order retained. Duplicate keys/invalid JSON fall back to bytes. Explicit ignored keys remain visible. Every comparison remains an observation |
| WEB-09 | Encrypted private map, default-deny provider consent, registered-secret rejection before provider admission, secret-safe validation, source-copy expiry, private worker receipt expiry and periodic cleanup. Existing maps adopt the consent marker at startup. Retention also erases linked legacy ARIA replay copies and requests cancellation when necessary |

## Supported boundaries

The authenticated profile supports **bodyless GET/HEAD without query strings**.
Only the selected identity's Authorization, Cookie and/or X-API-Key headers are
sent; other captured headers are omitted. Credentials are limited to 2,048
printable characters per header for this transport. Credential-bearing URLs are
rejected before an approval command is returned. POST/PUT/PATCH/DELETE, login
submission, mutations, redirects, retries and arbitrary shell execution are not
part of this profile. Browser navigation uses GET only.

Each HTTP job has a ten-second maximum deadline and a 32 KiB response limit.
Mapping-enabled scopes share 1–20 worker admissions, concurrency one, and a minimum
one-second admission interval. Cancellation, unknown results, HTTP 429 and 5xx
responses stop subsequent admissions for that engagement; use a new engagement
after review. A bodyless profile job sends one HTTP request. The worker repeats
scope validation, DNS pinning and its independent network/port ceiling.

Explicit `scope.web_authenticated_replay: true` is required. Reviewed program
snapshots remain blocked for this authenticated profile: Phase 1's bounded
unauthenticated curl permission is not silently expanded into authenticated
permission. Validation used isolated synthetic accounts/services. No public-target
authenticated testing or live model calls were performed.

Browser previews consume a separately approved job and render its bounded
response. Additional links/resources need their own supported approved requests;
automatic crawling and arbitrary interactive application/login flows are not
implemented. The API returns a PNG preview with `Cache-Control: no-store`.
There is no dedicated mapping form in the existing web UI; use the API.

Worker evidence preserves the original response content privately as a parsed HTTP
response snapshot; HTTP framing is reconstructed by the standard-library client.
This is not a packet-level wire transcript. Selected Burp captures retain their
original bounded request/response bytes. Header differences other than content
type are not part of the semantic equality decision. Equality never establishes
correct authorization or confirms a vulnerability.

## API workflow

Use Bearer authentication and an active directly owned engagement; no administrator
override. Read `GET /api/application-map/{session_id}` first. Mutations take its
`expected_revision` (initially zero); stale changes return 409. Reload after an
uncertain response or after browser/catalog activity changes the revision.

| Method and suffix under `/api/application-map/{session_id}` | Purpose / principal fields |
| --- | --- |
| GET (no suffix) | Redacted map/revision; no credentials or original HTTP content |
| POST `/identities` | `label`, `role`, `researcher_controlled: true`, optional `credentials` dictionary; returns opaque identity `id` |
| POST `/requests` | `identity_id`, `method` (`GET`/`HEAD`), `url`; saves a planned request, sends no traffic |
| POST `/captures` | `identity_id`, existing owned Burp `evidence_id`; requires exact credential-header match |
| POST `/identities/{id}/requests/{request_id}/replay-proposal` | Creates a pending shared execution proposal for a planned request |
| POST `/identities/{id}/captures/{capture_id}/replay-proposal` | Creates a pending proposal from a selected observation |
| POST `/browser-preview` | `identity_id`, approved `action_id`; consumes the approved GET, renders privately, catalogs observed endpoint evidence |
| POST `/replays/{job_id}/catalog` | Catalogs a successful private worker receipt; duplicate catalog delivery is idempotent |
| GET `/replays/{job_id}/comparison` | Compares a replay to its saved observed baseline; a planned request has no baseline yet |
| POST `/compare` | Observed capture IDs `left`, `right`, optional `ignore_json_keys` |
| POST `/objects` | `label`, `owner_identity_id`, selected `evidence_ids` |
| POST `/workflows` | `label`, `kind`, ordered `evidence_ids`, `before`, `after` |
| POST `/permissions` | `object_id`, `identity_id`, `operation`, `expected`, `rationale`, `evidence_ids` |
| PUT `/data-policy` | `retention_days` (1–90), `provider_sharing` (`deny` or `redacted_metadata`) |
| POST `/identities/{id}/revoke` | Revision only; erases mapped credentials/raw captures, fences/cancels engagement jobs and closes its browser context |

Approve using the existing `POST /api/execution/{action_id}/decision` with
`session_id` and `decision: approve`. For a direct replay, call
`POST /api/kali/execute` with that `action_id`, the exact returned `command`,
`tool: aria-http`, `session_id`, and `timeout: 10`. Use either direct execution
or browser preview: the same approval cannot be consumed twice. Pending/rejected,
modified, expired and stale-scope authorizations cannot dispatch.

Catalog a completed receipt before citing it as evidence. A planned request ID
cannot be used as object/workflow/permission evidence. Capture IDs identify map
observations; their `evidence_id` values are the references used by human records.
Researcher assertions of ownership/permissions are retained with their author and
supporting evidence; they are not automatically verified findings.

## Persistence, data consent and retention

The private snapshot is encrypted in `decision_logs`, outside model/chat context.
The authoritative engagement row serializes updates. Successful writes commit
before returning. The generic decision-log endpoint excludes this private row.
Limits are 20 identities, 500 records per other collection and 16 MiB of serialized
map content. Selected captures accept bounded 64 KiB requests / 1 MiB responses;
new worker responses use the stricter 32 KiB bound.

New maps default to seven-day credential/original retention and denied provider
sharing. Loading a map opts that engagement into this consent boundary. Provider
admission checks its authoritative policy and rejects registered credential values
before a physical provider call. Enabling `redacted_metadata` permits redacted
analysis subject to the existing model tariffs/budgets; the map itself is not
automatically submitted. Unlabelled personal data/unknown secrets still require
researcher review; no universal redaction guarantee is claimed.

Expiry is enforced on access, reconciled at startup and cleaned every minute while
the API/worker run. Shortening retention never extends existing expiry. Expired map
originals, linked ARIA source captures/legacy replay copies and private worker
request/response payloads are removed; attribution, hashes and human review history
remain. Revocation cancels/fences the engagement, so other active identities need
fresh proposals. Remote retention synchronization retries when a worker is
unavailable; disconnected services cannot be promised immediate deletion. Restored
backups, exported artifacts and native Burp project/history have their own operator
retention lifecycle. Broader customer-wide deletion remains OPS-02 work.

## Configuration and deployment

No owner `.env`, application/worker database, running ARIA deployment or VM network
configuration was changed. Alembic head remains **0003**; no schema migration is
required. The optional browser and worker encryption dependencies are hash locked.

1. Build `worker/Dockerfile` and deploy its reviewed immutable image ID with the
   existing local Docker/Podman worker configuration and restricted lab ceiling.
   The worker now installs the cryptography dependencies from
   `worker/requirements.txt`, extracted from the core hash lock.
2. Provision a dedicated persistent Fernet-format `HTTP_REPLAY_KEY` in both API and
   worker environments. Empty/invalid configuration leaves replay unavailable.
   Retain this key while private receipts need decryption; automatic rotation of
   these new receipt keys is not implemented. Ordinary map encryption continues
   to use the existing rotated `FERNET_KEY` mechanism.
3. For browser preview, install `python -m pip install --require-hashes -r
   requirements-browser.txt`, provision Firefox with `python -m playwright install
   firefox`, and set `BROWSER_MAPPING_ENABLED=true`. It defaults to false. Keep the
   existing single API process requirement for process-local browser contexts.
4. Enable mapping only for an explicitly scoped lab engagement. Configure its
   `web_authenticated_replay` and `web_request_budget`; these flags do not bypass
   the worker ceiling or shared approvals. Burp's existing user/loopback/token
   binding and disabled-by-default deployment flag remain in place.

The validated worker image was
`sha256:9e410ce197448c2927b2d832f9f3099d16e4dfb76743503d01fba11a05dba554`.
This is a local acceptance image, not a published artifact or deployment change.

## Validation and retained evidence

Validated on 2026-11-06 with Python 3.11.18 and Playwright 1.64.1:

| Check | Result / evidence |
| --- | --- |
| Full offline Python suite | 199 tests passed, including 22 Phase 3 mapping/profile regressions; providers mocked and network blocked |
| Frontend contracts | `node tests/frontend_contracts.cjs` passed |
| Dependency consistency / whitespace | `python -m pip check`, `git diff --check` passed |
| Real Firefox storage isolation | Three owner/engagement/identity contexts, isolated cookies/local storage, discarded closed-context state, blocked unapproved navigation/revocation. `.local-lab/phase3/browser.json` |
| Fresh PostgreSQL + isolated authenticated worker + real browser | Fourteen acceptance checks passed: two accounts, explicit approval denial/one-use, SQL reconstruction/owner isolation, objects/workflows/permissions, provider consent/secret guard, browser-to-worker endpoint catalog, redirect denial, acknowledged running cancellation, no restart replay, expiry, oversized response stop, deadline termination and startup consent reconciliation. `.local-lab/phase3/worker.json` |
| Official Burp Community runtime | Eight functional checks passed: native extension, capture, selected import/deduplication, Repeater staging, rejected replay, bounded legacy replay/mutation, one-use comparison and pre-dispatch cancellation. Fresh disposable SQL; `.local-lab/phase3/burp.json` and `.local-lab/burp-runtime/report.json` |
| Lab restoration | The target ignored ACPI shutdown. A clean guest-console shutdown restored `aria-metasploitable2` to its original **shut off** state; no forced power-off, owner DB access, or persistent VM/network reconfiguration |

The Community wrapper returned nonzero for its ACPI cleanup timeout after its
functional checks passed. The console shutdown and subsequent `virsh domstate`
check completed cleanup. Future runs on this old guest may need the same manual
clean shutdown; the harness intentionally does not force power off.

Reproduce using the isolated fixtures (never the owner database):

```bash
DEBUG=false .venv/bin/python -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
.venv/bin/python -m integration.phase3_browser
ARIA_PHASE3=1 ARIA_PHASE3_BROWSER=1 WORKER_TEST_RUNTIME=podman \
  WORKER_TEST_IMAGE=sha256:<reviewed-local-image-id> \
  .venv/bin/python -m integration.phase3_mapping
ARIA_PHASE3_BURP=1 WORKER_TEST_RUNTIME=podman \
  WORKER_TEST_IMAGE=sha256:<reviewed-local-image-id> \
  .venv/bin/python -m integration.phase3_burp
```

The full offline suite ran outside the filesystem/network sandbox because existing
synchronous FastAPI test dependencies stalled inside it; its own offline network
blocks remained active. The focused mapping/profile tests also pass inside the
sandbox. Lab JSON, source manifests, logs and preview PNGs stay under ignored
`.local-lab/phase3/`; they contain synthetic test data and are not deployment files.
