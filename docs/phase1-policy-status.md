# Phase 1: program discovery and scope policy

Implemented 2026-11-05. The Phase 1 acceptance gate passes for the supported
capability: bounded, unauthenticated curl GET/HEAD observations. Discovery and
import never authorize testing; only explicit owner review and activation can
replace an engagement's execution scope. This is local engineering acceptance,
not approval to test a public program or a production deployment change.

## Using the feature

Open **Settings → Program discovery and policy** after selecting an engagement.

1. Import an official public HTTPS program page, or paste its policy text. Choose
   paid bounty, disclosure only, or unknown. ARIA does not assume participation
   eligibility or source authority from the URL.
2. Load the source-linked draft. Supply exact source excerpts and your interpretation
   for included assets, exclusions, eligible issue classes, account requirements,
   automation/traffic restrictions, and participation prerequisites. Missing or
   ambiguous permission remains unknown and cannot be activated.
3. Enter asset rules, ports, schemes, request/concurrency/rate limits, exclusions,
   and third-party exclusions. Confirm account requirements, prerequisites, and
   permission for HTTP observations. Save the review, then explicitly activate it.
   Stop/reconcile unfinished execution before activation.
4. Assess technical fit, account access, eligible classes, automation compatibility,
   research cost, and participation eligibility. The private shortlist explains its
   score and shows unknowns and prerequisites. Its ranking grants no permission.

Asset rows in the UI use `hostname | path | ports | schemes`. Example:
`app.example.test | /api | 443 | https`. Ports/schemes can be comma-separated.
`*.example.test` matches subdomains at any depth and excludes the apex
`example.test`. Exact hosts never implicitly include subdomains. A path permits
itself and descendants on a segment boundary: `/api` includes `/api/items`, not
`/apix`. `/` permits all unambiguous paths. Exclusions always take precedence.

## Implementation and acceptance map

| Task | Implementation / evidence |
| --- | --- |
| SCOPE-01 | Typed engagement-owned program records and immutable policy snapshots; official URL, retrieval/import time, exact UTF-8 text SHA-256, revision, and owner |
| SCOPE-02 | Bounded public HTTPS import with TLS hostname verification and validated public-IP DNS pinning; manual text fallback for authenticated, redirected, dynamic, oversized, or unsupported pages |
| SCOPE-03 | Conservative heading-based candidate extraction for scope, exclusions, classes, accounts, automation, and prerequisites; human source annotation for unstructured text |
| SCOPE-04 | Every candidate has an exact source quote and character offsets; candidate permission remains unknown; every reviewed execution field references a category-correct source rule |
| SCOPE-05 | Separate durable human review and explicit activation; latest source/latest owner review required; incomplete, unknown, prohibited, rejected, or unconfirmed permission cannot activate |
| SCOPE-06 | Shared server/worker hostname, wildcard, path, scheme, port, exclusion and third-party checks; one URL/request; no redirects, DNS escape beyond the worker ceiling, custom headers, mutations, arbitrary options, or unsupported tools |
| SCOPE-07 | Immutable source/review/activation events; source or review changes suspend activated policy, invalidate old scope/epoch-bound approvals, and request worker/connector cancellation; new activation requires reconciliation |
| SCOPE-08 | SQL-serialized per-engagement request reservations, concurrency and minimum interval; independent durable worker enforcement; no request refunds/revision resets; stop on throttling, server failure, or missing status evidence |
| SCOPE-09 | Private owner-only catalog across engagements, ranked with explained technical/account/class/automation/cost scores; unknown values remain visible |
| SCOPE-10 | Paid bounty, disclosure only, and unknown are explicit; source prerequisites and independently assessed participation eligibility remain visible |

Programs are engagement-bound: create a separate engagement for each candidate.
The catalog uses the newest source revision per engagement. Fit assessments are
revision-bound; changed source resets fit to unknown until reassessed. Scores are
0–10, equally weighting five dimensions; unknown dimensions contribute no points
and remain explicitly labelled. Participation eligibility is a separate assertion,
not inferred from that score, rewards, or program type.

## API and persistence

All endpoints require live authentication. Research records, reviews, activation,
fit, and history are limited to the engagement owner, including when an administrator
is signed in. The engagement must be active for changes/history. The private
catalog also includes the owner's saved candidates from previous engagements.

| Method / path | Purpose |
| --- | --- |
| `GET /api/programs/catalog` | Private ranked candidates and visible unknowns |
| `GET /api/programs/{session_id}/history` | Source/review/activation/fit events and authoritative policy/budget status |
| `POST /api/programs/{session_id}/import-text` | Manual policy import |
| `POST /api/programs/{session_id}/import-page` | Public HTTPS page retrieval and draft import |
| `POST /api/programs/{session_id}/{snapshot_id}/review` | Source-linked human review or rejection; optional structured execution rules |
| `POST /api/programs/{session_id}/{snapshot_id}/activate` | Explicit confirmation of the latest owner review |
| `POST /api/programs/{session_id}/{snapshot_id}/fit` | Revision-bound program-fit assessment |

Manual imports accept `name`, `source_url`, `text`, optional timezone-aware
`retrieved_at`, and `program_type`. Unknown retrieval time remains null; import
time is separate. Public imports also retain a hash of response bytes before HTML
text extraction. HTML scripts/styles are ignored. Source authenticity remains
unverified until assessed by the owner; HTTPS retrieval alone cannot establish
that a page grants authorization. No imported content is executed or sent to a model.

Snapshots/reviews/activations/fit use the existing SQL `decision_logs` ledger,
independent of optional explanation logging. Active policy is stored in authoritative
engagement scope; budget counters live in engagement metadata. Imports, reviews,
activation, and budget admission lock the engagement row. Source snapshots are
immutable. No database migration is required: schema head remains **0003**.
Client-created session scopes cannot supply the reserved `program_policy` field.

## Execution limits

- Reviewed programs enable one unauthenticated GET/HEAD URL per curl job. Nmap,
  mutation, authenticated replay, connector execution, custom executors and legacy
  worker transport are denied for these policies. Adding profiles requires its own
  policy/budget acceptance tests.
- Paths with encoded or ambiguous normalization, URL globbing, credentials,
  user-defined headers, redirects, retries, and non-reviewed flags are rejected.
  Some valid real-world URLs will therefore be unsupported.
- The independent worker network/port ceiling remains mandatory. DNS is pinned
  into the job's hosts file; the firewall allows only approved destinations and
  the single requested TCP port. Whole-host explicit exclusions are also checked
  against resolved addresses, conservatively denying shared-address cases.
- API reservations count attempted worker jobs even when dispatch fails. The worker
  also records admitted jobs before container creation. Neither counter resets
  across policy revisions or process restart. Limits may be tightened; changes do
  not restore used requests. Maximums are 1,000 requests and five concurrent jobs;
  request spacing is at least one second. Human review must choose stricter values
  when documented limits require them.
- HTTP 429, 5xx, network/missing-status evidence stops further worker traffic for
  that engagement. The API records an overload/backoff state; worker stop persists
  across restart. Reassess conditions and use a new engagement after human review
  to resume; there is no automatic overload retry or budget-reset endpoint.
- Activated-policy updates suspend dispatch before cancellation I/O. Running traffic
  cannot be recalled; cancellation uses existing durable intent/tombstone handling.
  Unresolved jobs prevent reactivation. Normal shared execution authorization and
  command-bound approvals continue to apply.
- Existing manually scoped engagements retain their behavior until owner activation
  replaces their scope. Merely importing a candidate never changes their permission.

The worker controller must advertise `program_policy_version: 1`; older controllers
are denied for this workflow. The real-container acceptance reused the immutable
Phase 0 tool image because the new policy/budget controls run in the controller
and the constrained curl arguments are already supported by that image.
No owner service, schema, credentials, `.env`, or deployment was changed.

## Validation

Python 3.11 and the existing locked dependencies; no new dependency was added.
Offline suites run outside the documented ASGI sandbox limitation. Outbound test
sockets remain mocked. The real-service runner creates and removes its own private
network, PostgreSQL database and harmless HTTP target containers with synthetic
accounts and secrets. It never uses owner databases or live model providers.

| Command | Result |
| --- | --- |
| `DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q` | 156 tests passed, including policy fixtures and retained regressions |
| `node tests/frontend_contracts.cjs` | Passed |
| `node --check web/static/scripts/programs.js` and `node --check web/static/scripts/app.js` | Passed |
| `ARIA_PHASE1=1 WORKER_TEST_RUNTIME=podman WORKER_TEST_IMAGE=sha256:bb5f48b3d9a9ca41d4375ff50627db0ed0caeeee2d50f8f355c39a2925839e33 DEBUG=false .venv/bin/python -B -m integration.phase1_policy` | Real SQL, explicit activation, isolated curl receipt, source suspension, stale approval, concurrent admission, durable budget, catalog unknowns, and other-owner denial |
| `DEBUG=false .local-lab/browser-venv/bin/python -B -m integration.browser_program_policy` | Firefox: seven synthetic workflow checks, no page errors; screenshots retained |
| `git diff --check` | Passed |

Artifacts are ignored under `.local-lab/phase1/` and `.local-lab/phase1-browser/`.
The browser screenshots include `policy-activated.png` and `program-shortlist.png`.
Browser checks use synthetic API responses; the separate service runner exercises
real SQL and containers. Public retrieval is tested with mocked DNS/TLS streams,
including pinned addresses and redirect/private-network denial; no live public
program was fetched or tested for this acceptance. General policy interpretation
is human-assisted, with conservative draft extraction, rather than a claim of
complete natural-language understanding.

## Retained Phase 0 recheck

Before Phase 1 changes, all 132 original offline Python tests and frontend contracts
passed. The Phase 0 source manifest, synthetic backup, and report hashes matched
the retained acceptance record. Historical Phase 0 evidence remains in
[phase0-baseline.md](phase0-baseline.md). Phase 1 service acceptance uses a fresh lab;
it does not modify or replace those retained artifacts.
