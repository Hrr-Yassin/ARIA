# Phase 6 reports and outcome tracking

Updated 2026-11-06. Implemented in the working tree based on `11bc3e9`, for the
bounded, human-reviewed Phase 5 private-JSON disclosure verifier. The acceptance
below uses synthetic saved evidence and storage doubles. It does not establish
independent live lab reproduction, a platform's acceptance, or production readiness.
No service, database, worker, deployment, external submission or live provider was
changed or contacted.

## Implemented workflow

Open Settings → **Reviewed reports and outcomes**. Load saved Phase 5 candidates,
select findings, and create a bug bounty or pentest draft. Bug bounty drafts require
exactly one currently reportable finding. Pentest drafts may contain several verified
findings, separately labeled unverified observations, or an honest no-finding result.
They include recorded scope, coverage, gaps, limitations, human priority/remediation
recommendations, and saved retest status. Priority defaults to **unrated**.

Only supported verifier results establish demonstrated claims. Report titles,
actual behavior and demonstrated impact are generated from the checked private-JSON
comparison, rather than arbitrary scanner titles or impact prose. The report retains
exact human-recorded test/reproduction steps, clean-state procedures, controlled
identity/object IDs, expected permissions, selected content controls and attributable
evidence. Ownership and permission intent remain human-reviewed assertions.
Potential escalation is explicitly unverified and separate from demonstrated impact.
No model call is needed to render either template.

Each draft is immutable. An edited selection or new retest creates a new revision
with `previous_report_id`; one lineage cannot silently fork from an older revision.
There is no edit-in-place or automatic carry-over of sign-off. A draft binds its
scope, finding revisions, complete evidence catalog snapshots, coverage, retest
records, source manifest and exact ZIP hash.

Preview shows the Markdown and **all** redacted attachments, not excerpts. Human
sign-off requires review of this exact package, credential redaction, and recorded
reproduction from the report (or review of a no-finding report). Sign-off records
actor, reason, report revision and package hash in the durable event ledger. A
checkbox is a human attestation; it does not prove an independent researcher has
actually reproduced the application behavior. That live acceptance remains open.

Downloading creates a deterministic ZIP containing:

- `report.md`: platform-ready Markdown, with source text escaped as literal content.
- `report.json`: the same structured report and reproduction procedures.
- `manifest.json`: scope and finding bindings; evidence reference-to-file mapping;
  original and exported byte counts/hashes; explicit redaction and trust labels.
- `evidence/*-request.http`, `*-response.http` and `*-source.txt`: complete retained
  bounded HTTP observations and full supporting tool-output text, with credentials
  redacted. No PDF excerpt limit or catalog-summary truncation applies.

Original protected captures remain private. UTF-8 text is preserved where valid;
other HTTP octets are decoded as ISO-8859-1 and exported as UTF-8 with that encoding
recorded. Redaction changes bytes and can change HTTP content lengths; attachments
are saved observations, not automatically executable requests. Reproduction needs
fresh researcher-controlled credentials supplied locally. Headers, credential-like
fields, known application/deployment credentials, JSON escapes and URL-encoded
credential representations are redacted. The human must inspect remaining evidence
before signing. No protected source ciphertext or private credential store is
exported.

Draft evidence files are encrypted in a separate owner/session-bound DecisionLog
record, committed in the same transaction as the draft event. They are not stored
in the public polling event stream. The existing encryption configuration and SQL
ledger are reused; there is no migration or dependency change. A 16 MiB limit rejects
oversized bundles rather than silently truncating evidence; select fewer findings.
A hash-only worker receipt or missing complete source cannot substitute for complete
supporting evidence: retain/catalog a complete tool-output record or selected capture
before generating the report. Original observations were already bounded at capture.
This is completeness of retained evidence, not a claim of unlimited wire capture.

Preview, sign-off and export recheck ownership, active engagement, current scope,
Phase 5 controls/permissions, original availability, source hashes and redaction.
Expired/revoked originals, changed findings/coverage/retests, missing complete sources,
changed private bundles, or newly required redaction block export and require a new
review. Historical reports/sign-offs remain auditable. An idempotent retry returns
its historical receipt; it does not bypass the fresh export check.

Legacy HTML/Markdown/LaTeX/PDF generation remains available as an **observation**
report. Even a legacy `human_verified` flag does not certify a Phase 5 finding.
Only the separate signed Phase 6 workflow provides the evidence-gated package;
legacy formats do not acquire sign-off through this update. New verified PDF
layout/export is not implemented and is not needed to submit the Markdown draft.

## Outcomes, triage and retests

Submitted, triaged, duplicate, informative, rejected, accepted, resolved and paid
are distinct **human-recorded** outcomes. The first record must be an actual
submission of a signed report; ARIA does not submit it. Subsequent records append
an optimistic-revision-checked history with actor, recording time, platform reference
and note. Prior outcomes are retained, including triage corrections. Paid records
require an actual positive decimal amount and currency; other outcomes cannot claim
a payment. There is no assumed payout, platform polling or revenue forecast.

Triage answers are saved, deterministic drafts for reproduction, impact, historical
scope or retests. They reference the signed report and saved evidence, label
historical observations, distinguish potential impact, and never send messages.
They can describe historical scope after it changes, explicitly flag that change,
and cannot establish current behavior. No additional testing occurs.

Retests record **fresh saved evidence** and a human conclusion: fixed,
still_vulnerable or inconclusive. They require a signed report's finding, current
unchanged scope digest, cataloged hashed evidence, complete retained sources and
explicit human review. Aliases of original reproduction sources are rejected. This
endpoint does not execute a test, authorize one, alter a verified finding or rewrite
a signed report. Existing approvals still control any separately performed traffic.
Changed scope is rejected and needs a newly authorized verification/report workflow.
A new report revision is needed to include a retest; prior findings describe their
historical test/reproduction rather than claim unchanged present behavior.

All endpoints require the direct owner of an active engagement, with no admin
ownership override. Broader archive access for inactive engagements, engagement-wide
artifact deletion/retention operations, additional verifier classes and production
operations remain outside this implementation. Phase 8 retention work still applies;
export denial after source expiry does not claim deletion of every historical draft.

## API

Prefix: `/api/report/{session_id}/drafts`.

| Method / suffix | Purpose |
| --- | --- |
| GET / | List immutable drafts, sign-offs, outcome histories, saved retests and triage drafts. |
| POST / | Create `bug_bounty` or `pentest` draft using finding IDs, observation IDs, optional per-finding priority/remediation recommendations and previous report ID. |
| GET /{report_id}/preview | Revalidate and preview full redacted report and attachments, exact package hash and sign-off. |
| POST /{report_id}/signoff | Record human review/reproduction/redaction attestations against exact `package_sha256`. |
| GET /{report_id}/export | Export signed ZIP after fresh revalidation; `no-store`, fixed filename and `X-Report-SHA256`. |
| POST /{report_id}/outcomes | Record platform outcome with `expected_revision`, reference, note and paid-only amount/currency. |
| POST /{report_id}/retests | Record fresh saved-evidence retest with expected scope digest; no execution. |
| POST /{report_id}/triage-answer | Save an unsent draft for a selected finding and supported topic. |

Mutation bodies use UUID `request_id`s. Same request/operation is idempotent;
a request ID reused with different data fails. Events publish only after commit.
Failed storage does not expose a committed draft/sign-off. The browser renders
untrusted text with `textContent`, requires explicit human attestations, authenticates
binary downloads and discards delayed responses after switching engagement.

## Requirement audit

| Requirement | Implementation |
| --- | --- |
| REPORT-01 | Deterministic bug bounty template: title, derived asset, prerequisites, exact saved steps, expected/actual behavior, attachments, bounded impact and remediation. |
| REPORT-02 | Pentest scope, recorded coverage/gaps, limitations, separate findings/observations, human recommendations and retest history; no-finding reports supported. |
| REPORT-03 | Complete redacted retained evidence files, original/export hashes and manifest; missing or oversized sources fail closed. |
| REPORT-04 | Fresh Phase 5 eligibility and content controls; derived demonstrated claims; separate unverified observations and potential escalation. |
| REPORT-05 | Full browser/API preview, immutable revisions and exact-package persisted human sign-off. |
| REPORT-06 | Signed platform-ready Markdown/JSON/evidence ZIP; external submission is manual. |
| REPORT-07 | Separate human-recorded statuses, append-only history and paid-only actual amount/currency. |
| REPORT-08 | Saved-evidence triage drafts and human retest results, scope/freshness checks, no traffic or automatic messages. |

## Acceptance evidence

Final validation on 2026-11-06, working tree based on `11bc3e9`:

- `DEBUG=false .venv/bin/python -m unittest discover -s tests -t . -q`:
  **280 tests passed in 12.387 seconds**. This includes 10 new report workflow tests
  and a legacy human-verified-flag regression, in addition to the existing 269 tests.
- `node tests/frontend_contracts.cjs`: passed, including authenticated binary response handling.
- `node tests/report_frontend_contracts.cjs`: passed for literal preview rendering,
  explicit exact-hash sign-off, ZIP download and delayed-response isolation after an
  engagement switch; no execution/submission endpoint is called.
- `ARIA_PHASE6_UI=1 .local-lab/browser-venv/bin/python -m integration.phase6_reports_ui`:
  local Firefox preview/sign-off/export-control checks with synthetic in-page API
  responses and all browser requests aborted; no horizontal overflow at 440 pixels.
  Result and visually inspected screenshots are retained under ignored
  `.local-lab/phase6/browser.json`, `report-preview-mobile.png` and `report-signed-mobile.png`.
- `git diff --check`: passed.

The Python controls exercise complete retained sources beyond catalog excerpt length,
manifest/file hashes, private encrypted bundle storage, stale scope/permissions/source
and finding rejection, missing sources, tampered bundles, immutable revisions, exact
sign-off hash, idempotency, storage failure, redaction/escaped credentials, unsupported
claim fields, payment history, fresh retest records, scope-change refusal, unsent triage
drafts, and owner-only API admission. Acceptance uses synthetic HTTP content, mock
persistence and no target/provider I/O.
An independent human reproduction against a live lab from the exported report alone
was not performed; the report records that attestation when the researcher supplies
it. Do not infer that release gate from the automated checks.
