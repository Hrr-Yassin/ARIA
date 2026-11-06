# Phase 5 independent saved-evidence verification

Updated 2026-11-06. Implemented for supervised lab investigations in this working
tree; no PR, service, database, deployment, scan or external submission was created.
Acceptance is offline synthetic evidence, not live lab reproduction or deployment
acceptance. The reportable gate currently supports selected private JSON disclosure
on the Phase 4 bodyless GET/HEAD authorization/exposure path. Other investigation
classes can retain candidates and human validation, but cannot become reviewed or
reportable without a supported original-content control. Phase 4's deployment
limitations still apply.

Phase 6 follow-up: [reporting and outcomes](phase6-reporting-status.md) adds a
separate immutable, signed report workflow. Legacy report exports remain observations.

## Lifecycle and review

Owner-only endpoints under `/api/team/{session_id}`:

- `GET /findings`: verification history's current findings, effective readiness,
  local duplicate candidates and explicitly unknown private-program duplicates.
- `POST /findings`: create an observation from a collected specialty task and a
  nonempty subset of its cataloged evidence. Supply `request_id`, title,
  `underlying_cause`, `affected_workflow`, hypothesis, `expected_behavior`,
  `evidence_references`, `specialist_task_id`, and optional `potential_escalation`.
- `POST /findings/{finding_id}/review`: supply `request_id`, `expected_revision`,
  target `state`, and reason. Tested/reproduced transitions take `validation`;
  reviewed/reportable transitions require `human_signoff: true`.

The progression is observation → hypothesis → tested → reproduced → reviewed →
reportable. Rejection is available at every nonterminal state. Blocked or
inconclusive decisions require `smallest_missing_validation` and can restart at
hypothesis, discarding prior validation/sign-off. A rejection is terminal; preserve
it and create a new candidate when materially different evidence arrives.

The independent reviewer is the authenticated engagement owner acting in an
explicit human-review role, separate from specialist result collection. This fits
the single-researcher product: it does not require a second user or claim two-person
approval. Models have no verification dispatch or automatic transition path. Review
can reject a specialist or request one missing control. Agreement, confidence,
scanner labels and status codes are not accepted as verification inputs.

Every transition checks the current revision and allowed edge. Scope and catalog
fingerprints must remain current. Review events and their evidence snapshots commit
before polling exposes them, using the existing locked engagement/team-event
ledger. Duplicate request delivery returns the committed event; a changed operation
with the same request ID is rejected. No migration is required. Legacy SQL findings
and reports retain their existing unverified semantics; this ledger does not
silently promote them or certify legacy report output. Phase 6 report integration
remains separate.

## Reproduction and controls

A validation records steps, account/object identification, expected permission,
meaningful content, demonstrated impact, a clean-state procedure, and separate
positive, negative, ownership and permission catalog references. Explicit human
attestations of controlled accounts/objects, clean state, meaningful content and a
passing negative control are mandatory. Expected or ambiguous behavior cannot
advance as a tested finding. Original source identities distinguish positive from
negative observations; reproduction needs fresh positive AND negative sources,
disjoint from the first test and the candidate sources. Reusing aliases of one
catalog source fails. Identical response bytes alone are not independence; the
human reviewer remains responsible for actually carrying out the recorded reset
and reproduction. This API records and checks saved observations; it never resets
accounts, changes state or sends a network request.

Both runs need `content_control` before reviewed/reportable status. Its fields are
`object_id`, `owner_capture_id`, `outsider_capture_id`, `negative_capture_id`, and
`private_json_key`. The existing private application map supplies unexpired original
captures, controlled identities, ownership evidence and the latest read permission.
The selected outsider must be denied by that permission and its same-resource
response must contain the owner's selected private JSON string. The same outsider's
negative observation must lack that string. A public permission, generic success
page, missing original, mismatched evidence attribution or private content in the
negative control fails. Catalog source IDs must match the selected captures in the
positive/negative/ownership roles. Original request shape and scope are checked
without executing it. Only hashes and match results enter the public ledger.

Original content, current ownership/permissions and identity validity are rechecked
at subsequent transitions. GET readiness rechecks these controls too; expired or
revoked originals invalidate effective submission readiness without deleting the
historical human decision. The owner must block and revalidate changed evidence.
Historical event retries remain historical receipts, not fresh readiness checks.

Clean-state execution, object ownership, private classification and permission
intent remain human assertions supported by evidence; ARIA cannot independently
prove them from response bytes. The deterministic content check supplements these
assertions, rather than pretending to establish intent. It deliberately supports
only the reviewed private JSON disclosure comparison. Unsupported specialties stay
below the reportable gate.

Demonstrated impact lives in each validation separately from potential escalation
on the candidate. Successful reproduction records `stop_testing`; review and
sign-off retain it. There is no escalation automation or further execution from
this API. `reportable` means ready for a human to consider submission; nothing is
sent externally.

Local duplicate detection normalizes case/whitespace in the recorded underlying
cause and workflow and lists matching local candidates. This is an explainable
exact normalized match, not semantic root-cause inference; differently worded
causes need human comparison. Private program duplicate status remains unknown.

## Requirement audit

| Requirement | Implemented evidence |
| --- | --- |
| VERIFY-01 | Nine states, explicit edges, terminal rejection and retained review history. |
| VERIFY-02 | Revision, current scope, attributable hashed evidence, independent control sources, original-content gates. |
| VERIFY-03 | Explicit owner human-review role, rejection and smallest missing validation. |
| VERIFY-04 | Recorded clean-state supervised reproduction with fresh positive and negative observations; deterministic content recheck. No automatic reset or execution. |
| VERIFY-05 | Current controlled identities, ownership evidence, latest permission, actual selected private JSON comparison; human intent/ownership review required. |
| VERIFY-06 | Demonstrated impact separate from potential escalation; stop-testing marker after reproduction. |
| VERIFY-07 | Local normalized cause/workflow duplicate candidates; private duplicates unknown. |
| VERIFY-08 | Distinct persisted reviewed and reportable human sign-offs bound to evidence and scope. |

## Offline acceptance

`tests/test_finding_verification.py` covers the complete supervised disclosure path,
including JSON private-content evidence, negative controls, clean-state records,
independent reproduction sources, human review and reportable sign-off. It also
covers secure/public and misleading HTML successes, ambiguous results, missing
prerequisites, reused source aliases, skipped states, scope/evidence revocation,
original expiry, stale revisions, cross-owner denial, storage failure, event
re-materialization after restart, idempotent retry and local duplicates. Private
originals and database transactions use in-process test doubles. No actual reset,
request, container or independent human lab reproduction was performed.

Final validation on 2026-11-06, working tree based on `d1331f1`:

- `DEBUG=false .venv/bin/python -m unittest discover -s tests -t . -q`:
  **269 tests passed in 10.494 seconds** (262 existing tests plus 7 new tests).
- `node tests/frontend_contracts.cjs`: passed.
- `git diff --check`: passed.

These are offline regressions and synthetic control checks, not seven independent
live lab reproductions. No service integration or deployment acceptance was run.
