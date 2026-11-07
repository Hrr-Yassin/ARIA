# Phase 0 and Phase 1 implementation evaluation

Reviewed 2026-11-05 at `ed45186` against `aria-product-roadmap.md`, all 15
repository Markdown files present before this report, the six-commit Git history,
implementation code, tests, and retained local acceptance artifacts.

**Decision:** Phase 0 is supported as a completed engineering baseline. Phase 1
is substantially implemented for bounded unauthenticated curl GET/HEAD observations,
with the SCOPE-08 failure-path and Unicode review gaps repaired in the current
working tree. The findings below retain the original review evidence; see the
resolution record at the end. Neither phase establishes production readiness,
live model expertise, authenticated application testing, or bounty eligibility.

## Findings

Descriptions in this section record the original behavior before the follow-up fix.

### 1. Resolved — originally medium: missing-status cancellation does not persist the worker stop

`worker/service.py:109` cancels expired jobs; the missing-container branch at line
112 does likewise. `_cancel` persists cancellation without setting `overloaded`.
Only normal exited-container receipt processing computes that flag. Subsequent
worker admission checks that flag, so these failure paths permit more requests
after the normal spacing interval.

Reproduced offline with the existing `MemoryStore`, `FakeRuntime`, and program
fixture: submit job one, expire its deadline, obtain a confirmed cancelled receipt
with empty stdout, then submit job two. Job two reaches `running`; job one's
`overloaded` field is absent. No network traffic was generated.

The API mitigates this: `memory/worker_jobs.py:182` treats missing status as overload
and writes a 24-hour backoff. However, admission at lines 39–48 checks the timestamp,
not the persistent `program_overloaded` flag. Once that backoff expires, the API
can admit again, and this worker failure path has no durable stop to deny it.
This contradicts the Phase 1 status document's requirement to use a new engagement
after missing-status/network failure and its independent durable worker-stop claim.
Normal 429/5xx receipts do set the worker flag and remain blocked.

Recommendation: persist a conservative stop for abnormal missing-status termination
in the worker and enforce the permanent stop in API admission. Distinguish deliberate
owner cancellation if it should have different semantics. Add deadline,
missing-container, restart, and expired-backoff regression cases.

### 2. Resolved — originally medium: browser source offsets fail after supplementary Unicode characters

`web/static/scripts/programs.js:106` sends JavaScript `indexOf` offsets, measured in
UTF-16 code units. `memory/program_policy.py:156` validates with Python string
slicing, measured in Unicode code points. An emoji or other supplementary character
before a quoted rule shifts the browser offset and rejects a valid review with 422.
This affects policy review usability; it fails closed and does not grant permission.

Recommendation: calculate code-point offsets in the browser, and cover an imported
policy containing supplementary characters before its reviewed rules.

### 3. Resolved — originally low: route evidence does not include the Phase 1 API additions

`docs/phase0-route-inventory.csv` is a legitimate historical Phase 0 inventory.
`docs/aria-route-coverage.csv` also predates the seven `/api/programs` registrations
and does not describe them. The dynamic missing-identity test does cover current
protected HTTP routes, and Phase 1 has dedicated acceptance tests; the issue is
documentation completeness rather than demonstrated missing authentication.

Recommendation: preserve the historical baseline and publish an updated current
route coverage register. Distinguish historical security P0/P1/P2 remediation from
product roadmap Phases 0/1/2; these are different work streams.

## Roadmap assessment

| Requirements | Assessment | Evidence / qualification |
| --- | --- | --- |
| BASE-01 | Complete at baseline | Route, specialist, profile, migration and feature-flag inventory; current route register refreshed after review |
| BASE-02 | Complete at baseline | README and historical-register notices distinguish checkpoints; schema head is 0003 |
| BASE-03 | Complete | Disposable synthetic SQL/cache/worker lab with isolated configuration |
| BASE-04 | Complete | Retained 132-test baseline; current 156-test suite and frontend checks pass |
| BASE-05 | Supported by retained acceptance | Synthetic 0001 backup, restore, upgrade to 0003, retained-data check and rollback restore |
| BASE-06 | Supported by retained acceptance | Explicit approval → real worker receipt → stored evidence → owner-bound report; interpretation mocked |
| BASE-07 | Supported by retained acceptance | Controller/lifespan recreation blocks unfinished work, preserves history, denies replay |
| BASE-08 | Complete | Authenticated capabilities endpoint, Settings summary, offline and synthetic Firefox checks |
| SCOPE-01 | Implemented | Owner-bound typed records, immutable source snapshots, URL/time/hash/revisions |
| SCOPE-02 | Implemented with limits | Pinned public HTTPS retrieval and manual fallback; public retrieval acceptance is mocked |
| SCOPE-03–04 | Implemented; usability gap repaired | Conservative heading extraction, exact quotes and reviewed source links; Unicode offset finding above |
| SCOPE-05 | Implemented | Separate owner review and explicit activation; unknown/prohibited permission denied |
| SCOPE-06 | Implemented for bounded HTTP | Exact/wildcard hosts, paths, schemes, ports, exclusions, redirect denial and worker ceiling |
| SCOPE-07 | Implemented | Revision/review suspension, epoch-bound approvals, cancellation and reconciliation before activation |
| SCOPE-08 | Implemented; failure path repaired | Durable reservations, concurrency, spacing, permanent API stop and independent worker stop |
| SCOPE-09–10 | Implemented | Explained human-assessed fit ranking, visible unknowns, program types and prerequisites |

Human review supplies policy interpretation. Category-correct source references
prove attribution, not semantic correctness of the owner's interpretation. This
matches a human-assisted workflow rather than automatic policy comprehension.
Discovery/import does not authorize execution. Existing manually scoped engagements
retain their separate authorization behavior until an owner activates a program policy.

## History and validation

- `eab52a8`: historical architecture/security review.
- `07bbf90`: security remediation, delivery and manual lab foundation.
- `37d6cb0`: worker/research upgrades and initial product roadmap.
- `901a7ce`: Phase 0 baseline, trace runner, capability UI and provenance fixes.
- `ed45186`: Phase 1 policy/discovery, API/UI, enforcement and acceptance fixtures.
  Initial upload was `e03d0d9`.

Original review checks:

- `DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q`:
  **156 passed in 6.526 seconds**, outside the sandbox. The sandbox run stalled,
  consistent with the documented ASGI sandbox limitation.
- `node tests/frontend_contracts.cjs`: passed.
- `node --check web/static/scripts/programs.js`: passed.
- `git diff --check`: passed before this report.
- Phase 1 retained source manifest: all 110 listed files match current content.
  Phase 0 manifest differences correspond to later Phase 1 edits; it remains
  historical evidence, not an identical-source validation of HEAD.
- Retained Phase 0, Phase 1 and Phase 1 Firefox result files report success and
  agree with their status documents. These ignored local artifacts are supporting
  evidence, not independently reproduced service/browser runs in this review.

During the original review, real container, database migration/restore and Firefox
acceptance were not rerun. The follow-up reruns Phase 1 containers/SQL and Firefox;
the Phase 0 backup/restore acceptance remains historical.
No owner database, deployment, credentials, public target or live model was used.
The original review added documentation only. The follow-up resolution below
records the authorized implementation changes and new validation.


## Follow-up resolution

The API now rejects `program_overloaded` engagements independently of the backoff
clock. The worker saves that flag before cancellation cleanup for program-policy
jobs, including deadline expiry, missing containers, failed startup, owner Stop,
and restart reconciliation. Deliberate cancellation also stops further traffic
because its receipt has no trustworthy HTTP status; continuing requires a new
engagement after human review. Manual non-program scopes retain existing behavior.

The browser converts UTF-16 positions to Unicode code-point offsets before sending
review rules. Firefox acceptance now uses an emoji before the source rules and
validates every transmitted quote/offset against Python slicing.

The current route register includes all current route paths, including the seven
program endpoints and other previously omitted registrations. Historical Phase 0
inventory is preserved. Unattributed functional coverage remains explicitly untested.

New offline regression scenarios cover deadline expiry, missing containers, owner
Stop, restart recovery, failed cleanup, and an expired API backoff with its durable
stop flag still set. All 157 Python regressions pass; frontend contracts and the
Firefox program-policy acceptance pass with no page errors. Disposable SQL/worker
acceptance results are recorded in the Phase 1 status document.


The follow-up disposable SQL/Podman runner passed all ten acceptance checks,
including the new expired-backoff and missing-real-container stop regressions.
Its source-manifest hash is
`e1e7392ae8a78c8ff36d8a5d05aedcf722fa54f28e15da39b8d6db6c34f6417a`.
The runner completed successfully and cleaned up its lab resources. See
[Phase 1 status](phase1-policy-status.md#evaluation-follow-up) for exact commands.
No dependency, schema migration or owner-service restart was required.

**Next step:** begin Phase 2 with TEAM-01 through TEAM-03. These fixes close the
three findings in this evaluation within Phase 1's documented bounded HTTP scope.
