# Phase 4 bounded specialist implementation

Updated 2026-11-06. Phase 4 is implemented for the bounded, supervised workflows below.
The specialty positive/negative gate is covered by offline synthetic controls for all
five enabled specialties. This is not deployment or live-container acceptance of
the new profiles. No scans, services, databases, container images or deployments
were changed by this update; no external target or provider was contacted.

## Implemented scope

- The owner-only `POST /api/team/{session_id}/investigation-plan` returns structured,
  non-executing contracts. It checks the current engagement scope, jobs-v1 protocol
  and exact worker capability versions. It names the reviewed specialty profile and
  blocks unsupported capabilities. A template never establishes prerequisites or
  grants execution permission. General planners still filter commands against live
  tools and scope and block unvalidated fallback steps.
- `/api/application-map/{session_id}/authorization-review` compares saved, unexpired
  observations of the same bodyless GET/HEAD resource without query. It requires two
  active controlled identities, recorded owner evidence and the latest permission
  assertion. Identical responses remain observations, including public/error pages.
- `/authentication-review` compares a valid controlled session with a credential-free
  observation, or a separately recorded logged-out/expired controlled session.
  Captured credentials must match their attributed identities. Logout/expiry is a
  researcher assertion; the review neither performs logout nor independently proves
  invalidation or access to meaningful protected content.
- `/exposure-review` retains the assertion-only visibility/audience assessment.
  Optional `object_id`, `owner_capture_id`, and `private_json_key` jointly enable an
  evidence-derived content control: the same resource and current permission must
  pass authorization-review prerequisites, and a nonempty bounded private JSON
  string from owner evidence must match the outsider observation. Public/shared
  access is disconfirming; generic successes and ambiguous JSON remain inconclusive.
  Only a digest/match and evidence references are returned. This creates a candidate
  observation, never an independently verified finding. Visibility/sensitivity and
  ownership still require human review.
- `/input-validation-review` compares selected baseline and integer-query captures
  for the recorded controlled object. It checks identity/resource attribution,
  owner-supporting evidence, bounded bodyless GET shape and valid original responses.
  Boundary expectations/results are explicit human assertions.
- `/business-logic-review` reviews a controlled object's recorded workflow, invariant,
  expected state and two or more same-resource original observations. It validates
  and compares bounded responses; invariant satisfaction and causation remain human
  assertions. The execution profile below supports a separately approved controlled
  state change, with observations recorded before/after by the researcher.

## Reviewed execution profiles (disabled by default)

The existing `POST /api/application-map/{session_id}/requests` additionally accepts
`profile`, `object_id`, `action_authorized: true`, and `invariant`:

| Profile | Exact boundary |
| --- | --- |
| `integer_query` | GET with exactly one canonical integer query parameter; ASCII identifier of 1–32 characters and signed numeric text of at most six digits; no body. |
| `controlled_json_put` | PUT without query; `json_body` contains exactly one ASCII identifier field, a boolean, integer in -999999..999999, or at most 100 characters from letters/digits/spaces/underscore/dot/hyphen. Canonical JSON is bounded to 512 bytes. |

Both require the active controlled object owner and unexpired owner evidence for
that exact resource without query. Neither accepts arbitrary scripts or shell.
The identity, resource, method, body, object, invariant and attestations are bound
by the encrypted request digest. Proposal responses expose the reviewed method,
URL and redacted specialty/body for human inspection, never authentication headers.
Object evidence and current scope are rechecked when materializing dispatch.

Execution requires all of the following; this update enabled none of them in a
running deployment:

1. An updated, reviewed worker image containing the matching profile/runner code.
2. The existing shared `HTTP_REPLAY_KEY` and worker-side
   `HTTP_SPECIALIST_PROFILES_ENABLED=true`; otherwise `specialist_http_version` is 0.
3. Explicit engagement scope flags `web_authenticated_replay: true` and
   `web_specialist_profiles: true`; reviewed program snapshots remain unsupported.
4. jobs-v1 and exact integer `specialist_http_version: 1`, checked before proposal
   and dispatch. Boolean/string versions are rejected.
5. The existing one-use command-bound red-risk approval and independent worker
   network/port ceiling. Human attestations alone cannot bypass either boundary.

The worker repeats request-shape/digest validation before runtime creation. The
existing ten-second timeout, 32 KiB response bound, concurrency one, request budget,
rate spacing, overload stop, private retention, cancellation, idempotency and
restart-without-replay rules apply. The runner sends exactly one approved request,
without redirects/retries/proxies, and encrypts the original request/response.
Legacy bodyless GET/HEAD replay retains its separate capability version and bounds.

## Evidence-based completion

Specialist tasks declare `specialty`, `phase`, and distinct `security_questions`;
missing phase/questions are rejected. Completion requires each question to have
current tested coverage and cataloged engagement evidence, plus a collected result
and human review. Completion events retain immutable review snapshots. Phase
advancement checks current questions/evidence against these snapshots under the
engagement lock, requires the direct owner, and moves only one phase forward.
Automatic advancement is disabled; tool counts do not determine readiness.

Generic/legacy tasks remain compatible. Without declared questions they cannot
establish phase readiness. The owner migration endpoint preserves prior history,
checks revisions and idempotency, rejects unsupported states, and requires fresh
reviewed evidence when migrating completed tasks. Coverage remains a human assertion;
Phase 5 independent verification is still required before reporting findings.

## Requirement audit

| Requirement | Implemented boundary / evidence |
| --- | --- |
| SPEC-01 | Contracts for all five specialties in `orchestrator/specialist_investigations.py`. |
| SPEC-02 | Controlled-owner/other-identity same-resource saved authorization comparison. |
| SPEC-03 | Explicit authorized authentication/session comparisons, including saved logout/expiry controls; no automatic account lifecycle actions. |
| SPEC-04 | Public/shared/private assessment plus selected owner/outsider JSON-content evidence control; conclusions remain candidates. |
| SPEC-05 | Opt-in, approval-bound integer-query worker profile and saved input review. |
| SPEC-06 | Human-assisted invariant/workflow review plus one controlled scalar JSON PUT profile. |
| SPEC-07 | Actual exact-version capabilities and lab scope drive specialty plans/proposals/dispatch; unsupported profiles stay blocked. |
| SPEC-08 | Specialist question requirements, evidence-linked completion snapshots and owner-reviewed phase readiness; legacy compatibility does not confer readiness. |
| SPEC-09 | `tests/test_specialty_controls.py` exercises secure, vulnerable, misleading and missing-prerequisite controls for every enabled specialty. Existing per-specialty tests are retained. |

## Current offline acceptance

Final commands executed for this update on 2026-11-06:

- `DEBUG=false .venv/bin/python -m unittest discover -s tests -t . -q`:
  **262 tests passed in 10.532 seconds**.
- `node tests/frontend_contracts.cjs`: passed.
- `git diff --check`: passed.

These counts include existing regressions; they are not a count of independent
specialty controls or live deployment checks. Tests used process-local storage,
mock providers/transports and fake runtimes; no scans or live service/database
integration was run for this update.

`tests/test_specialist_profiles.py` additionally tests exact approved PUT bytes,
query target preservation, redirect refusal, overload stop, scope/worker opt-in,
malformed profiles, controlled-object evidence, exact capability versions, denial
before dispatch, cancellation, restart, duplicate submission and retention. HTTP
connections and container runtimes in these tests are doubles; no traffic is sent.
`tests/test_application_map.py` exercises private snapshot/request materialization,
revoked scope/evidence and owner-bound review routing with process-local storage.
The frontend contract suite remains unchanged and passes.

The supported specialty gate is offline fixture acceptance. Real deployment and
new-image container acceptance remain unperformed under the user's restriction on
service/database changes and scans. Broader inputs, arbitrary JSON, automatic
crawling, automatic session lifecycle actions, public-program authenticated replay,
independent reproduction and external submission are outside this implementation.
Do not infer production readiness or confirmed vulnerabilities from these tests.

## Historical isolated SPEC-07 / SPEC-08 validation (2026-11-06)

This earlier run predates the new profiles; its former limitations and counts are
historical. The current scope and offline audit above supersede that audit.

`integration.phase4_readiness` passed eight checks using a fresh disposable PostgreSQL database, a private internal container network, a synthetic HTTP service, and the reviewed local worker image `sha256:9e410ce197448c2927b2d832f9f3099d16e4dfb76743503d01fba11a05dba554`. The API and worker service ran in-process over ASGI; the successful approved request executed in an isolated worker container against the synthetic service. A test-only capability response suppressed advertised tools for the denial control; the real worker's response was used for the successful control. No external target or live provider was contacted.

The checks covered denial before worker submission for an unadvertised tool; an approved worker receipt and evidence catalog; blocking legacy task advancement without questions; blocking an unreviewed phase-tagged task despite tested evidence; migration with missing evidence and stale revisions rejected, idempotent retry, and an owner review snapshot; foreign-owner denial; rejection after question changes or evidence removal; and successful one-step advancement after restoring matching reviewed evidence. The test-created containers and internal network were removed. Synthetic output is retained at `.local-lab/phase4-readiness/result.json`; no owner database or deployment was modified.

The full offline Python suite passed 231 tests in 10.560 seconds; `node tests/frontend_contracts.cjs` and `git diff --check` passed. No application defect was confirmed by this run. This validates the bounded paths above, not every planner/profile combination or production deployment; the remaining SPEC-07 and SPEC-08 limitations in the audit remain open.

Reproduce with locally present reviewed images:

```bash
ARIA_PHASE4_READINESS=1 WORKER_TEST_RUNTIME=podman \
  WORKER_TEST_IMAGE=sha256:9e410ce197448c2927b2d832f9f3099d16e4dfb76743503d01fba11a05dba554 \
  .venv/bin/python -m integration.phase4_readiness
DEBUG=false .venv/bin/python -m unittest discover -s tests -t . -q
```

