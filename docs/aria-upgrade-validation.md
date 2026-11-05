# ARIA reliability / specialist / Community validation register

Date: 2026-11-04. This is a staged implementation, **not a release acceptance certificate**.
Existing uncommitted changes were preserved. The owner database `aria`, provider
credentials and Redis DB 0 were not reset or migrated. No service restart was performed.
Only `aria_test` and Redis DB 15 were reset for service validation.

## Executed evidence

| Layer | Result | Evidence |
| --- | --- | --- |
| Offline regressions | Passed: 121 tests; includes 30 agent/scenario subcases | `python -B -m unittest discover -s tests -t . -q` |
| Frontend VM and syntax | Passed | `node tests/frontend_contracts.cjs`, `node --check web/static/scripts/app.js` |
| Real Firefox / synthetic services | Passed: nine checks, no JS errors | `integration/browser_reliability.py`; `.local-lab/reliability-browser/report.json`, screenshots and `requests.json` |
| Owner screenshot sessions | Passed: four saved sessions in fresh and warmed Firefox profiles (eight checks), no JS errors | `integration/browser_owner_history.py`; `.local-lab/owner-history-audit/` |
| PostgreSQL / Redis | Passed: four tests, including concurrent encrypted Burp import deduplication; migrations, legacy adoption, durable run recovery/history and cache/login lifecycle | `integration/run_disposable_services.py`; real PostgreSQL and Redis |
| Montoya compilation | Passed against official Montoya API 2025.2, Java 17 target | `bash burp-community/build.sh .local-lab/montoya-api-2025.2.jar` |
| Live providers | Untested: **0 calls, 0 tokens** | Every provider response in offline logs is mocked. The HTTP-check demo is not general autonomous-planner validation. |
| Live Burp desktop | Blocked: no Burp installation was located | Compilation does not establish capture/Repeater runtime behavior. |

The original screenshots are retained at `.local-lab/owner_tests/`. The sessions
named `Browser HTTP test 1793827925`, `Browser HTTP test 1793828184`,
`Browser HTTP test 1793828341` and `Metasploitable manual test` retained respectively
3, 3, 4 and 4 saved messages. Their contents were rendered in both Firefox runs.
No original messages were rewritten. This establishes the presence and restoration
of the saved records; screenshot evidence alone cannot retrospectively identify
whether a historical failure was caused by a missing request or an old cached asset.

The new backend supplies a source-content `X-ARIA-Build` response header. The new HTML uses content-hashed asset URLs and `Cache-Control: no-cache`.
The live backend was not restarted, so backend upgrade/cache behavior must still be
validated in a two-build staging deployment. The real-owner audit exercised the
updated files served by the existing static mount, plus the existing backend.

## Findings register

| ID | Finding | State / evidence |
| --- | --- | --- |
| REL-01 | Empty history and stale rendering after session changes | Fixed; actual saved-history and synthetic stale-response checks pass. Empty and failed states differ, with retry. |
| REL-02 | Old static assets can survive an incompatible refresh | Content hashes and HTML revalidation implemented; a two-build warm upgrade remains untested. |
| REL-03 | No executable plan appeared as successful completion | Fixed; explicit blocked reasons and two corrective attempts, capability/scope feedback. Mocked regressions pass. |
| REL-04 | Run state lost after restart | Versioned `0002` table, required transition persistence, recovery blocks unfinished runs without replay; real SQL regression passes. |
| REL-05 | Completion without supporting worker evidence | Completed discovery requires nonempty successful output and a job ID from the shared worker path. Failed output is not parsed as successful evidence. |
| REL-06 | Run state or messages leak across sessions | Generation checks for restore/planning/socket/KB responses, socket closure and activity reset, captured session binding and duplicate Run suppression implemented. Broader multiple-tab stress remains untested. |
| AGENT-01 | Inconsistent specialist results and unsupported proposals | Shared typed public contract, owned evidence references, candidates/uncertainty, scope/capability/duplicate checks implemented. Synthetic fixtures pass; independent expert review and live-model expertise validation are **blocked/pending**. |
| AGENT-02 | Post-access suggestions without capable verified access | Real post-access entry point blocked. Controlled fixtures exercise missing prerequisites. No exploitation, dumping or persistence was executed. |
| BURP-01 | Community integration absent | Selection export, encrypted imports, endpoint map, Repeater staging, explicit approval and bounded availability checks implemented. Compiled and offline tested; real Community desktop validation blocked. |
| BURP-02 | Credential exposure and provenance | Originals encrypted using the existing rotated evidence cipher; model-facing capture summaries redact credential headers and strip query values from URLs. Authentication contexts use keyed fingerprints. Capture IDs appear in report manifests. Unlabelled secret detection remains best-effort. |
| BURP-03 | Scanner / active features falsely advertised | Scanner always false. Authenticated replay, mutation and Montoya active replay explicitly unavailable. Worker GET/HEAD availability checks disclose their different headers and require approval. |

## Scenario and feature coverage

`passed` means only the stated layer passed. `failed` is reserved for an executed
failure; earlier implementation failures were corrected and rerun. `blocked` needs
an unavailable capability or review. `untested` has not been exercised. Nothing here
establishes every possible use. Route/button inventories are separate CSV files.

| Scenario | Status | Layer / limitation |
| --- | --- | --- |
| Owner login and saved-session restoration | passed | Real Firefox and running owner deployment; login only mutation |
| Fresh profile, warmed profile and browser restart | passed | Real Firefox; synthetic API and actual owner history |
| Session switching, stale restore, empty history and failed retry | passed | Real Firefox synthetic fixtures |
| Logout, expiry and ownership denial | passed | Existing offline/API and frontend VM checks; complete real-browser flow untested |
| Settings / key controls | passed | Existing frontend VM; real-browser settings mutations untested |
| Prompt, plan rendering, approval, rejection, execution | passed | Mocked API/worker and frontend VM; no live autonomous model run |
| Run transition persistence and restart reconciliation | passed | Real PostgreSQL; no automatic replay |
| Unsupported goal / invalid proposal / two corrections | passed | Offline engine regressions |
| Step limit, cancellation, credential revocation | passed | Existing/new mocked engine and worker regressions; refresh-in-every-state browser coverage untested |
| Repeated Run / captured session binding | passed | Implementation and retained frontend tests; full rapid-click browser stress untested |
| Two-build cache-warmed upgrade | untested | Hash URLs and warmed reload pass separately |
| Multiple tabs, socket reconnect storms and all API outage combinations | untested | Stale socket guards implemented; existing mocked socket authorization checks retained |
| Database write failure stops dispatch | passed | Mocked run-store failure |
| Redis reconnect / cache persistence | passed | Disposable Redis integration; full UI outage recovery untested |
| Provider timeout/quota/malformed output | passed | Existing mocked pool/agent and planner tests; no live provider fault injection |
| Missing evidence / misleading output | passed | Receipt/output requirements and candidate-only fixtures; not live-model expertise proof |
| All specialist contract fixtures | passed | Synthetic contract checks; independent expert review pending |
| Selected Burp import, encrypted storage, concurrent duplicates | passed | Parser/offline cases; real PostgreSQL concurrent import/deduplication test passed |
| Community extension build | passed | Official API JAR; runtime behavior untested |
| Repeater handoff and connector disconnection | untested | Compiled implementation; real desktop unavailable |
| Approved GET/HEAD check and rejected-action refusal | passed | Rejected-action dispatch prevention mocked; live approved Burp workflow untested |
| Authenticated replay and mutations | blocked | Disabled capability; intentionally no fallback or silent request mutation |
| Burp Scanner / Professional APIs | blocked | Community-only; no Scanner calls or emulation |
| Bounded active lab scans in this upgrade | untested | No active scan executed during this implementation |
| Live model expertise / general autonomous planning | untested | 0/20 calls and 0/40,000 tokens used; broader HTTP demo claims rejected |

## Release gate and operations

**Do not enable the Burp connector or claim full release acceptance yet.** Its
default `BURP_COMMUNITY_ENABLED=false` preserves the gate. Independent agent review,
actual Burp Community capture/Repeater/browser workflow, approved live checks,
a two-build browser upgrade and the remaining real-browser interruption/outage
matrix are incomplete. Authenticated replay and mutations are not implemented.
These are explicit delivery gaps, not passed cases.

The updated backend requires revision `0002`. On a backed-up staging restore,
run `python -m alembic upgrade head`, `python -m alembic check`, then start one API
worker and validate the restore before migrating the owner deployment. Legacy
unversioned adoption validates the frozen `0001` schema before upgrading; it never
pretends the old schema already contains the new table. No owner migration ran here.
Run snapshots and original captures remain durable/private. A restart marks unfinished
planning/execution/approval snapshots blocked and requires inspection of durable jobs.
It never resubmits a command or reuses a consumed approval automatically.

Reproduce isolated browser checks with:

```bash
.local-lab/browser-venv/bin/python integration/browser_reliability.py
.local-lab/browser-venv/bin/python integration/browser_owner_history.py
ARIA_DISPOSABLE_SERVICES=1 .venv/bin/python -B -m integration.run_disposable_services
```

The second command logs into the existing owner application and reads history only.
The third resets only the documented disposable resources. Model validation remains
optional and must stop at 20 actual provider calls or 40,000 total tokens, counting
retries/failover. The engine's per-run planning counter is not a global token meter;
no live-validation token-budget enforcement is claimed by that counter.
