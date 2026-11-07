# ARIA real-user browser review — 7 November 2026

Tested the running application at `http://127.0.0.1:7000` (and its localhost alias)
with real headless Firefox in separate automation profiles. Desktop: 1440×1000;
mobile: 390×844, plus the report fixture at 440px. Private credentials came from
the existing ignored lab login file. Personal browser storage was not accessed.

## Fixes and retest evidence

1. **Execution unavailable:** the worker service was stopped. Starting the existing
   `aria-worker.service` exposed a second failure: `/capabilities` returned 503
   because reconciliation failed. `JobStore.expire_http()` embedded
   `"private_evidence_expired":true` in a SQLAlchemy `text()` statement; `:true`
   was parsed as a bind parameter. An EXPLAIN-only database probe reproduced
   `A value is required for bind parameter 'true'`. Replaced the literal with
   `jsonb_build_object`, preserving retention semantics. Restarted the worker;
   real UI capabilities became online and real TCP80 execution passed.
2. **Stop overwrote terminal state:** cleanup after a blocked autonomous run changed
   its saved state to `cancelling` although no task was running. Preserve completed,
   blocked and failed states when Stop is called. Regression tests cover all three
   states and preservation of the reason. Loaded the fix by restarting the API
   after checking that there were no active durable runs.
3. **Outdated branding and login accessibility:** replaced PentestAI v9/v10 names
   with ARIA on login and workspace; added associated username/password labels,
   password-manager autocomplete and an alert role for login errors.
4. **New review harness:** `integration/browser_live_review.py` records individual
   live checks, screenshots, JavaScript errors and server failures even when a
   check fails. Its first logout assertion expected only `/login`; the application
   also supports `/login.html`. Corrected the assertion and reran successfully.

## Real deployment checks

These use the actual API, database and UI, rather than mocked API responses.

| Check | Final result |
| --- | --- |
| real login and workspace | passed |
| create engagement through native prompt | passed |
| reload preserves new engagement and empty history | passed |
| all eight intelligence tabs | passed |
| settings and live worker capabilities | passed |
| team-refresh real saved data | passed |
| reports-refresh real saved data | passed |
| program-refresh real saved data | passed |
| 390px mobile settings and workspace overflow | passed |
| sign out clears token and protects workspace | passed |
| Existing history in fresh and warmed Firefox profiles | Passed: eight session/profile checks; no JavaScript exceptions |
| Stop preserves an already terminal run | See private `terminal-stop.json` and regression test |

The live UI review reported no JavaScript exceptions or HTTP 5xx responses.
The final capabilities check reported `Worker online. Available supported tools: curl, nmap.`
New session checks create empty engagements for `https://example.invalid`; these
never dispatch target requests. Four empty test engagements were created during
iterations and retained for inspection. The real execution run created its own
`Browser HTTP test …` engagement restricted to `192.168.77.20:80`.

## Real isolated TCP80 lab flow

`integration/browser_user_flow.py` was executed against the existing authorized
lab target `192.168.77.20`. The target returned HTTP 200 on the availability probe.

| Check | Result |
| --- | --- |
| login | passed |
| scoped plan | passed |
| manual run output | passed |
| refresh history | passed |
| worker health | passed |
| out of scope denied | passed (browser API) |
| approval rejection | passed (browser API; not dispatched) |
| approval rejection ui | passed (real dialog dismissed; fixture card; no dispatch) |
| auto start budget | passed |
| failure | AssertionError: Autonomous HTTP success receipt missing |

The autonomous HTTP-success assertion failed. The current planner requires a model
provider and engagement tariffs; the historical harness assumes a deterministic
model-free HTTP cycle. This test engagement had no tariffs, empty model usage and
no model reservation records. The saved run reported `invalid_planner_output`
with zero executed steps after three planning attempts. This is **blocked live
autonomous acceptance**, not a successful autonomous HTTP check. The later second
start/Stop scenario was not reached. Fixture tests cover active-run Stop; the
terminal-state fix has separate regression and live API evidence. No tariffs,
provider keys or security limits were changed to force the cycle through.

Scope denial and one approval rejection use authenticated browser API requests.
The confirmation-dialog rejection uses a deliberately persisted fixture card;
its click is real and dispatch is checked absent. Manual Nmap execution and
history restoration use real UI actions and actual worker output.

## Real Firefox with synthetic services

The following suites exercise the real UI in Firefox, but provider, worker or
policy responses are fixtures. These do not establish live model quality or
live Burp connector availability.

### Workflow matrix

| Check | Result |
| --- | --- |
| invalid login visible | passed |
| login and restore | passed |
| supported defaults | passed |
| settings keys skill risk | passed |
| rapid prompt submission | passed |
| manual rejection no dispatch | passed |
| manual approved execution analysis | passed |
| execution history reload | passed |
| report format download and restore | passed |
| ownership and scope denial | passed (browser API; real scope parser) |
| api outage history recovery | passed |
| stale planning response | passed |
| refresh during planning | passed |
| refresh during awaiting approval | passed |
| refresh during executing | passed |
| refresh during cancelling | passed |
| stop pending then terminal | passed |
| socket disconnect reconnect | passed |
| multiple tabs stop observation | passed |
| unsupported goal visible | passed |
| burp repeater staging ui | passed (synthetic connector) |
| burp replay rejection ui | passed |
| burp approved replay comparison ui | passed (synthetic connector) |
| burp replay history reload | passed |
| burp disconnection visible | passed |
| two ui builds warm cache upgrade | passed (real HTTP cache; no request interception) |
| token expiry redirect | passed |
| logout | passed |
| javascript errors | passed |

### Program policy

| Check | Result |
| --- | --- |
| manual import | Passed |
| fetch fallback | Passed |
| source xss | Passed |
| source linked review | Passed |
| explicit activation | Passed |
| fit unknowns | Passed |
| human rejection | Passed |

### Team work

| Check | Result |
| --- | --- |
| saved tasks | Passed |
| source xss | Passed |
| delegation and human review | Passed |
| evidence catalog | Passed |
| coverage gaps | Passed |
| rejected observations | Passed |
| model budget | Passed |
| session switch guard | Passed |
| no tool dispatch | Passed |

### Reviewed reports

| Check | Result |
| --- | --- |
| preview renders | Passed |
| human checkbox signoff | Passed |
| signed export controls | Passed |
| no horizontal overflow at 440px | Passed |

## Regression checks and failed setup attempts

- Final full offline Python suite: **289 tests passed** (including two retention
  SQL tests and one terminal-stop test with three state subcases).
- Targeted worker/stop regressions: **18 passed**.
- Node frontend contracts: passed.
- `git diff --check`: passed.
- First fixture-matrix launch failed before browser checks because inherited
  `DEBUG` was not a valid boolean. Rerun with the documented `DEBUG=false` passed.
- Repeated live login iterations reached the existing five-per-five-minute
  account throttle (429). No throttle was disabled or cleared.

## Artifacts and reproduction

All JSON, runtime logs and screenshots remain ignored under `.local-lab/`:

| Directory | Evidence |
| --- | --- |
| `live-review-2026-11-07/` | Live UI `report.json`, desktop/mobile screenshots, final offline log, targeted-fix log, terminal-stop API report |
| `owner-history-audit/` | Eight history checks, request log and screenshots |
| `browser-results/` | Real execution results, failure capture, restored history and approval screenshot |
| `browser-matrix/` | Detailed fixture matrix, requests, cache-upgrade screenshot |
| `phase1-browser/` | Policy result and screenshots |
| `phase2-browser/` | Team result and screenshots |
| `phase6/` | Report fixture result and mobile screenshots |

Run from the repository root, with the existing local services and private login:

```bash
ARIA_LIVE_REVIEW=1 .local-lab/browser-venv/bin/python integration/browser_live_review.py
.local-lab/browser-venv/bin/python integration/browser_owner_history.py
DEBUG=false .local-lab/browser-venv/bin/python integration/browser_matrix.py
DEBUG=false .local-lab/browser-venv/bin/python integration/browser_program_policy.py
DEBUG=false .local-lab/browser-venv/bin/python integration/browser_team_tasks.py
ARIA_PHASE6_UI=1 .local-lab/browser-venv/bin/python -m integration.phase6_reports_ui
DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
git diff --check
```

The historical real-execution harness can be reproduced with
`ARIA_BROWSER_LAB=1 DEBUG=false .local-lab/browser-venv/bin/python integration/browser_user_flow.py`;
its autonomous success expectation requires prerequisites absent in this run.
Space out live logins to respect the five-minute admission window.

Remaining coverage: live provider-backed investigations, independent reproduction,
real report sign-off/export from verified findings and the current live Burp
connector were not established by this review. Empty-state live checks and
synthetic workflow checks are identified separately above. The worker service was
started but its existing disabled-at-login setting was retained; automatic worker
startup after a future login remains an operational follow-up. Existing unrelated
benchmark/roadmap work was left intact.
