# Visible Chromium acceptance — 7 November 2026

Final result: **13/13 executed acceptance checks passed** against the running ARIA application at `http://localhost:7000`. Real Playwright Chromium launched with `headless=False` and `slow_mo=200`. No routes, provider responses, worker responses or findings were mocked.

The user selected **blocked autonomous testing only, with no paid model calls**. Successful model-driven autonomous investigation is not claimed. Kali and Metasploitable were not modified. Metasploitable TCP80 was reachable through the existing isolated worker; Kali was not the execution path and its health was not independently tested.

## Executed checks

| Check | Result / executed evidence |
| --- | --- |
| login | Passed — {"login_http": 200} |
| cancel new target | Passed — {"session_count_unchanged": 18} |
| create authorized lab target | Passed — {"session_id": "b0097f4e-d1df-4c0d-85ae-d6cfd35104b3", "persisted_scope": {"targets": ["192.168.77.20"], "exclusions": []}} |
| configure conservative execution | Passed — {"status": "online", "protocol": "jobs-v1"} |
| ambiguous exclusion does not dispatch | Passed — {"commands": 0, "jobs": 0} |
| request bounded tcp80 probe | Passed — {"command": "nmap -sT -sV -Pn -n -p 80 192.168.77.20", "dispatch_before_run": 0} |
| execute real probe and correlate worker receipt | Passed — {"job_id": "5e3b45e0-343d-43d2-8c87-b3108d23fa09", "exit_code": 0, "worker_output_matches_api": true, "receipt": "execution-ledger.json"} |
| reload restores real output | Passed — {"persisted_output": true, "message_count": 5} |
| inspect hosts findings and audit | Passed — {"findings_total": 1, "hosts_count": 1, "decision_records": 3, "vulnerability_claim": "No finding claimed from an open port"} |
| autonomous blocks without paid model calls | Passed — {"state": "blocked", "reason_code": "invalid_planner_output", "reason": "Planner could not produce a supported proposal after two corrective attempts: Expected a nonempty commands list; No execution proposal was accepted from an unavailable provider or malformed output; Expected a nonempty commands list", "physical_model_calls": 0, "new_worker_jobs": 0} |
| inspect real report and evidence workspaces | Passed — {"report_status": "Loaded 0 candidates and 0 report revisions. Submission remains your action.", "team_status": "Saved event 0. Results need human review; proposed commands use the existing execution workflow."} |
| url target produces host based scan | Passed — {"session_id": "2539bb6d-30d4-4c34-878c-4132e6433411", "target": "http://192.168.77.20", "nmap_host": "192.168.77.20", "job_id": "c3ef15c3-8642-4a2a-b3b0-0997b7660c4b", "worker_output_matches_api": true} |
| switch back restores original engagement | Passed — {"session_id": "b0097f4e-d1df-4c0d-85ae-d6cfd35104b3", "restored_original_probe": true} |

## Backend execution evidence

Targets were created through the native New session prompt. The actual persisted engagement scopes contain the selected host/URL and no exclusions; the UI does not supply a scope-port editor. Probe prompts explicitly requested **TCP port 80 only**. Independent worker plans confirm Nmap `-p 80`, destination `192.168.77.20/32`, and the unchanged worker network/port ceiling. No other target or port was scanned.

For each probe, the acceptance check verified the real `/api/kali/execute` response, the application SQL `worker_job` record, and the separate worker database receipt. Checks require matching job IDs, terminal success, exit code zero, termination and matching SHA-256 of stdout. Output reports `80/tcp open http` and the Apache service banner.

| Target entry | Engagement | Executed job |
| --- | --- |
| `192.168.77.20` | `b0097f4e-d1df-4c0d-85ae-d6cfd35104b3` | `5e3b45e0-343d-43d2-8c87-b3108d23fa09` |
| `http://192.168.77.20` | `2539bb6d-30d4-4c34-878c-4132e6433411` | `c3ef15c3-8642-4a2a-b3b0-0997b7660c4b` |

The IP-target findings API contains one **informational service observation**, sourced from the worker receipt and explicitly unverified. Its host vulnerability list is empty. No confirmed vulnerability or exploitation is claimed. Reload restored the real tool output, and switching back from the second engagement restored the original engagement.

## Confirmed ARIA defects fixed and retested

1. **Open ports incorrectly promoted to vulnerabilities.** The first Chromium run stored the Apache port observation as a medium-severity finding and added a KB vulnerability. The fallback parser now keeps port/version observations informational, including recognizable old-version banners, and states that vulnerability status is unverified. The live retest checks both saved severity and absence of KB vulnerabilities. Historical test records remain as evidence; no user findings were rewritten.

2. **URL target passed directly to Nmap.** Entering `http://192.168.77.20` produced `nmap ... http://192.168.77.20`. The explicit service-scan planner now validates the URL and uses its hostname while preserving the requested ports and shared scope validation. Invalid/credential-bearing URLs produce no scan proposal. The corrected URL probe was actually executed and independently matched to the worker receipt.

3. **Autonomous step counter misrepresented the saved budget.** Screenshot review showed `step 0 / 12` despite the actual request and backend run having a two-step limit. The UI now refreshes the counter for zero-step runs and restores the saved step count, limit and settings controls together. Visible Chromium asserts `step 0 / 2` after the blocked run and again after switching engagements; Node regressions cover both transitions.

4. **Missing favicon console 404.** Added a native SVG favicon and linked it from login/workspace. The final browser run recorded no console errors.

## Autonomous outcome and limits

The real UI launched HTTP availability mode with `max_steps: 2` and `green_only`. The backend ended as `blocked / invalid_planner_output`, with no successful steps or evidence job IDs. The existing engagement had no configured model tariffs. Independent application accounting showed **zero physical model reservations/calls** and the worker-job count did not increase. The status field `model_calls: 3` records logical planning attempts, not paid/provider calls; the reservation ledger remained empty.

This is a passed **blocked-flow acceptance check**, not evidence of successful autonomous scanning. Paid/provider-backed research, exploitation, full specialty investigation, verified report sign-off/export and Kali-specific execution were not tested. Settings/report/team empty-state inspection does not establish a full reporting lifecycle.

## Preserved failed attempts

| Run directory | Observed result |
| --- | --- |
| `20261107T052457Z` | Confirmed medium-severity open-port defect. Autonomous test assertion failed because the test reloaded after selecting its step budget; not a backend budget violation. |
| `20261107T052637Z` | All 11 initial checks passed after service-observation fix and test-sequencing correction. Screenshot later exposed the UI counter discrepancy. |
| `20261107T052724Z` | URL-entry test failed because a stale test-only dialog handler consumed the target prompt. Fixed the test handler; retained the failed report. |
| `20261107T052821Z` | Corrected URL test confirmed the full URL was placed into the Nmap proposal. It was not dispatched in that attempt. |
| `20261107T053003Z` | 13/13 passed, including actual corrected URL execution. Screenshot review led to the additional counter-display fix. |
| `20261107T053142Z` | Final 13/13 passed, including zero-step counter checks after launch and engagement switch; no JS/console errors. |

## Retained artifacts

Final evidence directory: `../.local-lab/chromium-acceptance/20261107T053142Z/`.

- [Final JSON report](../.local-lab/chromium-acceptance/20261107T053142Z/report.json)
- [Final workspace screenshot](../.local-lab/chromium-acceptance/20261107T053142Z/final-workspace.png)
- [Probe in progress](../.local-lab/chromium-acceptance/20261107T053142Z/probe-in-progress.png)
- [Application and worker ledger for IP probe](../.local-lab/chromium-acceptance/20261107T053142Z/execution-ledger.json)
- [Independent ledger for URL probe](../.local-lab/chromium-acceptance/20261107T053142Z/url-worker-ledger.json)
- [Saved informational finding](../.local-lab/chromium-acceptance/20261107T053142Z/findings.json)
- [Autonomous request/response](../.local-lab/chromium-acceptance/20261107T053142Z/autonomous-start.json)
- [Autonomous final status](../.local-lab/chromium-acceptance/20261107T053142Z/autonomous-status.json)
- [Artifact SHA-256 manifest](../.local-lab/chromium-acceptance/20261107T053142Z/sha256-manifest.json)
- [Service HTTP/startup log](../.local-lab/chromium-acceptance/service-http.log)
- [Final offline regression log](../.local-lab/chromium-acceptance/offline-regressions-final.log)

The final run retained 16 screenshots and 21 JSON artifacts, including response metadata/request IDs and before/after SQL snapshots. Artifacts remain in the ignored private lab directory. Login secrets, browser storage state and authorization headers are not included in the report. Test engagements were retained for inspection. Existing unrelated benchmark/roadmap work was left intact.

## Regression validation

- Full offline Python suite: **292 tests passed**.
- Focused service-observation and URL planner tests: **9 passed**.
- Node frontend contracts: passed, including the new budget-counter restoration checks.
- `git diff --check`: passed.

## Reproduce

Use the existing local services and private login file. A graphical desktop session is required. Do not substitute headless mode or mocked routes.

```bash
PLAYWRIGHT_BROWSERS_PATH=/tmp/aria-playwright-browsers .local-lab/browser-venv/bin/python -m playwright install chromium
ARIA_CHROMIUM_ACCEPTANCE=1 PLAYWRIGHT_BROWSERS_PATH=/tmp/aria-playwright-browsers .local-lab/browser-venv/bin/python integration/chromium_acceptance.py
DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
git diff --check
```

The browser harness makes state changes through actual UI actions. Direct API calls are authenticated GETs for evidence; direct SQL access is read-only. Respect the existing five-per-five-minute live login throttle. No provider tariffs are installed by this harness.
