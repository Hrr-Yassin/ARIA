# Browser flow implementation and validation

The latest executed acceptance uses **visible Chromium** against the real running
services. See [7 November Chromium acceptance](chromium-acceptance-2026-11-07.md)
for screenshots, independent worker receipts, defects fixed and the explicitly
blocked autonomous outcome with zero provider calls.

For the 7 November 2026 live deployment review, worker retention fix, browser
workflow matrix and remaining autonomous prerequisite, see the
[real-user testing report](live-user-testing-2026-11-07.md).

Historical validation checkpoint: counts and deployment statements below apply to
that recorded stage. See [the Phase 0 baseline](phase0-baseline.md) for the current
source inventory, schema head `0003`, and new validation results.

Validated locally on 2026-11-04 against ARIA at `http://localhost:7000` and the
existing isolated Metasploitable VM at `192.168.77.20`. Tests used real Playwright
Firefox in a separate headless profile; the user's personal browser storage was
not accessed. No API keys, passwords, authorization headers or browser traces were
saved in test artifacts.

## Implemented behavior

- Explicit HTTP/HTTPS/FTP/SSH scan requests retain their requested ports and use
  reviewed Nmap TCP options. Exclusions ask for clarification. Explicit numeric
  port lists are preserved. This path is deterministic and needs no model call.
- REST plans are checked against engagement targets and the shared worker profile
  before display. Unsupported tools/scripts/raw scans and Nmap commands exceeding
  explicit engagement ports are removed with an explanation. General natural
  language still uses the existing model planner; this is not a universal intent
  parser or validation of exploitation applicability.
- Authenticated worker health/tools routes use the jobs-v1 capabilities endpoint.
  Worker HTTP 403 becomes an explicit policy rejection instead of a generic 502.
- REST conversation history comes from the database. Prompts, returned plans and
  execution output are persisted. Session switching and reload restore messages
  and command cards. Late replies are not rendered into another active session;
  overlapping submissions from the same UI are disabled while awaiting a reply.
- Execution output preserves line breaks. Failed exit status/cancellation does not
  produce a success toast. Successful tool analysis is displayed when returned.
- The existing autonomous settings slider now supplies the backend's `max_steps`
  field (1..12). A bounded HTTP availability goal is available. Other autonomous
  goals retain their model planner; unsupported proposed commands are filtered.
  Pending termination stays visibly pending rather than being reported as stopped.

## Executed checks

| Scenario | Result |
| --- | --- |
| Real Firefox login and scoped session | Passed |
| `scan http port` produces one TCP port-80 command | Passed |
| Click Run, actual Nmap output contains open `80/tcp` | Passed |
| Refresh restores the prompt, plan and raw result | Passed |
| Worker health reports online | Passed |
| Out-of-scope proposal from authenticated browser context | HTTP 403, passed |
| Approval rejected through browser API | Passed, no execution |
| Real Run/confirmation UI rejection | Passed; labelled persisted fixture card, dialog dismissed, no execution request |
| Autonomous HTTP goal, two-step budget | Passed; durable `auto_execute` record contains real HTTP 200 |
| Second autonomous start and Stop | Passed; no cancellation pending |
| Browser JavaScript exceptions | None |
| Offline Python regressions | 99 passed |
| Real worker container scenarios | 7 passed, including five kernel-boundary probes |
| Frontend contracts, JavaScript syntax, diff whitespace | Passed |

Live tests generated screenshots and a JSON report under the ignored private
`.local-lab/browser-results/` directory: `manual-output.png`,
`restored-history.png`, `approval-rejection.png`, `autonomous-cycle.png` and
`report.json`. The labelled browser sessions remain available for inspection.
Approval fixtures are deliberately labelled as rejection tests and must not be
approved. The tested worker image is:

```text
sha256:bb5f48b3d9a9ca41d4375ff50627db0ed0caeeee2d50f8f355c39a2925839e33
```

## Reproduce

The lab services/VM must already be running. Install browser tools separately
from the locked application environment:

```bash
python3.11 -m venv .local-lab/browser-venv
.local-lab/browser-venv/bin/pip install playwright==1.64.1
.local-lab/browser-venv/bin/python -m playwright install firefox
ARIA_BROWSER_LAB=1 .local-lab/browser-venv/bin/python integration/browser_user_flow.py
```

The opt-in harness reads `.local-lab/login.txt`, creates its own engagement restricted
to TCP80, and performs real UI actions. Session creation and scope setup use an
API fixture; the rejection card uses a labelled database fixture. Scope-denial and
one rejection check use authenticated browser API requests. These are explicitly
identified in the report and are not represented as mouse-only tests. Set
`ARIA_BROWSER_HEADED=1` to display the separate automation browser.

The live run covers the bounded HTTP autonomous goal, not autonomous compromise,
credential dumping or pivoting. Stop/restart/outage/isolation cases have additional
worker tests; a browser pass is not production certification. No exploit, brute
force, out-of-scope execution or external provider transfer of credentials was
performed. General AI analysis still requires configured provider keys and remains
subject to provider availability and output quality.
