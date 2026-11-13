# ARIA Phase A — validation and review handoff

Date: 2026-11-13. Phase B has not started. Architecture: [audit and UX plan](aria-phase-a-architecture.md). Foundation: [design specification](aria-design-system.md). Interactive review specimen: `http://127.0.0.1:7000/static/design-system.html`.

## Implemented and changed files

| Files | Actual Phase A change |
| --- | --- |
| `web/static/styles/aria-foundation.css` | Shared semantic palette/type/spacing/radii, accessible opt-in form/button/panel/status/table/disclosure primitives, visible focus, forced-colors and reduced-motion support. |
| `web/static/styles/aria-legacy.css` | Maps existing page variables to shared tokens; narrow shell styling; readable filled controls; static state markers; repairs clipped mobile workspace actions; admin mobile reflow. |
| `web/static/design-system.html`, `styles/design-system.css`, `scripts/design-system.js` | Clearly labeled public design specimen with working token inspector, record-density setting, motion off switch, input examples, semantic data states and native disclosure. No API/account reads, persistence or execution actions. |
| `web/index.html`, `dashboard.html`, `login.html`, `admin.html` | Load shared foundation/adapter and existing IBM Plex font families. Workspace/admin skip links and main landmarks; sign-in main landmark; admin navigation uses native buttons and ARIA branding. Existing clients/handlers retained. |
| `integration/phase_a_design_review.py` | Repeatable Chromium review of real local APIs, all four shells, the specimen, keyboard interaction, contrast, responsive layout, and isolated test-only empty/error responses. |
| `docs/aria-phase-a-architecture.md`, `aria-design-system.md`, this file | Architecture/SPEC audit, capability/gap matrix, security boundaries, skills evaluation, phased implementation plan and design review handoff. |

The pre-existing changes to `web/static/styles/index.css`, the backend, tests and other documentation were not reverted or attributed to this phase. `dashboard.html`, its client/CSS, and several backend files were already untracked/modified when this task began; Phase A changes only the dashboard shell's common font/style links and body scope. No backend file, DB schema, dependency manifest or execution policy was changed in Phase A.

## Verification results

| Check | Command / evidence | Result |
| --- | --- | --- |
| Offline regressions | `LLM_ROUTING=cloud DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q` | 455 tests passed in 15.723s. Test fixtures block network. |
| Frontend behavior contracts | `node tests/frontend_contracts.cjs` | Passed: client rendering, proposal/approval/rejection and socket authentication. |
| Existing dashboard contracts | `node tests/dashboard_contracts.cjs` | Passed: real route references, DOM/security, responsive/accessibility contracts. |
| Report contracts | `node tests/report_frontend_contracts.cjs` | Passed: preview, human sign-off, export and engagement isolation. |
| Phase A Chromium review | `ARIA_PHASE_A_REVIEW=1 .local-lab/browser-venv/bin/python integration/phase_a_design_review.py` | Final run: 32 checks, zero failures, zero page errors. |
| Existing real dashboard acceptance | `ARIA_DASHBOARD_ACCEPTANCE=1 .local-lab/browser-venv/bin/python integration/dashboard_screenshots.py` | 24 checks, zero failures; real findings totals, graph selection, tabs/keyboard, worker presence, campaign absence, timeline and mobile layout; zero unexpected API/console/page errors. |
| Source hygiene | `git diff --check`, `node --check web/static/scripts/design-system.js`, Python AST parsing | Passed. |

Chromium sizes: 1440×1000 desktop, 390×844 mobile, and 320×844 specimen reflow. All four real page shells have one main landmark and no document horizontal overflow at reviewed sizes. The mobile workspace's existing Overview/Settings buttons are now reachable. Admin section buttons work with Enter and update the selected section. The component specimen makes no API requests.

The foundation passed 31 computed contrast pairs: text on intended surfaces and primary fill ≥4.5:1; control boundaries ≥3:1. Minimum tested text contrast: 6.00:1. Minimum tested boundary contrast: 3.50:1. Reduced-motion, explicit motion-off, forced-colors boundaries and visible keyboard focus passed. These are scoped checks, not a complete accessibility certification of every legacy component.

Real integration used normal owner login and read-only endpoints. Session listing returned 200 after authentication and 401 without it. A real session with no campaign returned expected 404. The existing dashboard renders this as no campaign; it does not treat it as an unexpected network failure. Empty-session and HTTP 503 checks use separate browser contexts with route interception, explicitly labeled in the report and screenshots. Production source/data contains no mock telemetry. No run, campaign, command, model call, target scan, user mutation or budget change was initiated by this review.

## Screenshots and inspection

Final Phase A machine-readable report: [report.json](../.local-lab/phase-a-review/20261113T013406Z/report.json). Existing dashboard acceptance: [report.json](../.local-lab/dashboard-review/20261113T012946Z/report.json).

- [Foundation desktop](../.local-lab/phase-a-review/20261113T013406Z/foundation-desktop-1440.png)
- [Foundation mobile](../.local-lab/phase-a-review/20261113T013406Z/foundation-mobile-390.png)
- [320px foundation reflow](../.local-lab/phase-a-review/20261113T013406Z/foundation-mobile-320.png)
- [Desktop shell contact sheet](../.local-lab/phase-a-review/20261113T013406Z/desktop-contact-sheet.png)
- [Mobile shell/contact-state contact sheet](../.local-lab/phase-a-review/20261113T013406Z/mobile-contact-sheet.png)
- [Real findings/dashboard desktop](../.local-lab/dashboard-review/20261113T012946Z/dashboard-desktop-1440.png)
- [Real findings/dashboard mobile](../.local-lab/dashboard-review/20261113T012946Z/dashboard-mobile-390.png)

Screenshots are local ignored artifacts, not committed evidence or public uploads. They include real saved engagement/user data, so retain them locally. Desktop/mobile layouts, typography, component boundaries, mobile action reachability and settings were visually inspected. Initial review found a 2.64:1 control boundary and clipped workspace actions; both were corrected before the final passing run. An initial browser-only fixture callback incorrectly received Playwright's request argument as its scenario; the harness was fixed and both isolated scenarios now pass.

## Unsupported or deferred capabilities

Full global historical replay/pagination, complete durable command proposal/denial history, securely retained prompt previews, universal model purpose/agent/error/correlation fields, worker fleet/container/queue telemetry, and live campaign budget/schedule editing have no complete current API contract. Do not simulate them. Detailed per-area sources and gaps are in the architecture audit.

This phase unifies foundations rather than rebuilding every legacy component. Existing layout, timeline aggregation, zero-default accounting behavior, hidden mobile session list and other information architecture issues remain scoped to the next reviewed phases. No full screen-reader audit, Firefox/WebKit matrix, PostgreSQL service integration rerun, multi-worker validation or long-duration endurance test was performed for these CSS/HTML changes. Eight-hour production endurance remains unproven by the existing synthetic SPEC-15 results.

Review the architecture, design direction, semantic state vocabulary, specimen density and incremental adoption strategy before authorizing Phase B.
