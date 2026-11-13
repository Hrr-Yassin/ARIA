# Kali worker: visible Chromium user test

On 7 November 2026, a visible Playwright Chromium browser tested the live ARIA
UI and the actual worker on Kali. No browser routes, worker responses, model
responses or findings were mocked. The authorized target was `192.168.77.20`,
with scan commands limited to TCP port 80. No paid model calls were made.

All 13 acceptance checks passed. They included login; creating and cancelling
engagements; worker status and risk controls; rejecting an ambiguous exclusion;
planning and executing a real Nmap scan; restoring output after reload; inspecting
hosts, findings, decision logs, reports and team workspaces; a URL-form target;
and switching between engagements. Both Nmap jobs succeeded, and each ARIA
response matched the separately queried Kali worker receipt and output hash.
The observed open port was recorded as informational, not a confirmed vulnerability.

Autonomous mode was tested through its real UI with a two-step limit and a
conservative risk threshold. It stopped before execution with `all_exhausted`:
no configured provider key was usable. The engagement recorded zero physical
model attempts and no additional worker job. This verifies the blocked user
experience; it does not establish successful model-driven autonomous discovery.
The currently configured Gemini keys have reached their ARIA request limits.

The run recorded no JavaScript or browser console errors, and no HTTP errors
among 72 captured browser responses. The frontend contract suite passed after
the run. The two test engagements and their logs were retained.

Private evidence directory:
`.local-lab/chromium-acceptance/20261107T165550Z/`. It contains `report.json`,
screenshots, actual execution responses, restored history, decision logs,
ARIA database audit snapshots, Kali worker ledger receipts, and recent ARIA
and Kali worker service logs. These artifacts can contain sensitive target and
system information and remain ignored by Git.

For a future authorized Kali run, the harness supports a read-only worker-ledger
audit over SSH via `ARIA_KALI_AUDIT=1`, `ARIA_KALI_KNOWN_HOSTS`, and `SSHPASS`
provided in the process environment. It does not store the SSH password in its
artifacts. Use a dedicated key-based credential for ongoing use.
