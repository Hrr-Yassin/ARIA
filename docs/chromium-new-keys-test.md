# Visible Chromium test after adding API keys

On 7 November 2026, visible Playwright Chromium tested the live ARIA UI, actual
Kali worker, and the authorized target `192.168.77.20`. Browser routes, provider
responses and worker responses were not mocked. The two explicit Nmap probes
were limited to TCP port 80. No paid model calls were made.

All 13 acceptance checks passed. The checks covered login, creating and
cancelling engagements, worker settings and risk controls, a scope-sensitive
rejection, command planning, real command execution and receipt verification,
history reload, host/findings/decision records, AUTO, reports and team
workspaces, URL target handling, and switching engagements. Both Nmap results
matched their independent Kali worker receipts. An open port was recorded as an
informational observation, not a confirmed vulnerability.

A separate visible Chromium check confirmed that the settings page rendered all
14 stored API-key entries returned by ARIA, across Gemini, Groq and OpenRouter.
This is a UI/storage check, not a provider-authentication or generation test
for every new key.

AUTO stopped before execution with `model_tariff_missing` and displayed:
“Configure an engagement tariff for the selected provider and model.” The
fresh test engagement had no provider tariff. Its audit recorded zero physical
model attempts and no additional worker jobs. This confirms the blocked flow;
it does not show that model-driven autonomous discovery works. Configuring a
model tariff and budget enables the possibility of billable provider calls, so
these were not changed during this no-paid-calls test.

The 13-check run recorded no JavaScript errors, browser console errors or HTTP
errors among 72 captured responses. The frontend contract suite and whitespace
check passed. The test engagements were retained.

Private evidence directory:
`.local-lab/chromium-acceptance/20261107T173433Z/`. It includes the report,
screenshots, key UI count check, execution responses, restored history,
decision logs, ARIA database audit snapshots, independent Kali worker receipts,
and recent ARIA and Kali worker service logs. These files can contain sensitive
lab information and are ignored by Git.
