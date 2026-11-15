# ARIA operational reliability mission

Primary mission: transform the fragile bounded agentic workflow into an observable, recoverable mission-management system that preserves authorized objectives, truthful state, evidence and budget controls. User program dated 2026-11-15 is authoritative. Do not silently change acceptance conditions.

## Engineering objectives and acceptance

All requirements in PLANS.md must be audited against actual implementation, focused tests and retained evidence. Only VERIFIED means demonstrated completion; IMPLEMENTED is insufficient. Preserve original objectives across browser/API/session/restart, distinguish phase and mission completion, contain invalid model output, attribute existing agents accurately, prevent duplicate dispatch, recover durable state without replaying uncertain actions, explain authorization blockers, and measure actual latency and costs. Improve the existing frontend with truthful operational information.

Validate twelve harmless synthetic operations separately from the bounded live discovery objective. Visible acceptance requires sandboxed Chromium with headless=False and graphical login/navigation; headless/API substitutions do not satisfy it. Progressive synthetic endurance durations are 15m, 30m, 1h, 2h, 4h and 8h: record only completed durations; remaining durations are NOT_TESTED. Final graphical audit must include every requirement, evidence, limitations and confidence. No global readiness percentage.

## Non-goals and boundaries

Do not maximize commands, findings, tools or agents. Do not expand security-testing capabilities, target scope or worker privileges. Do not modify Kali, Metasploitable, VM networking or worker privileges without explicit owner authorization. Preserve session ownership, shared execution authorization, isolation, human approvals and financial limits. Laboratory target is 192.168.77.20, restricted to previously authorized non-destructive discovery. Use synthetic fixtures/mock adapters for extended engineering tests. Model hypotheses are not verified findings. Preserve all pre-existing user changes; no destructive Git operations or remote writes.

## Budget and stop conditions

No additional paid model calls without existing explicit approval and a verified budget. Offline fixtures are the default. Stop dependent work on unavailable authorization, unsafe scope, unknown execution outcomes, exhausted budget, missing graphical prerequisites, or unavailable disposable infrastructure; continue independent safe work. Never treat elapsed waiting as approval. Checkpoint before session/resource limits. No eight-hour claim inferred from a short run.

## Evidence requirements

Record Git HEAD plus dirty-tree provenance, commands, timestamps, exact test counts/results, sanitized artifacts and unavailable measurements. Credentials, raw private evidence and .env stay untracked. Distinguish historical evidence from current reproduction, source existence from runtime use, and tests from live acceptance. Preserve original evidence. Final deliverables: reports/aria-operational-reliability-audit.html, reports/aria-acceptance-matrix.json, reports/aria-performance-metrics.csv. Completion requires every mandatory requirement VERIFIED; blocked requirements remain unmet.

## Iteration protocol

At iteration start read this file, the active phase in PLANS.md and latest PROGRESS.md checkpoint; select an unmet requirement and its required evidence. At iteration end inspect diff, run focused checks, record measured results, update status and select the next justified action. Append progress after every meaningful implementation/validation cycle. Status vocabulary: NOT_STARTED, IN_PROGRESS, IMPLEMENTED, VERIFIED, FAILED, BLOCKED, NOT_TESTED.
