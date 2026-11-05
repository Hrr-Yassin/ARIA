# ARIA: security research team roadmap

Updated: 2026-11-05. Status: Phase 0 completed on 2026-11-05; Phase 1 completed for bounded HTTP observations; later phases remain proposed backlog.

## Objective

Build an evidence-driven team of security agents that helps a human researcher
select suitable bug bounty programs, investigate authorized applications, verify
vulnerabilities, and prepare reproducible reports. Support a separate contracted
pentest workflow. Optimize verified findings, coverage, review time, and cost;
never promise vulnerabilities, bounty acceptance, or income.

First product: one researcher, web applications and APIs, researcher-controlled
accounts, bounded execution, and human-reviewed submissions.

## How to use this backlog

Each checkbox is a separate reviewable task, generally one small PR. Split tasks
further when implementation spans multiple independent changes. Record owner,
PR, validation evidence, and blockers alongside each task when work starts.
Unchecked tasks are not claims that all underlying functionality is absent:
first inventory existing implementations and extend them rather than duplicate them.
Complete the phase acceptance gate before enabling dependent capabilities.
Estimates assume one experienced developer; acceptance gates take priority over dates.

## Phase 0: establish the baseline (1–2 weeks)

Dependencies: none.

Completed by Codex in the Phase 0 working tree. Evidence, commands, limitations,
and the route inventory are in [the Phase 0 baseline](phase0-baseline.md).
No owner deployment or schema was changed.

- [x] BASE-01: Inventory existing routes, specialists, worker profiles, migrations, and feature flags; identify implemented, validated, and unavailable features separately.
- [x] BASE-02: Reconcile README and validation registers with the actual source revision; distinguish historical checkpoints from current results.
- [x] BASE-03: Document a staging configuration using disposable services and synthetic accounts, separate from owner data.
- [x] BASE-04: Run the offline Python and frontend suites; attach exact commands, revision, environment, and results.
- [x] BASE-05: Validate all pending migrations on an empty disposable database and a backed-up staging restore; document rollback through restore.
- [x] BASE-06: Trace one lab action through proposal, policy, approval, worker receipt, stored evidence, and report.
- [x] BASE-07: Verify restart reconciliation does not replay actions and preserves reviewable history.
- [x] BASE-08: Add a UI capability summary distinguishing supported tools from tools merely mentioned in prompts.

Gate: one complete lab assessment trace, consistent schema documentation, no
unexplained regression failures, and preserved session/authorization isolation.

## Phase 1: program discovery and scope policy (about 2 weeks)

Dependencies: Phase 0; preserve the shared execution gate.

Work started by Codex on 2026-11-05. See [implementation status](phase1-policy-status.md)
for the implementation, supported boundaries, and acceptance evidence.
Phase 1 is complete for bounded curl GET/HEAD observations. Discovery/import alone
cannot activate execution permission; unsupported profiles remain blocked.

- [x] SCOPE-01: Define program and policy-snapshot models with source URL, retrieval time, content hash, and engagement owner.
- [x] SCOPE-02: Add official program-page import, with manual text import when authenticated pages cannot be fetched.
- [x] SCOPE-03: Extract included assets, exclusions, eligible issue classes, account requirements, and automation restrictions into a draft.
- [x] SCOPE-04: Link every extracted rule to source text; mark missing or ambiguous rules unknown.
- [x] SCOPE-05: Add human policy review and activation; model output alone cannot activate permission.
- [x] SCOPE-06: Enforce exact hostname/wildcard semantics, relevant paths, ports, redirects, and third-party exclusions server-side and at execution boundaries.
- [x] SCOPE-07: Store policy revisions; suspend affected pending actions when a policy changes until revalidated.
- [x] SCOPE-08: Add shared per-engagement request/concurrency budgets; honor documented limits and stop/back off on overload or throttling.
- [x] SCOPE-09: Rank candidate programs by technical fit, accessible accounts, eligible classes, automation compatibility, and research cost; unknown values remain visible.
- [x] SCOPE-10: Separate paid bounty programs from disclosure-only programs; display participation prerequisites without assuming eligibility.

Gate: a policy fixture set rejects excluded assets, prohibited actions, redirect
escapes, ambiguous permission, and stale approvals. Program discovery never authorizes testing.

## Phase 2: durable team tasks and evidence (about 2 weeks)

Dependencies: Phases 0–1.

- [ ] TEAM-01: Define task records: owner role, objective, dependencies, evidence inputs, budget, expected output, and completion criteria.
- [ ] TEAM-02: Add task states: queued, running, awaiting_review, blocked, completed, cancelled, failed.
- [ ] TEAM-03: Persist task transitions before publishing UI events; make duplicate delivery idempotent.
- [ ] TEAM-04: Extend the coordinator to delegate and collect typed specialist results using existing result contracts.
- [ ] TEAM-05: Add a coverage ledger tracking security questions, tested features, unresolved questions, and reasons for gaps.
- [ ] TEAM-06: Add an evidence catalog with engagement ownership, job/capture references, timestamps, hashes, and redacted summaries.
- [ ] TEAM-07: Link observations and hypotheses to evidence; preserve contradictory and rejected observations.
- [ ] TEAM-08: Treat target pages, captures, retrieved text, and tool output as untrusted data; test prompt-injection attempts against action permissions.
- [ ] TEAM-09: Add global model accounting for actual provider calls, retries, tokens, and cost, with enforced engagement limits.

Gate: a multi-task lab investigation survives restart without duplicate execution;
every specialist conclusion has attributable evidence or explicit uncertainty.

## Phase 3: authenticated application mapping (2–3 weeks)

Dependencies: Phases 1–2.

- [ ] WEB-01: Define researcher-controlled identities and object ownership records; store credentials encrypted behind opaque handles.
- [ ] WEB-02: Add isolated browser contexts per identity and engagement; prevent cookie and storage leakage.
- [ ] WEB-03: Complete real Burp Community capture and Repeater handoff validation before enabling its connector.
- [ ] WEB-04: Build an endpoint catalog from selected captures and bounded browsing: method, route, parameters, role, and source evidence.
- [ ] WEB-05: Map workflows and state changes, including sharing, invitations, exports, and account settings.
- [ ] WEB-06: Record expected role/object permissions with human corrections.
- [ ] WEB-07: Implement structured authenticated HTTP replay as a reviewed worker capability; bind identity, target, policy, and approval.
- [ ] WEB-08: Add response normalization and semantic comparison; preserve original bounded evidence privately.
- [ ] WEB-09: Enforce retention, redaction, and provider data-sharing settings; prevent raw credentials entering model context.

Gate: two lab accounts remain isolated; ARIA maps their objects and permissions,
and every replay is scoped, attributable, bounded, and cancellable.

## Phase 4: focused specialist investigations (3–4 weeks)

Dependencies: Phases 2–3.

- [ ] SPEC-01: Define investigation contracts: hypothesis, prerequisites, minimum test, normal result, abnormal result, stop conditions, and disconfirming evidence.
- [ ] SPEC-02: Implement authorization comparison workflows using only researcher-controlled accounts and objects.
- [ ] SPEC-03: Implement authentication/session assessment workflows with explicit account and action prerequisites.
- [ ] SPEC-04: Implement sensitive-exposure analysis that distinguishes public/expected information from demonstrated unauthorized disclosure.
- [ ] SPEC-05: Add selected input-validation checks through reviewed, bounded profiles; avoid arbitrary shell execution.
- [ ] SPEC-06: Add human-assisted business logic workflows with expected invariants and controlled state changes.
- [ ] SPEC-07: Make planners consume actual worker capabilities and return blocked reasons for unsupported tests.
- [ ] SPEC-08: Replace tool-count completion with tested security questions and evidence-based task completion.
- [ ] SPEC-09: Add secure, vulnerable, misleading-response, and missing-prerequisite fixtures for each specialty.

Gate: each enabled specialty passes positive and negative controls. Version matches,
HTTP success codes, model confidence, and scanner labels alone cannot confirm findings.

## Phase 5: independent verification (about 2 weeks)

Dependencies: Phase 4.

- [ ] VERIFY-01: Add finding states: observation, hypothesis, tested, reproduced, reviewed, reportable, rejected, inconclusive, blocked.
- [ ] VERIFY-02: Implement deterministic transition prerequisites and evidence requirements.
- [ ] VERIFY-03: Add a reviewer role that can reject specialist conclusions and request the smallest missing validation.
- [ ] VERIFY-04: Reproduce candidates from clean state and check negative controls.
- [ ] VERIFY-05: Confirm account/object ownership, expected permissions, and meaningful response content.
- [ ] VERIFY-06: Separate demonstrated impact from potential escalation; stop once sufficient proof exists.
- [ ] VERIFY-07: Detect local duplicates by underlying cause and affected workflow, while acknowledging private program duplicates are unknown.
- [ ] VERIFY-08: Require recorded human review before a finding becomes ready for external submission.

Gate: independently reproducible lab findings pass; misleading and unsupported
claims are rejected or inconclusive. Agreement between models is not verification.

## Phase 6: professional reports and outcome tracking (1–2 weeks)

Dependencies: Phase 5.

- [ ] REPORT-01: Add a bug bounty template: title, asset, prerequisites, exact steps, expected/actual behavior, evidence, impact, and remediation.
- [ ] REPORT-02: Add a pentest template: scope, coverage, limitations, findings, priorities, and retest status.
- [ ] REPORT-03: Preserve complete reproduction evidence in attachments/manifests; do not rely on truncated PDF excerpts.
- [ ] REPORT-04: Validate every report claim against finding status and evidence; keep observations separate from confirmed findings.
- [ ] REPORT-05: Add report preview and human sign-off with immutable report revision and evidence references.
- [ ] REPORT-06: Export a platform-ready draft; external submission remains an explicit human action.
- [ ] REPORT-07: Track submitted, triaged, duplicate, informative, rejected, accepted, resolved, and paid outcomes separately.
- [ ] REPORT-08: Draft triage answers from saved evidence and record retest results without silently retesting changed scope.

Gate: an independent reviewer reproduces a finding from the report alone; secrets
are redacted and unverified impact is not represented as demonstrated fact.

## Phase 7: benchmark and supervised pilot (2–4 weeks)

Dependencies: Phases 0–6.

- [ ] EVAL-01: Freeze lab images, source revisions, model identifiers, prompts, tool versions, and budgets.
- [ ] EVAL-02: Prepare a ground-truth set containing secure cases, vulnerable cases, and unfamiliar variants.
- [ ] EVAL-03: Compare manual workflow, single assistant, and ARIA under equivalent starting conditions and budgets.
- [ ] EVAL-04: Measure precision, recall, independent reproduction, coverage, wall time, human effort, requests, and model cost.
- [ ] EVAL-05: Exercise restart, cancellation, provider failure, storage failure, duplicate delivery, and scope-change cases.
- [ ] EVAL-06: Publish baseline results and select justified precision/recall targets before a public-target pilot.
- [ ] EVAL-07: Review one current public program policy, confirm participation prerequisites, and choose one narrow feature area.
- [ ] EVAL-08: Run a supervised authorized pilot with fixed traffic/cost/time limits; retain no-finding outcomes honestly.
- [ ] EVAL-09: Review submission outcomes and decide whether to improve a specialty, change program fit, or expand capability.

Gate: zero scope violations in the acceptance set, complete evidence linkage,
independent reproduction of every reportable pilot finding, and documented limitations.
A pilot can pass engineering criteria without finding a bounty-eligible vulnerability.

## Phase 8: operational maturity and broader pentesting

Dependencies: successful supervised pilots; schedule based on measured needs.

- [ ] OPS-01: Validate protected deployment, backup/restore, audit retention, and incident recovery.
- [ ] OPS-02: Add engagement-level data retention/deletion and customer/provider data consent controls.
- [ ] OPS-03: Validate multi-tab use and long-running investigations under realistic interruptions and load.
- [ ] OPS-04: Add contracted-pentest policy templates, customer scope approval, coverage review, and retest deliverables.
- [ ] OPS-05: Introduce additional worker tool profiles only with authorization, isolation, cancellation, and evidence tests.
- [ ] OPS-06: Consider durable distributed scheduling only when measured concurrency requires it; retain a single authoritative policy boundary.
- [ ] OPS-07: Learn reusable playbooks only from reviewed outcomes, with sanitized explicit publication and regression evaluation.

Gate: operational recovery is demonstrated and broader capability has its own
acceptance evidence. Do not infer production readiness from offline suite results.

## Candidate environments and program selection

Policy references were researched on 2026-11-05. Re-fetch the full current policy
before any testing. The table is a research shortlist, not authorization or a
prediction of easy findings or earnings.

| Candidate | Purpose | Conditions |
| --- | --- | --- |
| Local OWASP Juice Shop | Repeatable web/API development | Run an isolated local instance with synthetic data |
| PortSwigger Academy | Specialist exercises and unfamiliar labs | Use assigned lab instances within service terms |
| GitLab local development environment | Source-informed, reproducible research | Review current HackerOne scope and eligibility before a bounty investigation |
| GitHub bounty | Later supervised authorization/API research | Exact scope review, owned test accounts/objects, bounded automation |

Program ranking should explain capability fit, eligible classes, test-account
availability, source accessibility, setup effort, and unknown policy details.
Do not assume advertised maximum rewards predict likely returns.

## Repository implementation map

| Area | Intended changes |
| --- | --- |
| `agents/` | Explicit tasks, specialist methods, independent review |
| `orchestrator/` | Dependency scheduling, hypothesis tracking, coverage |
| `memory/` | Policies, identities, tasks, evidence, finding lifecycle |
| `worker/` | Structured HTTP/browser profiles and traffic budgets |
| `llm/` | Actual usage accounting, output validation, data controls |
| `api/` | Engagement, review, evidence, and outcome endpoints |
| `web/` | Program shortlist, task board, evidence comparisons, report review |
| `tests/`, `integration/` | Positive/negative fixtures and acceptance scenarios |

## First implementation slice

Complete BASE-01 through BASE-07 first. Then implement SCOPE-01 through SCOPE-05
and TEAM-01 through TEAM-03. The first end-to-end feature is a two-account lab
investigation that produces a reviewed, reproducible report. Do not enable new
external active testing as part of writing or importing this roadmap.

## Success and research economics

Track verified findings, duplicates, accepted reports, paid rewards, research hours,
human review time, model costs, and infrastructure costs separately. Net cash return
is rewards actually received minus direct costs; researcher time is an additional
cost to evaluate. No revenue forecast is claimed before measured pilot outcomes.

## Sources

- [HackerOne Code of Conduct: AI-assisted work and report quality](https://www.hackerone.com/policies/code-of-conduct)
- [Bugcrowd: finding a program and reading its brief](https://docs.bugcrowd.com/researchers/participating-in-program/finding-program/)
- [GitLab testing guidance and policy changes](https://about.gitlab.com/blog/gitlab-bug-bounty-program-policy-updates/)
- [GitLab live program policy](https://hackerone.com/gitlab) — full JavaScript-rendered policy was not inspected during roadmap research.
- [GitHub rules](https://bounty.github.com/rules.html)
- [GitHub scope](https://bounty.github.com/scope.html)
- [OWASP Juice Shop](https://owasp.org/projects/juice-shop?tab=overview)
- [PortSwigger Academy labs](https://portswigger.net/web-security/all-labs)
