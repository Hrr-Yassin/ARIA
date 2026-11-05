# Phase 2: durable team tasks and evidence

Implemented in the working tree based on `32f157c`, 2026-11-05. This is product
roadmap Phase 2, separate from the historical security-remediation P2 checkpoint
in `p2-status.md`. Acceptance covers supervised analysis of saved observations;
live model expertise, authenticated mapping and distributed scheduling remain
outside this phase.

## Using team work

Select an active engagement, then open **Settings → Team tasks and evidence**.

1. Load saved team work. Catalog a terminal worker job receipt by its job ID, or a
   saved tool-output/capture record by its chat evidence ID. Catalog entries show
   source references, hashes, timestamps, provenance and redacted summaries.
2. Set the shared model budget before delegating analysis. Enter maximum calls,
   reserved tokens and reserved USD, and a conservative combined input/output rate
   for the exact configured provider/model. Missing tariffs block provider traffic.
   Model overrides may select a different model from a provider's default; each
   selected model needs its own tariff. Additional tariffs can be configured using
   the budget API. Rates are owner assertions, not current prices supplied by ARIA.
3. Create a task with a specialist role, objective, evidence inputs, expected output,
   completion criteria, optional dependencies and a budget. The UI supplies defaults
   of two attempts, five model calls and 50,000 reserved tokens per task; the task
   API supports explicit smaller/larger bounds within the validated maxima.
4. Delegate a queued task. Dependencies must first be completed after human review.
   The coordinator invokes the existing specialist and saves its typed result.
   It never dispatches a tool. Proposed commands still need the existing execution
   workflow and its scope/approval checks.
5. Inspect the evidence, observations, hypotheses and uncertainty. Record a review
   reason before completing a task, asking for more work, cancelling, or requeuing
   a blocked task. A failed task is terminal; create a new task after inspection.
6. Record tested features, unresolved questions and reasons for gaps in coverage.
   Tested coverage requires catalog evidence. Observations/hypotheses can link to
   contradicting records; rejected records and previous coverage revisions remain
   in the saved event history.

## Implementation and acceptance map

| Task | Implementation / evidence |
| --- | --- |
| TEAM-01 | Strict task contracts: specialist role, engagement owner, objective, existing-task dependencies, catalog evidence IDs, attempts/model/token budget, expected output and bounded completion criteria |
| TEAM-02 | Queued, running, awaiting_review, blocked, completed, cancelled and failed; deterministic transition rules, revision checks and explicit human completion |
| TEAM-03 | Engagement-row serialization; immutable SQL transition events commit before response/publication; request IDs bind operation fingerprints; saved cursor-based polling events serve as a durable outbox |
| TEAM-04 | Existing coordinator delegates durable tasks to recon, scan, web intel, vulnerability, correlation and report specialists; collects `AgentResult`; duplicate delivery never repeats a specialist call |
| TEAM-05 | Versioned coverage ledger: security question, application feature, tested/unresolved/blocked status, evidence references and gap reasons |
| TEAM-06 | Owner-bound catalog from actual saved tool/capture records or terminal worker receipts, with server-derived hashes, source/job references, timestamps, provenance and redacted summaries |
| TEAM-07 | Evidence-linked observations/hypotheses and explicit uncertainty; immutable contradictory/rejected statements and prior task-result events remain readable |
| TEAM-08 | Explicit untrusted source boundary, redaction and candidate-only conclusions; hostile target-page/capture/retrieved/tool-output fixtures cannot alter policy or dispatch tools |
| TEAM-09 | Shared SQL reservations before each pool provider attempt, including failover; provider-reported tokens/cost when available; call/token/declared-cost limits and cumulative per-task call/token limits; storage failure denies dispatch |

The gate uses two dependent tasks across web-intel and correlation specialists,
a real isolated HTTP worker observation, durable evidence links, explicit human
review, recreated task stores/recovery, and an unchanged worker-job count. Provider
responses are mocked; the test never contacts a live model. Recovery preserves
completed history and blocks interrupted delegation without automatic replay.

## Persistence and ownership

Task, evidence, knowledge, coverage and polling events use the existing SQL
`decision_logs` ledger. Model attempts/configuration also use that ledger, while
engagement/task counters live in authoritative engagement metadata. Optional legacy
reasoning logging does not control required persistence. No dependency change or
migration is needed; Alembic head remains **0003**.

All team routes require live identity and direct engagement ownership; there is
no administrator override. Engagements must be active for this workflow. Creation,
claim, transition, catalog and budget mutations lock the engagement row. Task
creation references only existing dependencies, so dependency cycles cannot be
introduced. At most 500 tasks may be created per engagement.

Task events are ordered by an engagement sequence, not wall-clock timestamps.
A retry with the same request ID and operation returns the original committed
event; changing its operation returns 409. In particular, repeating a run request
returns its saved claim, even if later transitions exist. Read the task view/events
for current state. A different request ID cannot claim an already running task.
Unfinished tasks are blocked at startup, not resumed. A human may explicitly queue
a blocked task within its remaining cumulative attempt/model budget.

Cancelling a task fences result collection and later model reservations. It cannot
recall a provider call already admitted. Request cancellation records a blocked
state; unfinished provider reservations remain charged. A worker action is never
started from task text or a specialist result. Existing worker cancellation and
program-policy overload behavior remains in its separate shared execution gate.

## Model accounting

The pool reserves every physical attempt separately, including failed keys and
failover. Calls from ordinary specialist/chat/report flows share the same
engagement counters as team tasks. Missing owner-bound engagement context,
missing/exhausted budgets or storage failure deny provider I/O. Owner-entered
provider/model tariffs form an explicit allowlist; existing deployments must
configure them before live model use with this source revision.

Reservations charge UTF-8 prompt/system bytes plus 8,192 tokens for framing/output
allowance, and an integer micro-USD ceiling using the configured conservative
combined rate. One USD is 1,000,000 micro-USD. This is a conservative accounting
policy, not an exact tokenizer or a guarantee about a provider's billing. Review
rates and model-specific behavior before live use. Limits can change, but consumed
reservations never reset or refund on failures, retries, missing usage or crashes.
A reported usage/cost overrun permanently stops further calls for that engagement.

Actual tokens and cost are recorded only when the provider reports them. Missing
values remain null and increment unknown counters; they are never represented as
free calls. Cost accounting currently understands an optional USD `usage.cost`;
providers that do not return it remain unknown. A crash between reservation and
network dispatch/settlement leaves an unresolved `reserved` attempt and its full
charge. It is not possible to infer whether that provider received the request.
No automatic retry replays that reservation. Live provider pricing/usage and
accuracy are not certified by mocked acceptance.

## API

Base path: `/api/team/{session_id}`.

| Method / suffix | Purpose |
| --- | --- |
| GET base | Current saved tasks, evidence, knowledge, coverage and cursor |
| GET `/events?after=N` | Up to 100 committed events; advance using returned cursor |
| POST `/tasks` | Create task with UUID request ID |
| POST `/tasks/{task_id}/run` | Delegate queued task using UUID request ID |
| POST `/tasks/{task_id}/transition` | Revision-bound owner review, cancellation or requeue |
| POST `/evidence` | Catalog owned saved chat/capture or worker receipt |
| POST `/knowledge` | Append observation/hypothesis, including rejection/contradiction |
| POST `/coverage` | Append a version of a coverage entry |
| GET `/model-budget` | Limits, cumulative reservations, reported usage and attempts |
| PUT `/model-budget` | Set limits and exact provider/model tariffs without resetting usage |

Creation, transition, evidence, knowledge and coverage operations carry UUID
`request_id` fields. Task transitions also carry `expected_revision`, `state` and a
review reason. Source text/model strings are rendered with `textContent` in the UI.
Generation/session checks suppress stale responses and old-engagement actions.

## Validation

The offline suite blocks network sockets/DNS and mocks providers/workers. The
service runner creates its own PostgreSQL database and harmless HTTP targets in a
unique private Podman network. It uses synthetic accounts and secrets, never owner
services or data. Firefox uses synthetic API responses and a temporary profile.

```bash
DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
node --check web/static/scripts/team.js
node --check web/static/scripts/app.js
DEBUG=false .local-lab/browser-venv/bin/python -B -m integration.browser_team_tasks
ARIA_PHASE2=1 WORKER_TEST_RUNTIME=podman WORKER_TEST_IMAGE=sha256:bb5f48b3d9a9ca41d4375ff50627db0ed0caeeee2d50f8f355c39a2925839e33 DEBUG=false .venv/bin/python -B -m integration.phase2_team
git diff --check
```

Run Python/Firefox/container acceptance outside the previously documented ASGI
sandbox limitation. The service runner upgrades/checks an empty disposable schema;
it does not change or adopt the owner database. Local results, sanitized source
manifest and screenshots are retained under ignored `.local-lab/phase2/` and
`.local-lab/phase2-browser/`. Screenshots include `task-awaiting-review.png` and
`team-ledger.png`.

## Acceptance results

| Check | Result |
| --- | --- |
| Full offline Python regressions | **177 passed**, 6.642 seconds |
| Frontend contracts and team/app JavaScript syntax | Passed |
| Synthetic Firefox team workflow | **Nine checks passed**, no page errors; includes clearing old engagement displays/drafts and refusing detached old-button actions |
| Disposable PostgreSQL/Podman team acceptance | **Seven grouped checks passed**, including concurrent duplicate delivery, two specialist roles, restart no-replay, evidence/coverage/history, owner and same-owner cross-engagement isolation, and shared model limits |
| Empty disposable schema upgrade and Alembic drift check | Passed; schema head 0003 |
| Diff whitespace | Passed |

The service run used source-manifest hash
`3ef1effc6dff1bcdc3aa420d9c6923a6f3ccf6bbfc34c0fbdd835c964a41fd23`
with base revision `32f157c` and working-tree changes. All backend implementation
files still match that manifest. Subsequent changes were limited to an offline
fixture correction and browser clearing/theme/acceptance refinements, covered by
the final offline/frontend/Firefox runs above. The immutable service manifest is
retained as recorded, rather than rewritten to claim it ran later source.

The Docker CI job now invokes the Phase 2 acceptance runner after its worker tests.
No GitHub Actions result is claimed here. The local runtime was rootless Podman.
The runner cleaned up its own containers/network. No owner database, account,
provider key, service configuration or deployment was changed. There were zero
live model calls; two mocked provider responses exercised the real pool/accounting
and specialist boundaries in the disposable service check.

## Limits

This remains a single-API-process research prototype. Delegation runs inside its
request, rather than a distributed background scheduler. Recovery blocks unfinished
work and requires review. UI polling is not a durable WebSocket delivery guarantee;
clients retrieve committed events by cursor. Session-active requirements apply to
team reads as well as mutations. General retention, archive browsing, operational
backup recovery and high-volume ledger performance remain future work.

Evidence summaries use best-effort redaction. Original protected capture storage
and worker ledgers keep their existing access rules; cataloging does not verify a
vulnerability, silently upgrade manual evidence provenance, or grant execution
permission. No new authenticated replay, post-access capability, public-target
pilot, provider-consent workflow or external report submission is enabled here.
