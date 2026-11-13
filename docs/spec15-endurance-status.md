# SPEC-15 — Autonomous Endurance & Reliability Validation

Status: implemented and validated on 2026-11-12. Scope stops at SPEC-15.

## Purpose

Validate that the autonomous campaign workflow is safe and reliable enough for a
synthetic 8-hour/day, 5-day/week schedule. This specification was validation
work, not feature development: no new agents, tools, targets or execution
paths were added. The only production change is one confirmed defect fix
described below.

Validation used synthetic engines, workers and provider accounting only. No
real model calls, external scans, real targets or worker submissions were made.
PostgreSQL checks used the disposable `aria_test` database; the production
`aria` database was never touched.

## Workflow audited

The validation exercises the whole durable autonomous path:

- campaign schedule, window/daily-runtime calculation and supervisor leases;
- supervisor start, restore, live-run supervision, pause/resume, cancellation,
  retry backoff and terminalization;
- bounded-run checkpoints, replay guards for executed commands and worker job
  IDs, and evidence-backed observations;
- worker dispatch receipts, cancellation fencing and worker-resume admission;
- campaign and engagement model ledgers, conservative reservations,
  settlement, unknown usage and accounting inconsistency;
- specialist investigation creation, deterministic identity, idempotent
  recovery and lease-gated dispatch;
- operational health, bounded event retention, alerts and durable audit rows.

## Confirmed defect fixed

**Retry streak was not cleared by durable progress.** `recover()` counts every
supervisor restart of a `starting`/`running` campaign as a retry. A long
campaign that crashed repeatedly after producing evidence could therefore
exhaust `max_retries` and fail with `retry_exhausted` even though every run had
advanced the checkpoint.

Fix: `orchestrator/campaign_supervisor.py:661` now records the previous
successful-step count, observes durable progress on each live supervisor tick,
and resets the retry streak to zero when the run advances. The bounded
`campaign_step_succeeded` operation and the existing retry maximum are
preserved. Unit coverage:
`tests/test_campaigns.py:509 test_durable_progress_clears_retry_streak`.
End-to-end coverage: the offline four-crash test and the PostgreSQL
three-crash test both fail without this fix and pass with it.

A narrow residual window remains: if the process crashes after a step is
checkpointed but before the next supervisor tick observes it (at most one
`CAMPAIGN_TICK_SECONDS` interval), that step does not clear the streak.
Repeated crashes inside that window can still exhaust retries. This is
called out under production risks rather than hidden by the fix.

## Validation harnesses

### Accelerated offline simulation (`tests/endurance_harness.py`)

Drives the real `CampaignSupervisor`, campaign schedule/ledger helpers and
`require_campaign_execution` guard against an in-memory campaign store, a
deterministic synthetic bounded run, an idempotent synthetic worker and a
synthetic provider ledger. Simulated time is advanced manually. The suite
includes a five-workday simulation (2,015 ticks), pause/resume and weekend
skips, repeated crash/recovery, budget and accounting failures, authorization
and scope changes, worker fencing, lease takeover, specialist idempotency,
operational bounds and a stalled-progress alert.

This is an accelerated simulation. It is not evidence of eight-hour wall-clock
reliability.

### PostgreSQL integration (`integration/test_endurance_postgres.py`)

Uses the real `SQLCampaignBackend`, real campaign leases, the real
`ModelAccounting` reservation/settlement path and the real execution guard
against disposable PostgreSQL. It adds:

1. a completed campaign with bounded durable growth and a healthy operational
   view;
2. three consecutive lease-expiry crashes with recovery, retry-streak reset,
   stale-token denial and no duplicate dispatch;
3. campaign-budget denial before any physical call or dispatch;
4. unknown provider usage that stops the campaign and denies the next physical
   call;
5. unresolved worker cancellation that fails closed before the run starts.

Simulated time starts at a future Monday so durable leases written by the
simulation stay ahead of wall-clock time. The tests still run against real
PostgreSQL transactions and real lease rows.

### Bounded wall-clock soak (`integration/endurance_soak.py`)

A real-time soak with a compressed synthetic workload: a 10-step campaign,
0.5-second supervisor ticks, a 5-second synthetic step interval, a 3-second
lease, a mid-run process crash, and a hard wall-clock bound (default 60
seconds, maximum 300). It reports wall duration, ticks, steps before/after the
crash, recoveries, provider calls, dispatches, duplicates, denials, retry
count, accounting totals, retained operations, durable-row bytes, CPU time and
peak RSS, then exits non-zero if any safety assertion fails. It uses an
in-memory store and makes no database, network, provider or worker contact.

## Acceptance results

| Area | Result | Evidence |
| --- | --- | --- |
| Crash recovery | **PASS** (accelerated and 60 s soak) | Offline single/repeated/paused crash tests; PostgreSQL three-crash test; soak crash at 30 s resumed and completed. No duplicate dispatch after recovery. |
| Scheduling correctness | **PASS** | Five-workday simulation: 2,015 ticks, exactly Mon–Fri 09:00–17:00 calls, daily runtime ≤ 3,900 s, weekend skip, Monday resume. Existing DST/window boundary tests also pass. |
| Execution safety | **PASS** | Stale supervisor token denied after takeover; authorization expiry, scope change and worker fence stop live runs before new calls/dispatches; the worker and specialist dispatch paths pass the real guard. |
| Budget enforcement | **PASS** | Campaign-budget denial returns 429 before any physical call or dispatch; reserved and reported totals match; unknown usage terminalizes with `campaign_accounting_inconsistent` and denies later calls; no bypass found. |
| Specialist integration | **PASS** | Deterministic task identity across recovery, one dispatch per investigation, unverified hypotheses, blocking without a live lease. |
| Operational observability | **PASS** | Health schema `aria.campaign.health.v1`, ring capped at 50, contiguous sequences, stalled-progress alert from durable state, accounting-consistency alerts, completed-campaign health. |
| Endurance stability (bounded) | **PASS** | Repeated recovery cycles with progress, bounded row/ring growth, 60 s wall-clock soak with no leaks observed in RSS or durable state. |
| Eight-hour wall-clock reliability | **NOT DEMONSTRATED** | Out of scope for a feasible bounded validation. Accelerated tests cannot establish it. Remains a production risk. |

### Repeated recovery and state bounds

- PostgreSQL: three consecutive lease-expiry crashes, each recovered to
  `scheduled` with retry 1, then reset to retry 0 after the next observed
  successful step; the campaign completed with one stable `run_id`, 10 unique
  work keys and 10 dispatches.
- Offline: four crash cycles with `max_retries=2` complete because each cycle
  produces durable progress.
- Operations: ring retention stayed at or below 50 with monotonic, contiguous
  sequences in both the 2,015-tick simulation and the soak.
- PostgreSQL growth for one completed four-step campaign: campaign row 4,361
  bytes, 7 retained operations, 8 immutable decision-log rows, 32,852 reserved
  tokens = 32,852 reported tokens. Relation-size growth was 0 bytes in the
  measured run because the table had free pages; the test asserts growth stays
  below 1 MB per campaign.
- Soak durable row: 7,804 bytes, 16 retained operations.

## Validation results

Environment: Python 3.11, 2026-11-12, disposable PostgreSQL `aria_test` on
`127.0.0.1:15432`, `LLM_ROUTING=cloud DEBUG=false`. No real provider, target
or worker was used.

| Check | Command | Result |
| --- | --- | --- |
| Focused offline endurance/campaign/specialist suites | `LLM_ROUTING=cloud DEBUG=false python -m unittest tests.test_endurance tests.test_campaigns tests.test_campaign_observability tests.test_campaign_execution_boundary tests.test_specialist_integration tests.test_specialist_hardening -q` | 109 tests, OK, 3.710 s |
| PostgreSQL integration sets | `ARIA_INTEGRATION=1 DATABASE_URL=postgresql+asyncpg://.../aria_test python -m unittest integration.test_campaign_postgres integration.test_campaign_execution_postgres integration.test_checkpoint_postgres integration.test_knowledge_store_postgres integration.test_specialist_postgres integration.test_observability_postgres integration.test_endurance_postgres -q` | 44 tests, OK, 31.633 s |
| Complete offline suite | `LLM_ROUTING=cloud DEBUG=false python -m unittest discover -s tests -t . -q` | 455 tests, OK, 15.742 s; wall 18.20 s; CPU user 17.24 s, system 0.51 s; peak RSS 125,700 KB |
| Frontend contracts | `node tests/frontend_contracts.cjs` | passed |
| Wall-clock soak | `LLM_ROUTING=cloud DEBUG=false python integration/endurance_soak.py --seconds 60 --tick 0.5 --lease 3` | 60.002 s wall, 113 ticks, 10 steps (5 before crash, 5 after), 1 recovery, 10 provider calls, 10 dispatches, 0 duplicates, 0 denials, 0 window violations; completed; CPU 2.489 s; peak RSS 97,840 KB; safe=true |

The complete offline suite grew from 438 tests (SPEC-14) to 455: 16 new
endurance tests plus the retry-streak unit test.

Integration runs require `ARIA_INTEGRATION=1`, a `DATABASE_URL` whose database
name ends in `_test`, and run `alembic upgrade head` first. The new test module
restores the integration environment after importing the offline harness,
because the `tests` package intentionally replaces process secrets and
`DATABASE_URL`.

## Accelerated versus wall-clock evidence

The five-workday and multi-crash simulations advance a simulated clock; they
prove workflow logic, durable transitions, lease handling and safety checks,
not real-time stability. The PostgreSQL suite is accelerated for scheduling but
real for transactions, leases and accounting. The 60-second soak is genuinely
wall-clock, but it compresses step cadence and uses one crash and an in-memory
store. None of these establishes eight-hour provider, network, worker,
database or host reliability. A real eight-hour soak against disposable
infrastructure remains future validation work.

## Remaining production risks

These are known risks, not endurance blockers under the synthetic acceptance
criteria.

1. **No eight-hour wall-clock validation.** Provider latency/rate limits,
   network partitions, worker outages, disk growth and host memory pressure
   over a full day were not exercised. The soak is bounded at 60 seconds by
   default and 300 seconds maximum.
2. **Worker-resume 409 classification.** A `409 Worker cancellation is
   unresolved` from the worker-resume preflight is mapped to the retryable
   `authorization_unavailable` code, not the terminal `worker_blocked` code.
   The behavior is fail-closed, but an unresolved cancellation consumes retries
   and ends as `retry_exhausted`; it is not a distinct operator diagnosis.
   Confirmed during the audit and deliberately not changed because it is not a
   safety or durability defect.
3. **Crash-before-observation window.** Progress clears the retry streak only
   when the supervisor observes new successful steps. A crash in the interval
   between a durable step and the next supervisor tick still counts as a retry.
   Repeated crashes inside that window can exhaust `max_retries`.
4. **Synthetic cost and usage.** The provider is synthetic; reservations and
   reported usage exercise the ledger but not real provider billing, token
   estimation error or provider-side overruns. A provider that reports usage
   above its reservation is handled by the existing fail-closed path but was
   not exercised against a real provider.
5. **Progress-based retry reset is intentionally unbounded in streaks.** A
   campaign that makes at least one step between crashes can reset its retry
   count indefinitely. Total steps, campaign budget and schedule windows still
   bound the work; operators should treat repeated crash/progress cycles as an
   infrastructure problem even though the campaign continues.
6. **In-memory harness parity.** The offline harness mirrors the campaign store
   API. PostgreSQL tests cover the durable store, lease, accounting, guard,
   worker resume and health paths, but a production-only store behavior not
   represented in either harness remains possible.
7. **Single-process assumptions.** The supervisor and process-local
   investigation state assume one API worker (`--workers 1`), as documented in
   SPEC-14. Multi-worker deployment was not validated.
8. **Operational retention.** The event ring retains only the latest 50
   events per campaign; older events exist only in the immutable decision log.
   There is no historical metrics rollup or log-retention job in this scope.

## Scope control

No new agents, tools, targets, execution paths or specifications were added.
SPEC-15 is complete; no later specification was started.
