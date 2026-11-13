# SPEC-14 — Operational Observability & Reliability

Status: implemented and validated on 2026-11-12. Scope stops at SPEC-14.

## Purpose

Make durable autonomous campaigns observable, diagnosable, and fail-closed for an
8-hour/day, 5-day/week workload without adding execution authority to monitoring.

## Design

### Durable campaign health

`memory/campaign_observability.py` builds `aria.campaign.health.v1` from the
campaign row and bounded, read-only summaries. A health view contains:

- state, terminal flag, goal, target, generation time;
- progress: steps taken/successful/remaining, model calls, current phase,
  waiting approval, last successful action with correlation ID;
- heartbeat: age, stale flag/threshold, lease holder/expiry;
- runtime, budget (reserved/reported/stop reason), schedule and next execution;
- pause reason, failures/retry count, pending worker and specialist work;
- accounting consistency issues and unknown-usage counters;
- retained operational events, bounded alerts, and the sanitized run/checkpoint;
- explicit limitations.

The view never executes work and never grants authorization. Provider failures
degrade to fixed alerts (`worker_unavailable`, `model_usage_invalid`, etc.) rather
than breaking the endpoint.

### Bounded operational events

Campaign rows carry a durable ring (`operations` JSON, schema
`aria.campaign.operations.v1`) capped at 50 events. Events have a closed
vocabulary, allowlisted attributes, monotonic sequence, dedupe support, bounded
message lengths and correlation IDs. Invalid rings are reset to a valid empty
ring (`operations_invalid` alert). The immutable `DecisionLog` remains the audit
source of truth; the ring is the bounded operational view and is never used for
authorization.

Correlation IDs are generated per HTTP request (`X-Request-ID` middleware), per
supervisor tick, and per recovery pass; `campaign_store` records the current
scope on each event.

### Fail-closed accounting

`memory/campaign_store.py` now tracks reserved and reported tokens/cost, unknown
usage/cost counters, and a closed `stop_reason` vocabulary (`""`,
`provider_overrun`, `unknown_usage`, `accounting_inconsistent`).
`llm/engagement_budget.py` settles physical calls into both the session ledger
and the campaign ledger under row locks:

- malformed ledgers, or reported usage above its reservation, deny further calls;
- a successful call without reported token usage stops the campaign with
  `unknown_usage`;
- accounting inconsistency maps to HTTP 409; budget exhaustion maps to HTTP 429;
- reservations are never refunded.

The supervisor checks accounting before acting, terminalizes unsafe campaigns
with `campaign_accounting_inconsistent`, and records the corresponding bounded
operations.

### Monitoring endpoints

- `GET /api/pentest/{session_id}/campaign/health`
- `GET /api/pentest/{session_id}/campaign/events?after=<sequence>&limit=<1..50>`

Both use the existing owner/session authorization boundary. Admins who are not
the session owner receive 403; missing campaigns return 404. Events are returned
after a sequence cursor with a hard limit of 50.

### Thresholds

| Setting | Default | Range |
| --- | --- | --- |
| `CAMPAIGN_HEARTBEAT_STALE_SECONDS` | 120 | 15–3600 |
| `CAMPAIGN_PROGRESS_STALE_SECONDS` | 1800 | 60–86400 |

Repeated retries are reported at two attempts; a running campaign with an
approval pending is not considered stalled.

## Migration

`migrations/versions/0005_campaign_operations.py` adds the non-null `operations`
JSON column with a canonical empty-ring server default. `database_models.init_db`
expects revision `0005`. Existing rows adopt the empty ring. Downgrade drops the
column; normal migration-adoption rules apply to populated legacy databases.

## Validation

Executed against synthetic fixtures, mocked providers/workers, and the disposable
`aria_test` PostgreSQL database. No external scans, real model calls, or worker
submissions were made.

| Check | Command | Result |
| --- | --- | --- |
| Focused offline observability | `python -m unittest tests.test_campaign_observability -q` | 26 tests, OK |
| New PostgreSQL integration | `python -m unittest integration.test_observability_postgres -v` | 5 tests, OK |
| All PostgreSQL campaign/checkpoint/knowledge/specialist/observability suites | `python -m unittest integration.test_campaign_postgres integration.test_campaign_execution_postgres integration.test_checkpoint_postgres integration.test_knowledge_store_postgres integration.test_specialist_postgres integration.test_observability_postgres -q` | 39 tests, OK |
| Frontend contracts | `node tests/frontend_contracts.cjs` | passed |
| Complete offline suite | `LLM_ROUTING=cloud DEBUG=false python -m unittest discover -s tests -t . -q` | 438 tests, OK |

Integration runs require `ARIA_INTEGRATION=1`, `DATABASE_URL` pointing at a
disposable database ending in `_test`, and run `alembic upgrade head` first.

## Operational limitations

- Monitoring is read-only and never grants execution or model calls.
- The event ring retains only the latest 50 events per campaign; older events
  remain only in the immutable decision log.
- Health alerts are capped at 12, one per code, ordered by severity.
- Worker and specialist summaries are bounded counts, not evidence; at most 20
  specialist task IDs are reflected per view.
- Reported cost is based on owner-entered conservative reservations, not actual
  provider billing; unknown usage is charged at its full reservation.
- A failed call with unknown usage increments counters but does not stop the
  campaign; a successful call with unknown usage does stop it.
- There is no historical metrics rollup, external metrics exporter, or log
  retention job in this specification. Views describe current durable state.
- Staleness thresholds depend on the single-worker supervisor deployment
  (`--workers 1`); multiple API workers would make process-local investigation
  state and heartbeats unreliable.
- The supervisor terminalizes inconsistent campaigns only on its next tick;
  between the inconsistency occurring and the tick, model reservations are
  already denied by the ledger checks.

## Scope control

SPEC-15 was not started.
