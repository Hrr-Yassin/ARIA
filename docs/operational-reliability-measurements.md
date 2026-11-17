# Operational measurement contracts

This inventory belongs to P06-01. It distinguishes a measured controller interval,
a deterministic boundary test, a synthetic workload and a deployed observation.
None is a substitute for another. The current controller changes are local;
the owner service was observed on build `84815990efa5b6f8` at
2026-11-15T14:45:55UTC. No reload or worker deployment accompanied this iteration.

## Thirteen layers and their evidence

| Layer | Boundary and correlation | Evidence | Remaining limit |
| --- | --- | --- | --- |
| API handling | Server monotonic handler entry to response headers, generated request ID | `api/main.py`, `tests/test_request_observability.py`; visible HTTP header samples | Excludes body consumption, network and rendering; middleware/request intervals overlap |
| Mission state | Run load, owner-only task ledger load, pure projection, separately | `api/routers/pentest.py`, request-observability tests and visible dashboard fixture | Denied owner-only ledger load is unavailable; different routes/workloads cannot establish an improvement |
| Model request | Request construction, observed HTTP attempt, response processing, client total and pool invocation; logical request/attempt IDs | Four clients, `llm/request_metrics.py`, provider fault fixtures and SQL model-attempt ledger | HTTP elapsed includes transport and provider work; isolated inference and unreturned provider charges unavailable |
| Authorization | Proposal and synthetic owner-decision calls, including SQL | Twelve-operation benchmark; scope/expiry/one-use/isolation suites | These are encompassing fixture calls, not isolated policy/cryptographic CPU or actual human deliberation |
| Human approval | Monotonic gate pending, polling, accepted decision and release intervals | `ApprovalRequest`, `_wait_for_approval`, continuity/expiry tests | No decision duration for expiry/stop; unknown or invalid proposal deadline blocks. Timers never renew authority |
| Worker communication | Controller HTTP stream entry through body read and response closure; JSON decode separate; client total includes setup/cleanup | `WorkerClient.request`, `tests/test_transport_observability.py`; job/session and controller-generated worker request IDs | Includes worker-side work; not isolated wire latency. Decoded HTTP response is not a validated receipt or successful job. No new deployed-worker timing claim |
| Queue waiting | Pool/owner lock wait separate from context construction; worker-local mutex wait/held intervals | Controlled-clock boundary tests and actual local worker fixture records | No comparable contention p95; owner/Kali latency and event queue residence unavailable |
| Container lifecycle | Real local create/start/inspect/output/stop call intervals | Existing internal-only WorkerLab with rootless Podman; two real job containers per cohort | CLI/backend overhead included. Separate hardware from Kali; not inferred tool duration |
| Tool execution | Validated curl/Nmap subprocess wall span and OS waited-child user/system CPU inside the unprivileged fixture container | `integration/reliability_tool_timing.py`, positive HTTP/port controls and zero exits | n=1 per tool, no p95. Wall span includes process creation/output collection; not owner/Kali/provider performance |
| Result processing | Generic JSON parser versus strict review validation, preparation and projection | Provider/review fixtures; worker JSON decode measured locally | Parser success does not validate task/review/worker identity or authority; heterogeneous samples stay separate |
| Database persistence | SQL statement counts, serialized statement bytes and statement wall intervals; review projection duration | Disposable SQL workload and journal/recovery suites | Statement and encompassing call durations overlap; pool/transaction/network work is not isolated server CPU |
| WebSocket delivery | Server serialization/ASGI send and flow control after live access recheck; per-connection stream ID plus session/run/sequence | Router tests and real isolated Uvicorn/graphical Chromium passive stream: four ordered events with matching browser identities | Correlation verifies receipt/order, not end-to-end latency or pixels. Queue residence unavailable; fan-out sends can share an event identity |
| Browser rendering | Browser-clock DOM update and two-animation-frame opportunity; bounded HTTP header measures | Real sandboxed graphical Chromium fixture and `app.js`/`dashboard.js` performance entries | Frame opportunity is not proof of physical display presentation. No server/browser wall-clock subtraction |

## Local transport diagnostics

`worker_http_exchange` logs only a generated `worker_request_id`, closed operation
label, trusted job/session references when available, HTTP status, outcome and
three local monotonic durations. It never logs URL/path/query, command, scope,
payload, token, response text or exception detail. A capabilities request has no
job/session binding; its references remain unavailable. `response_decoded` means
only that the bounded HTTP body decoded. Existing capability, identity, exit-status,
attestation and durable authorization checks still run independently afterward.
Failures/cancellation retain a measured attempted HTTP interval and an unavailable
decode interval if decoding never started. No retry is added.

`autonomous_websocket_send` logs stream/session/run/event references, closed
outcome and `websocket_asgi_send_ms`. It changes neither the event payload nor
sequence/persistence. Revocation before send produces neither delivery nor a
send measurement. Disconnect/cancellation preserve their original control flow.
No transport observation grants approval or enters the receipt/evidence ledger.

The retained `resume-cycle11/controller-transport-fixtures.jsonl` contains six
local-monotonic MockTransport samples, each a different success/fault case, and
four controlled-clock boundary records. Controlled values prove boundaries and
are not real latency samples. The boundary fixture inserts 3ms setup, 5ms HTTP
entry, 7ms body read, 11ms response close, 13ms decode and 17ms client cleanup:
only the middle HTTP stages enter the 23ms exchange; decode is 13ms and total is
56ms. These injected values must never be reported as deployed performance.

## Statistics, thresholds and limits

`integration/reliability_visible.py --visible --stream` additionally exercises the
ordinary authenticated socket through real graphical login/session selection on
a newly created database, with worker disabled and zero-call inference budget.
`integration/reliability_stream.py` emits four labelled passive fixture events;
it starts no engine loop, command proposal, model call or worker job. The last
event is truthfully blocked: discovery has not executed. A negative guard test
denies missing fixture marker, non-reliability databases and enabled workers.

Final run `visible-9e33a7a3c5ec` passed five checks, with zero page errors and
unchanged app, fixture and adapter source hashes. Its server ASGI sends measured
0.268526/0.270263/0.293474/0.221285ms. Four matching browser events retain their
own observer microtask and two-frame opportunity durations. A microtask does not
prove all application event listeners have completed. The first experimental run
used the misleading field name after_listeners_ms; retained unchanged, then
corrected to observer_microtask_ms and revalidated. No server/browser subtraction,
p95 from four samples, presentation proof or causal speedup is claimed. Earlier
source manifests covered app/web bytes; the final harness also checks integration,
worker and adapter sources. Owner deployment remains unchanged.

Cycle12 adds `worker/observability.py`: worker-local mutex waiting and held
intervals, plus runtime create/start/inspect/output/stop calls. It uses the
standard Uvicorn error logger with closed JSON fields and no new dependency.
There is no receipt/ledger field or admission/policy change. Failed diagnostic
sinks cannot interrupt cleanup or change authorization; missing diagnostics
remain unavailable. Runtime outcome `returned` does not assert successful tool
execution or acknowledged termination. Five runtime-stage and three admission
records are retained from an in-memory runtime fixture, with real local
monotonic clocks; no container/tool ran. Controlled clock tests prove boundaries,
including cancellation while waiting without releasing another task's lock.
The worker change is local only. Independent Kali deployment approval and actual
runtime observations remain prerequisites to any deployed timing claim.

Cycle13 ran the existing real HTTP/Nmap/idempotency fixture on its own internal
network, database and two harmless HTTP servers. The case passed in36.441165s;
34closed timing records cover two successful bounded job containers and admission.
Create/start/output/stop each have n=2; inspect has n=10. Means/medians/maxima are
descriptive within each stage; all five p95 values remain unavailable. The suite
cleaned up only its own resources; the independent4h database remained running.

A separate trusted fixture observer calls the ordinary policy planner first and
wraps only its validated argv. It runs under the unchanged container supervisor,
firewall, UID/capability drop and deadline. No production adapter is widened.
This case passed in35.107882s and retained32runtime records plus two measured
subprocess samples: curl wall12.584411ms, child user6.074ms/system4.992ms;
Nmap wall59.362857ms, child user50.393ms/system7.872ms. These clocks are read
inside the unprivileged container, never subtracted from host/browser clocks.
The two cohorts differ by observer overhead and are not pooled for speed claims.
All targets are newly created internal fixtures; no Kali,192.168.77.20,owner DB
or provider was used. Source observations were captured after testing and are
unsigned; they are not immutable loaded-source attestations. The cached runtime
image is separately pinned by its full SHA-256 identity.

Raw twelve-operation and endurance records retain per-operation identity,
failures, retries, conservative model reservations, CPU, RSS, database connections
and readiness. Summaries use mean, median and maximum within a named cohort.
Nearest-rank p95 is available only for at least twenty comparable samples;
missing stages and inadequate-sample p95 are null/blank, never zero. The six
heterogeneous HTTP fault cases do not form a performance cohort. A measured
zero is retained as zero. No latency speedup or cost saving is claimed.

Existing correctness gates require zero lost/duplicate/unauthorized dispatch.
The endurance harness retains its existing 10s readiness deadline and stops below
512MiB memory or disk headroom. Configured provider/worker timeouts remain final.
A future warning at twice the 30m baseline batch p95 for identical workload and
hardware is a proposal to investigate regression, not a retrospective acceptance
threshold. Source changes, machine load, process age and clock domains accompany
each sample; no causal comparison is justified without controlling them.

Actual 15m, 30m and 1h cohorts retain separate loaded-source manifests. The
original 2h process completed7200.000980s with240batches/2880operations and
1437readiness samples,zero failures. Later edits were not loaded by that process.
The4h cohort is now active on its own limited PostgreSQL16.6 container because the
owner database was stopped; no owner service was restarted. This different
resource context prevents a causal performance comparison. 8h remains NOT_TESTED.

P06 acceptance is the unchanged engineering criterion: unavailable layers must
be explicit, thresholds justified and workloads comparable. Its audit checks
all thirteen inventory entries, raw correlations, finite nonnegative durations,
separate cohorts/clocks, guarded p95 and the existing deadline/resource thresholds.
Unknown isolated wire latency, physical presentation, owner/provider performance
and billing remain explicitly unavailable. No numerical performance target was
added. This establishes the engineering baseline; live owner acceptance and
progressive endurance remain separate mandatory requirements. Optional Kali
telemetry deployment still requires the pending explicit owner authorization.
