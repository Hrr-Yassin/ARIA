# ARIA worker job contract

The `worker/` service implements the server separately from the ARIA process.
`memory/worker_jobs.py` implements the API-side client, persistent job records,
admission fencing and recovery. See [worker-setup.md](worker-setup.md) for its
restricted curl/Nmap profile and [worker-validation.md](worker-validation.md) for
executed checks and limitations.

## Default: `KALI_WORKER_PROTOCOL=jobs-v1`

Use an HTTPS `KALI_AGENT_URL` outside an explicitly isolated development network.
Every request sends `Authorization: Bearer <KALI_AGENT_TOKEN>`. Tokens never appear
in URLs or JSON bodies. Redirects are not followed. Responses are read with a
1,000,000-byte streaming limit, then validated.

| Method / path | Request | Required response |
| --- | --- | --- |
| `GET /capabilities` | Bearer authentication | `protocol: "aria-jobs-v1"`, `idempotency: true`, `cancellation: true`, `network_scope: true` |
| `POST /jobs` | `job_id`, `session_id`, canonical `command`, bounded `timeout`, authoritative `scope` | Snapshot with the same IDs |
| `GET /jobs/{job_id}` | Bearer authentication | Snapshot with the same IDs |
| `POST /jobs/{job_id}/cancel` | `session_id` and Bearer authentication | Snapshot; confirmed cancellation requires `state: "cancelled"` and `terminated: true` |

Snapshot states accepted from the worker are `queued`, `running`,
`cancel_requested`, `cancelled`, `succeeded`, and `failed`. Successful/failed
snapshots require an integer `exit_code` consistent with the state. Optional
`stdout` and `stderr` are bounded. A mismatched job/session ID, malformed response,
missing capability (including worker network scope), redirect or HTTP failure
does not authorize a retry.

The worker must persist idempotency keys across its own restarts, reject different
commands under an existing job ID, enforce timeouts, and terminate the full
process group before issuing a termination receipt. It must enforce the target
network boundary independently. A capability declaration is a contract, not proof
that the external implementation satisfies it.

## API-side safety and recovery

- Authorization is consumed before contacting the worker. A separate `worker_job`
  ledger row records job identity/state in PostgreSQL's existing `decision_logs`
  table. Complete stdout is not stored in that ledger; output hashes bind result
  ingestion to a completed job receipt.
- Job admission locks the engagement row and enforces at most five nonterminal
  jobs. Unknown/cancelling jobs prevent new admission. Stop/kill fences the
  engagement and increments a durable worker epoch, invalidating old approvals.
- The API records all cancellation intents before waiting for remote I/O.
  Cancellation cleanup survives cancellation of the requesting coroutine.
- Only an acknowledgement of termination produces `cancelled`. An unreachable
  worker, ambiguous submission, absent job or unsupported cancellation leaves an
  unresolved state, generally `unknown`; it does not mean the process was killed.
- At API startup, recovery reconciles/cancels nonterminal records. It never replays
  a submission. Shutdown also requests cleanup. Autonomous planning loops do not
  resume automatically.
- Explicit user proposal/start/execute actions can resume a fenced engagement
  after its jobs have reached terminal states. Agents cannot clear the fence.
  Pre-stop approvals remain invalid after resumption.
- `GET /api/jobs/{session_id}/{job_id}` and `GET /api/running/{session_id}` expose
  authorized durable status. Session archival is denied while cancellation is
  unresolved. Logout, password reset, role changes and deactivation revoke tokens
  and request job cleanup; an unavailable worker remains visible as pending.

PostgreSQL locking/concurrency semantics have unit coverage with mocked storage,
not a live PostgreSQL stress test. Worker isolation, DNS pinning, idempotency and
termination have a separate
opt-in container integration suite; its current results are recorded in
[worker-validation.md](worker-validation.md).

## Explicit compatibility mode

`KALI_WORKER_PROTOCOL=legacy-execute` retains the old synchronous `/execute`
transport using the shared Bearer header. There is no automatic downgrade from
jobs-v1. Legacy responses require an integer exit code and still receive a durable
API job ID and receipt hashes.

Legacy workers have no acknowledged cancellation contract. If the request times
out or disconnects, ARIA cannot assert termination; the engagement remains blocked
until the outcome is independently resolved. Use jobs-v1 for cancellation/recovery
evaluation. Never report a cancelled HTTP request as a killed remote process.

Jobs-v1 workers predating `network_scope: true` must be upgraded; the client fails
closed instead of silently accepting a worker without that capability. The built-in
worker requires UUID job/session IDs, a 16 KiB request maximum and a timeout of
1..300 seconds. Legacy compatibility does not provide these new isolation guarantees.


## Optional Phase 3 authenticated HTTP extension

A configured `HTTP_REPLAY_KEY` enables capability `authenticated_http_version: 1`.
The API and worker must use the same dedicated Fernet-format key. This capability
uses `aria-http <identity-id> <capture-or-request-id> <request-digest> <GET|HEAD> <url>`
commands and an additional encrypted `protected_http` field in `POST /jobs`.
The command/digest, current identity, scope and one-use approval are revalidated;
there is no legacy-execute or custom-executor fallback.

The profile accepts bodyless GET/HEAD without query strings, userinfo, fragments,
redirects or retries. Only registered authentication headers are sent. Its maximum
timeout is ten seconds and its response bound is 32 KiB. Mapping-enabled scopes
share a 1–20 admission budget, concurrency one and one-second admission spacing.
Reviewed program snapshots do not authorize this profile.

Worker snapshots carry encrypted private HTTP evidence. The API validates and
stores that encrypted payload, but emits only status/digest metadata to ordinary
chat/tool/model paths. This is an exception to ordinary hash-only result storage;
plaintext originals are never placed in the job ledger.

`POST /jobs/{job_id}/retention` takes `session_id` and an aware ISO `expires_at`.
It can only shorten the existing private-evidence deadline, cancels an expired
running job, and erases terminal encrypted payloads while retaining identity/state
history. Both services also perform periodic expiry cleanup. A disconnected worker
leaves synchronization pending; no immediate remote deletion is claimed.

See [Phase 3 acceptance](phase3-mapping-status.md) for setup, private snapshot
format limits, API workflow and executed two-account/browser controls.


## Optional Phase 4 specialist HTTP extension

The Phase 3 extension retains bodyless GET/HEAD without queries. Separately,
`HTTP_SPECIALIST_PROFILES_ENABLED=true` on a configured updated worker advertises
exact integer `specialist_http_version: 1`; its default is 0. It requires a reviewed
matching container image, jobs-v1, the shared replay key, explicit lab flags
`web_authenticated_replay` and `web_specialist_profiles`, and one-use red-risk
approval. No running worker or engagement was enabled by this source update.

The same encrypted transport/digest additionally binds one canonical integer GET
query or one bounded scalar JSON PUT body, controlled object, invariant and human
attestations. The worker rejects unsupported shapes before container creation.
The API rechecks active controlled ownership, exact resource evidence, scope and
exact capabilities before dispatch. Existing independent network/port ceilings,
budgets, overload stops, timeout, private evidence and cancellation remain in force.
There are no arbitrary methods, shell, bodies, redirect following or retries.
See [Phase 4 status](phase4-investigations-status.md) for exact bounds, owner API
fields and offline validation; live acceptance of the new profiles is unperformed.
