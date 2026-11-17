# Infrastructure reliability evidence

The original dependency outage and historical214controller restarts are explained
in [the outage investigation](operational-reliability-outage.md). The containers
stopped cleanly during host shutdown;missing boot dependency startup and an
ineffective restart-rate window caused the controller loop. Those observations
are separate from later boots and counters.

On 2026-11-17 the repaired dependency unit reached readiness at14:03:59.254UTC,
before API startup completed at14:04:02.817UTC. This was an actual host boot,
observed without inducing a reboot. Read-only SQL inspection found the same80worker
jobs and95model attempts,all terminal,with no active/uncertain work or observed
replay. The API still uses one process,loopback binding,contained service processes
and five failed starts per300seconds. Existing PostgreSQL/Redis containers,images,
volumes and authorization configuration are preserved.

Two additional runtime defects were reproduced and corrected:

- PostgreSQL restart left closed idle connections in the SQLAlchemy pool. The
  first subsequent statement failed with InterfaceError. Pool pre-ping now checks
  a connection before a new transaction;it never retries a statement or an
  uncertain transaction. An isolated real restart preserved exactly one committed
  marker and served the first checkout without API restart.
- Redis cache writes/invalidation could fail after a successful SQL commit,
  incorrectly returning failure to the caller. Cache operations now have bounded
  timeouts and fail independently from durable SQL outcomes. Failed invalidation
  changes the process cache generation;cached data from old generations or old
  API processes is ignored. Authoritative ownership/scope reads bypass cache I/O.
  Failed initial Redis clients close,and logs contain closed error types rather
  than connection strings. Cancellation and SQL errors still propagate.

`/api/ready` retains database/schema readiness and now separately reports optional
cache availability and degradation. A cache outage does not fabricate a database
outage. This does not guarantee every endpoint works through a Redis outage;
security controls such as shared login admission retain their existing failures
and must not silently weaken to preserve availability.

Validation cohorts remain distinct:

- Before correction:one actual PostgreSQL restart test failed in1.900seconds.
- After correction:two real disposable PostgreSQL/Redis failure/recovery tests
  passed in4.418seconds. The cache case preserved two SQL session commits and an
  update across Redis loss/restart. Owner dependency PIDs/start times did not
  change. Exact isolated runs are infrastructure-0a1c5898bdde(failure) and
  infrastructure-ebd7dfca1e7b(pass),retained privately.
- Current offline798tests passed in33.202seconds;42focused cache,lifecycle,
  authorization and isolation tests passed in1.971seconds. A new readiness test
  initially mocked a read-only SQLAlchemy instance method incorrectly;its two
  fixture errors and the failed full run are retained. The corrected fixture
  changes no production assertion or behavior.
- The later read-only observer has six focused classification tests;these are
  separate from the798-test cohort.

An actual API-only deployment restart3499→43988 loaded build46cd122b9f10328f.
PostgreSQL/Redis PIDs/start times and the80/95durable counts were unchanged.
Readiness reported database/cache available and degraded=false,NRestarts0.
Private source manifests,logs and deployment proof are in resume-cycle21.

The installed `aria-infrastructure-observer.timer` samples every30seconds. Its
oneshot service only reads local readiness,systemd properties and container
metadata. It never restarts a service,submits work or replays an action. A15-second
unit deadline,128MiB memory ceiling,10%CPU quota,private files and a maximum50recent
events bound resource use. It distinguishes required database/controller loss,
optional cache degradation,restart counters per boot and measured host-sleep gaps.
The current state is private at
`.local-lab/operational-reliability/supervision/current.json`.

Point observations cannot prove availability between samples or through sleep.
This monitor does not supply external notification,automatic failover,backup
restoration or an operational8/5 result. The deferred eight-hour test remains
DEFERRED_BY_OWNER. Further runtime changes require their own scoped validation.

To disable this observer,use
`systemctl --user disable --now aria-infrastructure-observer.timer`;its inactive
service performs no work. Existing application and dependency units are separate.
