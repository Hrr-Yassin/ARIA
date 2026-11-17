# Fedora dependency outage and restart investigation

The November15/16 outage was a host shutdown/reboot followed by missing dependency
startup. It was not a PostgreSQL/Redis crash or an observed authorization bypass.
Filtered read-only evidence is retained privately in
`.local-lab/operational-reliability/resume-cycle14/outage-investigation.json`.

- November15 at21:48:55UTC: PostgreSQL received a fast shutdown request and Redis
  received SIGTERM during the user manager's shutdown transaction. Both exited0;
  neither was OOM-killed. Their attempted container restarts failed while the
  user manager was exiting. A new boot started at21:49:27UTC.
- The effective checkout override intentionally cleared `ExecStartPre` and used
  `KillMode=process` to preserve Podman helpers when restarting the API. The manual
  instructions required starting dependencies separately. No dependency unit was
  configured to do so after login/reboot. Container `unless-stopped` policy alone
  did not start them at the next boot.
- Uvicorn failed in `init_db()` with connection refused. `RestartSec=5` and the
  effective10-second rate-limit window allowed an indefinite loop: each startup
  took enough time that five attempts never fell within that window. The recorded
  214th restart occurred at2026-11-15T22:17:59.837244UTC in boot `dada127f…`.
  The counter reached253 before the previously documented recovery. Counters from
  later boots are separate observations, not the same214 restarts.
- November16 at06:45:47UTC: another host/user-manager shutdown cleanly stopped
  the owner containers and the disposable endurance PostgreSQL. The endurance
  child recorded cancellation in that same second. Its `operator_cancelled`
  reason labels the received signal; it does not prove a human explicitly
  cancelled the test. Its3383.178759 monotonic seconds do not verify4h. Wall-clock
  time was28266.733043 seconds greater than monotonic elapsed time; suspended time
  or wall-clock changes cannot count as executed endurance.

One application defect was reproduced from the shutdown traceback: failure in
worker reconciliation skipped `drain_cleanup()` and connection closure. Shutdown
now attempts all cleanup stages, logs only their closed stage/error type, and
still fails explicitly when required reconciliation or cleanup fails. Cancellation
is preserved. This never confirms uncertain worker termination or replays work.
Before-fix evidence:3tests,1failure/2missing-helper errors, including the actual
lifespan failure. After correction:50existing/new lifecycle checks passed;
expanded55checks passed. Full offline767tests/37.940s passed. Later final lab
service contract/readiness checks passed8tests/0.315s separately.

The corrected Fedora templates put the existing containers and bounded read-only
schema/Redis readiness probe in `aria-lab-dependencies.service`. The API requires
and starts after that separate remaining-active unit, so API restart does not
kill dependency helpers. Both service templates bound failed startup attempts to
five per300seconds and retain one API worker, loopback binding and private umask.
No container, image, volume, scope, schema or credential is recreated. Installation
and actual restart evidence must be recorded separately from template/unit tests.

These corrections support recovery and observability. They do not demonstrate
eight-hour operation, paid-provider reliability, actual laboratory completion, or
the8hours/day,5days/week operational goal. A host shutdown interrupts a cohort;
it cannot be silently stitched into a continuous successful endurance result.
