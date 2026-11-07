# Worker validation — 2026-11-04

Historical validation checkpoint: counts and deployment statements below apply to
that recorded stage. See [the Phase 0 baseline](phase0-baseline.md) for the current
source inventory, schema head `0003`, and new validation results.

Implemented in `worker/`, with ARIA scope delivery in
`memory/execution_authorization.py` and `memory/worker_jobs.py`.
See [setup](worker-setup.md) and [protocol](worker-contract.md).
Changes remain local; no deployment, commit, push or GitHub Actions run is implied.

## Executed results

| Check | Result |
| --- | --- |
| Full offline Python suite | **92 tests passed** (`python -m unittest discover -s tests -t . -q`) |
| Real worker lab | **7 scenarios passed**, 74.021 seconds, including five consecutive kernel-boundary probes |
| Frontend contracts | Login/session/plan/approval/rejection/socket scenarios passed |
| New Python source syntax | All ten new Python files parsed successfully |
| Tracked diff whitespace | `git diff --check` passed |

The real lab used CPython 3.11, rootless Podman and PostgreSQL 16.6. The final
locally built and tested worker image is:

```text
sha256:68c1f53a44f2b169795dc9d7a80069b8030e8a5d1d56f31f2ca96ba97fe93a81
```

The opt-in suite created only a uniquely named internal bridge network, two
harmless HTTP servers and a disposable worker database. A positive control first
verified that both servers and both TCP ports were reachable before applying the
job firewall. No existing VM, application database, provider or external scan target
was used. The suite removes its own containers, anonymous volumes and network.

## What the real lab verifies

1. Actual curl HTTP and Nmap TCP jobs return successful bounded receipts. Identical
   simultaneous submissions share one job; the saved receipt survives controller
   recreation and PostgreSQL reconnection. A changed payload under an existing ID
   is rejected.
2. Five successive isolated probes reach the approved IP/port while blocking the
   reachable second server and an unapproved port on the approved server. The
   pinned hostname resolves correctly. Tools run as UID 65534 with zero effective
   capabilities and no-new-privileges, cannot write the root filesystem, and cannot
   open raw sockets.
3. Cancellation removes a real container containing a detached child process and
   returns a confirmed termination receipt. Recreating the controller cancels an
   unfinished job without replaying its submission.
4. The in-container supervisor ends a long-running process at its deadline even
   without controller polling. Runtime inspection confirms exit code 124 before
   the controller records cancellation/removal.
5. PostgreSQL ownership prevents a second controller. Terminating the owner's
   database connection causes subsequent dispatch to fail before container creation.
6. The actual worker application's startup/shutdown, environment validation, local
   controller lock, authentication and job endpoints run through ASGI with the real
   PostgreSQL ledger and real job containers.

Offline tests additionally cover absent/invalid authentication, bounded requests,
UUID/timeout validation, modified job IDs, cancellation before delayed submission,
storage outages, unresolved cancellation across recovery, same-session admission
blocking, scope exclusions, mixed DNS answers outside the ceiling, IPv6 policy
formatting, unsupported tools/shell syntax, runtime inspection failure, transient
container states and delivery of authoritative ARIA scope to the worker.

## Limits of these results

- The local runtime tested was rootless Podman. A separate Docker CI job was added;
  its GitHub Actions outcome and a local rootful Docker run are not verified here.
- Worker endpoint tests use ASGI transport. External TCP/TLS deployment and a full
  browser → ARIA approval → worker workflow were not exercised.
- Recovery tests recreate the controller and reconnect storage; they are not a
  comprehensive host power-loss, database restore, runtime-crash or long soak test.
  Network probes are bounded regression checks, not an exhaustive firewall audit.
- Live IPv6 networking, DNS infrastructure failures, resource-exhaustion benchmarks
  and hostile-kernel/container escape testing remain outside this validation.
- Only curl and Nmap TCP profiles are enabled. Arbitrary commands, NSE/raw/UDP
  scans, other Kali tools and distributed controllers are unsupported.
- The existing ARIA `.env`, running service and lab VM configuration were preserved.
  Activating the worker requires a separate database, protected token environment,
  approved network/port ceiling and runtime settings from the setup guide.

## Later manual lab activation

After the isolated integration checks, the worker and ARIA were activated against
the existing lab VMs at the user's request. [fedora-lab.md](fedora-lab.md) records
the local services, private configuration, exact target/port ceiling and successful
HTTP HEAD through the real ARIA authorization and worker path. This later action
updated the local `.env` and user services; the preservation statement above refers
to the earlier implementation-validation phase. No provider call or exploitation
was performed during activation.

## Browser and worker-profile follow-up

The updated worker profile and real UI workflows are recorded in
[browser-validation.md](browser-validation.md), including the current image ID,
99 offline regressions, seven real-container scenarios and browser screenshots.
