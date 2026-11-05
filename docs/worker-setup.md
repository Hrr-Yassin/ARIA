# Isolated worker setup

The `worker/` service implements ARIA's jobs-v1 protocol. It runs separately from
ARIA and uses its own PostgreSQL database and a local Docker or rootless Podman
engine. The initial supported tools are **curl and Nmap TCP scans**. Other tools,
Nmap raw/ICMP scans and NSE scripts are rejected; there is no host-shell fallback.
No new Python dependencies are needed beyond the locked core environment.

## What the worker enforces

- Each accepted job gets one named container with a private PID/network namespace,
  read-only root, no host mounts, one CPU, 256 MiB memory, 64 processes, bounded
  rotating logs and 32 MiB temporary space. The image must be a preinstalled,
  immutable local `sha256:` image ID. Jobs cannot select images or runtime flags.
- The trusted entrypoint installs an nftables default-deny firewall before starting
  a tool; firewall bootstrap is itself deadline-bounded (at most five seconds).
  Only TCP to the job's validated destination IPs and approved ports is
  allowed. Input accepts established replies; forwarding, other protocols and
  unlisted destinations/ports are blocked. Failure to install rules exits without
  running the submitted tool.
- Both the API's engagement scope and the worker operator's IP-network/port ceiling
  must permit a target. Optional engagement `ports` further narrows the ceiling.
  Exclusions are checked after resolution, including aliases. Domains resolve once
  on the worker host, all answers must fit the ceiling, and the resulting IPs are
  pinned through `/etc/hosts`. DNS inside the job is blocked. Curl redirects are
  disallowed by the shared command policy; the firewall independently limits tools.
- Bootstrap has only NET_ADMIN, SETPCAP, SETUID and SETGID. Before running any tool,
  `setpriv` changes to UID/GID 65534, clears all capabilities and sets no-new-privs.
  Submitted commands use argument arrays; no host or container shell interprets them.
- PostgreSQL commits the unique job ID, complete request fingerprint and deadline
  before container creation. Repeated identical submissions return the existing
  record; changed command, scope, session or timeout under that ID returns 409.
  Records survive restarts and must not be deleted while retries remain possible.
- Cancellation first commits intent, then kills/removes the job container and
  verifies its absence. Only this confirmation returns `cancelled, terminated:true`.
  Daemon uncertainty leaves `cancel_requested` and remains retryable. Cancellation
  before submission creates a tombstone that blocks a delayed job request.
- Startup/shutdown cancel and reconcile unfinished jobs without resubmission. An
  advisory lock and a private local file lock permit only one controller. A supervisor
  inside every container enforces the absolute deadline even if the worker API dies.
  Restarting the worker cancels remaining jobs rather than resuming investigations.

## Provision and run

Use a dedicated Linux worker account/VM and keep the engine local. Docker daemon
access is powerful; do not give jobs its socket. Rootless Podman is selectable with
`WORKER_RUNTIME=podman`. Use a bridge network that can reach only the intended lab;
network names `host`, `none`, and container-sharing modes are rejected. Keep the
runtime's standard seccomp and AppArmor/SELinux confinement enabled.

From the repository root, build the image with the chosen engine:

```bash
docker build -f worker/Dockerfile -t aria-worker:local .
docker image inspect --format '{{.Id}}' aria-worker:local
```

Review/scan the image and record the printed ID as `WORKER_IMAGE`. Base image and
APT repositories are mutable build inputs; the Dockerfile is not a reproducible OS
lock. `.dockerignore` restricts the build context to the required source files.

Create a **separate empty worker database**, owned by the worker account. Apply
`worker/schema.sql` with `psql -v ON_ERROR_STOP=1 -d <worker-database> -f worker/schema.sql`.
This is worker schema revision 1, independent of ARIA's Alembic migrations. Startup
checks the revision and never silently creates/updates tables. Back up this ledger;
restoring an old ledger can lose idempotency tombstones. Use direct PostgreSQL or
session pooling, not transaction-mode PgBouncer: ownership uses a session lock.
Use one dedicated account and the same private `WORKER_STATE_DIR` for this engine;
do not share the worker ledger across different runtime hosts. The local file lock
prevents another controller starting while an old process survives a lost DB lease.

Supply these variables through a protected environment file or service manager:

| Variable | Value |
| --- | --- |
| `KALI_AGENT_TOKEN` | Same random token as ARIA, at least 32 characters |
| `WORKER_DATABASE_URL` | `postgresql+asyncpg://<user>:<password>@<host>/<worker-database>` |
| `WORKER_IMAGE` | Reviewed local image ID, `sha256:<64 hex characters>` |
| `WORKER_RUNTIME` | `docker` (default) or `podman` |
| `WORKER_STATE_DIR` | Private local state directory; default `~/.local/state/aria-worker` |
| `WORKER_NETWORK` | Local bridge network name; Docker default is `bridge` |
| `WORKER_ALLOWED_NETWORKS` | JSON list of approved IPs/CIDRs, e.g. `["192.0.2.10/32"]` |
| `WORKER_ALLOWED_PORTS` | JSON list of approved TCP ports, e.g. `[80,443]` |

Documentation addresses above are examples; replace them with your authorized lab.
Empty network/port ceilings and default routes are rejected. Do not put secrets in
Git, shell history, image layers or job environment variables.

```bash
.venv/bin/python -m uvicorn worker.app:app --host 127.0.0.1 --port 7001 \
  --workers 1 --limit-concurrency 16 --timeout-keep-alive 5
```

In ARIA set `KALI_WORKER_PROTOCOL=jobs-v1`, `KALI_AGENT_URL` to this service and the
same token. Both processes need their protected environments loaded; the worker
itself does not load ARIA's `.env`. Use TLS plus network access controls between
hosts; direct HTTP is appropriate only on loopback or an explicitly isolated lab.
Restart after changing the worker ceiling/image. Do not expose the engine API.

## Validation

Offline checks:

```bash
.venv/bin/python -m unittest tests.test_worker_server tests.test_p1_workers tests.test_execution -v
```

Real lab checks (Docker; substitute `podman` for both commands when appropriate):

```bash
docker build -f worker/Dockerfile -t aria-worker:test .
export WORKER_TEST_IMAGE="$(docker image inspect --format '{{.Id}}' aria-worker:test)"
ARIA_WORKER_INTEGRATION=1 WORKER_TEST_RUNTIME=docker \
  .venv/bin/python -m unittest integration.test_worker -v
```

The opt-in suite creates a uniquely named internal network, two harmless HTTP
servers and a disposable PostgreSQL 16.6 database. It removes only its own containers,
volumes and network. It never contacts the existing VMs or application database.
It checks actual HTTP/Nmap jobs, kernel IP/port blocking, DNS pins, privilege drop,
read-only files, duplicate delivery across controller/database reconnection,
termination of containers containing detached descendants, restart reconciliation,
independent deadlines and single-controller ownership. CI includes a separate
Docker job; a local pass does not establish its GitHub Actions result.

## Limits

This is an initial worker implementation, not production certification. Containers
share the host kernel; use a dedicated disposable VM for hostile targets. Keep the
kernel, runtime and image patched. Raw scans, UDP, NSE scripts, reverse callbacks,
other tools and distributed controllers need separate reviewed profiles. The
firewall permits approved TCP ports only; unsupported scan flags cannot bypass it.
A container runtime or host-kernel compromise is outside this boundary.

The ledger and container logs may contain sensitive command arguments/output.
Protect database storage, engine storage and backups. Output is truncated to 100,000
stdout and 10,000 stderr characters. Finished container logs are removed; final
bounded receipts remain in PostgreSQL. Durable records have no automatic retention
policy: removing job IDs weakens replay protection. At most four unfinished jobs
are admitted per worker; unresolved cancellations retain their slots. DNS resolution
and container operations are serialized with admission, so cancellation may wait
for a bounded in-progress runtime operation. Full investigation recovery, provider
consent, browser hardening and audit linkage remain separate work.

Validation results are recorded in `docs/worker-validation.md` after execution.
