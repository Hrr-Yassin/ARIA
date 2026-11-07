# P2 implementation and verification

Historical validation checkpoint: counts and deployment statements below apply to
that recorded stage. See [the Phase 0 baseline](phase0-baseline.md) for the current
source inventory, schema head `0003`, and new validation results.

Worker follow-up: an initial curl/Nmap container worker is now included. See
[worker setup](worker-setup.md) and [executed validation](worker-validation.md).
Worker-absence statements below describe the earlier remediation checkpoint.

This status supersedes the P2 baseline in [technical_revow.md](../technical_revow.md)
and the historical installation/migration notes in [security-review.md](security-review.md).
Existing P0/P1 changes were retained. No real worker execution, model call or
external security scan was performed during P2 validation.

## Findings disposition

| Finding | Current change / disposition |
| --- | --- |
| ENG-09 | Earlier work already fixed persistence, counters, retry and version-pattern generation. This pass rejects service substring matches, mismatched versions, missing versions and legacy wildcard patterns during planner selection. Suggestions remain untrusted historical evidence; exact version equality is not proof of vulnerability applicability. |
| ENG-10 | Claims narrowed as the review permits. Planner lookup exists; automatic success-path saving and the standalone ReAct helper remain outside the main workflow. No automatic learning, integrated ReAct traces or verified exploitation success is claimed. Modules are retained. |
| ENG-12 | Alembic baseline `0001` uses a frozen schema, independent of future ORM changes. Startup verifies the expected revision instead of creating tables. CI adds locked installation, existing offline/frontend checks, and disposable PostgreSQL/Redis integration tests. |
| ENG-13 | CPython 3.11 support is enforced; core direct/transitive dependencies have exact versions and SHA-256 hashes. Optional embeddings are excluded from the supported core environment. Setup uses only a local venv and refuses root. A loopback, single-process user-systemd example replaces the root-service installer. API metadata/liveness agree on v10; readiness checks the database/schema; request logs and responses carry generated request IDs. |
| ENG-15 | Loading/encoding runs in a single background inference slot with no waiting queue. Inference input is limited to 8,192 characters; async queries wait at most two seconds before keyword fallback. A timed-out/cancelled inference retains its slot until it actually finishes. Legacy synchronous queries use keywords; synchronous inserts can request best-effort background enrichment. Only an explicitly configured local model is loaded, with downloads disabled. |

## Reproducible core environment

Supported and locally checked: Linux x86_64, CPython 3.11. Other operating systems,
architectures and Python minor versions are not validated. The host default Python
3.14 is deliberately unsupported. `pyproject.toml`, `.python-version`, runtime and
setup checks agree on the supported series.

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip check
```

`bash setup.sh` performs these steps as an unprivileged user. It neither installs
OS packages nor copies secrets or changes services. Provision PostgreSQL, optional
Redis, protected `.env` and persistent signing/encryption/worker secrets separately.
The service template assumes the checkout is at `~/aria` and the venv and `.env`
exist there. Apply migrations before starting it. A user service requires an active
user manager; boot persistence/lingering is an operator decision.

To deliberately refresh the core lock, use a separate disposable tool venv with
Python 3.11, `pip==25.1.1` and `pip-tools==7.5.1`, then run:

```bash
pip-compile --generate-hashes --output-file=requirements.txt requirements.in
```

Review the resulting versions/hashes, install into a fresh environment and rerun
all checks. Normal setup consumes the checked-in lock and does not resolve updates.
The optional semantic stack/model is experimental and separately provisioned; it
is not covered by this lock or CI's dependency support claim. Keep a model revision,
artifact hashes and optional environment manifest for any semantic experiment.
No current dependency advisory audit or license grant is implied by locking versions.
The repository still has no project license; choosing one requires the owner.

## Versioned schema and legacy adoption

For an empty, deliberately provisioned database:

```bash
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic check
.venv/bin/python -m api.bootstrap_admin
```

Revision `0001` freezes the existing v10 baseline (eight application tables plus
Alembic's version table). It preserves the existing JSON/ledger design. Future schema
changes require a new revision, never an edit to `migrations/schema_v1.py`; update
the expected startup revision in `memory/database_models.py` along with the migration.
`alembic check` detects ORM/schema drift, but is not an exhaustive database audit.

Existing unversioned installations must **not** run the initial upgrade over their
tables. Stop API writes, take a verified database backup, restore it to a separate
staging database and point the environment at that restore. Then run:

```bash
.venv/bin/python -m api.adopt_schema
.venv/bin/python -m alembic upgrade head
.venv/bin/python -m alembic check
```

Adoption checks table inventory, primary/check constraints, enum definitions and
Alembic's type/default/index/foreign-key comparisons before stamping `0001`; it
does not rewrite user data. Unknown schema differences are refused for manual
reconciliation. It is an operator maintenance command, not an online concurrent
schema-change protocol. Verify the restored data and application startup before
repeating the checked procedure against the backed-up original database. A real
production backup/restore has not been validated; synthetic legacy adoption passes
the separate integration suite.

`alembic downgrade base` is destructive: it drops all application tables and enum
types. It is appropriate only for disposable migration tests. For operational
rollback, use a verified backup/restore procedure. Do not downgrade an active system.

## Tests and executed results

```bash
.venv/bin/python -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
for file in web/static/scripts/*.js; do node --check "$file"; done
bash -n setup.sh
git diff --check
```

Local results: 78 Python tests passed; mocked Node login/session/plan/approval/socket
scenarios passed; all frontend JavaScript and installer syntax checks passed; the
hash-locked installation and `pip check` passed in two local venvs, including a fresh runtime-only environment. The full Python suite also passed in that fresh environment. Offline Alembic generation
produced upgrade and downgrade PostgreSQL SQL. Python sources parse successfully.
These checks use mocked providers/workers and do not establish external compatibility.

The separate integration suite requires disposable PostgreSQL and Redis, protected
test-process secrets, `REPORT_OUTPUT_DIR` pointing to a writable temporary directory,
`DATABASE_URL` naming a database ending in `_test`, and `REDIS_URL` using DB 15:

```bash
ARIA_INTEGRATION=1 .venv/bin/python -m unittest discover -s integration -v
```

The suite upgrades/checks/downgrades/reupgrades, reconstructs an unversioned schema
with retained data and verifies adoption, exercises real startup/readiness,
login/session persistence after cache eviction, encrypted Redis vector round trips,
and concurrent SQL playbook increments and private retrieval. It never submits a
worker job or calls a model. Use a fresh database per run: it is destructive and
leaves disposable test records behind. It does not replace a real backup/restore test.

Both integration scenarios now **pass on Fedora with rootless PostgreSQL 16.6
and Redis 7.4.1 containers**. This verifies migrations, legacy schema adoption,
retained data, live startup/login/session persistence and concurrent playbook
counters against real services. The earlier sandbox-only run skipped these tests;
host access and rootless containers enabled this later validation. Logs are kept
locally in `.local-lab/integration.log`. At local validation time the GitHub workflow had not been run; check GitHub
Actions after publication for its separate result. A user-systemd ARIA service is also running and its HTTP/login checks pass;
real worker/provider and browser end-to-end behavior remain unverified. See
[fedora-lab.md](fedora-lab.md) for the manual lab installation. Runner/action and
container tags are not immutable image digests; the dependency lock does not imply
a bit-for-bit OS image reproduction guarantee.

## Remaining risks

- External worker process isolation, scope/DNS confinement, idempotency and actual
  remote termination still require the absent worker implementation. See
  [worker-contract.md](worker-contract.md). No external provider/browser end-to-end
  test or live deployment validation was performed.
- Native inference cannot be killed by cancelling an asyncio future. A hung model
  can occupy the one inference thread until restart and can delay interpreter exit.
  Real-model concurrency, memory/CPU consumption and throughput are unbenchmarked.
  Busy inserts can remain keyword-only; synchronous APIs intentionally use keywords.
- Learning/ReAct remain deferred capabilities with narrowed claims. Exact service
  and version matches do not validate prerequisites or CVE applicability. Do not
  interpret historical success counts or model confidence as authorization.
- One API process is still required. Full attack-KB/run/UI recovery, global resource
  and retention limits, strict typed model output/engagement data-consent policy,
  browser token/CSP hardening, infrastructure TLS and comprehensive audit linkage
  remain incomplete as described in [security-review.md](security-review.md).
