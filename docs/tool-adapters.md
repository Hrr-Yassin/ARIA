# Typed security adapters — implementation and Kali deployment record

## Phase 2 deployment and laboratory validation — 13 November 2026

The previous offline-only statement below describes the Phase 1 state. Phase 2
deployed reviewed digest-pinned images to the existing rootless Podman worker on
Kali `192.168.77.10` and used ARIA jobs-v1 against the authorized
`192.168.77.20/32` lab target only. The isolated `aria-lab` network and the
worker destination/port ceiling were rechecked before deployment. No Fedora,
Metasploitable, VM/network, Kali network, SSH, firewall or unrelated service
configuration was changed. The worker service and its private profile/source
files were updated under the authorized worker tree. PostgreSQL ledger and
authorization/evidence verification remained enabled.

Images use Python 3.11 pinned to `docker.io/library/python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39`, Debian bookworm snapshot `20261101T000000Z`, locked Python wheels, and vendored binaries/source. Kali image IDs, not mutable tags, are the runtime identities. The runtime base includes Nmap 7.93+dfsg. Tool releases are pinned as follows: httpx 1.7.1, Katana 1.1.2, Nuclei 3.4.10, ffuf 2.1.0, Subfinder 2.9.0, ZAP 2.16.1, Playwright 1.56.0 with Chromium 141.0.7390.37, SQLmap 1.9.11 at source commit `0599f7c1b6fe679106d18744b49f90fd1f340cff`, Semgrep 1.99.0, and Java 17.0.19. The resolved release lock and SHA-256 inventory were retained in the ignored local deployment workspace. Exact executable/image IDs are in the matrix. Images were transferred to Kali and executed there; no host command execution path was added to ARIA.

| Tool | Image ID (Kali rootless Podman) | Capability enabled after validation | ARIA execution / receipt | Runtime result |
| --- | --- | --- | --- | --- |
| Nmap | `sha256:b8982e2e539f7503ee91e3cb038600322eae1c924bc9722305f04bea3a72f7e7` | yes | job `6f67dfc2-436c-4b9a-a5b6-593d3ae0a0a5`; receipt verified | TCP discovery of approved ports succeeded; five approved ports observed open. |
| ProjectDiscovery httpx | `sha256:938b67c9ac2ff95a72af3d09fd0acfa93962f0acfd923738d0bcf871936d6693` | yes | job `90e6cb9c-6984-4966-9346-2dabf74ba4f6`; receipt verified | HTTP 200 and title observation succeeded. |
| Katana | `sha256:aa9f30cf5c9d5ef4af2521804dd89bca9b19cb5304c3572d605e672e32cf7b87` | no | job `01cabcee-8eb6-4272-8256-3e1879ac86e3`; terminal receipt verified | Container exited 137 at the ordinary 256 MiB cgroup memory limit. Binary/version verified, crawl did not complete. Disabled pending measured resource approval or optimization. |
| Playwright / Chromium | `sha256:778fd6be2ad8048abe133b04ff7f7b2d7db960b7b4c4883fd2437996aa2ed2d2` | no | job `db9c0ce0-fa1d-4b49-a5c8-9b13ed085f30`; terminal receipt verified | Chromium sandbox failed at `sys_chroot("/proc/self/fdinfo/")` under the existing container security policy. No sandbox bypass was introduced. Disabled pending a separately reviewed compatible isolation policy. |
| Nuclei | `sha256:118601592a0d69199c1bbb4c9f058f68f6fc7612f98aa6f3f56fcca2e1b1f366` | yes | job `e97894e8-2945-4602-adf4-bc727d9f6e3c`; receipt verified | Supplied single informational HTTP observation template completed; no vulnerability claim. |
| OWASP ZAP | `sha256:eb7f95db6bcde53612d14606cbbb4517f9f754c30d698bd320ffb3d4a4ca6d93` | no | no ARIA job | ZAP version probe completed, but consumed 131040 KiB of the 128 MiB `/tmp` envelope, leaving 32 KiB. Disabled; passive report job was not attempted. |
| ffuf | `sha256:eaca8423a30b0adb87eba31d71ac95c0ade7c15d01a22123dc1b92fd154fa3b4` | yes | job `e00652ea-43d9-4dc9-b2d7-d1084714b851`; receipt verified | Four bounded dictionary observations completed. |
| SQLmap | `sha256:62c64a47d3effbec7372d4eb2810f906729bb33d75210b9c1f703341a92be0b7` | no | job `5459e3e9-dee8-4e5c-a39d-c0aa172360ee`; terminal receipt verified | Pinned runtime/version probe passed. ARIA worker returned “could not start the isolated job” before command execution; no SQL probe ran. Disabled pending worker startup diagnosis. |
| Semgrep | `sha256:134a95690847b7a53eb06f2b712517aa889f25bc5f4a63e2c5f5755042db07ee` | yes | job `ffcda00a-399e-4f2b-852d-466daaa06459`; receipt verified | Local disposable source fixture produced the expected `eval` candidate; finding remains unverified. |
| Subfinder | `sha256:16bd43a00838d1898a874840a8f3673a65504490c2893a4c83c4d7b59b88381f` | yes, offline only | job `bd3b9f21-26c5-4851-9cc7-229e7999f2a7`; receipt verified | Offline fixture returned `child.aria-fixture.test`; no DNS/CT provider query or external disclosure occurred. |

All ten adapter contracts are implemented and registered in code. All ten
executables were present in the pinned worker images and their version/executable
probes succeeded. Only the six tools marked enabled were in the final worker
profile after the observed failures. Nmap, httpx, Nuclei, ffuf, Semgrep and
offline Subfinder have authorized ARIA execution and verified evidence receipts.
The three failed jobs have verified terminal receipts, which establish job
origin and failure, not successful tool execution. ZAP has no ARIA job. Profile
discovery after disabling the failed tools returned exactly the six enabled
capabilities; an unauthenticated worker capability request returned HTTP 401.
The worker's rootless cgroup enforcement had been directly probed at both the
ordinary 256 MiB/64 PID/1 CPU envelope and the browser/ZAP 1024 MiB/128 PID/1 CPU
envelope. No limit was raised during validation.

The API autonomous investigation was also exercised using the configured local
Ollama model (qwen3:4b-instruct), not OpenRouter. It ended `blocked` with
`invalid_planner_output` after two corrective attempts and zero tool steps; run
ID `ae66f2f9-6675-458c-9083-719fe0b96bea`, session
`4b37be65-0256-489f-8a83-13c421e6635d`. The local model produced 967 prompt and
146 completion tokens according to the API log. OpenRouter calls and spend:
**0 calls, $0.00**. Thus autonomous agent-to-tool use is not accepted yet even
though direct ARIA proposal/execute jobs for six adapters are verified.

The original regression baseline and the post-deployment regression both pass:
**618 Python tests passed** using
`.venv/bin/python -B -m unittest discover -s tests -t . -q`; frontend contracts
pass using `node tests/frontend_contracts.cjs`. The disposable HTTP fixture,
adapter mocks and worker resource-enforcement tests remain offline. Live
authorized jobs above used only the target's approved ports and bounded
operations. Out-of-scope and unauthorized job denials remain covered by the
existing contract/security tests; the worker's unauthenticated request was
additionally checked live and denied with 401. No public target, provider query,
destructive action, extraction or database dump was run.

### Deployment changes and rollback

The deployment changed only ARIA worker files under
`/home/kali/.local/share/aria-worker/`, the rootless worker image store, the
worker's private environment/profile, and the worker service's systemd drop-in
needed for its existing per-user Podman cgroup delegation. Backups are private
under `/home/kali/.local/share/aria-worker/phase2-backup-e1b4ae2/`; the original
image ID was
`sha256:bb5f48b3d9a9ca41d4375ff50627db0ed0caeeee2d50f8f355c39a2925839e33`.
Rollback, using the existing authorized Kali guest maintenance channel:

1. Stop `aria-kali-worker.service` and confirm no active jobs.
2. Restore the backed-up original `worker.env` and application source tree from
   `phase2-backup-e1b4ae2/` and restore its original worker image reference.
3. Remove only the Phase 2 worker service drop-in created for the user-session
   dependency. Preserve the underlying `user@1000.service` package/unit.
4. Start/restart `aria-kali-worker.service`; check its health and authenticated
   jobs-v1 capability response. Do not alter firewall, VM/network or target.
5. Keep Phase 2 images and private backups until the owner confirms rollback;
   remove them later only through a separately authorized cleanup.

The following owner decisions are required before retrying blocked acceptance
cases: (1) approve a larger `/tmp` limit for ZAP, suggested starting measurement
at 256 MiB while keeping CPU 1, memory 1024 MiB and PIDs 128; (2) approve either
a reviewed narrow Chromium sandbox compatibility change or accepting Playwright
as unavailable under the current kernel/container policy (no `--no-sandbox` or
privileged fallback); and (3) approve a measured Katana memory adjustment if
runtime optimization at the current 256 MiB limit does not suffice. No such
changes have been made. SQLmap also needs diagnosis of the worker's isolated-job
startup failure before a bounded Boolean-only test can be accepted.

Implemented on branch `autonoms_pentesters`. The current deployment status is
recorded above; the Phase 1 statements below are retained as the offline
implementation and pre-deployment test record.

The saved `/tmp/aria-mission-baseline-tests.log` contained 475 tests with three
failures and two errors. The affected model-routing, provider-credential/quota and
planner-readiness tests inherited `LLM_ROUTING=local`, entered the real Ollama
client and encountered the suite's socket blocker. An initial rerun with
`LLM_ROUTING=cloud DEBUG=false` passed all 475 tests. `tests/__init__.py` now sets
cloud routing for the test process, whose provider clients are mocked. Local
client tests explicitly override routing. Production `.env` was preserved.

Implementation and registration are complete for these bounded operations:

| Tool | Registered capability | Unit tests | Jobs-v1 integration-contract tests | Runtime status / deployment prerequisites |
| --- | --- | --- | --- | --- |
| Nmap | `nmap.tcp.connect.v1` | 6 pass, plus shared policy/XML tests | 6 pass | Reuses existing TCP connect worker policy. Typed profile not deployed; pin Nmap binary and image. |
| ProjectDiscovery httpx | `httpx.http.probe.v1` | 6 pass, plus shared controls | 6 pass | Not runtime validated; install the Go binary at `/opt/tools/httpx`, pin binary/image. Python httpx is a separate library. |
| Katana | `katana.http.crawl.v1` | 6 pass, plus shared controls | 6 pass | Not runtime validated; pin `/opt/tools/katana` and image. Review crawler compatibility on disposable fixtures. |
| Playwright / Chromium | `playwright.browser.observe.v1` | 6 pass, plus isolated-context/cleanup tests | 6 pass | Not runtime validated; matching pinned Python package, Chromium bundle, shared libraries and sandbox support are required. |
| Nuclei | `nuclei.http.observe.v1` | 6 pass, plus shared controls | 6 pass | Earlier session detected a Kali binary; current typed profile unvalidated. Pin binary/image and the supplied observation template hash. |
| OWASP ZAP | `zap.http.passive.v1` | 6 pass, plus HAR/no-replay checks | 6 pass | Not runtime validated; pin distribution, JRE, automation/import-export/passive/report add-ons and image. |
| ffuf | `ffuf.http.paths.v1` | 6 pass, plus shared controls | 6 pass | Earlier session detected a Kali binary; current typed profile unvalidated. Pin binary/image; wordlist is generated from at most 16 validated path segments. |
| SQLmap | `sqlmap.http.boolean.v1` | 6 pass, plus bounded-operation checks | 6 pass | Earlier session detected a Kali binary; current typed profile unvalidated. Pin launcher, package tree and image; validate boolean-only operation on fixtures. |
| Semgrep | `semgrep.source.scan.v1` | 6 pass, plus artifact/hash/network checks | 6 pass | Not runtime validated; pin complete package/core, image, supplied local rules and an authorized content-addressed source tree. |
| Subfinder | `subfinder.domain.passive.v1` | 6 pass, plus provider/output checks | 6 pass | Not runtime validated; pin binary/image. Separate engagement and worker approval for `crtsh` provider egress is mandatory. |

All ten adapters exist in code, export input/output schemas and register advisory
agent roles through authenticated `GET /api/tool-registry`. The existing legacy
catalog remains disabled metadata. New entries appear under `typed_adapters`;
`typed_registry_sha256` identifies the reviewed typed implementation. Static tool
names never enable a typed operation. By default every typed adapter is unavailable
on the worker. `runtime_validated=false` describes this implementation's validation
record; it is not a live binary health measurement.

`security_tools/adapters.py` supplies the shared adapter interface, canonical
closed requests, fixed argv construction, scope policy and normalization.
`security_tools/models.py` supplies ten input/output contracts. Nmap reuses
`TCPConnect`, `worker.policy.prepare` and its TCP flags; it does not add another
network policy. No input accepts an executable, raw flags, host path, credentials,
headers, request body, arbitrary template/rule or command string.

The API/agent bridge is `security_tools.service.ToolOperations`. Its public flow is:

1. `POST /api/tool-operations/proposals` with `session_id` and `operation`, e.g.
   `{"tool":"httpx","parameters":{"url":"http://192.0.2.1:8080/"}}`.
2. Review the canonical proposal. Nuclei, ffuf and SQLmap require the ordinary
   command-bound approval through `POST /api/execution/{action_id}/decision`.
   Other operations retain the existing owner/scope authorization policy.
3. `POST /api/tool-operations/execute` with the same structured operation,
   `session_id` and `action_id`. This consumes the existing authorization ledger
   entry and uses the ordinary jobs-v1 client. Existing session cancellation/job
   status endpoints apply. There is no alternate execution or approval store.

An `aria-tool` token is canonical base64url JSON data. The token binds parameters
and the adapter implementation digest; it is never passed to a shell. API and
worker independently validate it against authoritative scope. Worker compilation
resolves/pins all DNS answers and intersects them with the existing independent
network/port ceiling and exclusions before container creation. New profiles reject
program-policy and bug-bounty scopes because their single-request budget contract
has not been extended to scanners. Human approval cannot override that restriction.

The worker repeats per-session admission checks: at most 20 typed jobs, one active
job and at least one second between admissions. The container entrypoint retains
its firewall, capability drop, unprivileged UID and process-group deadline. The
new child supervisor bounds stdout to less than 100,000 bytes and stderr to less
than 10,000 bytes, kills the tool process group on timeout/cancellation/output
exhaustion, and never invokes a shell. Ordinary profiles retain 1 CPU, 256 MiB,
64 PIDs, 32 MiB tmpfs and 8 MiB shared memory. Browser/ZAP use 1 CPU, 1024 MiB,
128 PIDs, 128 MiB tmpfs/shared memory. Every profile retains read-only root,
no-new-privileges, all tool capabilities dropped and no submitted host mounts.
Larger resource settings are source definitions only; no deployed limit changed.

Playwright fetches exactly one bounded unauthenticated response through the
worker's pinned network plan, refuses redirects and renders it in a fresh sandboxed
Chromium context with JavaScript disabled. Only that navigation is fulfilled;
subresources, further navigations, WebSockets, service workers and downloads are
blocked. Context and browser cleanup runs on errors too. This operation returns a
bounded page-title/status observation; it does not support arbitrary browser
scripts, authentication or interaction. ZAP imports one similarly captured HAR
response with `sendRequests=false`, waits for passive scanning and emits a JSON
report. It launches no spider, active scan or API listener.

Nuclei runs only the supplied single-GET, info-level observation template. No
community pack, OAST, code/headless/workflow template or update capability is
exposed. Katana is limited to depth 1–2, concurrency 1, rate 1/s and a ten-second
crawl duration; redirects/headless/form-filling are not enabled. ffuf uses one
thread, rate 1/s, at most 16 words and a 20-second duration. SQLmap uses one explicit
simple GET parameter, level/risk 1, one thread, boolean technique only, five-second
network timeouts, no retries and a one-second delay. There are no enumeration,
credential extraction, database dump, file read/write, shell, command or destructive
operation inputs. All jobs also have fixed outer deadlines of 15–60 seconds.

Semgrep has no permitted network destinations. Its target is an engagement-approved
SHA-256 directory baked read-only into the worker image. Before execution the
worker rejects symlinks/special files and verifies a deterministic tree digest
(relative path, NUL, binary file digest in sorted order), up to 128 files, 64 KiB
per file and 1 MiB total. It uses one local pinned Python rule; no repository build,
Git hook, remote rule download, telemetry or automatic dependency installation is
performed. Source ingestion is an operator-reviewed image prerequisite; no host
path upload or arbitrary archive extraction endpoint was added.

Subfinder admits only the `crtsh` passive source. Engagement scope must explicitly
contain `passive_sources: ["crtsh"]`; the worker profile must separately contain
that same grant. Only controller-resolved `crt.sh` TCP/443 destinations enter its
firewall, intersected with the worker ceiling. This is intentionally unavailable
under a target-only lab ceiling. Returned subdomains remain candidate evidence;
they never expand authorized scan scope.

Results pass the existing owner/session/output/exit-code receipt verification
before normalization. Terminal typed receipts additionally bind capability,
request digest, registry digest, immutable runtime image, declared version and
binary digest; the API persists that attestation in its existing job ledger.
Malformed/mismatched receipts cannot produce observations. Parsers enforce byte,
row, URL/origin, numeric/status and schema limits and return `invalid_output` on
corruption. Nmap permits only its exact inert DOCTYPE; external/internal entity
DTDs are rejected. Scanner errors, timeouts, resource exhaustion, cancellation and
unknown outcomes remain explicit. Cancelled/unknown outcomes have no evidence
provenance envelope. SQLmap logs need a completion marker and a recognized positive
or negative result; arbitrary complete-looking text is not a negative finding.

The returned provenance includes request/registry/output/stderr hashes, job and
session IDs, actual selected image ID and separately labelled declared tool
version. `tool_version` stays null because a deployment declaration is not an
independent version measurement. Audit logs include identities/digests/error/count,
not raw output or source text. A verified receipt establishes origin, not a
verified vulnerability: every observation remains `unverified`. No existing
knowledge-store evidence verification was weakened or automatically bypassed.

Offline dependency definitions are in `worker/adapters/dependencies.json` and the
hash-locked `python-contracts.txt` copied from the core lock. The separate optional
Dockerfile consumes an approved, fully vendored filesystem overlay plus its exact
inventory lock and a digest-pinned base. `verify_bundle.py` rejects changed bytes,
permissions, symlink escapes and special files. The build performs no downloads.
The listed upstream versions are dependency targets, not installed-version
observations. The full vendor bundle/base digest/add-on/browser locks have not
been assembled or runtime-certified in this phase. They must be retained together
for reproducible deployment; mutable upstream tags alone are insufficient.

The validation commands are:

```bash
.venv/bin/python -B -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
.venv/bin/python -B -m integration.tool_adapter_fixture
git diff --check
```

Final executed results on 2026-11-13: **616 Python tests passed in 23.149 s**,
including 141 new adapter/dependency tests. Frontend contracts and whitespace
checks passed. The disposable loopback fixture passed single-response capture,
redirect refusal and response-byte limits. Fourteen new Python files also passed
AST parsing. The final suite ran with the ordinary command above, without a
shell routing override. Logs remain in `/tmp/aria-adapters-final.log` and the
initial failure log remains preserved at `/tmp/aria-mission-baseline-tests.log`.

The two adapter test modules provide six dedicated unit tests and six complete
mocked jobs-v1 contract tests for each tool, plus shared DNS/exclusion/port,
capability/approval, API ownership, argv safety, output provenance, process
supervision, browser cleanup, artifact, resource-envelope and upgrade/recovery
checks. The separate HTTP fixture binds an OS-selected loopback port, captures one
synthetic page, rejects redirects/oversized responses and tears down its server.
It executes no scanners. Container-runtime tests use mocks; these do not establish
real firewall isolation, Chromium/JVM compatibility, tool CLI compatibility,
throughput or hostile resource-exhaustion resistance.

The following items describe the pre-deployment Phase 1 approval checklist; the
authorized Phase 2 work above supersedes its statement that deployment had not
occurred. The outstanding owner approvals and blockers are listed in the Phase 2
section:

1. Assemble/review the vendor overlay, complete wheel/library/browser/add-on locks
   and SBOM; choose the digest-pinned base and build each selected worker image.
   Capture/review local immutable image IDs and the actual binary/asset hashes.
   Approve installation of these images on Kali. This includes Chromium/Java
   libraries inside images, not Fedora/Kali host package installation.
2. Deploy matching API and worker-controller revisions. Set
   `WORKER_ADAPTER_PROFILES` to an owner-managed JSON file whose keys are tool
   names and whose values contain `image_id`, `tool_version`, `binary_sha256`,
   `assets`, `artifacts` and `passive_sources`. `assets` must contain exactly
   `http-observation.yaml` for Nuclei or `aria-python.yaml` for Semgrep, with their
   SHA-256 values. Semgrep additionally needs installed/approved artifact digests.
   Leave other typed profiles absent until individually reviewed. No database
   schema migration is required; existing JSON job/authorization ledgers are used.
3. Approve restarting the API/worker service and the browser/ZAP resource envelopes.
   Validate non-root Chromium sandbox support with the default container security
   policy. If it fails, review a narrowly scoped seccomp/user-namespace change
   separately; the implementation has no sandbox-disabling fallback. Do not use
   privileged containers, host networking/IPC, unrestricted egress or host sockets.
4. Keep the current isolated `aria-lab` network and target ceiling unchanged for
   initial disposable-container fixtures. Before Subfinder can run, separately
   approve provider egress and disclosure of the test domain to `crt.sh`, exact
   resolved provider networks/TCP 443, and the engagement's passive-source grant.
   This is an explicit additional deployment/network decision; do not silently
   broaden the lab ceiling or modify VM networking to make it work.
5. After disposable-image acceptance, approve an explicit per-tool lab target,
   port, time/request budget and test window before live validation against
   `192.168.77.20`. Active Nuclei/ffuf/SQLmap jobs additionally require their
   existing one-use command-bound human approval. Live acceptance must check
   positive reachability, denied destinations/DNS rebinding/redirects, UID/caps,
   filesystem isolation, deadlines/output/resource limits, cancellation/restart,
   real output formats and evidence verification. No deployment acceptance is
   claimed by the offline tests above.
