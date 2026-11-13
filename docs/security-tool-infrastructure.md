# ARIA security tool infrastructure — audit and registry phase

Scope: local source audit and a read-only registry on branch
'evidence-driven-team'. No additional tools, Kali changes, VM changes, production
policy changes, external scans or model API calls are authorized in this phase.
The existing dirty working tree is preserved.

## Architecture audit

This is a source audit on 2026-11-13. Deployment statements are taken from
[kali-worker-deployment.md](kali-worker-deployment.md), dated 2026-11-07; this work
does not contact 192.168.77.10 or claim a fresh deployment/health verification.

| Boundary | Existing implementation and control | Gap / required change |
| --- | --- | --- |
| Fedora → Kali | 'memory/worker_jobs.py': bearer-authenticated jobs-v1, no redirects, bounded responses, required idempotency/cancellation/network-scope flags. Deployment notes identify Kali 192.168.77.10:7001 and Fedora 192.168.77.1. | HTTP is an isolated-lab deployment, not TLS. A name list is not a tool/version/operation inventory. Add a separately versioned structured-operation extension later; never silently downgrade. |
| Authorization | 'memory/execution_authorization.py': live principal/engagement ownership and scope, auth revision, worker epoch, command-bound expiring single-use approvals, durable decisions before dispatch. Red risk requires human approval. | Future operation approvals must additionally bind canonical input, registry digest, exact capability, image/version, template/rule digest and execution limits in this same authority. Discovery and a permission-name list cannot authorize execution. |
| Admission and budgets | API 'SQLJobStore': engagement row lock, at most five nonterminal jobs, fences and unresolved-job rejection. Worker service: four global active jobs. Campaign leases, daily runtime, step/model/token/cost ceilings remain separate constraints. | Future per-tool limits must intersect every existing limit. Do not invent a second budget ledger or refund ambiguous work. Lab curl/Nmap do not have a general per-tool request/probe rate limiter. |
| Worker jobs | 'worker/app.py', 'service.py', 'store.py', 'ownership.py': strict 16 KiB requests, UUID IDs, timeout 1–300 seconds, PostgreSQL job fingerprints, local controller lock and database advisory lock. Durable intent precedes container creation. | Job request still carries a canonical command string. Future agents must submit typed operations; use a reviewed adapter and retain authoritative validation on the worker. This phase adds no submission endpoint. |
| Tool adapters | 'orchestrator/execution_policy.py' tokenizes and reconstructs known argv. 'worker/policy.py' allows curl and Nmap TCP only; denies shell, unknown tools, raw/UDP scans, NSE, target files and redirect following. Nmap receives '-sT -Pn -n'. | The broad legacy policy and 'config/tools_registry.py' mention many unavailable tools. Neither is an installed-tool registry. Current agents still generate proposals as strings; their migration is a later phase. |
| Network boundary | Worker intersects current scope with independent network/port ceiling; rejects any DNS answer outside it and overlaps with exclusions; pins all resolved addresses. In-container nftables drops traffic except approved destination TCP ports, including before DNS destination NAT. | DNS tooling, passive third-party APIs, crawler/browser subrequests and redirects require distinct reviewed network policies. No blanket Internet/DNS/proxy access. A discovered hostname never expands scope automatically. |
| Container isolation | 'worker/runtime.py': immutable local sha256 image ID, '--pull=never', bridge network, read-only root, CPU 1, memory+swap 256 MiB, 64 PIDs, nofile 256, 32 MiB noexec tmpfs, 8 MiB shm, bounded logs, no-new-privileges. Trusted entrypoint installs firewall then drops UID/GID to 65534 and clears capabilities. | NET_ADMIN/SETPCAP/SETUID/SETGID exist only during trusted initialization; tools do not retain them. New profiles must retain this boundary, not use privileged/host-network containers. Browser memory/seccomp needs separate validation. |
| Image supply chain | 'worker/Dockerfile' uses hash-locked Python dependencies, but a mutable python:3.11-slim-bookworm base tag and unpinned apt packages. Runtime rejects mutable tags. | Immutable execution identity does not make rebuilds reproducible. Future builds need base digest, OS snapshot/package versions, tool checksums, template/rule/database lock, architecture, SBOM and reviewed image identity. Historical image hashes are not evidence of the current installed image. |
| Evidence | 'worker_jobs.py', 'memory/knowledge_store.py', 'evidence_context.py': receipt/job/session linkage, output hashes, bounded owner-bound observations and redacted untrusted evidence context. Private authenticated HTTP evidence is separately encrypted and expires. | A scanner match is an observation/candidate. New parsers must preserve original evidence hashes and truncation/error metadata; never mark a scanner label or version match independently verified. A result schema cannot establish ownership/provenance by itself. |
| Authenticated HTTP | 'worker/http_profile.py', 'http_runner.py': optional exact integer authenticated_http_version and specialist_http_version, encrypted identity/digest-bound requests, explicit lab flags, one-use red-risk approval, ten-second deadline and private evidence retention. | Preserve these separate capability contracts. The new unauthenticated registry entries cannot supply headers, identities, bodies or state-changing requests. |
| Browser rendering | 'orchestrator/browser_mapping.py' + 'worker/browser_contexts.py': optional API-side Playwright/Firefox rendering, fresh identity contexts, route fulfillment only from approved worker receipts, blocked service workers/WebSockets/downloads. | This is not a containerized Kali Playwright/Chromium tool profile. Browser process isolation and network escape resistance need a separate worker implementation and real container tests before adding those capabilities. |
| Monitoring | Authenticated '/api/capabilities', '/api/kali/health', '/api/kali/tools', session-owned job/history/evidence and campaign health/events; admin host metrics separately protected. | Names are static worker advertisements; health checks reconciliation, not every binary/container. No measured tool versions, per-container resource history or complete global execution ledger. Dashboard work must preserve unknowns and ownership. |

## SPEC-10 through SPEC-15 preservation map

These mechanisms were inspected in the current working tree, including existing
uncommitted work. Prior documentation is historical validation, not a test run
performed for this registry.

| Spec | Source / existing regression evidence | Extension invariant |
| --- | --- | --- |
| SPEC-10 | 'memory/knowledge_store.py', 'evidence_context.py'; knowledge/context tests | Keep receipt-backed owner/session/scope-bound observations, evidence budgets and untrusted-data framing. Do not turn raw scanner text into trusted instructions. |
| SPEC-11 | 'memory/autonomous_runs.py', engine restore; 'test_checkpoints.py' | Restore revalidates scope/principal/epoch, checkpoint digests and durable receipts; no replay of consumed approval or uncertain job. Future checkpoints need exact registry/capability identities. |
| SPEC-12 | 'campaign_store.py', 'campaign_supervisor.py', migration 0004; campaign tests | Preserve timezone/windows/weekdays, eight-hour daily ceiling, lease fencing, bounded retry/backoff, daily runtime and model budgets. Missing capability remains blocked. |
| SPEC-13 | 'specialist_integration.py', 'team_coordinator.py', 'campaign_execution.py'; specialist/boundary tests | Deterministic task/evidence identity, campaign lease checks before model dispatch, human review, no unrestricted team dispatch. A specialty mapping is advisory. |
| SPEC-14 | 'campaign_observability.py', migration 0005; observability tests | Read-only sanitized health, correlation IDs, 50-event ring, conservative accounting and unknown usage. Monitoring never authorizes/retries jobs. |
| SPEC-15 | 'tests/endurance_harness.py', 'test_endurance.py', disposable PostgreSQL/soak harnesses | Retain crash/idempotency, bounded retry, schedule, budget, scope and approval-expiry coverage. Accelerated fixtures do not prove eight-hour production endurance or hostile resource-exhaustion isolation. |

## Capability matrix and tool evaluation

Rows below are an integration assessment, not enabled capabilities or verified
installed versions. Only curl/Nmap have current worker adapters. Every additional
tool remains outside the shipped registry and unavailable for execution.
Separate profiles are proposed per workload; tools sharing a profile family still
need separate image/version/operation review.

| Tool | Candidate structured operation / agent | Profile family | Authorization and compatibility gate |
| --- | --- | --- | --- |
| curl | 'http.headers', 'http.get'; recon/web_intel, GET also vuln | http-observer | Registry schemas now present; one unauthenticated HTTP(S) URL, no query/body/headers/redirects/proxy. Existing legacy worker support; registry dispatch disabled. |
| Nmap | 'tcp.connect'; scan | tcp-discovery | Registry schema now present; one host, 1–32 explicit TCP ports, no service probes/NSE/raw/UDP. Existing worker TCP support; registry dispatch disabled. |
| [Subfinder](https://docs.projectdiscovery.io/opensource/subfinder/overview) | passive domain enumeration; recon | passive-recon | Requires reviewed third-party source destinations/credentials/terms and rate budget. Returned names are candidates, not authorization. Incompatible with the current target-only egress profile without a separate policy. |
| [Amass](https://github.com/owasp-amass/amass) | bounded domain enumeration; recon | domain-recon | Separate passive/active operations and source/DNS destination lists; disable unreviewed active expansion. |
| [dnsx](https://docs.projectdiscovery.io/opensource/dnsx/overview) | bounded explicit record lookup; recon | dns-observer | Current job firewall allows destination TCP only and blocks DNS. Needs reviewed resolver IPs/ports/transports and answer limits; never enable general outbound DNS. |
| [httpx](https://docs.projectdiscovery.io/opensource/httpx/overview) | bounded HTTP fingerprint; recon/web_intel | http-fingerprint | Fix probe set, destinations, concurrency/rate/redirect behavior; distinguish ProjectDiscovery binary from Python httpx. |
| [Katana](https://docs.projectdiscovery.io/opensource/katana/running) | bounded scoped crawl; web_intel | web-crawler | Revalidate every discovered URL, DNS answer and port; enforce path/exclusions, depth/page/request limits; disable form submission and headless mode initially. Its own crawler scope is not the worker boundary. |
| [Playwright](https://playwright.dev/docs/docker) | reviewed navigation/screenshot; web_intel | browser-observer | Pin library and matching browser image; sandboxed non-root browser, per-request scope, blocked WebSockets/service workers/downloads and per-navigation approval/budget. Separate resource envelope and seccomp review. |
| [Chromium](https://playwright.dev/docs/docker) | browser engine for a reviewed operation | browser-observer | Not an independent arbitrary browser CLI capability. Do not adopt '--no-sandbox', host IPC or privileged examples. |
| [testssl.sh](https://github.com/testssl/testssl.sh) | bounded TLS configuration checks; scan/vuln | tls-assessor | Allowlist checks and handshake counts; explicit TLS port and SNI/DNS pinning. Exclude stress/DoS tests and arbitrary script options. |
| [SSLyze](https://github.com/nabla-c0d3/sslyze) | explicit TLS scan commands; scan/vuln | tls-assessor | Fixed commands, connection/time limits, JSON validation; separate potentially disruptive checks and approval. |
| [Nuclei](https://github.com/projectdiscovery/nuclei/blob/dev/README.md) | approved-template scan; vuln | template-assessor | Lock engine and reviewed template commit+content hashes/IDs; disable runtime updates, OAST/Interactsh, code/headless/file/workflow and unreviewed network templates; hard rate/concurrency/destination budgets and human approval for intrusive checks. Severity/tags are not a template approval policy. |
| [OWASP ZAP](https://www.zaproxy.org/docs/docker/about/) | bounded crawl/passive analysis; vuln/web_intel | zap-assessor | Baseline includes spider traffic; passive analysis does not mean zero active requests. Separate active scan capability requires human approval. Lock add-ons, context, JVM resources and authenticated API exposure; no public listener. |
| [Schemathesis](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/) | reviewed API cases; vuln | api-assessor | Bind imported schema hash, base URLs and operation IDs, fixed examples/budgets and permitted methods. Stateful testing can create/change objects; require controlled accounts/objects and approval. No arbitrary Python hooks. |
| [mitmproxy](https://docs.mitmproxy.org/stable/overview/features/) | inspect imported flows, later controlled capture; web_intel | flow-analysis | Start offline with scoped encrypted artifacts. No arbitrary add-ons, transparent routing, trust-store/VM changes, arbitrary replay or public proxy. Capture/replay must separately bind scope, identities and approval. |
| [Semgrep](https://docs.semgrep.dev/running-rules) | scan reviewed source artifact/rules; vuln | code-analysis-offline | Read-only uploaded artifact by ID/hash, pinned local rules, no runtime rule download, telemetry or host paths. Do not execute project build/install hooks. |
| [Trivy](https://github.com/aquasecurity/trivy) | scan imported image/archive/SBOM; vuln | dependency-analysis-offline | No Podman/Docker socket; bind artifact and vulnerability DB digest/age. Preload approved DB; block updates/network during jobs. |
| [OSV-Scanner](https://google.github.io/osv-scanner/usage/) | scan imported lockfiles/SBOM; vuln | dependency-analysis-offline | Pin scanner plus offline database snapshot; restrict extraction/plugins and artifact traversal. Live OSV queries need separate approved service egress. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | scan imported source/history; vuln | secret-analysis-offline | Local pinned rules, read-only artifact, no host Git config/hooks. Redact secrets at ingestion; encrypted originals under retention policy, never raw matches in models/dashboard/logs. |

Compatibility gates are design judgments based on the existing worker boundary and
the linked upstream documentation reviewed for this audit. No additional binary,
image, template, database, browser or version has been installed or certified.

Existing team roles are recon, scan, vuln, web_intel, correlation and report.
The registry maps recon/web_intel to HTTP observations, scan to TCP connect, and
vuln to bounded GET evidence. Correlation/report remain evidence-only. The
authorization/authentication/exposure/input_validation/business_logic specialties
retain their existing separate investigation-capability checks; exposure can
review saved evidence, while other specialties need their existing explicitly
enabled identity/profile capabilities. Exploit/post-access agents receive no new
capability.

## Implemented registry contract

- 'config/security_tools.json' is declarative deployment-independent metadata.
  'config/security_tool_registry.py' validates bounded, duplicate-free manifests,
  hard isolation requirements, reviewed adapters, unique names/operations,
  permissions, risk, schemas and health-check definitions. Unknown fields/tools/
  operations, mutable images, missing pin pairs and enabling edits fail closed.
- All entries are explicitly disabled; mode is 'catalog_only'. The model permits
  only enabled=false. Version and image ID are null because current worker
  advertisements do not establish them. Pins must be an exact version paired with
  a local sha256 image ID; historical documentation hashes are not copied in.
- Input schemas cover one HTTP(S) URL without authentication/query/fragment or
  one host with bounded numeric TCP ports. 'validate_request(payload, scope)'
  returns canonical structured data, invokes no subprocess/network/model, and
  reuses the existing worker command/scope policy as a compatibility check. Scope
  must be loaded by a future trusted caller, never accepted as LLM authority.
  This helper is planning validation, not an execution/authorization API.
- HTTP/TCP capability IDs are versioned, e.g. 'curl.http.headers.v1' and
  'nmap.tcp.connect.v1'. Operation permission names are requirements for a future
  authorization adapter; they do not add grants to current policies.
- Registry digest covers all definitions, schemas' references, pins and limits.
  Exported input/output schemas come from reviewed Python models. Changing a
  model contract requires a schema/capability version review.
- Output schema carries job/session/operation identity, registry/request digests,
  exact image/version, nullable duration, bounded evidence IDs+hashes, state,
  consistent terminal exit code and normalized error codes. Verification is
  always 'unverified'. No parser, ingestion path or provenance check is replaced.
- Resource/network/audit/rate declarations describe requirements for future
  adapters. Existing worker enforcement is untouched. There is no new scheduler,
  execution path, cache of approvals or claim that dormant limits are enforced.
- Health-check definitions are local version probes with a five-second deadline
  and network=none. No health probe runs in this phase; measured version, check
  time and container health remain unknown.
- Authenticated GET '/api/tool-registry' exports this catalog, schema contracts,
  advisory agent mappings and sanitized live jobs-v1 name discovery with a
  three-second deadline. Worker unavailable/malformed/unconfigured states yield
  no advertised tools; invalid local catalog returns sanitized 503. There is no
  POST/dispatch route. The existing API/dashboard contracts remain unchanged.
  Online means a valid capability response, not binary or container health.
- No dependencies, database migrations, production settings, worker source,
  container builds, Kali software or VM policies change in this phase.

Example planning data (does not execute):

~~~json
{
  "schema_version": 1,
  "tool": "curl",
  "operation": "http.headers",
  "parameters": {"url": "http://192.0.2.1:8080/"}
}
~~~

## Subsequent implementation phases and acceptance gates

1. Registry phase (this change): audit/matrix, schemas, disabled definitions,
   authenticated discovery and offline negative controls. Stop before deployment.
2. Low-risk adapter integration: structured agent proposals and worker extension,
   exact build/tool pins and real version health, retained shared authorization/
   receipt/budget path, per-operation rate limits. First curl observations and
   bounded Nmap TCP only. No shell fallback. Local disposable-container validation
   must pass before requesting any Kali deployment or production-policy approval.
3. Add separate HTTP/TLS and offline artifact profiles individually. Establish
   upload-by-ID/hash, traversal defense, rule/database locks and resource envelopes.
   Then review DNS/passive providers, crawlers, approved templates, browsers and
   API mutation profiles separately. No bulk-enable switch.
4. Dashboard/agent migration: consume the real registry and session-owned ledgers.
   Show declared pins separately from measured versions, health observation time,
   mapping versus authorization, active/unknown jobs, durations/errors/evidence and
   measured resource usage only where collected. Existing admin host metrics are
   not container metrics. Do not expose raw private output, secrets or invented
   execution history.

Future real-container acceptance uses only disposable PostgreSQL/Redis, internal
synthetic HTTP/TLS/DNS/API services and synthetic source/SBOM/secret fixtures.
Check positive reachability before testing denied IP/port/redirect/DNS rebinding;
UID/caps/read-only root/raw socket restrictions; duplicate/changed job IDs;
restart without resubmission; lost receipts/cancellation ambiguity; deadline,
OOM/PID/output exhaustion; admission/rate/budget limits; scope/approval expiry;
parser corruption/truncation and evidence linkage; mismatched worker version/
image/capability; agent compatibility. No external targets or real model calls.
Existing opt-in 'integration.test_worker' and disposable service harnesses are
reused in that phase; adding new images is outside this phase.

## Validation record

Final local validation on 2026-11-13:

| Check | Command / scope | Result |
| --- | --- | --- |
| Focused initial registry suite | '.venv/bin/python -B -m unittest discover -s tests -t . -q -p test_security_tool_registry.py' | 19 tests passed in 0.255 s; a subsequent risk-parity test brings final registry coverage to 20 tests. |
| Final complete offline regression | 'env LLM_ROUTING=cloud DEBUG=false .venv/bin/python -B -m unittest discover -s tests -t . -q' | 475 tests passed in 16.045 s, including all 20 registry tests, existing worker policy/lifecycle tests and SPEC-10–15 regressions. |
| Frontend contracts | 'node tests/frontend_contracts.cjs' | Passed: rendering, approval/rejection and socket authentication. |
| Whitespace | 'git diff --check' | Passed. New files were also checked directly for trailing whitespace. |

The first complete run inherited the workspace's LLM_ROUTING=local setting and
had three failures/two errors among 474 tests. Test socket blocking rejected
attempted connections. Repeating with the suite's documented cloud-routing test
setting passed all 474 tests. Final review preserved curl GET's existing orange
risk (HEAD is green), added explicit risk-parity coverage, and rejected null/list
worker capability advertisements; the final 475-test run then passed. The real
'.env' and production routing were not modified.

The 20 registry tests cover disabled discovery, strict schemas/no shell fields,
URL/port/host bounds, exact hostname/IPv6 scope, exclusions, program-policy
rejection, current risk parity, no subprocess/DNS activity, immutable pin pairs,
malformed/oversized/duplicate manifests, isolation/audit/permission requirements,
agent mapping, digest stability, unverified output contracts, authentication,
absent dispatch routes and sanitized worker/registry failures.

Exact change scope: five new files ('config/security_tool_registry.py',
'config/security_tools.json', 'api/routers/tool_registry.py',
'tests/test_security_tool_registry.py' and this document), plus one router import
and one include in the already-modified 'api/main.py'. Existing unrelated changes
were retained. No migration, settings, worker/runtime/policy or image recipe was
changed by this phase.

No real container/isolation, Kali health, throughput, resource-exhaustion,
additional-tool parser, deployment, browser or live provider validation was run.
Those checks need the future adapters/profiles described above. The shipped
registry is disabled metadata and planning validation, with genuine read-only
capability discovery when used against a configured worker; it is not a claim of
new executable tool support.
