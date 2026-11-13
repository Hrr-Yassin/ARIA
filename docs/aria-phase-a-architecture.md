# ARIA interface redesign — Phase A architecture audit

Date: 2026-11-13. Scope: audit, UX architecture, shared design foundation, and visual validation only. Phase B requires review of this document and the component specimen. Existing uncommitted backend, dashboard, specification, and test work is preserved. Findings describe the inspected working tree, not just HEAD.

## Decision and concise UX plan

Retain FastAPI, static HTML, vanilla JavaScript, native SVG, and existing dependencies. Introduce shared CSS tokens and opt-in components with a temporary adapter for current pages. Do not migrate frameworks or add chart/3D libraries in Phase A.

The future product shell should answer: what is running, what last happened, what is waiting, why did it stop, and what authorized action can the owner take? Use an operations overview, searchable session index, and session-scoped workspace. The workspace keeps campaign/run identity and target visible, with views for orchestration, commands, model accounting, investigation, and events. Use a shared contextual inspector for provenance, timestamps, identifiers, failure reasons, and recovery prerequisites. Preserve URLs and browser history when adding views. Never derive execution from a session's ACTIVE label.

Start with a 2D SVG task graph and accessible list equivalent. Add optional 3D only after a reviewed use case and dependency justification; no fabricated links or packet animations. Default to a dense but readable record view with progressive disclosure. Observed event motion must be transient, opt-in, and disabled by reduced-motion preferences.

## Actual architecture

| Layer | Implementation inspected | Implication for the UI |
| --- | --- | --- |
| Hosting | `api/main.py`, FastAPI, explicit HTML routes and confined `/static` mount; content-hashed assets through `render_page` | No Node build, React, Tailwind, or bundler. Shared assets can be adopted incrementally. |
| Pages | `web/index.html`, `dashboard.html`, `login.html`, `admin.html`; page scripts and styles under `web/static` | Workspace, operations dashboard, sign-in, and admin are independent shells. Settings contains team, report, and policy integrations. |
| Authentication | `api/auth.py`, `api/session_access.py` | JWT/cookie authentication, revision-based revocation, ownership/scope checks remain server authority. Existing client token storage is unchanged by Phase A. |
| Persistence | SQLAlchemy async PostgreSQL models and Alembic; current expected migration `0005` | No migrations are needed for the design foundation. Populated databases must not be recreated or auto-adopted. |
| Session state | `memory/session_manager.py`; PostgreSQL and optional Redis TTL cache | List is owner-scoped and excludes archived sessions. Updated time is not a reliable execution heartbeat. Redis cached detail can omit creation time. |
| Orchestration | `agents/autonomous_engine.py`, `orchestrator/team_coordinator.py`, `specialist_integration.py` | Bounded autonomous run plus evidence-driven specialist tasks; not an always-running swarm. |
| Durable supervision | `orchestrator/campaign_supervisor.py`, `memory/campaign_store.py`, `campaign_execution.py` | Single API process, scheduled windows, leases, retries, pause/cancel fences, budget enforcement, and recovery. |
| Execution | `memory/execution_authorization.py`, `command_lifecycle.py`, `worker_jobs.py`, `worker/*` | Shared authorization gate, validated job identity and evidence receipts, restricted curl/Nmap profiles. No arbitrary shell control. |
| Knowledge/evidence | `memory/knowledge_store.py`, `evidence_context.py`, `attack_knowledge_base.py`, team evidence, application map, findings | Evidence-backed, owner-bound observations; hypotheses must stay unverified. Not all in-memory projections are durable event sources. |
| Models | `llm/pool_manager.py`, provider adapters, `engagement_budget.py`, `local_client.py` | Task-based local/cloud routing, fallback, durable pre-I/O reservations and settlement. Key health is separate from call telemetry. |
| Logs and events | `DecisionLog`, team event outbox, campaign ring, chat WebSocket and autonomous WebSocket | Multiple source-specific histories. There is no unified global stream or complete replay endpoint. |

### Database and lifecycle details

`PentestSession`, `Finding`, `ChatLog`, `AuditLog`, `DecisionLog`, `Playbook`, `AutonomousRun`, `AutonomousCampaign`, and `WebAction` are the principal models. Team events, worker job state, model attempts, knowledge observations, and private application-map data also use typed `DecisionLog` records/metadata. Do not serialize every metadata record into a frontend event feed.

Sessions persist `active`, `paused`, `completed`, and `archived`. There is no first-class idle, blocked, failed, or unknown session enum. Campaigns persist `scheduled`, `starting`, `running`, `pausing`, `paused`, `cancelling`, `completed`, `cancelled`, `stopped`, and `failed`. Show session, run, campaign, task, and worker job states separately. A derived display state must name its source and remain unknown if execution cannot be established.

Startup initializes DB/cache, recovers worker jobs/runs/team/web actions, then starts the campaign supervisor. Durable checkpoints retain progress, objective/completion criteria, scope binding, evidence references, run/campaign/specialist identity, and replay guards. Restore rechecks current authorization and execution fences; a stored authorization must never be reused as authority. Cancellation can remain unresolved and must block new work. One API worker remains required because some investigation and event state is process-local.

## SPEC-10 through SPEC-15: implementation evidence

Some specifications have no standalone status document in this tree; labels below follow code and regression names rather than assuming the build-plan document is an implementation specification.

| Specification | Inspected implementation | Evidence and boundary |
| --- | --- | --- |
| SPEC-10 / context integrity | `memory/knowledge_store.py`, `evidence_context.py`, `agents/base_agent.py`, objective/completion handling in autonomous engine | `tests/test_knowledge_store.py`, `test_context_integrity.py`; bounded, relevant, owner/session-bound evidence and durable observations. SPEC-10.3 is explicitly named by context tests. Evidence integrity is not full agent-message retention. |
| SPEC-11 / checkpoints | `memory/autonomous_runs.py`, `AutonomousRun`, engine restore | `tests/test_checkpoints.py`, `integration/test_checkpoint_postgres.py`; validated checkpoints, replay guards, scope/owner checks, restore leases. No automatic unsafe replay. |
| SPEC-12 / campaigns | `campaign_store.py`, `campaign_supervisor.py`, migration `0004` | `tests/test_campaigns.py`, campaign PostgreSQL suites; windows/timezones/weekdays, runtime and token/cost ceilings, leases, retry/backoff, recovery, pause/resume/cancel. |
| SPEC-13 / specialists | `orchestrator/specialist_integration.py`, `campaign_execution.py`, team ledger/coordinator | Specialist integration/hardening/boundary regressions; deterministic task identity, durable evidence, lease-gated dispatch, human review, fail-closed scope and ownership. Not unrestricted agent-to-agent messaging. |
| SPEC-14 / observability | `memory/campaign_observability.py`, migration `0005`, health/events endpoints | `docs/spec14-observability-status.md`, observability tests; sanitized health schema, bounded alerts, 50-event ring, monotonic sequence/correlation IDs, conservative accounting. The old document's closing statement that SPEC-15 had not started is superseded by the SPEC-15 document/code. |
| SPEC-15 / endurance | Supervisor progress resets retry streak; offline harness, PostgreSQL tests and bounded soak | `docs/spec15-endurance-status.md`, `tests/endurance_harness.py`, `test_endurance.py`; synthetic accelerated schedule/crash validation. Eight-hour wall-clock production endurance is explicitly not demonstrated. |

## Product capabilities and missing integrations

Paths below include router prefixes. All session/campaign/team sources require the existing authorization boundary; campaign and team views are specifically owner-bound, including when the caller is an admin.

| Product area | Existing source/actions | Present frontend and required later work |
| --- | --- | --- |
| Operations | `GET /api/health`, `/api/ready`, `/api/capabilities`; session list; per-session campaign health | Existing dashboard has real per-engagement summaries. No global campaign aggregate or normal-user system resource API; bounded client aggregation must show coverage/partial failures. `/api/health` is liveness, not supervisor proof. |
| Sessions | `GET /api/session/list`, `/{id}`, `/{id}/restore?offset=&limit=`; create/archive | Existing workspace list/dashboard picker. Add search/filter and explicit provenance. Session list lacks pagination, explicit last execution time, objective, run/campaign association. Detail may require additional calls; avoid unbounded fan-out. |
| Orchestration | `GET /api/team/{id}`, `/events?after=`; task dependencies/state; autonomous status and socket | Existing team panel/dashboard task roster; dashboard SVG is target/service/finding graph, not agent orchestration. Add real task/dependency graph and handoff inspection only where recorded; no assumed agent messages or 3D telemetry. |
| Commands | `POST /api/execution/proposals`, `/execution/{action_id}/decision`; authorized `/api/kali/execute`; `GET /api/running/{id}`, `/jobs/{id}/{job_id}`, `/history/{id}` | Workspace has proposal/approval and command history. Need unified inspector joining action/job/evidence IDs. Legacy command history is process-local, not a complete durable lifecycle ledger. No collection API lists every proposal/denial; don't claim complete coverage. Output must pass server redaction and use text rendering. |
| LLM observability | `GET /api/team/{id}/model-budget`, `PUT` same path; `/api/v8/llm-status`; model_attempt metadata | Team settings/accounting/dashboard summaries exist. Attempt rows include id, session/task/campaign, provider/model, reservation/start time, terminal state, reported tokens/cost, finished time. They do not securely retain prompts or hidden reasoning. Purpose, autonomous agent name, normalized errors, and operation correlation are not consistently persisted per attempt. End-to-end elapsed time can be derived from timestamps if both exist; it is not provider-only latency. Returned adapter latency is not a durable trace field. |
| Campaigns | `GET /api/pentest/{id}/campaign`, `/campaign/health`, `/campaign/events?after=&limit=`; `POST /campaign/start`, `/pause`, `/resume`, `/cancel`; autonomous start/stop/status/restore/approvals/approve | Dashboard already renders health/schedule/budget and pause/resume/cancel; workspace has bounded autonomous controls. Later work should unify them, add reviewed creation/scheduling, and explain stop reasons/recovery. There is no campaign budget/schedule PATCH or retry-now API. Start accepts limits and schedule; do not invent live budget editing or forced retries. |
| Investigation | Findings, `/api/kb/{id}`, `/api/pentest/{id}/kb-snapshot`, team evidence/tasks/review, `/api/application-map/{id}`, report/program routes | Current features live across workspace/settings/dashboard. Integrate into one investigation view with source/evidence distinction and existing review controls. Attack-surface links must reflect recorded relationships, not inferred exploitation. |
| Infrastructure | `/api/capabilities`, `/api/kali/health`, `/api/kali/tools`, job status; admin-only `/api/admin/health` | Current dashboard worker availability and admin health. Admin endpoint measures API host CPU/memory/disk using psutil. It does not expose per-container, per-worker resource histories or a worker fleet inventory/queue depth. Never broaden admin access to populate ordinary pages. |
| Global timeline | Campaign ring, team outbox cursor, session decision log (`limit`, maximum 500), command history, model attempts (bounded) | Dashboard merges decisions/campaign/team into a limited view. Need provenance, source IDs, filters, truncation/gap indicators and stable deduplication. No unified pagination or global historical replay endpoint; decision endpoint has no offset/cursor, team events have no bounded page size. Full archival replay requires backend work and a separate review. |

### Event identity and observability contract for later phases

Normalize only public allowlisted fields into `{source, source_id, session_id, campaign_id?, run_id?, task_id?, action_id?, job_id?, evidence_ids?, correlation_id?, recorded_at, observed_at, state, summary}`. Optional fields remain absent, never generated to imply a causal link. A campaign event identity needs campaign ID plus sequence; a team event uses its durable event ID and sequence; a decision/model attempt uses its stored UUID. Request `X-Request-ID` and campaign correlation IDs have different scopes. Shared timestamps alone never prove causality.

Campaign ring retention is 50, not an archive. Show oldest available sequence and retention limits, request subsequent sequences when possible, and explain gaps. Historical replay may replay retained observations only and must visibly say historical. A paused replay must not change real execution.

Every read surface needs explicit loading, empty, not-started, not-recorded, unavailable, blocked, failed, and unknown variants as applicable. Zero is permitted only when the source establishes a count. A missing field or failed read is not zero. Preserve last good data only with a stale marker and last retrieval timestamp. Existing dashboard `normalizeUsage` currently defaults absent fields to zero; correct this during integration work before claiming complete accounting visibility.

A missing campaign returns an expected 404. Treat this as “Not started / No campaign” only for an authorized, accessible session whose campaign read returned 404. A 401 means reauthenticate; 403 means forbidden; transport/5xx means unavailable. Do not turn arbitrary 404s into empty success. Existing dashboard already allows campaign 404s and fetches health/events only when a campaign exists.

### Data and authorization constraints

- Do not expose credentials, registered identities, private sealed application-map metadata, raw provider exceptions, or arbitrary `DecisionLog.metadata`.
- The legacy decision endpoint returns a `reasoning` field and observation/action text. Do not route it into new LLM previews or inspectors: it is not an approved prompt/message or hidden-reasoning display contract. Future surfaces must use sanitized outcome summaries and allowlisted metadata.
- Prompt/message previews are unsupported until secure retention, consent, redaction and per-record access rules exist. Never reconstruct prompts from chat or internal logs.
- Costs use owner-entered conservative tariffs; reported cost is not verified provider billing. Reservations are never refunded. Preserve unknown usage, stop reasons, accounting anomalies and budget denials.
- Socket auth is first-message token with origin and repeated ownership/revocation checks. No query-string credentials. Live engine sockets are process-local and not historical replay.
- Monitoring must not authorize, auto-approve, resume, or retry execution. Only existing guarded owner actions can mutate execution.

## Skills evaluation

Local skill catalog/files were inspected. Neither `frontend-design` nor `ui-ux-pro-max` is installed. No installer, dependency search script, remote executable, npm package, or generated design database was executed.

Reviewed primary upstream documents on 2026-11-13:

- [Anthropic frontend-design](https://github.com/anthropics/skills/blob/main/skills/frontend-design/SKILL.md): adopted intentional visual direction, coherent typography/spacing, working implementation and plain interface copy. Its general aesthetic guidance is subordinate to operational legibility, accessibility and truthful telemetry.
- [UI UX Pro Max](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/blob/main/.claude/skills/ui-ux-pro-max/SKILL.md): adopted the public priority guidance for contrast, keyboard access, touch targets, semantic colors, reduced motion, responsive layout and chart labels. Its searchable scripts/data are absent and were not run; the chosen palette is project-authored, not claimed as a generated or verified database recommendation.

Available Sites and visual artifact skills were considered. This work modifies an existing local FastAPI application, not a hosted Sites project or separate inline visualization, so those workflows add no needed capability. No external design assets are needed for this phase.

## Reviewable phase boundaries

| Phase | Planned deliverable | Gate |
| --- | --- | --- |
| A — current | This audit, foundation specification, common tokens/primitives/legacy adapter on four page shells, static review specimen and browser evidence | User reviews architecture and design system. Stop here. |
| B | Shared navigation/search/shortcuts, session index/state provenance and operational overview | Use existing scoped reads; disclose aggregate coverage. |
| C | Actual agent/task graph, source-aware retained timeline, command inspector | Establish safe joins and show missing lifecycle coverage. |
| D | Model attempt inspector and campaign creation/control integration | No prompts, hidden reasoning, fabricated purpose/error fields, forced retry, or unimplemented budget mutation. |
| E | Unified investigation/evidence/report/policy surfaces and authorized infrastructure | Preserve role boundaries, evidence provenance and human review. |
| F | Full desktop/mobile integration, accessibility, empty/error/recovery and visual regression validation | Tests against real APIs plus explicitly isolated test-only fault injection. |

## Phase A change scope and validation

New reusable styles: `aria-foundation.css` (tokens/primitives), `aria-legacy.css` (compatibility), `design-system.css` (review-only layout). The review specimen is `/static/design-system.html` and its script performs only local density, motion and token-disclosure interactions. It reads no account or operational data and requires no new API route.

All four page shells load the common styles and the existing IBM Plex font families with system fallbacks. Sign-in has a main landmark, workspace/admin have skip targets, and admin section items are native buttons. Their existing handlers and APIs are retained. The foundation adds no backend dependencies, migrations, execution actions or production mock telemetry. Existing page layouts are intentionally retained for subsequent reviewed phases.

See `docs/aria-phase-a-validation.md` for actual command results, browser checks, limitations and screenshots. Existing legacy selectors and literal colors will be retired progressively; the adapter is a migration boundary, not a claim that every old component now uses new primitives.
