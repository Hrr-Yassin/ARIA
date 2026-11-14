# Autonomous investigation intelligence — 14 November 2026

Current status is recorded in **Validated continuation — Part A and research
architecture** at the end of this document. Earlier sections retain historical
checkpoints, including the former pending-approval state; they are superseded by
that continuation. Worker profiles and resource limits remain unchanged.

The initial investigation below used local Ollama `qwen3:4b-instruct` and no
OpenRouter inference. The continuation uses the approved DeepSeek engagement.

## Request and validation path

1. Authenticated autonomous start resolves owned engagement scope, current
   authorization revision, worker epoch, capabilities and model-budget readiness.
2. `AutonomousEngine._plan_next_step` permits at most three proposals with
   corrective feedback. `_validated_plan` supplies the original objective,
   completion criteria, completed observations, open ports and receipt identities.
3. `BaseAgent.process` independently loads owned scope/evidence/capabilities;
   `_ground_prompt` prefixes authoritative constraints and labels evidence
   untrusted. `OrchestratorAgent._bounded_assessment_plan` selects a strict
   legacy or typed Pydantic contract from actual worker availability.
4. Task routing goes through `query_llm_smart`, `LLMPoolManager.query_for_task`,
   engagement accounting reservation/settlement, and the configured local client.
   There is no cloud fallback when local routing is selected.
5. Ollama now receives the actual Pydantic JSON schema through an asynchronous
   context variable, rather than only `format="json"`. Structured requests have
   a 768-token ceiling and a measured 180-second transport deadline. Ordinary
   requests retain the previous 192-token/60-second envelope. Truncated responses
   are rejected explicitly. The context variable is reset after each call.
6. Pydantic still forbids extra fields and requires exactly one action. Typed
   parameters use the existing closed adapter input models. Server code encodes
   the typed operation; the model never generates an encoded command or flags.
7. The public agent result and autonomous validator apply the existing typed
   scope validator to typed envelopes and the existing constrained command
   validator to legacy commands. Availability, missing-observation and replay
   checks remain independent. The authorization ledger then binds the exact
   request; its approval policy remains authoritative.
8. Dispatch uses the shorter of the engine deadline and the adapter deadline.
   Typed output must normalize successfully before it can satisfy completion.
   Valid negative output is not treated as a scanner failure.
9. After required observations, a local model reviews current-run outputs fetched
   from the worker and independently checked against durable receipts. Its
   structured hypotheses must cite owned current-run job IDs. Conclusions remain
   unverified and follow-ups are proposals; they never dispatch commands.

## Failure investigation and limits of historical evidence

The November 13 run `ae66f2f9-6675-458c-9083-719fe0b96bea` retained three model
attempt/accounting rows, public validation feedback and the terminal checkpoint.
The rows contain no response body, prompt body or validation field locations.
Therefore its exact invalid output cannot be recovered and its precise schema
violation cannot honestly be identified retrospectively. The recorded feedback
shows that the strict plan contract rejected model output, then the loop rejected
an empty commands list. A fresh minimal generic-JSON request returned a valid
legacy plan (413 tokens); a grounded reproduction timed out at 60 seconds.
Neither result proves what the historical model wrote.

The investigation exposed and corrected concrete implementation defects:

- Generic JSON generation did not enforce the server's one-action schema and
  used a small output envelope shared with unrelated analysis requests.
- Typed agent selections were passed through the legacy worker-command checker,
  which rejected typed Nmap for lacking a shell `-p` argument and rejected other
  adapter names outright. The typed scope validator already existed and is now
  used at those boundaries; no worker policy was loosened.
- The engine submitted its generic timeout to bounded adapters; the authorization
  layer correctly rejected it with `Timeout exceeds adapter limit` before dispatch.
- Completion previously had no standalone receipt-bound hypothesis review.

New private planner transcripts are encrypted with the existing evidence cipher
in owned `DecisionLog` rows. Public errors expose validation types/locations,
not model input values. Failure to persist the transcript prevents dispatch.
These rows are diagnostic records, not an alternate authorization or evidence
ledger. Historical missing responses are not reconstructed from later runs.

## Reproduction

Offline regressions: `python -m unittest discover -s tests -t . -q` and
`node tests/frontend_contracts.cjs`.

`LLM_ROUTING=local python -m integration.planner_intelligence` uses real local inference on six
synthetic planning scenarios, validates the selected envelopes against fixture
scope, and writes private results under `.local-lab/intelligence/`. It executes
no scanners. It is distinct from the authenticated live investigation.

Live runs use the normal authenticated session/start/status API and jobs-v1.
The configured orange-action approval gate remains enforced; approvals of
model-selected, exact lab port discovery requests use the owner's existing
bounded laboratory authorization. Neither tool choice nor follow-up ordering is
supplied as a manual action sequence.

## Additional observed semantic failures

The retained live responses included a Nmap port-80 operation labelled
`expected_evidence="http_response"`, followed by ffuf for the same missing HTTP
observation. The old prompt alone did not prevent these choices. The server
rejected them, and generation now receives only operation schemas eligible for
the outstanding observation. Scope, capability and replay checks still run after
generation. Eligibility is deterministic policy; it is not evidence of unrestricted
model tool-selection accuracy.

In the six local semantic cases, the original ffuf output substituted
`["admin", "api", "login", "dashboard"]` for the requested dictionary
`["test", "admin"]`. A stronger prose instruction still returned only `admin`.
An exact dictionary can now be supplied as structured `ffuf_words` context,
validated by the existing adapter input model, included as a schema constant,
and independently checked after generation. A mismatch cannot become a proposal.
This is a constraint on parameter generation, not authorization to scan more paths.

The first evidence review timed out at 180 seconds when it consumed raw tool
logs. The review now re-verifies those raw receipts and normalizes them before
building model context, preserving job identities and bounded observations while
removing unrelated scanner metadata. The model is asked for at most three short
observations, one hypothesis and two limitations. Conclusions remain unverified.

Typed capability advertisements also now survive checkpoint serialization and
rehydration; boolean or unsupported version values are rejected. Historical
checkpoints that never stored typed advertisements do not acquire new grants.

The first completed compact-review run still generated inadmissible *suggestions*:
`dirb`/`dirsearch` with 1,000 requests and sensitive file paths, unsupported Nmap
version flags, and public-advisory follow-ups. None executed. That review was
rejected during acceptance and is not counted as a successful safe investigation.

The accepted review contract now allows at most one hypothesis. Follow-ups are
keys in a server-built catalog, not free-text commands: `bounded_http_paths`
compiles to ffuf with exactly `admin` and `test`; `http_observation_template`
compiles to the pinned informational Nuclei template. Both require observed,
receipt-backed HTTP evidence, current advertised capability and successful scope
validation. The selected HTTP job must appear in the hypothesis's evidence IDs.
Both retain the existing human-approval requirement, and neither is dispatched
by report generation. The model can select `none` when no check is supported.
Unsupported raw tool names, budgets, flags and paths cannot become a follow-up
operation. Hypothesis descriptions and validation criteria remain unverified text.

## Accepted bounded laboratory investigation

Session `31cb48b6-f8b1-4329-b67e-611d04091957`, run
`78472c91-cf67-45e2-b6e5-af53963ea8f9`, reached `completed` with two successful
jobs and three real local-model calls. The terminal snapshot recorded 256 seconds,
including the configured approval gates. The model selected typed Nmap, then
httpx after the receipt-backed port observation. Neither response was supplied by
the harness. The owner-authorized exact operations passed the ordinary approval
ledger because the configured policy remains `green_only`.

| Observation | Worker receipt ID | Result |
| --- | --- | --- |
| Nmap TCP connect, ports 21,22,80,139,445 | `07ffdb98-b88d-42ed-a027-949ef98635bc` | Five approved ports open; exit 0 and verified receipt. |
| httpx, `http://192.168.77.20` | `d6820ff7-c9d6-46f5-a65b-e7b1006ea57b` | HTTP 200, title `Metasploitable2 - Linux`; exit 0 and verified receipt. |

The model generated one unverified hypothesis: public HTTP configuration paths
or endpoints may be accessible. It selected `bounded_http_paths`, which the
server compiled to `ffuf` against the same scoped URL with words `admin` and
`test`. This proposal requires approval and **did not execute**. Its server
criterion compares `/admin` and `/test` status codes without following redirects;
a non-404 response is only a path candidate, not proof of a vulnerability.

The raw model criterion mistakenly called the words “query parameters”, and its
port-to-service interpretation inferred service identities from port numbers.
These are not accepted as facts. Report formatting now takes observations from
normalized verified receipts, preserves model statements separately as unverified
interpretations, and supplies check criteria from the server's compiled operation.
The actual captured response is retained as a regression fixture for that
postprocessing; no model or tool response was fabricated for the live run.

Measured acceptance:

- Useful receipt-backed facts: **six** (five TCP port states and one HTTP result).
- Confirmed vulnerabilities: **zero**. No vulnerability precision or recall can be
  inferred from this discovery experiment. No unsupported model conclusion is
  promoted to a verified finding.
- Final live selections: **2/2 eligible operations**, with **zero corrective
  planning attempts**. Eligibility is server policy, not a claim of unrestricted
  model tool-selection accuracy.
- A real model generated the hypothesis and selected the subsequent typed
  investigation. Its execution and vulnerability confirmation remain pending;
  this is a completed bounded discovery investigation, not autonomous exploitation.
- Live model accounting: **3 calls, 2,947 reported tokens, zero unknown-usage calls,
  $0.00**. All three calls used local Qwen3; no OpenRouter request was made.
- Six synthetic local planning cases: all six tool names matched; initial
  parameter fidelity **5/6**. The stronger-prose ffuf retest also failed; the
  structured exact-dictionary retest passed. Final constrained cases cover all
  six capabilities. Across those eight calls: **3,749 reported tokens**, $0.00.
- Exploratory authenticated API runs retained **21** local model-attempt rows,
  including the accepted run: **14,986 reported tokens**, with **six** timeout or
  cancellation attempts lacking reported token totals. Adding the eight semantic
  calls and the 413-token minimal reproduction gives **30 physical local calls**
  and **at least 19,148 reported tokens** across the mission. Unknown exploratory
  usage is not presented as zero. No paid model endpoint was called.

The live run used the normal application on temporary loopback port 7002 with
`LLM_ROUTING=local`; `.env` was preserved when it was found to select cloud routing
on continuation. Existing ARIA PostgreSQL/Redis containers were started after
being found stopped. No Fedora system configuration, worker profile, worker
resource limit, Kali networking or target configuration changed. Both lab VMs
and the target's `52:54:00:77:00:20` / `192.168.77.20` lease were reverified.

Private receipts, transcripts, usage and fixtures remain under
`.local-lab/intelligence/` and the owned SQL ledgers. The reproducible API harness
is `integration/autonomous_intelligence_lab.py`; it requires a private token file,
supplies no action sequence and leaves approvals to the ordinary API/UI.

Final code validation: **634 Python tests passed in 25.413 seconds**; frontend
contracts and whitespace checks passed. Additional focused context/checkpoint/
intelligence tests passed after transcript grounding changes. The actual typed
review response is a fixture that checks that server facts and path criteria
replace unsupported model wording without inventing new model evidence.

Rollback is a code revert of the intelligence commit followed by an application
restart. There is no new dependency, database migration, worker image/profile or
resource setting to roll back. Keep the private evidence and failed-run ledgers.

## OpenRouter migration — pending paid acceptance (2026-11-14)

The working branch was already at `350ceed`, a descendant of the requested
`f30f958`; existing history and environment settings were retained. The existing
active OpenRouter key was located in `user_api_keys`, encrypted with the existing
Fernet key. No credential was printed or copied. `LLM_POOL` is not a configuration
variable in this revision: `LLMPoolManager` loads per-user SQL keys;
`BaseAgent.query_llm_smart` delegates task routing to that pool.

OpenRouter's public `/api/v1/models` catalog was retrieved on this date:

| Model | Input USD/M tokens | Output USD/M tokens | Context | Advertised JSON schema |
| --- | ---: | ---: | ---: | --- |
| `deepseek/deepseek-v4-flash` | 0.09 | 0.18 | 1,048,576 | yes |
| `deepseek/deepseek-v3.2` | 0.26 | 0.38 | 163,840 | yes |
| `moonshotai/kimi-k2.5` | 0.50 | 2.50 | 262,144 | yes |

Source: <https://openrouter.ai/api/v1/models>. Catalog support is not proof of
live Pydantic compliance. Kimi was not selected: listed output prices exceed
both DeepSeek candidates. V4 Flash is the new default only where no explicit
OpenRouter model is configured. Planning, analysis and review prefer OpenRouter;
existing other-provider settings and local selection remain available.
The transport forwards the existing context-local planning JSON schema, requires
provider parameter support, disables OpenRouter provider fallback and caps output
at configurable `OPENROUTER_MAX_OUTPUT_TOKENS` (at most 4096). A failed physical
OpenRouter request returns failure without switching providers. Pool requests
share a configurable process semaphore (default one), in addition to per-user
serialization. The deployment still requires one application worker.

The budget button previously refused all saves unless the separate team-load
button had first populated internal state. Approval now fetches the current
owner-scoped ledger itself, preserves other tariffs and submits a PUT to
`/api/team/{session_id}/model-budget`. API validation errors now render their
JSON detail instead of `[object Object]`. The backend validates `ModelLimits`,
locks the active owned engagement, writes limits to session metadata and commits
a human-involved decision record. Refresh reads the persisted ledger. Default
cost ceiling is $2; a hosted call still requires an explicitly saved exact-model
tariff. Defaults do not authorize hosted spending.

Each physical call reserves byte-bounded input plus an 8192-token allowance in
SQL before provider I/O. Call, token and conservative cost ceilings are checked
under the engagement row lock. Settlement records actual provider-reported token
and micro-USD usage exactly once. Missing usage retains the full reservation;
a successful OpenRouter response missing tokens or cost stops subsequent calls.
Reservations are not refunded, so exhaustion can occur before actual cost reaches
the spending limit. A restarted/cancelled request cannot erase its charge.
Existing campaign and task budgets and execution authorization remain enforced.

Validation so far: 635 offline Python regressions passed, frontend contracts
passed, and `node tests/team_budget_button.cjs` verifies approval without prior
loading and preservation of other tariffs. The new transport regression checks
schema forwarding, the output cap and actual usage parsing. No worker profile,
resource limit or networking changes were made.

Paid acceptance is pending explicit owner approval using the actual UI. No paid
inference was issued by this migration session. No hosted latency, Pydantic live
compliance, cost per investigation or discovery improvement is claimed. The
previous Qwen baseline above remains the only completed live investigation.

The manual tariff procedure and public catalog prices above describe the earlier
checkpoint. The authenticated endpoint resolution below supersedes that procedure
and those prices. Keep private tokens untracked; execution approvals remain separate.

## OpenRouter activation repair — owner approval boundary (2026-11-14)

The existing development branch and pre-existing working-tree changes were
preserved. Part A is implemented through non-billable verification and browser
regression acceptance. **Paid acceptance and Part B remain pending.**

### Diagnosed blockers and configuration

The real acceptance engagement `1f2e2cd2-c37d-4c00-a1ba-5134705f89dd`
had **no `model_limits` or `model_usage` metadata**, not merely a stale button.
It has one active encrypted OpenRouter key in its owner's SQL key records.
The tariff was therefore the immediate blocker. Additional defects were the
absence of authenticated price discovery, expiry validation, upstream endpoint
binding and a distinction between proposed limits and persisted approval.
The real workspace was initially unreachable on port 7002; it was started using
the existing environment and one Uvicorn worker. PostgreSQL and Redis were
reachable; no container, worker profile, OS security setting or resource limit
was changed. Playwright and Chromium were already installed.

The existing key was decrypted only in memory. Authenticated non-billable GETs
to `/api/v1/key`, `/api/v1/models/user`, and the V4 Flash endpoint catalog returned
HTTP 200. The account catalog includes V4 Flash and V3.2 and advertises
`response_format` and `structured_outputs` for both. This verifies authentication
and catalog availability; live inference, upstream availability and actual schema
compliance require the later paid acceptance. No key, key fragment or key-account
metadata was printed or included in the evidence artifacts.

Current authenticated account catalog, retrieved during this repair:

| Model | Catalog input USD/M | Catalog output USD/M |
| --- | ---: | ---: |
| `deepseek/deepseek-v4-flash` | 0.014 | 0.45 |
| `deepseek/deepseek-v3.2` | 0.2088 | 0.3096 |
| `moonshotai/kimi-k2.5` | 0.49 | 2.50 |

Catalog prices can refer to a different upstream than one supporting the required
parameters. The resolver therefore selects a priced, available endpoint advertising
structured outputs, temperature and output limits, and rejects additional nonzero
charges it cannot account for. Kimi K2.5 showed no price advantage in this check;
no Kimi model was selected or inferred against.

### Effective tariff and approval semantics

The persisted real quote selects **OpenRouter / `deepseek/deepseek-v4-flash` /
`baidu/fp8`**, input **$0.0147/M**, output **$0.0294/M**; conservative combined
reservation rate **$0.0294/M tokens** (29,400 micro-USD per million tokens).
This is a live provider-advertised discounted rate, not an assumed permanent price.
Source: [OpenRouter endpoint catalog](https://openrouter.ai/api/v1/models/deepseek/deepseek-v4-flash/endpoints).
The UI shows retrieval/expiry metadata; quotes expire after 24 hours. Refreshing
a quote changes its identity and requires approval again, even if prices match.

`POST /api/team/{id}/model-tariff/refresh` checks engagement ownership, authenticates
the existing owner key, resolves the configured model, and saves the quote and
an audit decision in SQL. **It never writes spending limits or approval.**
`PUT .../model-budget` validates that OpenRouter tariffs match the saved quote's
provider, model, identity, rate and expiry before writing a human-involved approval
and timestamp. Invalid, missing, expired or altered quotes fail closed. Unknown
models cannot be approved by inventing a tariff. Other providers retain their
existing manual conservative tariff mechanism.

Every OpenRouter attempt reserves under the existing owned engagement row lock
before provider I/O, includes the structured schema in its byte-based token bound,
and carries its quote into the attempt audit record. The transport pins that
upstream and sends `max_price` input/output caps, disables fallbacks and requires
parameter support. A rate increase or unavailable endpoint must fail rather than
silently change model or upstream. Reservations remain charged after settlement;
changing limits retains all usage. Unknown OpenRouter tokens or costs now stop
later calls even after an unsuccessful response/timeout. Incomplete responses and
model mismatches are rejected while retaining any reported usage for settlement.
Pricing caps follow [OpenRouter's documented provider routing](https://github.com/OpenRouterTeam/docs/blob/main/guides/routing/provider-selection.mdx).

### Chromium and regression evidence

Reproduce with `.venv/bin/python -m integration.openrouter_budget_browser` while
ARIA runs at `http://127.0.0.1:7002`. The harness uses the existing private token
file, creates a uniquely named disposable `aria_budget_*_test` PostgreSQL database,
applies real Alembic migrations and runs the actual application on port 17012 with
only provider discovery mocked. It uses real HTTP requests, UI clicks and SQL
persistence; there are no browser route fixtures for successful test approval.
Test databases are retained for inspection. Chromium runs with
`chromium_sandbox=True`; no sandbox-disabling flag or system change is used.

Browser checks passed:

- Real workspace/session selection, configured provider/model, non-billable key
  verification, effective tariff display, persistence after reload, and pending
  owner approval. A mutation guard prevents the real browser from approving,
  starting inference or executing tools.
- Missing pricing disables approval; provider failure appears visibly and keeps
  approval blocked. The refresh button shows its disabled/loading state.
- Invalid limits return a visible API validation error; a corrected approval
  saves the exact $2 ceiling, and reload restores it from PostgreSQL.
- Synthetic usage is reserved and settled; a subsequent call is denied at the
  call ceiling. Lowering the cost ceiling retains usage and denies another
  reservation. Unknown models, altered rates and expired quotes are rejected.
- A different real test identity cannot read, approve or refresh another owner's
  engagement. These negative checks use only the disposable database.

Private artifacts under `.local-lab/openrouter-activation/`:
`provider-verification.json`, `browser-result.json`, `synthetic-approved.png`,
`real-pending-approval.png`, `fixture-server.log`, and `offline-tests.log`.
No browser trace is saved because traces can capture bearer headers. Screenshots
and sanitized result files are retained instead.

Final validation: **640 Python tests passed in 29.251 seconds** using
`.venv/bin/python -m unittest discover -s tests -t . -q`;
`node tests/frontend_contracts.cjs`, `node tests/team_budget_button.cjs`, and
`git diff --check` passed. Final Chromium acceptance passed against disposable
database `aria_budget_42af74c60f_test`. The real quote was retrieved at
`2026-11-14T17:11:19.118115+00:00` and expires at
`2026-11-15T17:11:19.118115+00:00`. Real ARIA remains running on loopback port 7002
with the final code; the fixture server was stopped after acceptance.

Source changes: `llm/provider_tariffs.py`, the budget ledger and OpenRouter
transport/pool, owner-scoped team API, and the existing team budget controls.
New offline tariff tests exercise bad/zero/nonfinite prices, unsupported endpoints,
expiry, forged quotes and sanitized authentication failures. Accounting tests
cover schema reservation and fail-closed unknown costs. The browser harness and
guarded fixture application live in `integration/openrouter_budget_browser.py`
and `integration/openrouter_budget_fixture.py`. No dependency or database schema
migration was introduced by this repair; quotes use engagement metadata and audit
decisions.

### Exact pending owner action and remaining mission

In the real workspace, select the **OpenRouter budget acceptance** engagement,
open Settings → Team tasks and evidence → Load saved team work → Shared model
budget. Inspect the verified V4 Flash tariff, leave the proposed ceiling at **$2**
(20 calls / 200,000 reserved tokens), and personally click **Approve spending
limit**. If the quote expired, verify/refresh it first. Automation has left the
engagement pending with no approval, no model attempts and no reported usage.

**Real paid inference calls: 0; repair spending: $0.** No actual input/output costs,
live structured planner result, paid settlement or paid exhaustion are claimed.
After the owner approves through ARIA, minimal live acceptance must verify those
properties under the cumulative $2 ceiling and stop if actual accounting cannot
be reconciled. V3.2 is comparison metadata only; no paid model switch is authorized.

Part B has deliberately not started. No new intelligence lifecycle, laboratory
vulnerability discovery or Qwen/DeepSeek benchmark comparison is claimed by this
activation repair. Confirmed/rejected laboratory vulnerability findings added:
**0/0**. The earlier bounded Qwen discovery remains the baseline. Progress toward
the 8-hours/day, 5-days/week objective is currently activation infrastructure and
budget verification; autonomous research readiness and cost per confirmed finding
remain unmeasured.

## Validated continuation — Part A and research architecture (2026-11-14)

### Review of changes since the last commit

The checkout remains based on `350ceed`. All existing uncommitted changes were
preserved, including tariff discovery, budget controls, transport accounting,
research modules and acceptance harnesses. No commit was reverted. Review found
that this document's pending-approval statements were obsolete: the owner had
approved the exact-model $2 budget at **17:17:23 UTC**, and private receipts already
contained paid smoke/planner acceptance and two failed comparison attempts.
Those original artifacts were retained rather than overwritten or treated as new
inference. No additional spending approval or model switch was required.

### Part A: actual authentication, tariff, browser and paid acceptance

The original missing-tariff diagnosis remains valid. The exact-model quote,
separate owner approval and persistent SQL reservations now unblock the normal
OpenRouter pool. The active configuration is `LLM_ROUTING=cloud`,
`OPENROUTER_MODEL=deepseek/deepseek-v4-flash`, a maximum of 4096 output tokens,
and one application worker. Credentials remain encrypted in the owner's SQL key
records; no `.env`, provider credential or private evidence was committed.

Fresh non-billable authentication/account-model/endpoint requests passed at
**18:38:36 UTC**. The eligible endpoint was again **`baidu/fp8`**, advertising
**$0.0147/M input** and **$0.0294/M output**. The quote already approved by the
owner was left intact; its retrieval/expiry times are **17:16:27 UTC November 14**
and **17:16:27 UTC November 15**. These are observed rates, not permanent prices.
[Provider endpoint source](https://openrouter.ai/api/v1/models/deepseek/deepseek-v4-flash/endpoints).

The owner's saved limits are **20 calls, 200,000 reserved tokens and $2**. Refresh
pricing only when needed, inspect the new quote and personally approve its exact
identity. Refreshing invalidates the preceding quote approval. Every physical
hosted attempt reserves before I/O, pins the approved endpoint and price caps,
disables fallback, and settles actual usage once. Limits changes retain usage;
unknown usage/cost still stops later calls. Execution authorization remains a
separate requirement.

The actual UI was restarted at `http://127.0.0.1:7002`, using PostgreSQL/Redis and
one Uvicorn worker. `.venv/bin/python -m integration.openrouter_budget_browser`
passed with real sandbox-enabled Chromium. Its final disposable database was
`aria_budget_fc36d3e30a_test`; only its provider discovery was mocked. Real
engagement requests were restricted to reads: the harness did not refresh the
approved quote, approve spending, generate inference or dispatch tools.

Browser acceptance covers missing/expired pricing, visible provider/validation
errors, SQL-persisted $2 approval after reload, reservation/settlement and call/cost
ceilings, forged/unknown tariffs and cross-owner denial. The new persistent
research panel also passed real API/SQL creation and reload, displaying supporting
evidence, alternatives, controls, uncertainty and history. A hypothesis containing
`<img>` rendered as text, with no injected image element. The real engagement's
approved tariff/budget survived reload unchanged.

The original smoke response was valid `{"ready":true}` with reconciled usage.
Its harness initially marked failure because the optional historical generation
lookup returned 404; `smoke-reconciliation.json` records a non-billable correction.
No second smoke inference was substituted. Response usage is the accounting
source; the unavailable generation record remains disclosed. The real structured
planner then returned an admissible typed Nmap plan, passed ordinary adapter/scope
validation and dispatched **no tool**. Real token-exhaustion preflight rejected an
oversized request without altering the ledger; monetary/call ceilings were
exercised in disposable PostgreSQL browser acceptance.

Final reconciliation, including the original failed benchmark call:

| Measurement | Actual result |
| --- | ---: |
| Hosted physical calls | 6: 5 successful responses, 1 failed response |
| Provider-reported tokens | 15,639 |
| Actual input charge | $0.0001406496 |
| Actual output charge | $0.0001784874 |
| Actual total charge | **$0.0003191370** |
| SQL settled cost, rounded upward per call | 322 micro-USD |
| Conservative retained reservations | 81,175 tokens / 2,389 micro-USD |
| Unknown token/cost calls | 0 / 0 |
| Budget ledger stopped | false |

The smoke cost was $0.0000053802; planner cost $0.0000221088; the failed original
benchmark cost $0.0000755139; the successful revised comparison cost $0.0002161341.
Each receipt reconciles input/output components, total cost, token totals, tariff
ceilings and SQL settlement. A failed output may have a fully reconciled bill:
that does not turn it into valid model output.

### Implemented intelligence architecture

`memory/research.py` adds an owner-bound immutable event projection using the
existing team/decision ledger. It supports up to 500 simultaneous hypotheses,
idempotent creation, revision conflicts, bounded history, and
`OBSERVED → HYPOTHESIZED → PLANNED → TESTED → CONFIRMED / REJECTED / INCONCLUSIVE`.
Inconclusive investigations can reopen with refreshed context. Each hypothesis
stores evidence references, alternative explanations, related graph entities,
prerequisites, validation strategy, positive/negative controls, confidence,
uncertainty, prioritization inputs, history and final state.

The queue ranks by `(0.4 × information value + 0.4 × security relevance +
0.2 × feasibility) / (1 + estimated cost in USD)`. These scores are planning
estimates, not calibrated probabilities. Current top hypotheses, evidence IDs,
controls, cost estimates and a bounded application graph enter the planner's
specialist context. They never grant execution authority or satisfy completion.

The application model represents assets/components, endpoints, authentication,
sessions, identities, roles/permissions, owned objects, workflows, states,
services and trust boundaries. Typed relations express ownership, authentication,
role assumption, authorization, calls, data flows and state transitions. Locators
must pass existing scope policy and cannot contain credentials, queries or
fragments. Graph assertions require cataloged evidence and retain uncertainty;
a list of endpoints is not treated as a complete model.

Review corrected a concrete stale-context defect: graph scope/evidence changes
previously could survive a hypothesis reopen. Graphs now snapshot their evidence
hashes and scope; stale graphs invalidate dependent queues and cannot enter
planner context. Creating or reopening investigations against them fails until
the graph is revalidated. Changed hypothesis evidence and changed graph revisions
also require revalidation. Historical graphs without the new snapshot fail closed.

Autonomous receipt-bound reviews now accept up to three proposals and persist
them idempotently. Collected specialist results project into the same store with
deterministic identities; a crash before projection is repaired when context is
loaded again. Existing specialists receive shared structured hypotheses and
controls. Correlation explicitly challenges discovery claims. This reuses the
existing specialists instead of creating additional model agents.

`orchestrator/research_verifier.py` is a separate deterministic verification
specialist. It consumes original captures and recorded controls, not the discovery
prompt. It rechecks owner/outsider/negative content, scoped capture provenance,
current evidence, distinct discovery/reproduction sources, and existing human
review/signoff. Research confirmation requires that verifier and a linked
reportable finding; scanner output, model confidence or two agreeing explanations
cannot confirm anything. A later expired or altered capture removes displayed
confirmation. Current production confirmation supports the existing private-JSON
content-control contract; other impact types are still a limitation.

New owner-authenticated endpoints under `/api/team/{session_id}`:

- `GET /research`: current model, hypotheses and prioritized queue.
- `POST /research/hypotheses`: evidence-bound candidate creation.
- `POST /research/hypotheses/{id}/transition`: revision-checked lifecycle changes.
- `PUT /research/application-model`: evidence/scoped semantic graph replacement.

The existing team panel displays persistent research using safe text nodes.
Planning/testing records grant no worker, browser-action or approval authority.
All existing authorization, receipt, isolation, human approval and audit paths
remain in place. No Kali, Metasploitable, worker profile or resource limit changed.

### Reproduced failures and corrections

The original all-at-once Qwen comparison timed out after 180.245 seconds. The
original DeepSeek attempt failed the transport completeness/model check and
reported exactly 768 completion tokens, its output cap. That strongly suggests
truncation, but its historical finish reason was not saved, so the precise reason
cannot be recovered. Its cost was nevertheless known and settled.

The old acceptance helper incorrectly required every historical attempt to have
succeeded before reconciling billing; this obscured the useful response error.
Billing reconciliation now explicitly accepts failed attempts with complete,
consistent receipts, while successful-output checks remain separate. Unknown
costs still block continuation. Transport receipts now retain bounded finish
reasons; SQL settlement retains the safe error code, and truncation has an
explicit error. No response content or hidden reasoning is added to that ledger.

The revised benchmark uses three six-case batches and an explicit 2048-token
output context for both transports, bounded at 4096 and by the hosted configuration.
It preserves default transport limits elsewhere and resets context after the run.
Named run directories preserve prior failures. Each batch checkpoints candidates,
usage and errors; no automatic retry occurs. The independent lab verifier now
recomputes controls and violations from observations instead of trusting discovery
booleans, and rejects mismatched source identities and changed response content.

### Laboratory findings and equivalent model comparison

`evaluation/research_lab.py` implements 18 secure/vulnerable ASGI fixtures across
nine labeled research classes: IDOR/BOLA, access control, authentication/session,
API authorization, business logic, input validation, cross-service trust,
information disclosure and multi-step workflow. All identities/data are synthetic;
all requests stay in-process. Fresh fixture instances provide independent
reproduction with positive and negative controls. No external target/worker ran.

These classes use three simplified control patterns. In particular, an index
validation case is not a database injection exploit, and the cross-service case
is not a deployed multi-service environment. The model sees normalized HTTP
observations from deterministic probes and chooses candidates and verification
templates. This measures research triage, not autonomous collection or production
vulnerability recall.

The revised run `batched-v2` used identical observations, schemas, order and output
caps for both models. Input digest:
`2902aefaa2489cbc301ea01ee95f1e97a40af15eb66f6d33e3080ed62d2917a7`.
`integration.research_comparison` checks those equivalence properties without
making another model call.

| Metric | Qwen3:4B instruct | DeepSeek V4 Flash |
| --- | ---: | ---: |
| Completed model calls | 3 | 3 |
| Independently confirmed synthetic violations | 7/9 | 8/9 |
| Confirmed false positives / secure fixtures | 0/9 | 0/9 |
| Candidate false positives / secure fixtures | 3/9 | 0/9 |
| Verified labeled-class coverage | 7/9 | 8/9 |
| Independent confirmation / all selected candidates | 7/12 | 8/9 |
| Verification-template accuracy | 9/12 | 8/9 |
| Mean investigation depth, discovery + reproduction | 1.500 | 1.444 |
| Controlled fixture requests | 87 | 83 |
| Total model/verification wall time | 337.983 s | 56.995 s |
| Provider-reported tokens | 4,512 | 9,816 |
| Provider charge | $0 | $0.0002161341 |
| Tokens per confirmed synthetic finding | 644.57 | 1,227 |
| Charge per confirmed synthetic finding | $0 | $0.0000270167625 |
| Failed calls / automatic retries in revised run | 0 / 0 | 0 / 0 |

DeepSeek selected all nine vulnerable cases but chose `integer_control` instead of
`workflow_control` for the negative-quantity business-logic case `c00`. The server
withheld confirmation for that wrong strategy. Qwen also chose the wrong strategy
for `c00` and for the input-validation case `c06`; it proposed secure `c02`, `c05`
and `c11`. Secure responses/controls and incompatible strategies prevented those
from becoming findings. Confirmed DeepSeek cases were `c04`, `c06`, `c07`, `c08`,
`c09`, `c13`, `c15`, `c16`. Qwen confirmed that set minus `c06`.

Separately, `.venv/bin/python -m integration.research_lab_acceptance` challenged
**all 18** fixtures using their correct test templates: **9 reproduced synthetic
violations and 9 rejected secure hypotheses**, with 116 controlled requests and
zero model calls. This verifies the verifier; it is not additional model discovery
and must not be added to the model finding counts. Production findings added: **0**.

Both models supplied nonempty explanation fields, but many restated the suspected
violation instead of presenting an alternative explanation. The retained
`hypothesis_alternative_completeness` metric in these artifacts measures only
nonempty syntax; future runs name it `hypothesis_alternative_nonempty_rate`.
Substantive hypothesis quality is not established by that number. Confidence is
not calibrated. Hardware/energy and operator time are excluded from local cost.
The observed wall-time ratio is about 5.93, from one small run; it is not a general
performance ranking. Provider tokenization/reasoning differ, and transport
deadlines remain 180 seconds local versus 90 seconds hosted.

Across original and revised comparison calls, each arm had one failed original
call followed by three successful revised calls. Recovery required an engineering
change to batching/output limits and a deliberately named rerun, not automatic
recovery. Unknown token usage for the original local timeout remains unknown.

### Source changes, validation and reproduction

Core changes are in `memory/research.py`, `memory/team_tasks.py`,
`agents/autonomous_engine.py`, `agents/orchestrator_agent.py`,
`agents/base_agent.py`, `orchestrator/team_coordinator.py`,
`orchestrator/research_verifier.py`, and `api/routers/team.py`. Provider work is in
`llm/provider_tariffs.py`, `llm/engagement_budget.py`, `llm/openrouter_client.py`,
`llm/local_client.py`, `llm/base_llm.py`, `llm/pool_manager.py` and
`config/settings.py`. The existing web page, team script and API-error rendering
were extended. No dependency or database schema migration was needed; research
and quote records use existing owner-bound ledgers.

Acceptance modules are `integration/openrouter_budget_browser.py`,
`integration/openrouter_budget_fixture.py`,
`integration/openrouter_paid_acceptance.py`, `integration/research_postgres.py`,
`integration/research_benchmark.py`, `integration/research_comparison.py`, and
`integration/research_lab_acceptance.py`. Focused offline tests cover tariff
forgery/expiry, hosted schema/usage/truncation, lifecycle/idempotency/conflicts,
graph invalidation, planner grounding, real-content confirmation and false-positive
rejection. Existing execution/ownership/cancellation regressions remain intact.

Run from the repository root:

```bash
.venv/bin/python -m unittest discover -s tests -t . -q
node tests/frontend_contracts.cjs
node tests/team_budget_button.cjs
.venv/bin/python -m integration.research_lab_acceptance
.venv/bin/python -m integration.research_postgres
.venv/bin/python -m integration.openrouter_budget_browser
.venv/bin/python -m integration.research_comparison --run-id batched-v2
```

The PostgreSQL/browser commands require the existing local services and create
fresh disposable `*_test` databases, retained for inspection. The browser also
requires the private owner token and loopback API. Do not run migrations against
an existing populated database to reproduce these disposable tests.

Paid reproduction, only while the exact quote and owner budget remain valid:

```bash
.venv/bin/python -m integration.research_benchmark qwen --run-id NEW_RUN_NAME
.venv/bin/python -m integration.research_benchmark deepseek --run-id NEW_RUN_NAME
.venv/bin/python -m integration.research_comparison --run-id NEW_RUN_NAME
```

Run the arms sequentially when creating a new observation file. A prior named arm
is never overwritten. Before another paid call, inspect and reconcile all prior
attempts; stop on an unknown or inconsistent charge. This continuation made no
further paid calls after the completed three-batch DeepSeek comparison.

Disposable PostgreSQL research acceptance passed on
`aria_research_63d2684c0c_test`: real migrations/evidence/model persistence,
idempotent retries, concurrent revision conflict, reconstruction after pool
restart, cross-owner denial and scope invalidation. Browser acceptance passed on
`aria_budget_fc36d3e30a_test`. Full Python regression validation passed
**656 tests in 31.123 seconds**; focused planner/specialist context checks also
passed (33 tests). The loopback API was restarted with the final code and its
existing single-worker configuration.
Frontend contracts, budget-button checks, JavaScript syntax and whitespace checks
passed.

Private evidence remains untracked under `.local-lab/openrouter-paid/`,
`.local-lab/openrouter-activation/`, and `.local-lab/research-benchmark/`.
Key files include `final-ledger-summary.json`, `current-provider-verification.json`,
`browser-result.json`, `synthetic-research.png`, `real-current-budget.png`,
`verifier-acceptance.json`, `postgres-result.json`, and
`batched-v2/{qwen,deepseek,comparison}.json`. No credential-bearing browser traces
were produced.

### Remaining limitations and measured progress toward 8/5

The persistent lifecycle, semantic model, bounded planner context, independent
content verifier, UI inspection and repeatable model comparison are implemented
and exercised. This is measurable engineering progress; no eight-hour/day or
five-day/week autonomous endurance run was attempted, and no equivalent senior
researcher workload was measured. An 8/5 readiness percentage would be invented.

Automatic multi-step application exploration, automatic full semantic-model
construction, production verification for business-state/injection/session
impacts, substantive hypothesis-quality scoring and calibrated uncertainty remain
incomplete. Existing bounded tool eligibility and approvals still constrain
research execution; adding a lifecycle does not add tool capabilities. The
laboratory is transparent and small, and cannot establish complex-application
coverage, real-world false-positive rate or general cost per finding. Independent
saved-content verification retains human review/signoff. The deployment remains
single-process. Long-duration recovery, multiple repeated benchmark seeds,
real multi-service laboratories and authorized complex-app acceptance are needed
before claiming the requested operational target.

### Exact live prerequisite boundary

A final read-only inspection found **no owned engagement with application mapping
or authorized authenticated replay**, and the existing worker advertised
`authenticated_http_version=0` and `specialist_http_version=0`. Its advertised
ordinary tools were curl, ffuf, httpx, nmap, nuclei, semgrep and subfinder. The
sanitized inspection is retained in `live-prerequisites.json`; no scope was
changed and no tool was dispatched by that inspection.

Further live authenticated/multi-step acceptance therefore requires the owner to
supply or provision an explicitly scoped complex laboratory application with two
controlled identities, synthetic owned objects and reviewed permission/workflow
expectations. Authenticated replay and specialist profiles must be explicitly
authorized for that engagement and made available by the existing isolated
worker before such actions can execute. **Pending action: owner provision and
authorization of that lab and any required worker capability change.** This
continuation does not enable a worker profile, expand scope or manufacture
identities/authorization for an existing target. Unauthenticated discovery alone
cannot satisfy that acceptance criterion.

Canceled specialist tasks with retained results are excluded from new hypothesis
projection. A dedicated cancellation regression passed alongside graph freshness,
planner evidence grounding and production confirmation/revocation tests.
