# Autonomous investigation intelligence — 14 November 2026

This mission changes planner/analysis code only. The six worker profiles and all
worker resource limits remain unchanged. Local inference uses the configured
Ollama `qwen3:4b-instruct`; OpenRouter is not used.

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
