# P3 LLM intelligence and cost efficiency — first increment (2026-11-22)

## Constraint

The owner kept model-provider sharing **denied** on every approved engagement, so no live model call was made. This increment is therefore limited to changes whose effect can be measured offline against the frozen reasoning cases, without spending provider funds.

## Measurement before change

Per review prompt in the 13-cycle scripted set (characters):

| Component | Total | Share |
| --- | --- | --- |
| Structured-output schema | 30,334 | 51% |
| Instruction | 15,184 | 25% |
| Context (evidence, follow-ups, prior reasoning) | 14,327 | 24% |

The schema also counts toward ARIA's per-call token reservation, which limited the planned live run to 7 of 13 cycles.

## What was implemented

| Change | Where | Effect |
| --- | --- | --- |
| Schema compaction: drop generated titles and defaults, which Pydantic enforces anyway; keep required fields, enums, bounds and `additionalProperties` | `llm/context_budget.py`, `review_schema` | Lossless for the contract (tested). |
| Compact JSON context encoding | `_review_response` | Removes insignificant whitespace. |
| Review-necessity supervisor decision: skip the model review when every receipt fact is already in the reasoning state | `orchestrator/reasoning.review_needed`, engine | No call, no conclusions; the skip is recorded as an `investigation_review` event with status `skipped`. |

The instruction wording is unchanged: its quality effect cannot be measured without a model.

## Results (`python -m evaluation.reasoning_eval --mode scripted`)

> These first-increment figures exclude the evidence guidance that production appends to every system prompt, so absolute sizes are understated. Corrected figures are in the evaluation section below; the comparisons hold.

| Arm | Model calls | Prompt chars | Est. tokens |
| --- | --- | --- | --- |
| Pre-change pipeline | 13 | 34,831 | 8,707 |
| Reasoning, before P3 | 13 | 59,719 | 14,929 |
| Reasoning + compaction | 13 | 56,095 (−6.1%) | 14,023 |
| Reasoning + compaction + review gate | **10 (−23%)** | **40,978 (−31% vs before P3)** | 10,244 |

Quality is unchanged between the ungated and gated reasoning arms on every decision and safety metric: false-positive rejection, contradiction handling, decision accuracy and consistency, replanning and overclaims. Distinct supported claims live at the end of each case: **12/12 in both arms**.

Per-proposal "supported retention" falls from 1.00 to 0.76 for the gated arm. The 3 skipped cycles only restated claims that were already live, and that metric counts restatements.

## Limitations

- These are scripted development cases. Token figures are character-based estimates; billed tokens need a live run.
- The gate assumes identical receipt facts carry no new information. A model asked to re-read them could still phrase a new alternative explanation; that potential benefit is forgone.
- The deployed API has not been restarted with this increment.

## Next P3 work (blocked on owner-approved model sharing)

1. Run the capped DeepSeek V4 Flash A/B (legacy versus current prompt) to measure billed tokens, schema adherence and supervisor challenge rates.
2. Tighten the instruction (25% of characters) and measure adherence before and after.
3. Route by task: deterministic kernel decisions first, a model call only for informative reviews, and specialist calls only for live claims (already partly done in P1).

## Reasoning defect fixes (2026-11-22)

| Defect | Fix |
| --- | --- |
| Unsupported definitive claims entered research | `unhedged_assertion`: a conclusion with no uncertainty language is an assertion, not a hypothesis, and is rejected. The review instruction asks for hedged hypotheses. |
| 401/403 were not interpreted | Facts carry a typed signal: `access_denied` (401/403/forbidden/unauthorized) contradicts only claims of unauthenticated or public access to the named path, and **corroborates** existence or "behind authentication" claims. Ambiguous wording ("reachable", "exposed") gets no automatic relation. `absent` (404/410) contradicts path claims; `unreachable` (closed/filtered/refused) contradicts port claims. |
| Existence confused with accessibility | As above; tested with a single 403 against three claims (contradicts, supports, no relation). |
| Changed or missing support caused automatic rejection | Superseded or vanished support is **stale**: the claim becomes contested with `requires_revalidation`. Rejection needs contradiction with no current or stale support. |
| Completed-but-unresolved claims were dropped from planning | A claim whose analysis completed without contradicting it stays open and drives `collect_missing_information`. A contradicted claim is not reopened. |
| Prior context ignored the evidence under review | Claims about the reviewed evidence come first in `prior_reasoning`, with an omitted count. Evidence itself is never trimmed. |
| Token accounting understated every review call | Production appends `EVIDENCE_ANALYSIS_GUIDANCE` to the system prompt (`BaseAgent.query_llm_smart`). Evaluation accounting now uses that exact text; the live runner now sends it, so a live run measures the production prompt. |

Provenance (canonical ledger evidence IDs) and stable claim IDs (`h-` plus 12 hex characters) are unchanged.

## Evaluation (scripted responses; no model inference)

All sets were written by the implementation author: **not independent validation**. Each held-out set was frozen with a recorded SHA-256 before its first run (`.local-lab/p3-blinded-freeze.txt`).

**Held-out v3** (`reasoning-heldout-v3.json`, sha256 `bee71578…`). First run, identical cases:

| Metric | Pre-change pipeline | Previous kernel (`a9f0771`) | Current kernel |
| --- | --- | --- | --- |
| Supported conclusions accepted | 10/10 | 10/10 | 10/10 |
| Unsupported conclusions rejected | 0/4 | 0/4 | **4/4** |
| Contradictions handled (incl. 401/403) | 0/3 | 1/3 | **3/3** |
| Ambiguous results kept open | 3/3 | 3/3 | 3/3 |
| Changed or missing evidence contested, not rejected | 0/2 | 2/2 | 2/2 |
| Competing hypotheses linked | 0/1 | 1/1 | 1/1 |
| Replanning on evidence change | 0/2 | 2/2 | 2/2 |
| Decisions correct | 11/12 | 11/12 | **10/12** |

**Incorrect decisions in that first run:**

- `admin-401 c2`: both kernels stopped after the 401 instead of collecting information about the supported existence claim.
- `ambiguous c2`: the previous kernel was right only because it accepted a false positive.

The planning fix above (open-claim rule) was then made; after it, v3 decisions are 12/12. That figure is **contaminated**, because the fix was informed by v3.

**Earlier sets after all fixes (contaminated references).**

- v1: unsupported 6/6, contradictions 2/2, decisions 12/13. The remaining miss is a debatable label: collecting information about a new access-controlled claim.
- v2: unsupported 4/4, contradictions 3/3, decisions 9/9.
- Development set: unchanged (all 1.0).

**Cost** (production accounting, v3, 12 cycles):

| Arm | Calls | Prompt chars | Reserved tokens | Pipeline processing |
| --- | --- | --- | --- | --- |
| Pre-change | 12 | 42,418 | 140,722 | 0.7 ms |
| Previous kernel | 12 | 62,166 | 162,902 | 6.2 ms |
| Current kernel | 12 | 63,304 | 164,038 | 6.3 ms |

The review gate saved nothing on v3: every cycle brought new facts. On the development set it saves 3 of 13 calls (reserved 180,842 → 136,883). Latency is pipeline processing only; no model latency was measured.

## Live acceptance (outstanding requirement)

- **Blocked.** Engagement `c5486358` preflight returns `model_provider_sharing_denied`; zero provider calls were made.
- **Prepared run:** 14 calls (both arms, 4 development cases), 193,939 reserved tokens against a 200,000 cap, $0.05 actual-spend ceiling, production system text.
- **Owner action required:** set the application data policy (`PUT /api/application-map/{sid}/data-policy`, `provider_sharing: "redacted_metadata"`), then run:

  ```
  python -m evaluation.reasoning_eval --mode live --session-id <sid> --max-calls 14 --max-cost-microusd 50000 --cases banner-overclaim,competing-explanations,contradiction-retraction,evidence-change-replan
  ```

- **Deployment:** the deployed API has not been restarted with P3. Live engine behaviour needs an owner-approved restart; the offline evaluation does not.

**P3 is not complete.** Live acceptance is outstanding.
