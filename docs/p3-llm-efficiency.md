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
