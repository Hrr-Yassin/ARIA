# P1 multi-agent orchestration — first increment (2026-11-22)

## Audit at entry

**Already present:**

- The team ledger (`memory/team_tasks.py`) has structured tasks: objective, dependencies, evidence inputs, budget, expected output and completion criteria.
- Claim and collect are idempotent: a retried delivery never calls a specialist twice for the same run.
- Restart reconciliation blocks interrupted runs.
- Dependents claim only after their prerequisites are `completed` by owner review.
- `TeamCoordinator.run_internal` provides concurrency and dependency ordering, but only for correlation saved-evidence reviews.

**Missing:**

- a planner that delegates a structured multi-specialist plan;
- concurrent dispatch of general specialists;
- use of the P0 reasoning state in specialist planning or result interpretation;
- cross-specialist supervision;
- replanning on failure or contradiction;
- a persisted plan.

## What was added

| Component | Behaviour |
| --- | --- |
| `orchestrator/collaboration.py` `Delegation` / `DelegationPlan` | Structured delegation with key, role, objective, prerequisites, cataloged evidence, completion criteria, budget and P0 focus hypotheses. Plans are validated as acyclic with no duplicated work. |
| `CollaborationCoordinator.create_plan` | Creates ledger tasks idempotently, reuses identical live work from other plans (same role, objective, evidence and resolved prerequisites), and persists the plan in a new `orchestration_plans` ledger collection. |
| `advance` | In each round: interpret new results through the P0 kernel, supervise, replan, then dispatch every ready task concurrently (bounded by `max_concurrency`) through the existing `TeamCoordinator.run`. Run IDs are deterministic. |
| P0 integration | Specialists receive `investigation_reasoning` scoped to their evidence (`task_reasoning_context`). Results feed the shared reasoning state: duplicate claims merge, competing claims link, unsupported claims are rejected, and reviewer rejections become evidence-backed retractions. |
| Supervision | Reports unsupported claims, the same conclusion reached by several specialists, reused duplicate work, reviewer contradictions with origin attribution, and competing claims from different specialists. |
| Replanning | A failed or blocked specialist is replaced once and its queued dependents are cancelled and re-pointed. A contested hypothesis gets one targeted correlation challenge. Queued work focused only on rejected hypotheses is cancelled. |
| API | `POST /api/team/{sid}/collaboration-plans` and `POST /api/team/{sid}/collaboration-plans/{plan_id}/advance`, both owner-authenticated. |

Unchanged: the owner-review gate on dependencies, the analysis-only specialists, the evidence attribution checks in `collect`, and the absence of tool dispatch.

## Acceptance evidence

`tests/test_collaboration.py`: 8 tests. They use the real coordinator, ledger store and reasoning store over an in-memory ledger, with scripted specialists.

| Criterion | Demonstrated by |
| --- | --- |
| Two independent analyses run concurrently | A barrier requires both specialists to be inside `process` at once; max active = 2. |
| Correct dependency ordering | The cross-review stays queued until both analyses are owner-completed, including after only one is completed. |
| Shared evidence provenance | Every collected result cites only cataloged ledger evidence; reasoning hypotheses are keyed by the same IDs. |
| No duplicate execution after retry or recovery | Re-delivering a collected run returns `duplicate: true`. A fresh coordinator (restart) resumes from the ledger with zero additional specialist calls. |
| Supervisor rejects unsupported conclusions | The unhedged RCE claim is rejected with `unsupported_conclusion`. |
| Replanning on contradicting evidence | The reviewer rejects the `/admin` claim using the 404 follow-up. The claim becomes contested, and a `contradiction_challenge` delegation is created and executed. |
| Replanning on failure | A failing `vuln` specialist is replaced by `analysis-vuln~r1`, and the dependent review is re-pointed to `cross-review~r1`. |
| Persistent task and reasoning state | Plan, tasks and reasoning state are present in the materialized ledger after restart. |

## Evaluation

Command: `python -m evaluation.collaboration_eval`. Each scripted specialist call takes a fixed 0.25 s. Every arm starts from the same first-pass errors.

| Arm | True kept | False accepted | Precision | Contradictions | Duplicates in output | Calls | Prompt chars | Wall time |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Single specialist, raw | 2/2 | 2/2 | 0.50 | 0 | 1 | 1 | 1,890 | 0.32 s |
| Single + P0 supervisor | 2/2 | 1/2 | 0.67 | 0 | 0 | 1 | 1,890 | 0.28 s |
| Collaborative | 2/2 | 0/2 | 1.00 | 2 | 0 | 4 | 8,344 | 1.00 s |

The P0 supervisor alone removes the overclaim. Only the dependent cross-review, using the contradicting follow-up evidence, removes the `/admin` claim. Collaboration costs 4× the calls and about 4.4× the prompt volume.

The two independent analyses overlapped for the full 0.25 s. The review and challenge stages are dependent, so the total wall time roughly equals four serial calls. Concurrency saved one stage, and the added stages took it back.

## Remaining P1 gaps

1. **No live model measurement.** Provider usage is counted, not billed. The live run is blocked by model-provider sharing policy, the same blocker as P0.
2. **Owner review is simulated in evaluation.** In production every dependency waits for human completion, so wall time is dominated by review latency, which was not measured.
3. **Retractions match reviewer claims to hypotheses by lexical similarity (≥0.5)**, not by explicit prior-claim indices.
4. **Restart mid-run relies on the existing reconciliation** (`running` → `blocked`), followed by a single replacement. There is no disposable-PostgreSQL restart test yet.
5. **The P0 engine and specialists cite the same receipt under different identifiers** (worker job ID versus ledger evidence ID). Reasoning merges them only by claim text.
6. **No UI for plans.** Plans and supervision are visible through the API and the mission timeline stage only.
7. **The scenario is author-written and small** (one scenario, three arms). There is no independent or blinded case set.
