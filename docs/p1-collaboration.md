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

## Gap closure (2026-11-22, after commit 689ae2d)

| Gap | Resolution | Evidence |
| --- | --- | --- |
| Evidence identifiers | The ledger catalog ID is canonical. The engine catalogs worker receipts with the shared request identity (`worker_evidence_request`) and stores ledger IDs in reasoning. The model still cites job IDs, and prior support is translated back for the prompt. | Engine test; PostgreSQL: reasoning IDs ⊆ ledger catalog, no raw job IDs; research catalog identity resolves to the same entry. |
| PostgreSQL restart | `integration/collaboration_postgres.py` runs a fresh rootless postgres:16.6. The crash process is SIGKILLed during a specialist call; the restart process runs the production `team_store.recover()`, redelivers, replans and completes owner reviews. | `running` → `blocked`; redelivery returned a duplicate; the web specialist was called once; a second restart made 0 new calls; 3 reasoning cycles; 5 plan revisions; 13.8 s. |
| Wording-similarity retractions | Replaced by stable claim IDs. `professional_result` now preserves validated `claim_id` (`h-` plus 12 hex characters) and `disposition`, which were previously dropped, so real reviewer rejections never reached reasoning. A rejection binds only to a live hypothesis on the task's evidence; otherwise it is reported as `unattributed_rejections`. | Tests for a forged ID, a missing ID and a valid ID; PostgreSQL contradiction via `claim_id`. |
| Human approval for dependents | Unchanged gate, now with an explicit regression test: a dependent claim before owner completion returns 409, and the orchestrator never completes tasks. | `test_dependent_cannot_be_claimed_without_owner_completion`. |
| Unnecessary specialist calls | A challenge is skipped when a reviewer already judged the claim over a superset of its evidence. A dependent review with no live claims is cancelled. Overhead is measured. | Evaluation: 4 → 3 calls, prompt characters 8,344 → 5,784, wall time 1.00 → 0.68 s, coordinator overhead 0.14 s; quality unchanged. |

## Remaining P1 gaps

1. **No live model measurement.** Model-provider sharing is denied on every approved engagement.
2. **Owner review latency is unmeasured.** The evaluation simulates review.
3. **Recovery replaces an interrupted specialist rather than resuming it.** The interrupted attempt's provider call may have been billed. This is disclosed, and capped by one replacement.
4. **No UI for plans.**
5. **The evaluation scenario is small and author-written.**
