# P0 reasoning engine — acceptance report (2026-11-22)

## Scope

The first P0 increment adds:

- a deterministic reasoning kernel (`orchestrator/reasoning.py`);
- a persistent reasoning state on the team ledger (`memory/investigation_state.py`);
- an extended review contract and prompt (`agents/orchestrator_agent.py`, and `REVIEW_INSTRUCTION` and `review_schema` in `agents/autonomous_engine.py`);
- an evaluation harness (`evaluation/reasoning_eval.py`, fixture `evaluation/fixtures/reasoning/reasoning-cases-v1.json`).

## Verdict

| Area | Status | Evidence |
| --- | --- | --- |
| Implementation and offline behaviour | ACCEPTED (development scope) | 18 focused tests. The scripted A/B shows all behavioural metrics at 1.0 versus the pre-change emulation (below). |
| Live DeepSeek V4 Flash evaluation | BLOCKED — owner action required | No provider call was made and no money was spent. See "Live evaluation". |
| Safeguards preserved | ACCEPTED (offline) | Receipt re-verification, review journal, enum-bound citations, follow-up approval and research confirmation path are unchanged. The reasoning state grants no execution authority. |
| Static checks | ACCEPTED | Pyright 1.1.414 reports 0 errors in the new modules. The touched engine and agent files gain no errors over 19 pre-existing ones. |

P0 does **not** demonstrate general cybersecurity intelligence. The scripted cases are author-written, and the supervisor was tuned while writing them.

## Scripted evaluation

Command: `python -m evaluation.reasoning_eval --mode scripted`. It covers 7 cases and 13 cycles; the fixture sha256 starts `641467f05a10…`.

| Metric | Pre-change emulation | Reasoning engine |
| --- | --- | --- |
| Hypothesis precision | 0.81 | 1.00 |
| False-positive rejection | 0/4 | 4/4 |
| Supported retention | 1.00 | 1.00 |
| Evidence attribution | 0.95 | 1.00 |
| Contradiction handling | 0/1 | 1/1 |
| Competing explanations linked | 0/1 | 1/1 |
| Decision accuracy | 10/13 | 13/13 |
| Decision consistency | 2/3 | 3/3 |
| Replanning on evidence change | 0/1 | 1/1 |
| Redundant decisions | 1 | 0 |
| Duplicate hypothesis entries | 6 | 0 |
| Overclaims reaching research | 2 | 0 |
| Estimated prompt tokens (chars/4) | 8,707 | 14,929 (+71%) |
| Kernel CPU, all cycles | — | 6.8 ms |

## Live evaluation

The run authenticated as `labadmin` through `POST /api/login`. The token is stored with mode 0600 in `.local-lab/intelligence/auth.json` and was not displayed.

`GET /api/session/list` and `GET /api/team/{id}/model-budget` found 10 engagements with an approved DeepSeek V4 Flash budget. Every engagement with enough headroom for the planned run failed the existing read-only provider preflight:

| Engagement | Preflight result |
| --- | --- |
| c5486358, 64ff8224, 5a004f8e, ef52248a, f511cab8 | `model_provider_sharing_denied`: the application-map policy denies sharing with the model provider |
| e946e509, 1f2e2cd2, c3cd80c7 | `model_budget_denied` |
| 39a45080 | Accounting stopped (`unknown_usage`) |

The planned run was 14 calls (both arms on 7 cycles) and 178,464 reserved tokens, inside c5486358's limits of 20 calls and 200k tokens, with an actual-spend ceiling of $0.05. It stopped at preflight. Engagement usage stayed `{}` with 0 attempts: zero provider calls, zero tokens, $0. The record is in `reports/reasoning-eval/live-blocked.json`. That folder is git-ignored.

**Owner action needed.** Allow model-provider sharing in the application-map policy of one approved engagement, preferably c5486358, which is unused. Then run:

```
python -m evaluation.reasoning_eval --mode live --session-id <id> --max-calls 14 --max-cost-microusd 50000 \
  --cases banner-overclaim,competing-explanations,contradiction-retraction,evidence-change-replan
```

The runner re-checks approval, tariff, call, token and cost headroom before starting. Before each call it re-reads the settled spend and stops before the $0.05 ceiling could be crossed. It records the model identity, provider, tokens, latency, cost and schema validity for every attempt.

## Remaining offline failure

`tests.test_team_tasks.TeamTasks.test_internal_api_runs_overlapping_reviews_then_releases_dependencies` fails with a timeout. The underlying error is an assertion inside the test's fake provider: it expects `'no commands'` in the system prompt of `CorrelationAgent.review_saved`. That method and its prompt ("Exclude commands and target actions.") exist only in an uncommitted change to `agents/correlation_agent.py` made before P0 began (file mtime 12:46).

The failure reproduces with the P0 ledger and fixture edits reverted. It runs on the team coordinator's saved-review path, which calls neither the engine review nor the reasoning kernel. It **predates P0 and does not affect it**. It is left for the owner of that change.

## Limitations

- The cases are author-written over retained synthetic receipts and one retained lab observation. They are not an independent or blinded holdout.
- The baseline is an emulation of pre-change semantics. Its decision rule is "first proposed follow-up".
- Overclaim detection is lexical: a conservative floor, not semantic judgement.
- No live model measurement exists yet.
- Persistence was tested against the in-memory ledger. A disposable PostgreSQL check is still open.
