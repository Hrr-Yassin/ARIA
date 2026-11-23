# P5 real autonomous operational acceptance (2026-11-23)

**Verdict: partial.** Deployment, authorization, the human approval gate, real tool execution, evidence persistence, reasoning ingestion and the operator interface were accepted on the live lab. **Model-driven autonomy was not demonstrated.** Both real DeepSeek V4 Flash calls were rate-limited (HTTP 429) by OpenRouter, and ARIA's accounting then stopped model calls, as designed. No senior-engineer-level autonomy is claimed.

## 1. Actual operations

All of these ran on the deployed Fedora API and the isolated Kali worker, engagement `c5486358`.

| # | Operation | Approval | Result |
| --- | --- | --- | --- |
| 1 | Deploy P4: bundle backup (`.local-lab/p5-rollback/`), Mission Control rebuild, API restart | Owner | `/api/engagements/*` live; existing engagements reported `legacy` |
| 2 | Migrate `c5486358` to a Private Lab profile (revision 1) | Owner | Targets 192.168.77.20; ports 21/22/80/139/445; 4 typed capabilities; sqlmap prohibited; approval `all`; 20 operations/hour; 60 s cap |
| 3 | Redeploy the readiness fix | Owner | Readiness: 4 ready, Semgrep and Subfinder blocked by the profile |
| 4 | Enable model sharing (application data policy revision 1, profile revision 2), refresh tariff, re-approve budget at $0.05 | Owner | Preflight `ready`. The tariff refresh made no inference. |
| 5 | `nmap.tcp.connect.v1` on 192.168.77.20, ports 21/22/80/139/445 | Owner, recorded through ARIA (proposal `pending`, then `approved`) | Job `339f5c74…`, exit 0, 6.97 s, receipt verified, image `sha256:b8982e2e…`, nmap 7.93. **All 5 ports filtered.** Evidence `31347928…` ingested. |
| 6 | Raise the ARIA per-key request quota from 30 to 60 | Owner | Allowed the approved calls |
| 7 | Single and collaborative specialist analyses on the real httpx and nmap receipts | Owner | 2 physical calls, both **HTTP 429** (1.15 s, 1.47 s); 0 analyses completed |
| 8 | Owner reconciliation of the first 429 | Owner | Settled at full reservation (595 micro-USD); accounting resumed, then stopped again after the second 429 |
| 9 | Visible Chromium acceptance of Mission Control | — | 20 of 21 checks passed, 0 page errors |

The nmap result is correct. Read-only `virsh` showed **`aria-metasploitable2` shut off**, while the retained P2 httpx probe saw `HTTP 200` when the VM was up.

## 2. Successful and failed steps

- **Succeeded:**
  - deployment with rollback;
  - profile migration and audit;
  - profile-aware readiness;
  - human approval of a sensitive operation;
  - worker execution with a verified receipt;
  - canonical evidence and reasoning ingestion;
  - new engagements created profile-required through the UI;
  - the operator views render.
- **Failed or blocked:**
  - every model call (provider 429);
  - therefore the hypothesis → delegation → specialist → verification → replanning → report chain was not demonstrated live;
  - tool readiness is not shown in the Mission Control UI (API only).

## 3. Human interventions

The owner made 8 explicit decisions in chat:

1. the deployment;
2. the profile migration;
3. the readiness redeploy;
4. the nmap run;
5. enabling DeepSeek sharing;
6. the key quota;
7. adding reconciliation and retrying once;
8. the earlier contract decision, carried from P2.

ARIA's own gate added one in-app approval: the nmap proposal was `pending` under approval level `all`.

## 4. Reasoning quality and false positives

- **No live model reasoning was measured.** Deterministic reasoning ran on the real receipts.
- **Defect found by real evidence:** "HTTP 200 on port 80" followed by "tcp/80 filtered" raised no conflict, and the decision was `no_further_analysis`. Fixed (`f540ccc`): the conflict is now recorded and re-verification is planned. A replay of the two real receipts confirms this.
- No false finding was produced. No hypothesis existed to accept or reject.

## 5. Tool selection quality

On the live state (one HTTP fact, no hypotheses), selection proposed **only** the bounded nmap check:

- httpx was excluded because the identical request had already run;
- Semgrep and Subfinder were excluded by the profile after the readiness fix.

## 6. Execution latency

| Measurement | Result |
| --- | --- |
| nmap proposal → approval → execution | Execution 6.97 s on the worker |
| Profile panel render | 785 ms |
| Operational views | About 2.8 s each, including a 2.5 s settle wait |
| Model attempts | 1.15 s and 1.47 s to the HTTP 429 |

## 7. Model usage and cost

| Source | Figure |
| --- | --- |
| Physical OpenRouter calls | 2, both HTTP 429 |
| **Actual provider spend** | **$0** (OpenRouter key usage unchanged at $0.000476; `usage_daily` 0) |
| ARIA ledger, reported | 595 micro-USD: the conservative settlement of attempt 1 |
| ARIA ledger, reserved | 1,190 micro-USD (2 × 595) |
| ARIA ledger, unsettled | Attempt 2 still unknown |
| Accounting state | Stopped |
| Cap | $0.05, never approached |

## 8. Recovery behaviour

- **Accounting.** An unknown-usage stop halted all model work. Owner reconciliation is now available (`a6c23c1`, `c1889fc`); it settles at full reservation, is audited, and resumes accounting only when every unknown attempt is settled.
- **Collaboration.** Live runs exposed five replanning and task defects, all fixed with regression tests. The disposable PostgreSQL crash/restart acceptance still passes.

| Defect | Commit |
| --- | --- |
| Task budget below one real reservation | `464e67f` |
| Double cancel when two prerequisites fail in one round | `464e67f` |
| Queued tasks of another plan reused, causing a deadlock | `fd99571` |
| Identical replacements after deterministic denials | `464e67f`, `0a21c68` |
| Dependent key collision on sequential failures | `0a21c68` |

- **Specialist context.** Specialists previously received receipt metadata only. They now get the receipt facts and open conflicts (`aa3c694`).

## 9. Authorization compliance

- Every execution went through `ExecutionAuthorization` under the Private Lab profile with approval `all`; no unapproved dispatch occurred.
- Profile changes are audited with before and after scope digests.
- New engagements are profile-required (`af29075`). Legacy engagements keep their unchanged scope rules and can migrate only through the owner route.
- Model sharing was enabled only after explicit owner approval, at both the data policy and the profile.
- No external target was contacted, and the API/worker contract is unchanged (`d7a9090e…`).

## 10. Remaining blockers

1. **Provider availability.** OpenRouter rate-limits DeepSeek V4 Flash for this key or route. The second unknown attempt needs owner reconciliation before any retry.
2. **The lab VM `aria-metasploitable2` is shut off.** Starting it requires owner approval.
3. **The full live pipeline** (model hypotheses, delegation, specialist analysis, verification, replanning, report) and the live single-versus-collaborative comparison remain **unverified**.
4. **Tool readiness is not surfaced in Mission Control** (API only).
5. **Five of six typed capabilities are not runtime-verified** under the current digest; only httpx is.

Evidence is in `.local-lab/p5/`: `profile-migration.json`, `tool-selection.json`, `nmap-acceptance.json`, `collaboration*/`, `openrouter-key-after.json` and `browser/` (screenshots and `result.json`).
