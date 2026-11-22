# P2 intelligent tool integration — first increment (2026-11-22)

## Audit at entry

**Already present:**

- Ten typed adapters (`security_tools/adapters.py`, `models.py`) with strict input models, scope validation and bounded normalization. Normalization returns coarse error codes (`none`, `invalid_output`, `tool_failed`, `timeout`, `resource_exhausted`, `cancelled`, `unknown`).
- Command-bound owner approval (`ToolOperations.propose`/`execute`).
- Receipt provenance: job, request, registry and output hashes, image and declared version.
- Owner capability restrictions.
- Worker advertisement relayed by `GET /api/tool-registry`.
- Retained runtime validation (`docs/tool-adapters.md`): 6 capabilities enabled with verified receipts; katana, playwright, zap and sqlmap disabled after failing.

**Gaps:**

- No version-compatibility policy: a declared version was displayed but never compared with what was validated.
- Errors carried no retryability or operator action.
- No objective-driven tool selection.
- Typed results never reached P0 reasoning or P1 plans.
- The operator saw only "available", never "ready, and why not".

`contract_digest()` hashes the adapter files, and approvals plus the worker's advertised hash bind to it. All P2 logic is therefore in a new module, `security_tools/intelligence.py`. Approvals and worker compatibility are unaffected.

## What was added

| Area | Implementation |
| --- | --- |
| Discovery and version compatibility | `readiness()` compares each advertised capability with `VALIDATION_BASELINE` (validated version, image ID and receipt job from the retained matrix), the worker contract digest and owner blocks. The resulting status is `ready`, `unconfirmed` (pins or contract not reported), `incompatible` (version or image drift, or contract mismatch), `unvalidated`, `blocked` or `unavailable`, each with explicit reasons. |
| Typed contracts | Unchanged and reused. Recommendations are built with `encode`/`decode` and the adapter's own `validate_scope`, so every proposal is a canonical, in-scope request. |
| Output interpretation and error classification | `classify_outcome()` maps a result to `observed`, `no_observations`, `tool_failure`, `timeout`, `resource_exhausted`, `cancelled`, `malformed_output`, `truncated` or `unknown`. Each category carries retryability, an operator action and whether the evidence is usable. |
| Evidence provenance | `ingest_tool_result()` catalogs the receipt under its canonical ledger evidence ID (the same identity the engine, research and specialists use). The outcome is recorded with request and output digests, declared version and image. |
| Objective-driven selection | `select_tools()` ranks selectable, in-scope operations by the information they add to live P0 hypotheses and open dependencies, discounting unconfirmed readiness. Requests already executed (including prior outcomes in the reasoning state) are excluded. Every entry has `requires_approval: true, executed: false`. |
| P0 and P1 integration | `ToolOperations.execute` now classifies and ingests each result. Changed facts mark dependent hypotheses for revalidation. On its next advance, the P1 coordinator issues a challenge whose evidence includes the superseding tool observation. Tool outcomes appear in `planner_summary`. |
| Operator visibility | `GET /api/sessions/{sid}/tool-readiness`: per-capability status and reasons, contract state, ranked recommendations and recent classified outcomes. |

No tool was added and no execution path was changed. Nothing dispatches a tool without the existing approval.

## Deployed acceptance (2026-11-22)

**Deployment inspection.**

- The Fedora API (`aria.service`) runs from this repository through the `checkout.conf` drop-in. The owner restarted it at 18:15 with the current tree.
- The Kali worker (`aria-kali-worker.service`, `192.168.77.10:7001`, ceiling `192.168.77.20/32`, TCP 21/22/80/139/445) was inspected read-only through the operator QEMU guest-agent channel. Its contract digest was `d7a9090e…` against the API's `165dad0f…`. Of the six digested files only `adapters.py` differed: the worker ran the committed version, while the API tree carried an uncommitted owner capability-block check.
- `worker/service.py` on the worker matches `e1b4ae2`.
- Backups were taken under `/home/kali/.local/share/aria-worker/p2-backup-20261122T183022Z/`. `worker.env`, profiles, firewall, runroot and the job store were not changed.

**Execution sequence.** Each step below had owner approval in chat.

1. **httpx probe of `http://192.168.77.20`** (one GET, 1 thread, rate 1, 5 s timeout, 0 retries). The worker rejected it with 403 at admission because of the contract mismatch. No tool ran.
2. **2-file worker redeploy** (`adapters.py`, `worker/app.py`). The digest then matched in the worker app, and the worker newly reported its digest and pins. The retry reached the pinned image and failed with exit 65. The receipt was verified, and its stderr digest equals the runner's "Tool profile or output validation failed". The images bake the committed contract, so **the image is the real compatibility boundary**.
3. **Contract restored.** The capability-block check moved to `security_tools/restrictions.py`, enforced by `ExecutionAuthorization._validate` with the same 403 `capability_blocked`. `adapters.py` was returned to the committed version, the worker's copy restored from backup (keeping the `app.py` digest and pin reporting), and both services restarted.
   - API and worker both report `d7a9090e…` (`typed_contract_status: matched`).
   - All six pins equal the validation baseline: nmap 7.93, httpx 1.7.1, nuclei 3.4.10, ffuf 2.1.0, semgrep 1.99.0, subfinder 2.9.0.
   - Readiness showed 6 `ready` and 4 `unavailable`.
4. **Retry succeeded.** Job `ac5747a7-0a3e-40de-aa8b-a73ebb8c7303`: exit 0, 4.35 s.
   - Observation: `HTTP 200: Metasploitable2 - Linux`, unverified.
   - Receipt verified; image `sha256:938b67c9…`; declared version 1.7.1; request `29400a7a…`; output `f82719b3…`.

**Evidence flow.**

- Ledger evidence `2e064b9d-d9e1-52d9-9668-d16ed80b09d3` has `source_id` set to the job and `worker_receipt` provenance.
- P0 reasoning revision 2 holds the fact `o-fe9ab8d0c794` keyed by that ledger ID (no raw job IDs) and a `verification_results` entry (`observed`, registry `d7a9090e…`).
- P1 `delegations_from_reasoning` builds an analysis and a dependent cross-review over that evidence. Reviewer context offers claims on it by stable ID.
- Specialist dispatch was not run, because model sharing is denied.

**Operator view.** `GET /api/sessions/{sid}/tool-readiness` shows httpx `ready` and `runtime_verified`, with both outcomes listed. The failed attempt is ignored for readiness because it ran under a different contract digest.

**Fixes found by this acceptance.**

- Readiness now marks a capability `failing` when its latest outcome under the current digest is unusable. Advertisement is not execution.
- The ingested outcome now keeps `exit_code`.

Records are in `.local-lab/p2-worker/`: `kali-inspection.json`, `kali-file-comparison.json`, `redeploy.json`, `httpx-acceptance*.json` and `p0-p1-integration.json`.

**P2 completion criteria**

| Criterion | Status |
| --- | --- |
| Deployed worker compatible with current contracts | met |
| At least one approved tool execution succeeds | met (job `ac5747a7…`) |
| Evidence persisted | met |
| P0 consumes the evidence | met |
| P1 can use the updated state | met for plan construction and context; specialist dispatch blocked by the sharing policy |
| Operator can inspect the execution | met |
| Regressions and Pyright | met (967/968, with the one pre-existing failure) |

## Validation

- `tests/test_tool_intelligence.py`: 12 tests. They cover readiness states, including the observed live advertisement shape; outcome categories; selection, including executed, blocked and out-of-scope exclusion; and the end-to-end path from a changed tool observation through a contested hypothesis to a P1 challenge carrying the tool evidence.
- `tests/test_tool_adapter_contracts.py` still passes. It runs real `ToolOperations.execute` through a fixture worker, now including ingestion.
- Pyright reports 0 errors in the new modules.

## Remaining P2 gaps

1. **Contract changes require rebuilding the six pinned images and revalidating them.** The worker app and the images must move together. Owner policy features belong outside the digested files.
2. **Only one live capability (httpx) is runtime-verified** under the current digest.
3. **Selection rules are lexical** (claim and dependency patterns to capability), with one parameter template per tool.
4. **Scope violations in returned output are classified as `malformed_output`.** Distinguishing them would require an adapter-contract change and a new approval digest.
5. **No UI panel.** Readiness is visible through the API only.
