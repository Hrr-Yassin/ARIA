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

## Real worker compatibility evidence (read-only)

`GET /api/tool-registry` on the running lab service (authenticated as `labadmin`, 2026-11-22T17:54Z) reported the worker `online`, advertising exactly the six validated capabilities. Applying `readiness()` to that advertisement (`.local-lab/p2-worker/readiness.json`) gives:

- 0 `ready` and 6 `unconfirmed`. The worker reported no declared-version or image pins and no contract digest.
- 4 `unavailable`: the capabilities that failed validation.

The running service started 2026-11-21 and predates the code that reports the worker's contract status, so worker contract equality is **unverified**.

No tool was executed against the lab. A live typed run needs an owner-approved, command-bound proposal. This work did not self-approve one.

## Validation

- `tests/test_tool_intelligence.py`: 12 tests. They cover readiness states, including the observed live advertisement shape; outcome categories; selection, including executed, blocked and out-of-scope exclusion; and the end-to-end path from a changed tool observation through a contested hypothesis to a P1 challenge carrying the tool evidence.
- `tests/test_tool_adapter_contracts.py` still passes. It runs real `ToolOperations.execute` through a fixture worker, now including ingestion.
- Pyright reports 0 errors in the new modules.

## Remaining P2 gaps

1. **Worker pins and contract digest are not reported by the running worker or service.** Redeploying the current service and worker would let readiness reach `ready`. Owner action.
2. **No live typed run in this cycle.** One approved httpx or nmap run against `192.168.77.20` would validate ingestion end to end.
3. **Selection rules are lexical** (claim and dependency patterns to capability), with one parameter template per tool.
4. **Scope violations in returned output are classified as `malformed_output`.** Distinguishing them would require an adapter-contract change and a new approval digest.
5. **No UI panel.** Readiness is visible through the API only.
