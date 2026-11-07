# Phase 7 benchmark and supervised pilot

Updated 2026-11-07. Owner: Codex (engineering implementation); no PR created.
Phase 7 is **partially implemented**, with offline component acceptance. The public
pilot and measured manual/single-assistant/ARIA comparison have not been run.
Earlier live acceptance gaps in Phases 4–6 remain prerequisites, not waived gates.

## Delivered

`evaluation/benchmark.py` freezes the Git base revision plus actual source hashes
(including uncommitted benchmark sources), installed package versions, Python,
fixture digest, budgets and quality targets. This baseline uses in-memory saved
HTTP evidence; there is no lab image, model identifier or executed prompt to invent.
Agent/prompt/worker source and dependency locks are hashed. A future live experiment
must additionally pin actual image digests, worker executable versions, exact model
identifiers, prompt bytes and sampling settings in its experiment protocol.
The file is a reproducibility manifest, not a signature or proof of honest input.

Six labeled controls exercise the actual `exposure_review` implementation: denied
access, private disclosure, misleading HTTP success, reordered/extra JSON fields,
a different private object, and duplicate JSON keys. The latter three are structural
variants; their public availability means they are not demonstrably unfamiliar to a
model. This evaluates one bounded private-JSON candidate detector, not all specialties,
end-to-end verification, model intelligence, bounty eligibility or generalization.
Every decision retains the complete synthetic comparison and capture hashes.

`integration/phase7_benchmark.py` also executes named existing regressions for
restart, cancellation, provider/specialist failure, storage failure, duplicate
delivery, policy revision and excluded host/path/port boundaries. These exercise
actual application boundaries with offline doubles; container/service failures
and live providers remain unmeasured. The retained JSON records test identifiers,
pass/fail and log hashes. Runner failure exits nonzero. No target traffic is emitted.

## Run and compare

From the repository root:

```sh
DEBUG=false .venv/bin/python -m integration.phase7_benchmark --output docs/phase7-baseline.json
DEBUG=false .venv/bin/python -m evaluation.benchmark --output /tmp/aria-benchmark.json
DEBUG=false .venv/bin/python -m evaluation.benchmark --runs /tmp/measured-runs.json --output /tmp/aria-comparison.json
```

The last command accepts an array with one record per measured arm. Example shape
(the `rows` array must contain all six case IDs, including no-finding decisions):

```json
[{
  "arm": "manual",
  "manifest_sha256": "copy the frozen manifest hash",
  "operator": "researcher identifier",
  "model_identifiers": ["none"],
  "protocol_sha256": "hash of the separately retained experiment protocol",
  "rows": [{
    "case_id": "secure-denial",
    "candidate": false,
    "independently_reproduced": false,
    "evidence_sha256": ["64 lowercase hex characters from retained evidence"]
  }],
  "usage": {"wall_seconds": 0, "human_seconds": 0, "requests": 0, "model_cost_usd": 0},
  "scope_violations": 0
}]
```

Use arms `manual`, `single_assistant`, `aria`. The scorer rejects omitted/duplicate
cases, missing evidence hashes, mixed manifests, duplicate arms, invalid decisions
and negative/nonfinite usage. It reports precision, recall, independent reproduction
rate, case coverage, elapsed time, human effort, requests and model cost. No candidates
means undefined precision, not perfect precision. Independent reproduction is a
human-recorded measurement requiring an independent reviewer identifier and retained
reproduction evidence hashes; the scorer cannot establish its authenticity from a flag.
All three missing arms remain visible in the published component baseline.

Before measuring, a human experiment custodian must prepare identical reset lab
states, owned accounts, evidence inputs and question sets for all arms; keep the
truth labels outside participant inputs; counterbalance arm/case order and prevent
cross-arm memory leakage. Retain raw timing, request receipts, actual provider
usage/retries/pricing and an independent researcher's reproduction package. Fix one
protocol hash across arms, record model differences, and review setup parity before
interpreting comparisons. The script checks declared manifest parity, not experimental
blinding, truthfulness or independent execution. Coverage here means classified cases;
real pilot coverage must also use the application's evidence-linked question ledger.

Common ceilings: 30 minutes wall time, 30 minutes human effort, 30 target requests,
USD 2 actual model spend per arm. These are experimental ceilings, not an activation
of traffic permission. Candidate precision target 1.0 and recall floor 0.8 prioritize
avoiding misleading claims while detecting both positive controls in this small set.
Those are provisional engineering thresholds; six cases cannot justify statistical
or public-program performance claims. Publish all misses and no-finding runs. A target
failure requires investigation, never relabeling ground truth after seeing predictions.
The comparison always reports `public_pilot_ready: false`: no score authorizes testing.

## Public policy review and proposed pilot

Read-only review on 2026-11-07: [GitHub rules](https://bounty.github.com/rules.html)
and [scope](https://bounty.github.com/scope.html). Rules require testing owned
accounts/objects without affecting other users; prohibit excessive automated traffic;
require reproducible written reports and restrict handling/disclosure of private data.
The rules also describe employment/contractor exclusions, applicable-law requirements,
and reward eligibility restrictions. No numeric request ceiling is granted by this
review. Re-fetch and save full current policy sources/hashes in the existing Phase 1
review/activation flow immediately before any pilot, including target-specific guidance,
terms and ineligible issue classes. This document is not an activated policy snapshot.

Proposed narrow area: read access to a researcher's own synthetic private repository
metadata using two researcher-controlled accounts and one explicit expected-deny
permission. Do not enumerate other users' objects. This is a fit hypothesis, not a
claim that GitHub has a vulnerability. Authenticated public-program execution remains
unsupported by ARIA's enabled profiles, so this candidate is currently blocked.
Do not bypass that boundary with manual scope or a custom executor.

Before any pilot, the owner must confirm participant eligibility, terms acceptance,
account/object ownership, exact host/route/action scope, current policy review and
explicit human supervision. Finish independent live report reproduction and the
three-arm comparison first. Use a fixed ceiling of 30 requests, one concurrent action,
at least five seconds between requests, 30 minutes and USD 2 model spend, or any
stricter program limit. Stop on policy change, uncertainty, throttling/overload, unexpected
private data, sufficient proof or any budget exhaustion. These are proposed limits;
they are not a policy assertion or support for an unavailable execution profile.

Record zero-finding outcomes explicitly. For every reportable finding retain fresh
positive/negative controls, independent reproduction and exact signed Phase 6 report.
External submission remains a human action. Use existing outcome tracking for triaged,
duplicate, informative, rejected, accepted, resolved and paid results; no submission,
acceptance or reward has occurred. After actual outcomes, retain a human decision to
improve the specialty, change program fit or expand capability, with evidence and costs.

## Requirement status

| Item | Status / remaining evidence |
| --- | --- |
| EVAL-01 | Implemented for offline saved-evidence baseline; live images/models/tools require actual experiment freeze. |
| EVAL-02 | Secure/vulnerable and structural variants implemented; genuinely unfamiliar blinded cases remain pending. |
| EVAL-03 | Validated measurement import/comparison implemented; actual three-arm measurements pending. |
| EVAL-04 | Metrics implemented; live human effort, provider cost and independent reproduction pending. |
| EVAL-05 | Seven named offline resilience/boundary regressions executed; live failure acceptance pending. |
| EVAL-06 | Component baseline published with provisional justified thresholds; comparative baseline pending. |
| EVAL-07 | Current policy reviewed and feature proposed; participant prerequisites and executable capability unresolved. |
| EVAL-08 | Not run: unsupported authenticated public-program profile, eligibility and prerequisite gates unresolved. |
| EVAL-09 | No submission outcomes exist; decision deferred until measured pilot evidence. |

No database, service, execution boundary, deployment or external submission changed.
Phase 7's full gate remains open. The isolated offline set has complete synthetic
capture linkage and zero emitted target requests; this does not establish zero scope
violations or independent reproduction in a real pilot.

## Validation

On 2026-11-07: the full offline Python suite passed (286 tests), both
`node tests/frontend_contracts.cjs` and `node tests/report_frontend_contracts.cjs`
passed, and `git diff --check` passed. The named seven-scenario runner and its
six-case actual-component baseline are retained in `phase7-baseline.json`.
No live providers, targets or owner services were used.
