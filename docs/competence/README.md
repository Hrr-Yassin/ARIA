# Competence engineering checkpoint

The active C15–C23 register is in GOALS.md, PLANS.md and PROGRESS.md. Original
P00–P14 criteria, accepted reliability work, blocked senior comparison and the
owner-deferred eight-hour obligation remain preserved. This program verifies
local engineering work; fresh model intelligence and full operational acceptance
remain unavailable. Source changes have not been deployed to the running owner API.

The generated audit is `reports/aria-cybersecurity-competence-audit.html`, with
`aria-cybersecurity-competence-results.json`, `aria-cybersecurity-competence-metrics.csv`
and an artifact hash index beside it. Reports and raw evidence remain untracked.
Private reproductions, failed answers, source provenance, test logs and graphical
proofs are under `.local-lab/competence/cycle01/`.

To reproduce a component measurement, choose a new output filename:

```bash
.venv/bin/python -m evaluation.competence \
  --cases evaluation/fixtures/competence/http-development-v1.json \
  --output /tmp/aria-http-reproduction.json
.venv/bin/python -m evaluation.verify_competence_audit
```

The eight named deterministic components have ten frozen criteria each. Their
80 development cases and ten separately reserved security variations are separate
cohorts. Expected mappings derive from primary standards, but authorship and grading
are engineering-authored. The reserved cases are simple same-author variations;
they cannot establish blinded independent generalization. Runtime/fixture drift
invalidates the old proof. Preserve earlier outputs and explicitly version any
future protocol; never edit expected answers or thresholds to improve a result.

The coding agent is exposed only through authenticated
`POST /api/coding/{session_id}/proposals` with an `objective` and optional explicit
text artifacts. Existing ownership and durable model accounting apply. There is
no code execution, install or deployment endpoint. Its fixed static reviewer
never imports or executes candidate Python. Static acceptance is not semantic
correctness, secure-code certification or independent review.

Burp's existing analyze action now reviews owned imported HTTP evidence
deterministically without a model call. Only supported final HTTP/1 captures on
TCP80 are imported; originals remain encrypted and redacted views expose status,
framing and duplicate fields. Missing responses remain unknown. Current desktop
compatibility is blocked by the absent JAR referenced by the Fedora launcher;
pinned API compilation and controlled-sender Java checks are separate evidence.

No new inference or target action was run. The previous actual-model benchmark
remains 3/12 decision checks, 5/10 reasoning checks, 1/2 hypothesis checks and
unavailable collaboration. The unchanged allocation has 3926 tokens remaining,
below the 8192 minimum reservation. New intelligence, generated-code quality,
specialist complementarity and balanced model comparison need an admissible
allocation. Senior equivalence requires independent human assessment; no such
reviewer is available. The input-only packet is retained for that future review.
