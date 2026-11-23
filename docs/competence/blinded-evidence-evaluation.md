# Blinded saved-evidence evaluation

The frozen corpus has nine cases spanning clear positives and negatives, ambiguity, disagreement between observations, incomplete evidence, reused evidence, and an unsupported vulnerability claim. It draws on the November 22 catalog and PostgreSQL browser records, the associated synthetic archive, and a retained HTTP receipt. The questions share sources, so nine questions represent fewer than nine independent experiments. The private source manifest records each artifact digest and the field used to prepare each observation.

## Packet and submissions

Generate the packet from the repository root with the project virtual environment.

```sh
.venv/bin/python -m evaluation.blinded_evidence export --output .local-lab/intelligence-evaluation-20261122/reviewer-packet.json
```

Give each reviewer the exported packet and the submission format below. Ask reviewers to work separately and retain their first responses before any debrief. For a repeatability check, use round 2 with the same packet and keep earlier answers and grades out of view. The operator retains the corpus key, ARIA outputs, and scoring artifacts outside the reviewer packet. Reviewers attest to blinding and independence. The scorer verifies the packet binding and structure, and assessor identity depends on the recorded review process.

A reviewer file has this shape. Replace the placeholders with values from the packet and provide one decision per reviewed case.

```json
{
  "schema_version": "aria.blinded-evidence.review.v1",
  "packet_sha256": "<value from packet>",
  "reviewer_id": "reviewer-01",
  "kind": "independent_human",
  "round": 1,
  "blind_attestation": true,
  "decisions": [
    {
      "case_id": "<case ID>",
      "disposition": "<supported, rejected or inconclusive>",
      "evidence_sufficient": true,
      "confidence": 75,
      "citations": ["<observation ID>"],
      "conflicts": [],
      "rationale": "<brief evidence-based rationale>"
    }
  ]
}
```

Use the same reviewer ID for both rounds. A conflict is an unordered pair of distinct cited observation IDs from the same case. Set evidence sufficiency according to whether the records settle the claim, and report confidence in your chosen disposition.

```sh
.venv/bin/python -m evaluation.blinded_evidence score --output .local-lab/intelligence-evaluation-20261122/assessment.json reviewer-01.json reviewer-02.json
```

Omit submission files to get an intake report before independent reviews arrive. Fixture submissions use `scorer_fixture` and stay in their own cohort.

## Measurement

| Measure | Basis |
| --- | --- |
| Reviewer agreement | Pairwise exact disposition agreement and Cohen's kappa over cases shared by two first-round reviewers. Kappa is null when its denominator is zero. |
| False positives | Supported claims among reviewed cases the frozen design key rules out. Affirmations on inconclusive controls have their own denominator. |
| Evidence sufficiency | Agreement with the design key on whether the evidence settles the claim, with required citation coverage reported separately. |
| Uncertainty calibration | Brier score for the reported confidence in disposition correctness, plus accuracy and mean confidence by fixed confidence band. |
| Contradiction handling | Correct disposition and complete identification of the reference conflict pairs on answered contradiction cases. |
| Decision reproducibility | Within-reviewer disposition agreement across paired blind rounds, with case coverage stated for each round. |

Design-key comparison and independent agreement answer different questions. The key was written during corpus preparation. A unanimous independent reference requires at least two first-round reviewers and a response from every participating first-round reviewer on that case. Missing reviews, disagreements, and insufficient evidence remain visible. These small, partly shared-source controls support a calibration exercise. An independent finding-quality claim requires paired ARIA outcomes tied to the same frozen case inputs and reconciled provider receipts.

## Provider and infrastructure evidence

The existing saved-review pilot covers different frozen questions. Keep its admission, provider receipts, and model outputs separate from this packet. For a future provider cohort, preserve the actual model ID, physical request count, terminal receipt, latency, reported tokens, cost and input binding. Pair against blinded dispositions by case ID after collecting the independent references. Transport fixtures establish orchestration and accounting behavior in their stated scope.
