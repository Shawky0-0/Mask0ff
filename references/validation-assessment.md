# Validation assessment and persistence

The assessment is a calibrated evidence summary, not an oracle. It reports what the preserved evidence supports and what remains unknown. It must never convert a suspicion into a verified bug merely because a numeric threshold is reached.

## Run it

Run after every material evidence or gate change:

```powershell
.\scripts\mask0ff.cmd assess E:\research\finding-work\finding-record.json `
  --output E:\research\finding-work\assessment.json
```

`bundle verify` also returns the assessment summary and can write the full artifact with `--assessment-output`.

## Scores

`validation_confidence` ranges from 0 to 100 and combines:

| Component | Contribution |
|---|---:|
| Weighted gate completion, including X1 | 70% |
| Artifact integrity, claim support, controls, repeats, and independent adversarial validation | 30% |

The evidence-quality portion is divided into 25 points for valid contained artifacts, 15 for supported claims, 20 for controls distinct from the proof, 15 for repeat runs with distinct IDs and evidence sets, and 25 for a complete X1 handoff with distinct owners, a valid blind packet, independent reproduction evidence, and a bound review artifact.

State caps prevent score inflation:

| Effective state | Maximum score |
|---|---:|
| Blocked | 15 |
| Candidate | 39 |
| Substantiated | 69 |
| Verified | 89 |
| Reportable | 100 |

Authorization errors cap the score at 10. Other validation errors cap it at 29. Gate labels alone cannot earn full confidence when artifacts, claims, controls, repeats, or validator independence are weak. Self-review never earns the X1 component.

The score is not CVSS, severity, legal authorization, novelty, or a guarantee of objective truth. Severity remains deferred until `I1` passes and the finding is verified; then calculate or review CVSS from demonstrated impact and preconditions.

## Verdicts and recommendations

- `blocked`: active testing stops; passive analysis or an owned local reproduction may continue.
- `invalid-record`: repair evidence integrity or schema errors before drawing a conclusion.
- `candidate`: the signal is not demonstrated; execute the recommended next gate.
- `substantiated`: a controlled effect exists, but controls, repeatability, independent X1 validation, impact, or authorization/report gates remain.
- `verified`: the boundary failure is supported; do not escalate impact further, and finish D1/Q1.
- `reportable`: stop technical escalation, redact, and prepare authorized submission.
- `refuted-or-not-reproducible`: preserve the failed hypothesis and pivot only from a new observed signal.

Always return the verdict, score and confidence band, false-positive risk, errors, gate table, independent-validation status and evidence, severity recommendation, duplicate status, decision, continuation mode, next gate, and next safe action.

## Bounded persistence

Continue productive work while `continuation.continue_work` is true. Use `continue_technical_testing` to decide whether target interaction remains allowed; otherwise switch to the returned passive, owned-local, analysis, record-repair, or reporting mode. Do not stop merely because one hypothesis fails: log it as refuted, return to observed signals, and select the next falsifiable hypothesis.

Do not loop indefinitely:

1. If the same action fails twice, change method or reduce it to passive/local proof.
2. If the same blocker persists for three consecutive investigation cycles, mark it blocked and name the exact missing input or external decision.
3. Stop active work immediately when authorization is invalid, the next proof would be unsafe, third-party data would be required, or the safe stopping point is reached.
4. Treat `reportable`, evidence-refuted, and authorization/safety-blocked as terminal for the current hypothesis.

Persistence means always returning a useful next action or precise blocker. It does not mean repeating requests forever, bypassing controls, or escalating beyond minimum-safe proof.
