# Submission quality and severity calibration

## Evidence before severity

Choose severity only after preconditions, demonstrated primitive, crossed boundary, affected population, required interaction, repeatability, and safe blast radius are known. Keep the score vector and the narrative impact mutually consistent.

The mask0ff validation-confidence score is not a severity score. Do not translate 80/100 validation confidence into CVSS 8.0 or any other severity rating.

Do not use high-severity labels as substitutes for evidence. In particular:

- Reflection is not command or script execution.
- A writable field is not authorization impact until a downstream trust decision is demonstrated.
- A public record is not sensitive disclosure without a private-field differential.
- An administrator-only action is not a privilege escalation unless a lower role reaches it.
- One contaminated session is not repeatability.
- A synthetic service-account command primitive does not prove root access.
- A single-object proof does not automatically establish platform-wide blast radius.

## Report invariants

- Title the security-boundary failure and resulting primitive, not the payload.
- State the attacker role and every configuration precondition early.
- State the black-, gray-, white-, or hybrid-box assessment mode and the source/deployment mapping when source is used.
- Name only controlled session labels, roles, and tenants; never include credential values, Authorization headers, cookies, signed URLs, or private keys.
- Separate observed impact from bounded potential impact.
- Include the baseline, changed variable, vulnerable result, negative control, repeat, and fix control.
- Use exact versions, commits, hashes, timestamps, and evidence IDs.
- Ensure each material claim in the finding record cites known evidence and that the report cites at least one supporting evidence ID for every claim.
- Explain why the closest public issue is the same, a variant, an incomplete fix, unrelated, or unknowable.
- Give remediation at the invariant or root-cause decision, then recommend an adjacent-path audit.
- Include a safety statement describing owned data and deliberately avoided actions.
- Treat modern-technique catalog matches as cited hypothesis leads, never as evidence that the target is vulnerable.

## Platform-neutral submission structure

Use the report template under `assets/evidence-bundle/report.md`. The same factual structure works for coordinated disclosure, vendor trackers, and common bug-bounty platforms. Adapt field labels to the platform, but do not remove controls, duplicate analysis, or uncertainty simply to shorten the report.

Before submission, run:

```powershell
.\scripts\mask0ff.cmd report E:\research\finding-work\report.md E:\research\finding-work\finding-record.json --require-reportable
.\scripts\mask0ff.cmd bundle verify E:\research\finding-work
```

## Triage communication

- Answer requests with the smallest new artifact that resolves the stated uncertainty.
- If a video is requested, keep it continuous and show version, inputs, authoritative UI or API state, and final controlled impact.
- Never combine separate runs into a misleading continuous proof.
- When a live dependency or quota blocks the last step, provide deterministic source-level evidence and clearly label what the live run did and did not complete.
- If the vendor states an internal duplicate, preserve the technical record and ask only for clarification allowed by the program; do not claim public novelty as proof against internal knowledge.
