# Verification gates

Use `pending`, `pass`, `fail`, `blocked`, or `not_applicable`. Every `pass` requires evidence identifiers. Every `not_applicable` requires a reason.

| Gate | Requirement | Pass condition |
|---|---|---|
| A0 | Authorization and scope | The preserved program/owner receipt and validation artifact are hash-bound, and the exact target plus normal-testing action or group are in scope and within applicable time/policy constraints. |
| A1 | Target model | Assessment mode, assets, authenticated roles/tenants, objects, source/runtime mapping when available, state transitions, trust boundaries, and attacker control are recorded. |
| H1 | Falsifiable hypothesis | The claim names the actor, controlled input, missing or unsafe decision, boundary, and expected result. |
| B1 | Baseline | A normal or secure control establishes expected behavior before the tested change. |
| P1 | Controlled proof | Owned or synthetic data demonstrates the suspected primitive without third-party harm. |
| C1 | Controls | Negative and differential controls rule out caching, reflection, intended sharing, wrong role, stale state, and setup error as applicable. |
| R1 | Reproducibility | Two recorded independent clean-state runs with unique run IDs and distinct evidence sets agree. |
| X1 | Independent adversarial validation | A separate validator receives a hash-bound blind packet, rechecks scope, uses fresh state, reproduces with evidence not used by P1/C1/R1, replays controls, challenges alternative explanations and every essential chain link, and returns `confirmed`. Self-review cannot pass. |
| I1 | Impact boundary | Observed impact is separated from bounded inference; preconditions and blast radius are explicit. |
| S1 | Root cause | Source path, data flow, missing check, parser behavior, or strong black-box root-cause evidence is recorded. |
| V1 | Affected range | First affected, last tested, current release, and relevant configuration are recorded when versioned software is involved. |
| F1 | Fix control | The proposed fix or equivalent guard prevents the effect while preserving the legitimate path when feasible. |
| D1 | Duplicate review | Source status, both bundled public searches, and current primary-source searches are logged; likely matches are compared by root cause and path. |
| Q1 | Report quality | A vendor can reproduce safely from exact steps and evidence; claims match the proof. |

## State model

- `blocked`: A0 does not pass for active work, or required evidence cannot be obtained safely.
- `candidate`: H1 exists but the controlled proof or controls are incomplete.
- `substantiated`: B1, P1, and at least one meaningful control pass.
- `verified`: A0, B1, P1, C1, R1, X1, and I1 pass.
- `reportable`: verified plus D1 and Q1 pass; S1, V1, and F1 pass or have justified applicability statuses.

Assessment mode is separate from work mode. Black-box does not weaken evidence gates; it may make source-root-cause, affected-range, and fix-control gates `not_applicable` with reasons. White-box and hybrid work should normally produce source/deployment mapping, local regression evidence, sibling-variant review, and fix-invariant controls.

Authenticated evidence records session labels, roles, tenants, and fresh-session state. It never stores password, token, cookie, API-key, or client-certificate values.

X1 is deliberately stricter than two repeat runs. R1 may be produced by the discovery owner; X1 requires a different owner and independent reproduction artifacts. If a separate agent, model/process, qualified human, or independently operated deterministic replay is unavailable, leave X1 pending and cap the finding at `substantiated`. Read [independent-validation.md](independent-validation.md).

## Required control selection

Select controls based on failure mode:

- Authorization: correct owner, wrong owner, unauthenticated, invalid ID, intended share, role downgrade.
- State/workflow: fresh session, replay, expired object, wrong order, duplicate action, server-side state inspection.
- Injection/parser: benign literal, quoted/terminated form, invalid syntax, patched delimiter or escaping, side-effect marker.
- Client/UI approval: baseline visible action, malicious action with hidden effect, renderer differential, execution-argument capture.
- Version regression: first fixed release, suspected incomplete-fix release, current release, current source revision.
- Independent challenge: fresh environment, independently reconstructed baseline, new proof and control artifacts, explicit alternative explanations, and link-by-link exploit-chain review.

## Evidence quality rules

- Store raw artifacts and hashes when possible.
- Every material claim must name its basis (`observed`, `derived`, `inferred`, or `external-source`) and reference known evidence IDs.
- Label inferred results explicitly.
- Do not treat an error message, reflection, or model-generated claim as proof of backend impact.
- Do not infer command execution from parser behavior when a controlled side effect can safely prove it.
- Do not infer cross-tenant access from an identifier change without a controlled second tenant.
- Run the validation assessment after gate changes; use its score to locate evidence weaknesses, never as a substitute for the underlying artifacts or severity analysis.
