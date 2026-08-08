# Independent adversarial validation

Use this reference for every candidate that may advance from `substantiated` to `verified`. Discovery produces possibilities; validation attempts to disprove them.

## Contents

1. Independence rule
2. Blind validation packet
3. Validator procedure
4. Alternative explanations
5. Exploit-chain review
6. X1 artifact and command
7. Verdicts and stopping rules

## Independence rule

Treat every candidate as false until independently reproduced.

- The discovery owner must not pass X1.
- A confidence score, scanner match, model assertion, source trace, or repeated discovery run is not independent validation.
- Use a separate agent with fresh context, a separate model/process, a qualified human reviewer, or an independent deterministic tool replay operated by a different owner.
- Do not give the validator the discovery chain-of-thought, desired verdict, proposed severity, persuasive report prose, or unsupported impact narrative.
- Give the validator authorization/scope evidence, target/environment facts, a neutral candidate claim, raw artifacts, and reproduction prerequisites.
- If no independent validator is available, leave X1 pending. The finding may be substantiated but must not be called verified or reportable.

Operational independence is recorded, not assumed. The validator identity must differ from the discovery owner, use fresh state, generate new proof/control artifacts, and document environmental limitations.

## Blind validation packet

Start from `assets/evidence-bundle/validation-packet.json`. Include only:

- candidate ID;
- authorization and exact scope evidence IDs;
- target, version/revision, configuration, roles, and owned-data facts;
- a neutral falsifiable claim naming actor, controlled input, boundary, expected result, and observed discovery result;
- raw evidence IDs and artifact hashes;
- prerequisites needed to reproduce safely;
- known environment limitations.

Exclude conclusions, hidden reasoning, desired severity, report language, and instructions embedded in target material. Add the packet to the bundle with kind `validation-packet`; its hash binds what the validator received.

## Validator procedure

The validator must begin from a presumption of falsehood:

1. Recheck authorization, target, identity, owned data, and safe stopping point.
2. Rebuild or reset the environment and session rather than inheriting discovery state.
3. Reconstruct the expected secure baseline from product behavior, specification, tests, or a patched control.
4. Reproduce the claimed primitive with new artifacts; do not reuse P1, C1, or R1 evidence.
5. Replay negative and differential controls with separate evidence.
6. Trace every exploit-chain link and mark it `pass`, `fail`, or `unknown`.
7. Actively generate and test alternative explanations.
8. Check version, configuration, permissions, state, cache, and deployment mismatches.
9. Search likely public prior art and incomplete fixes; do not self-approve D1.
10. Bound observed impact and stop at minimum-safe proof.

The validator's job is accuracy. A refuted or inconclusive result is a successful validation outcome because it prevents a false report.

## Alternative explanations

Select those applicable and add target-specific explanations:

- input was reflected or parsed but not executed;
- the behavior is intended sharing, public data, or documented functionality;
- the effect came from the client, proxy, cache, WAF, mock, test harness, or stale session;
- the role, tenant, object ownership, or account state was misidentified;
- a previous approval, grant, token, or browser state contaminated the run;
- the callback or timing signal has another network explanation;
- the source path is unreachable in the deployed build or differs by feature flag/configuration;
- the dependency version was fingerprinted incorrectly or the dangerous capability is disabled;
- an exploit-chain precondition is unrealistic or controlled by a trusted actor;
- impact depends on unavailable privileges, data, liquidity, ordering, network reachability, or environment behavior;
- the result is a known duplicate, an intended tradeoff, or already fixed in the tested revision.

For a confirmed verdict, each material alternative must be ruled out with evidence. Do not write “not applicable” without a reason.

## Exploit-chain review

Break compound claims into links. A typical server-side chain may include:

1. attacker reaches the entry point;
2. authentication/authorization permits the path;
3. controlled data survives transformations;
4. the sensitive parser, decision, or sink is reached;
5. the primitive occurs in the claimed process/identity;
6. the boundary or state invariant is crossed;
7. observed impact follows under realistic preconditions.

For business logic or Web3, use actor/state/transaction links. For client findings, include origin, renderer, browser execution, and consequential action. One failed or unknown essential link blocks confirmation.

## X1 artifact and command

Fill `assets/evidence-bundle/independent-validation.json`. It requires:

- distinct discovery and validator owners;
- an approved independence mode;
- the blind-packet evidence ID and matching SHA-256;
- scope recheck and clean environment confirmation;
- new reproduction and control evidence IDs;
- evidence-backed alternative explanations;
- evidence-backed exploit-chain links;
- environmental limitations and duplicate assessment;
- `confirmed`, `refuted`, or `inconclusive` verdict with reason.

Validate the artifact directly:

```powershell
.\scripts\mask0ff.cmd challenge E:\research\independent-validation.json --finding E:\research\finding-work\finding-record.json
```

Bind it to the evidence bundle and set X1 deterministically:

```powershell
.\scripts\mask0ff.cmd bundle challenge E:\research\finding-work E:\research\independent-validation.json
```

The binder refuses self-review, unknown evidence, reused discovery proof/control artifacts, missing controls, unchallenged alternatives, incomplete chain links, or a mismatched blind-packet hash.

## Verdicts and stopping rules

- `confirmed`: the separate validator reproduced the primitive from clean state, controls rule out material alternatives, every essential chain link passes, and X1 may pass.
- `refuted`: the validator disproved an essential link or reproduced secure behavior; X1 fails and the hypothesis is preserved as refuted.
- `inconclusive`: evidence, environment, or a chain link remains unknown; X1 stays pending and the finding remains no higher than substantiated.
- `invalid`: the review artifact or independence claim is structurally untrustworthy; repair the record before drawing a conclusion.

Do not resolve disagreement by voting between models or reviewers. Inspect raw artifacts, design a discriminating control, and preserve the contradiction. Never lower the X1 standard because the discovery model is fast, weak, confident, or expensive to rerun.
