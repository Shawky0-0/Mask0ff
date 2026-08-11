# Triage failure modes and anti-Informative review

A technically real behavior is not automatically a security vulnerability. Before submission, try to close the candidate using the same arguments a skeptical vendor triager would use.

## Common failure modes

### Working as designed

The implementation behaves exactly as documented or intentionally configured. The candidate must identify a security guarantee that the behavior violates, not merely an inconsistency or surprising result.

### Explicit consent or administrator authorization

If the user, administrator, developer, or deployment owner explicitly authorized the exact action, do not re-label that authorized outcome as an attacker bypass. Prove a security rule that is supposed to survive that consent or configuration.

### Same trust principal

Two components may look separate in metadata or UI while the product treats them as the same security principal. Prove that the product defends a boundary between them or that one gains a capability unavailable to the shared principal.

### No attacker-controlled component

A developer-controlled configuration bug, self-selected endpoint, or purely local misuse can be real correctness behavior without adversarial influence. Name the attacker and exact controlled input.

### Equivalent authority already exists

If the alleged attacker can already perform the same operation through an intended path, the path may not create new authority. Record before/after capabilities and the counterfactual capability removed by the fix.

### Stale or already-fixed version

A reproducible issue on an old build may be irrelevant to a current bug-bounty program. Verify the current supported release or deployment before deep exploitation or submission.

### Functional correctness only

Incorrect routing, state loss, surprising defaults, or API inconsistency is not enough by itself. Prove confidentiality, integrity, availability, authorization, isolation, or another defended security property.

### Self-imposed or unrealistic preconditions

A finding that requires the victim to deliberately disable the claimed protection, inject its own malicious value, or create an implausible environment may be hardening rather than a vulnerability.

### No security contract

A missing check matters only if a security decision was required there. Establish the contract from product documentation, protocol/specification, explicit implementation policy, tests, prior fixes, or a defensible trust boundary.

### Potential impact only

Do not promote "could lead to" into demonstrated impact. Prove the smallest benign effect that establishes the security boundary; label additional consequences as bounded inference.

### Accepted risk or known behavior

Program policy, documentation, or prior vendor decisions may explicitly accept the behavior. Record this before submission.

### Duplicate or known issue

Novel payloads do not create a new root cause. Compare the exact root cause, path, boundary, affected range, and fix invariant.

## Required outcome

A candidate becomes reportable only when all applicable rejection arguments are defeated with evidence. If one applies, classify the result accurately: `working-as-designed`, `hardening`, `functional-bug`, `outdated-or-fixed`, `duplicate-or-known-issue`, `insufficient-attacker-control`, or `insufficient-security-impact`.

Preserve rejected candidates as negative evidence. They improve future ranking and prevent repeated report noise.
