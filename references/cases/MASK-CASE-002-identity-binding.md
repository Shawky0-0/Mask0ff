# MASK-CASE-002: Identity lifecycle and invitation binding

## Signal

An ordinary self-update API accepted a security-relevant identity field. A later invitation resolver trusted the raw profile value before consulting verified identities.

## Hypothesis

An authenticated user could pre-claim an address they did not control, causing a later administrator invitation to bind directly to the attacker's user identifier.

## Verification pattern

1. Use two researcher-owned accounts, a private test project, and a synthetic address.
2. Confirm the attacker has no project visibility or edit permission before the test.
3. Change only the attacker's unverified identity field and record the server response and persisted value.
4. From the controlled administrator, create an invitation for that address.
5. Inspect whether the invitation remains email-bound or becomes user-bound.
6. Accept from the attacker account and record the permission transition.
7. Run a negative control without the identity change and a normal positive control with the verified owner.
8. Trace serializer selection, invitation lookup, and authorization comparison to identify the missing verification invariant.

## Duplicate lesson

Search by identity-verification workflow, invitation binding, serializer symbols, and permission transition. Generic account-email bugs are not duplicates unless they reach the same authorization decision.

## Quality lesson

Show the before/after authorization state, not merely that an arbitrary email value is stored. The security impact comes from the downstream trust decision.
