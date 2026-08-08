# MASK-CASE-004: Approval equivalence and file-policy enforcement

## Signal

A consequential-action renderer displayed only a fixed number of parameters, while execution retained the complete argument object. A connector attachment path selected a filesystem implementation that did not enforce the active read-deny matcher.

## Hypothesis

Two actions with identical visible approval text could have materially different hidden effects, including an undisclosed recipient and upload of an explicitly denied local canary.

## Verification pattern

1. Construct a baseline action with only the visible fields.
2. Construct a differential action with the same visible fields plus a controlled hidden recipient and synthetic attachment.
3. Assert that both render to the same approval text.
4. Capture the complete post-approval argument object to prove hidden fields remain bound to execution.
5. Add an exact read-deny rule for the synthetic canary and separately prove the policy matcher denies the path.
6. Capture a localhost upload and compare its bytes and hash with the canary.
7. When permitted, confirm delivery only between researcher-owned accounts.
8. Repeat the renderer, policy, and end-to-end paths independently.

## Duplicate lesson

Treat the approval truncation and file-policy bypass as related primitives that compose into impact. Compare prior issues by renderer field coverage, execution binding, filesystem implementation, and fix location.

## Quality lesson

A differential control is decisive: if safe and malicious actions produce the same authoritative approval, the user cannot distinguish their effects. Preserve both UI output and execution arguments.
