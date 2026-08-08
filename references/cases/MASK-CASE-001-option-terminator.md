# MASK-CASE-001: Option terminator and incomplete-fix analysis

## Signal

A repository-derived filename was inserted into a command argument vector. The configured filename grammar allowed values beginning with `-`, and an earlier security fix had hardened adjacent repository calls.

## Hypothesis

A project-scoped editor could cause the repository client to interpret a filename as command configuration, changing command dispatch under the shared application service identity.

## Verification pattern

1. Trace the exact caller from a user-writable configuration field to the command wrapper.
2. Confirm the real permission path with a non-staff, non-superuser controlled account.
3. Use a local integration environment and a synthetic marker; do not access system or third-party files.
4. Preserve a normal baseline using a benign filename.
5. Demonstrate a controlled side effect and command identity through the normal update path.
6. Repeat the vulnerable run independently.
7. Add a patched differential that changes only the argument vector by inserting `--` before the path.
8. Test the first release containing the prior fix, the current release, and current source to bound an incomplete-fix range.

## Duplicate lesson

Compare exact callers and sinks from the older advisory. A shared CWE or repository client is insufficient. Classify as an incomplete-fix candidate only when the older patch omitted this reachable path and the required invariant is the same.

## Quality lesson

Parser errors or reflected arguments are weaker than a harmless, controlled backend side effect. Prove the permission boundary and preserve both benign and patched controls.
