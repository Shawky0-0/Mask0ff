# MASK-CASE-003: Per-origin trust for execution-bearing definitions

## Signal

A developer tool correctly blocked one execution-bearing field from an untrusted secondary directory, while adjacent extension fields were still parsed and launched.

## Hypothesis

Adding a repository only for contextual file access could silently grant process execution through extension definitions whose source-folder trust was not checked.

## Verification pattern

1. Use a trusted primary workspace and a separate researcher-controlled untrusted folder.
2. Avoid global allowlists, unsafe permission flags, aliases, symlinks, and modified shell environments.
3. Place unique benign canary commands in each execution-bearing definition type.
4. Confirm the UI recognizes the secondary folder as untrusted through the protected control path.
5. Invoke definitions one at a time and record process creation, permission prompts, and trust dialogs.
6. Repeat in a fresh profile or clean configuration.
7. Compare protected and unprotected paths at the origin-trust decision.

## Duplicate lesson

An internally known issue may be impossible to discover publicly. Record the public search and the residual internal-duplicate risk. Compare each extension field separately because adjacent loaders can require distinct fixes.

## Quality lesson

Remove alternative explanations. A strong proof states the default permission mode and shows that execution did not depend on an already-approved shell, symlink, alias, or broad unsafe flag.
