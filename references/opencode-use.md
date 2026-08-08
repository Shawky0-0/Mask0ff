# OpenCode adapter

The OpenCode distribution places the complete skill at `.opencode/skills/mask0ff/` and a selectable primary agent at `.opencode/agents/mask0ff.md`.

OpenCode discovers directory skills through `.opencode/skills/<name>/SKILL.md`. The adapter uses the same portable Markdown, JSON, SQLite, SHA-256, and Python command contract as Codex. Supporting files remain relative to the skill directory.

The primary agent allows normal read/search, web research, evidence-file edits, and commands, but its prompt requires the imported program profile before active target interaction and forbids secret values in files or command text. OpenCode permissions are not authorization; the evidence profile and A0 gate remain authoritative for the engagement.

After extraction into a project root, select `mask0ff` as the primary agent or invoke the `mask0ff` skill. Keep engagement workspaces on the drive chosen by the user.

Validate an extracted distribution before use:

```text
sh .opencode/skills/mask0ff/scripts/mask0ff.sh opencode <extracted-package-root>
```

The validator checks native discovery paths, skill identity, agent mode and permissions, the official schema URL, and cache-file cleanliness. It does not validate a target engagement; run `profile verify`, `auth`, and the evidence gates separately.
