# mask0ff Codex to Claude conversion notes

Written 2026-08-05 while Ahmed napped. Converts the `mask0ff` v4 Codex skill into a
Claude WordPress-first adapter while preserving the reusable recon and evidence core.
V2 was implemented after Codex audit. This file records the format delta, scope
decisions, safety decisions, verification status, and installation notes.

## What was produced this session

- `mask0ff/SKILL.claude.md` : the converted core skill, Claude format, WordPress-first
  default, reusable recon retained, evidence pipeline and safety gates restored,
  defender output and learning capsule added. Written **beside** the original
  `SKILL.md` so its relative references and script paths resolve.
- `D:/Second_brain/wiki/learning/wordpress-pentest-lab.md` : a small disposable
  WordPress lab to test the skill on, with the safety rules and the exercise loop.
- `D:/Second_brain/wiki/projects/wp-vuln-skill.md` : the vault's project page and status.
- `_checkpoints/2026-08-05-v2-pre-edit/` : pre-edit copies of the two changed files.

The original Codex skill under `mask0ff/` was not modified. This is additive.

## The format delta, Codex skill vs Claude skill

Grounded in the actual files here (`mask0ff/SKILL.md`, `mask0ff/agents/openai.yaml`)
and Ahmed's Claude skills under `D:/Second_brain/.claude/skills/`.

| Piece | Codex | Claude | Action |
|---|---|---|---|
| Instruction file | `SKILL.md`, frontmatter `name` + `description` | `SKILL.md`, frontmatter `name` + `description`, optional `disable-model-invocation`, `argument-hint` | rewrite frontmatter + refocus body (done as `SKILL.claude.md`) |
| Interface manifest | `agents/openai.yaml` (`display_name`, `short_description`, `default_prompt`, icons) | none; the description carries triggering, invocation is by name or by the model | drop the yaml; its `default_prompt` becomes a usage hint only |
| Invocation model | `$mask0ff` mention, plus program default prompt | model invoked (description in context every turn) or user invoked (`disable-model-invocation: true`, zero context load) | chose **user invoked** for safety: a pentest skill should fire only when Ahmed types it |
| Scripts | `scripts/mask0ff.cmd` PowerShell router | invoked the same way from Claude via PowerShell or Bash | **reuse unchanged**, model agnostic |
| References, assets, evals, datasets | plain files | plain files | **reuse unchanged** |
| Subagent adapters | `assets/custom-agents/*.toml`, `assets/opencode/*` | Claude uses the Agent tool or the `codex-*` skills for delegation | leave as is; optional, only when asked |

The headline: converting this skill is mostly a **frontmatter plus refocus** job, not a
152 file rewrite, because the scripts, references, and datasets are model agnostic. The
only genuinely Codex specific artifact is `agents/openai.yaml`.

## Refocus decisions (WordPress variant)

- **Kept and strengthened:** the four work modes, the four assessment modes, the A0 to
  Q1 evidence pipeline, the untrusted data rule, the secret handling rule, the command
  router, the technique library, the integrity checks, and the full report/version
  workflow. Lab first was promoted to a stated rule.
- **Narrowed by default, not cut:** broad external asset discovery is not the current
  WordPress default. Authorized WordPress surface mapping remains part of A1, and the
  reusable recon library remains available for later projects or an explicit scoped
  request.
- **Removed only as a default:** bounty payout and platform-economy behavior. Internal
  report quality, duplicate review, affected-version tracking, and safe handoff remain.
- **Reframed:** the duplicate gate became a defensive known-vulnerability and prior-art
  check for the exact plugin, theme, core version, path, root cause, and fix.
- **Added:** a defender output (fix plus the hardening control that stops the class), a
  learning boundary tied to the current Stage 1 Step 2 study lane, a local-lab ownership
  A0 path, and a learning capsule (mechanism, find by hand, fix, recall question) on
  every finding. These are Ahmed's explicit asks: defend, learn, and stay bounded.

## V2 implementation and verification

V2 changed `mask0ff/SKILL.claude.md` and this notes file. The original Codex
`mask0ff/SKILL.md` remains unchanged. Implemented changes:

1. Recon remains reusable; broad external discovery is opt-in, while WordPress target
   mapping remains in scope.
2. Stage 1 learning boundaries and the canonical three-part gate are explicit.
3. Local-lab ownership and active-authorization A0 paths are distinguished.
4. Full command flow includes profile, session, plan, authorization, evidence, finding,
   assessment, report, and bundle verification.
5. WordPress hardening output includes authentication/2FA, XML-RPC, HTTPS, permissions,
   uploads, `wp-config.php`, file editor, roles, and update policy.
6. Technical wording and portability issues from the Codex audit are corrected.

Checks completed:

- `mask0ff.cmd --help` passed.
- `bundle`, `finding`, `assess`, `report`, `duplicate`, `sources`, `versions`, `plan`,
  `profile`, `session`, and `bundle gate` help checked against the scripts.
- The four referenced files from the original pending note exist. The earlier
  `references/finding-record.json` wording was corrected: the real template is under
  `assets/evidence-bundle/finding-record.json`.
- Full `integrity` and `audit --fail-on-issues` remain blocked by filesystem ACL denial
  on `references/techniques/04-api-graphql-websocket-cors/websocket.md`; no corpus pass
  is claimed until that file can be read.

## Installed as a live Claude skill (done 2026-08-05)

Installed and live, invoked as **`/maskoff`** (Ahmed's chosen name, no zero). This was
**not** the copy-everything approach: only the small methodology `SKILL.md` sits in the
vault, and the heavy assets stay isolated here in `D:\sec-research`.

- Location: `D:\Second_brain\.claude\skills\maskoff\SKILL.md`, `name: maskoff`,
  `disable-model-invocation: true` (user invoked, zero context cost until typed).
- The live `SKILL.md` is `mask0ff/SKILL.claude.md` plus two deployment edits: the
  `maskoff` name/title, and an "asset root" note that resolves `references/`, `assets/`,
  `scripts/`, `evals/` paths under `D:\sec-research\mask0ff-codex-v4\mask0ff\` and
  `wiki/...` paths under `D:\Second_brain\`.
- The offensive corpus (technique library, scripts, CVE/OSV datasets) is **not copied**
  into the vault; it stays here in `D:\sec-research`.
- `.claude/skills/maskoff/` is **gitignored** (verified with `git check-ignore`), so the
  corpus and even this methodology file never reach the public GitHub repo.

To re sync after a source change: copy `mask0ff\SKILL.claude.md` over the live vault
`SKILL.md`, then re apply the `name: maskoff` line/title and the asset root note.

## Codex audit record

Two clean spots, matching Ahmed's "Codex as audit" ask:

- Completed audit questions: conversion fidelity was partial rather than exact; broad
  recon removal was corrected to narrowing-by-default; bounty economics were removed
  but internal reporting was restored; authorization and minimum-safe-proof rules were
  retained and made operationally clearer.
- `/codex:review` (the Codex plugin) on the scripts and any code touched, if the CLI or
  datasets get changed.

Different model, different blind spots. Ahmed signs off last.

## Current boundary

WordPress remains current study focus. External discovery is not automatic. A supplied
company clone is not treated as a disposable lab merely because it is off production;
company ownership, code, data, credentials, integrations, and written scope still
determine the work mode and A0 evidence.
