# Triage workflow

Use this reference when the task is to evaluate a report or finding — your own, a colleague's, or a third-party submission — rather than to discover a new vulnerability. The finder produces possibilities; the triager decides. Act as a triager: presume the report may be wrong, incomplete, or a duplicate, and demand proof before any acceptance.

## Contents

1. When to triage
2. Triage gates
3. Verdicts and decisions
4. Impact proof requirements
5. Duplicate handling
6. Severity and priority
7. Output contract

## When to triage

Run `triage` when the user supplies a report (or a finding record) and asks to evaluate, validate, reproduce, rank, or decide on it. Inputs:

- `report` (required): the markdown report under review.
- `--finding`: the evidence-bundle finding record, when artifacts are available.
- `--profile` / `--authorization`: program scope so the target can be checked.
- `--target` / `--action` / `--action-group`: the claims being checked.

```powershell
.\scripts\mask0ff.cmd triage E:\reports\report.md `
  --finding E:\research\finding-work\finding-record.json `
  --profile E:\research\program-profile.json --target "api.example.com"
```

## Triage gates

| Gate | Check | Failing state |
|---|---|---|
| T0 Threat model | An attacker-controlled source exists, a cross-principal boundary is crossed, and the behavior is not working-as-designed or outside the vendor's stated threat model | `rejected` (no-attacker-controlled-impact-or-boundary), `needs-more-info` (threat-model-clarity-required) |
| T1 Scope | Target and action are in scope under the current profile or authorization receipt, within the window | `rejected` (out-of-scope), `blocked` (no check possible) |
| T2 Claim | Report states expected and observed behavior and falsifiable reproduction steps | `needs-more-info` (incomplete-report) |
| T3 Evidence | Artifacts exist, are hash-verified, and every claim binds to evidence IDs | `rejected` (invalid-evidence) |
| T4 Impact | The claim demonstrates an observable effect, not an assertion | `needs-more-info` (impact-not-demonstrated / impact-asserted-not-demonstrated) |
| T5 Severity | Score is derived from demonstrated impact, not guessed | reviewer calibration required |
| T6 Duplicate | Root cause, path, versions, and fix compared against strong prior-art leads | `possible-duplicate` |
| T7 Verdict | Decision and next action recorded | — |

T0 runs before every other gate. A report whose own prose disclaims attacker control ("not attacker-controlled", "no security boundary", "working as designed", "same trust principal") is rejected regardless of evidence quality. Read [threat-model-assessment.md](threat-model-assessment.md) for the five questions and vendor prior-art sources.

## Verdicts and decisions

- `accepted`: in-scope, complete, evidence-verified, impact demonstrated, no strong duplicate. Escalate to fix/response.
- `needs-more-info`: incomplete report or asserted-only impact. Return the report with the exact missing evidence; never accept it "pending" silently.
- `possible-duplicate`: strong prior-art match. Compare root cause, reachable path, security boundary, affected versions, and fix before deciding.
- `rejected`: out of scope or invalid evidence. Respond with the specific deficiency.
- `blocked`: no scope/authorization check is possible. Resolve that before any decision.

A report that cannot be reproduced from its own steps, or whose impact is only asserted (`we believe`, `likely`, `appears to`), must be returned for more information rather than accepted or escalated.

## Impact proof requirements

Mirror the finder-side rule: a scanner match, error string, or status code is not impact. For a report to pass T4 it must contain demonstrated impact evidence:

- RCE/command execution: raw command output (`uid=`, `id`, `whoami`, `cat /etc/passwd`, `uname -a`).
- SQL injection: projected benign value or banner (`SELECT @@version`, `SELECT 1`).
- File read: the read file contents or a benign marker.
- SSRF: captured response from a researcher-owned or localhost callback.
- XSS: browser execution evidence (alert/console marker, callback request).
- Authorization: preserved unauthorized response from the wrong role/tenant/object owner.
- Business logic: before/after state delta from the authoritative source.
- Race: repeatable state-invariant violation with two clean runs.

Hedged language without a demonstrated effect forces `needs-more-info`, regardless of the claimed severity.

## Duplicate handling

The triage command reports local analogy scores and public/advisory leads. A score or overlap above 0.5 is a strong-lead flag, not a decision. Compare the canonical fingerprint fields (component, entry point, source/sink, boundary, primitive, impact, fix) and the affected versions before concluding duplicate.

## Severity and priority

Severity comes from demonstrated impact and program rules, never from the reporter's claim alone. When the finding record supplies a CVSS score or rating it is used; otherwise the report's explicit rating is a lead and the verdict records `requires-reviewer-scoring`. Priority combines severity band with validation confidence only after T4 passes.

## Output contract

`triage` returns a JSON verdict: `final_verdict`, `reason`, `scope`, `report_quality`, `evidence`, `severity`, `duplicate`, `priority`, `next_action`, and a calibration caveat. Exit codes: 0 accepted, 2 needs-more-info/possible-duplicate, 3 rejected, 4 blocked. The verdict is a decision aid from supplied evidence; the reviewer keeps final judgment.
