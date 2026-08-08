# Duplicate-review gate

## Canonical fingerprint

Normalize the candidate into these fields:

- Product and component.
- Entry point and reachable caller.
- Attacker-controlled input.
- Source, transformation, sink, or missing authorization decision.
- Required account, role, configuration, and user interaction.
- Crossed security boundary.
- Primitive and concrete impact.
- Affected versions or introduction commit.
- Proposed fix location and invariant.

Store the fingerprint in the finding record and run `.\scripts\mask0ff.cmd duplicate <finding-record.json> --json`. The command searches the methodological case library, normalized CVE List V5 database, and GitHub-reviewed advisory database. All results are leads.

## External search order

First run `.\scripts\mask0ff.cmd sources --json` and preserve its timestamp, local revision, remote revision, and status for both public datasets. Then search current primary sources and record the access date:

1. Official vendor advisories, security pages, release notes, and changelogs.
2. The official source repository's issues, pull requests, commits, tests, and advisory database.
3. Public disclosures from the relevant program.
4. Official CVE and GHSA records and their upstream project references.
5. Previous fixes in adjacent methods or callers that may be incomplete.

Build queries from exact symbols, endpoints, error strings, permission names, fix invariants, and the source-to-sink pair. Do not search only by CWE.

## Comparison outcomes

- `same`: Same root cause and reachable path, materially the same boundary and fix.
- `variant`: Related root cause or fix family, but a distinct caller, permission boundary, affected range, or impact path.
- `incomplete-fix`: A prior fix covered adjacent paths but left the reported reachable path open.
- `unrelated`: Shares a weakness label or impact but not the root cause/path.
- `unknown`: Public evidence is insufficient or only the vendor can compare an internal issue.

## Decision discipline

Do not self-close a finding merely because a similar CVE exists. Demonstrate whether the old fix changed this exact data flow and whether the current release remains affected. Conversely, do not market a cosmetic variant as new when it reaches the same check and requires the same fix.

Log every query, URL or record ID, access time, source revision, examined result, matching fact, difference, and confidence in `assets/evidence-bundle/duplicate-review.md`. If source status is offline or unknown, record that limitation. Never claim public research eliminates the risk of an internal or unpublished duplicate.
