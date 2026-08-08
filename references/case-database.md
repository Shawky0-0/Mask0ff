# Official prior-art databases

## Purpose and coverage

The skill bundles two normalized, full-text-searchable SQLite datasets:

- `references/cases/case-dataset.sqlite3`: 12,500 recent published CVE List V5 records. It ingests the required CNA and CVE Program containers plus every available ADP container, preserving purls, version statements, CWEs, metric provenance, ADP providers, SSVC, and CISA Known Exploited Vulnerabilities enrichment when present.
- `references/cases/advisory-dataset.sqlite3`: all GitHub-reviewed OSV advisories in the pinned source snapshot, including aliases, ecosystem/package, affected versions and ranges, CWEs, severity, CVSS vectors, and official references.

Every row preserves a source-relative path and SHA-256. Each database's `metadata` table is authoritative for its source URL, exact revision, generation time, record count, coverage window, and source terms or license. The advisory metadata also preserves the SHA-256 of the pinned source archive.

These are public prior-art lead indexes. They do not contain private bug-bounty reports and cannot rule out unpublished or internal duplicates.

## Query

Use specific package names, components, symbols, entry points, source/sink pairs, permission names, and fix invariants:

```powershell
.\scripts\mask0ff.cmd cases "mercurial option terminator command injection" --limit 10 --json
.\scripts\mask0ff.cmd cases "invitation authorization" --since 2025-01-01 --known-exploited --details --json
.\scripts\mask0ff.cmd advisories "django-debug-toolbar raw_sql" --ecosystem PyPI --json
.\scripts\mask0ff.cmd duplicate E:\research\finding-work\finding-record.json --json
```

The combined duplicate command reranks broad full-text candidates by canonical fingerprint overlap. It returns methodological analogies, CVE leads, and GitHub-reviewed advisory leads. It never emits an automatic duplicate decision.

## Interpretation

- Open the official record and upstream references before relying on a match.
- Compare exact root cause, reachable path, security boundary, preconditions, affected range, and fix.
- Record the external review in the D1 artifact even when both databases return no close match.
- Preserve source revisions and query time; the feeds change frequently.
- Treat missing severity, affected-range, or ADP data as unknown, not as evidence of absence.

Run `.\scripts\mask0ff.cmd sources --json` before D1. `update-available` is informational: it means the local snapshot is valid but not equal to the current upstream HEAD. `unknown` means the live check failed and must not be described as current.

## Transactional CVE update

Use an official local checkout. The updater validates the origin, optionally performs a fast-forward-only pull, builds a separate candidate, checks schema/integrity/count/FTS/revision, runs evaluations, and replaces the installed database only after all checks pass. It restores the prior database on a post-replacement failure.

```powershell
.\scripts\mask0ff.cmd update-cases E:\CodexCLI\mask0ff-dev\sources\cvelistV5 --git E:\path\to\git.exe --pull
```

The default source set is the current and previous year, selection is newest by publication time, and the retained limit is 12,500. Use `--sort-by updated` only when an update-recency corpus is intentionally wanted.

## Transactional advisory update

Supply a pinned official GitHub Advisory Database archive, its full Git revision, and preferably its independently recorded SHA-256. The updater validates the complete ZIP and CRCs, minimum reviewed count, source hash, schema/integrity/count/FTS/unique IDs, evaluation suite, and manifest before replacement.

```powershell
.\scripts\mask0ff.cmd update-advisories E:\sources\advisory-database.zip `
  --source-revision <40-character-commit> `
  --archive-sha256 <64-character-sha256>
```

Do not weaken firewall, antivirus, or execution-policy controls to refresh a dataset. A pinned offline archive is supported specifically so updating can be separated from validation and installation.
