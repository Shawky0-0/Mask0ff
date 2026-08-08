# Corpus provenance

## Imported technique library

The technique references were copied from the available live `2face` knowledge directory as a starting corpus. They are retained as research notes, not as authoritative or current product documentation. Their examples may contain offensive commands, payload strings, prompt-injection text, stale techniques, uncited claims, or material whose original licensing is unclear. Use them only to generate hypotheses, and verify important facts against current primary sources.

## Source-package audit

The supplied outer archive had SHA-256:

`16c4e428c8975e8ee536e499916f8d092062aeef67f19d049e9a3a84c4eb44d7`

Its preservation records were inconsistent:

- 62 listed resource checksums matched.
- `knowledge/06-server-side-injection-file-data/file_upload.md` was listed but absent.
- The nested source archive's actual SHA-256 was `935e016124d9aac6912ca7709d94eb5e3edb098795b1294176ce07bf1d59122b`.
- The declared nested-archive SHA-256 was `62c5d930aef4f8e5fb25013e3e094c8ed7bf4c561454ef09280947a947093072`.

The broken nested archive and stale preservation metadata are not included in `mask0ff`. `MANIFEST.sha256` covers the actual files in this skill and can be verified with `scripts/verify_integrity.py`.

## Redacted case library

The four `MASK-CASE-*` walkthroughs are methodological abstractions derived from researcher-controlled reports. They exclude private program messages, credentials, third-party data, and full private report text. Treat them as proof-design patterns, not as public disclosures or target-specific facts.

## Public prior-art databases

`references/cases/case-dataset.sqlite3` contains 12,500 normalized published records from the official CVE List V5 repository. It processes the CNA and CVE Program containers plus all available ADP enrichment containers. Use of the records is subject to the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse).

`references/cases/advisory-dataset.sqlite3` contains every GitHub-reviewed OSV advisory present in the pinned official GitHub Advisory Database archive used for the build. The source declares the reviewed advisory data under CC-BY-4.0.

Each row preserves its source-relative path and SHA-256. The SQLite `metadata` tables hold the exact source URL, revision, build time, count, coverage range, and terms or license; do not copy mutable values into prose as if they were permanently current. Full-text matches are prior-art leads and never automatic duplicate decisions.

## Text-corpus sanitation and licensing boundary

The inherited technique notes contained embedded NUL/control characters and broken private citation markers. Version 3 normalizes those artifacts to visible text, and `scripts/audit_corpus.py --fail-on-issues` prevents their reintroduction. The large XSS index is navigation-only research material, not proof and not a recommended spray list.

Original item-level provenance and licensing for much of the inherited technique library remains unclear. Do not republish that library as a standalone corpus or treat its uncited prose as authoritative. Important claims must be rechecked against current primary sources. This uncertainty does not apply to the separately attributed CVE and GitHub-reviewed datasets or to the researcher-authored redacted methodological cases.

## Current compact technique catalog

`references/techniques/current-techniques.json` is a separate routing index reviewed on 2026-08-02. Every entry names a source, assessment modes, surfaces, signals, and a minimum-safe validation design. Its source registry attributes PortSwigger Research's expert-curated 2025 list and official OWASP Top 10:2025, WSTG, API Security, and Agentic Applications material. It summarizes technique names and testing implications without copying payload collections or claiming that a source match proves a target flaw.
