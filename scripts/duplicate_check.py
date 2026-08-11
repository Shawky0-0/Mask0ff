#!/usr/bin/env python3
"""Rank local methodological analogies using canonical finding fingerprints."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "references" / "cases" / "cases.json"
DEFAULT_DATABASE = ROOT / "references" / "cases" / "case-dataset.sqlite3"
DEFAULT_ADVISORY_DATABASE = ROOT / "references" / "cases" / "advisory-dataset.sqlite3"
WEIGHTS = {
    "component": 1.5,
    "entry_point": 2.0,
    "controlled_input": 1.5,
    "source_sink": 3.0,
    "preconditions": 1.5,
    "boundary": 2.5,
    "primitive": 2.0,
    "impact": 1.5,
    "fix_invariant": 2.0,
}


CAMEL_SPLIT = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def tokens(value: Any) -> set[str]:
    if isinstance(value, list):
        value = " ".join(str(item) for item in value)
    result: set[str] = set()
    for raw in re.findall(r"[A-Za-z0-9_.:/-]+", str(value)):
        token = raw.lower()
        if len(token) > 2:
            result.add(token)
        result.update(part for part in re.split(r"[_.:/-]+", token) if len(part) > 2)
        for part in re.split(CAMEL_SPLIT, raw):
            part = part.strip("_.:/-").lower()
            if len(part) > 2:
                result.add(part)
    return result


def jaccard(left: set[str], right: set[str]) -> float:
    return len(left & right) / len(left | right) if left or right else 0.0


def compare(candidate: dict[str, Any], case: dict[str, Any]) -> tuple[float, dict[str, float]]:
    scores: dict[str, float] = {}
    weighted = 0.0
    total = 0.0
    other = case.get("fingerprint", {})
    for field, weight in WEIGHTS.items():
        score = jaccard(tokens(candidate.get(field, "")), tokens(other.get(field, "")))
        scores[field] = score
        weighted += score * weight
        total += weight
    return (weighted / total if total else 0.0), scores


def public_query(candidate: dict[str, Any]) -> str:
    stopwords = {
        "with", "from", "into", "through", "that", "this", "allows", "before",
        "after", "under", "application", "user", "controlled", "attacker",
    }
    ordered: list[str] = []
    for field in ("component", "entry_point", "source_sink", "primitive", "impact", "boundary"):
        for token in re.findall(r"[A-Za-z0-9_.:/-]+", str(candidate.get(field, ""))):
            normalized = token.strip("._:/-").lower()
            if len(normalized) > 3 and normalized not in stopwords and normalized not in ordered:
                ordered.append(normalized)
    return " OR ".join(f'"{token.replace(chr(34), chr(34) * 2)}"' for token in ordered[:18])


def public_matches(database: Path, candidate: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    if not database.is_file():
        return []
    query = public_query(candidate)
    if not query:
        return []
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT c.case_id, c.published, c.updated, c.title, c.summary,
                   c.vendors, c.products, c.purls, c.versions, c.cwes,
                   c.severity, c.cvss_score, c.severity_source,
                   c.adp_providers, c.known_exploited, c.references_json,
                   bm25(cases_fts, 0.0, 4.0, 3.0, 0.5, 1.0, 1.5, 2.0, 1.5, 2.0, 0.5) AS rank
            FROM cases_fts
            JOIN cases c ON c.case_id = cases_fts.case_id
            WHERE cases_fts MATCH ?
            ORDER BY rank, c.updated DESC
            LIMIT ?
            """,
            (query, max(20, min(limit * 12, 250))),
        ).fetchall()
    finally:
        connection.close()
    candidate_tokens = tokens(
        " ".join(
            str(candidate.get(field, ""))
            for field in ("component", "entry_point", "source_sink", "primitive", "impact", "boundary", "fix_invariant")
        )
    )
    results = []
    for row in rows:
        item = dict(row)
        item["references"] = json.loads(item.pop("references_json"))[:3]
        case_tokens = tokens(
            " ".join(
                str(item.get(field, ""))
                for field in ("title", "summary", "vendors", "products", "purls", "versions", "cwes")
            )
        )
        item["fingerprint_overlap"] = round(jaccard(candidate_tokens, case_tokens), 6)
        results.append(item)
    results.sort(key=lambda item: (-item["fingerprint_overlap"], item["rank"], item["case_id"]))
    return results[: max(1, min(limit, 50))]


def advisory_matches(database: Path, candidate: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    """Return GitHub-reviewed OSV leads, never an automatic duplicate verdict."""
    if not database.is_file():
        return []
    query = public_query(candidate)
    if not query:
        return []
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            """
            SELECT a.advisory_id, a.published, a.modified, a.aliases, a.summary,
                   a.ecosystems, a.packages, a.versions, a.ranges, a.cwes,
                   a.severity, a.cvss_vectors, a.references_json,
                   bm25(advisories_fts, 0.0, 2.0, 4.0, 2.5, 1.0, 2.0, 1.5, 2.0, 1.5) AS rank
            FROM advisories_fts
            JOIN advisories a ON a.advisory_id = advisories_fts.advisory_id
            WHERE advisories_fts MATCH ? AND a.withdrawn = ''
            ORDER BY rank, a.modified DESC
            LIMIT ?
            """,
            (query, max(20, min(limit * 12, 250))),
        ).fetchall()
    finally:
        connection.close()

    candidate_tokens = tokens(
        " ".join(
            str(candidate.get(field, ""))
            for field in ("component", "entry_point", "source_sink", "primitive", "impact", "boundary", "fix_invariant")
        )
    )
    results = []
    for row in rows:
        item = dict(row)
        item["references"] = json.loads(item.pop("references_json"))[:3]
        advisory_tokens = tokens(
            " ".join(
                str(item.get(field, ""))
                for field in ("aliases", "summary", "ecosystems", "packages", "versions", "ranges", "cwes")
            )
        )
        item["fingerprint_overlap"] = round(jaccard(candidate_tokens, advisory_tokens), 6)
        results.append(item)
    results.sort(key=lambda item: (-item["fingerprint_overlap"], item["rank"], item["advisory_id"]))
    return results[: max(1, min(limit, 50))]


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("finding", type=Path, help="Finding-record JSON")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--advisory-database", type=Path, default=DEFAULT_ADVISORY_DATABASE)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--public-limit", type=int, default=10)
    parser.add_argument("--advisory-limit", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    record = json.loads(args.finding.read_text(encoding="utf-8-sig"))
    candidate = record.get("fingerprint", record)
    cases = json.loads(args.cases.read_text(encoding="utf-8-sig"))["cases"]
    ranked = []
    for case in cases:
        score, fields = compare(candidate, case)
        ranked.append((score, case, fields))
    ranked.sort(key=lambda item: (-item[0], item[1]["id"]))

    local_results = []
    for score, case, fields in ranked[: args.limit]:
        strongest = sorted(fields.items(), key=lambda item: (-item[1], item[0]))[:3]
        strength = ", ".join(f"{field}={value:.2f}" for field, value in strongest)
        local_results.append(
            {
                "score": round(score, 6),
                "id": case["id"],
                "title": case["title"],
                "walkthrough": case["walkthrough"],
                "strongest_fields": strength,
            }
        )
    public_results = public_matches(args.database, candidate, args.public_limit)
    advisory_results = advisory_matches(args.advisory_database, candidate, args.advisory_limit)

    if args.json:
        print(
            json.dumps(
                {
                    "warning": "Matches are research leads, not duplicate decisions. Complete the D1 comparison.",
                    "methodological_analogies": local_results,
                    "public_case_leads": public_results,
                    "github_advisory_leads": advisory_results,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0

    print("Matches are research leads, not duplicate decisions. Complete the external D1 review.")
    print("\nMethodological analogies:")
    for item in local_results:
        print(f"{item['score']:.3f}  {item['id']}  {item['title']}  ({item['strongest_fields']})")
        print(f"  walkthrough: {item['walkthrough']}")
    print("\nRecent official CVE leads:")
    if not public_results:
        print("  No case database found or no matches. Run build_case_db.py first.")
    for item in public_results:
        print(
            f"{item['case_id']}  {item['published'][:10]}  "
            f"{item['severity'] or '-'} {item['cvss_score'] or '-'}  "
            f"{item['products'] or item['vendors'] or '-'}"
        )
        print(f"  {item['title']}")
        print(f"  CWE: {item['cwes'] or '-'}")
        if item["references"]:
            print(f"  {item['references'][0]['url']}")
    print("\nGitHub-reviewed advisory leads:")
    if not advisory_results:
        print("  No advisory database found or no matches. Run build_advisory_db.py first.")
    for item in advisory_results:
        print(
            f"{item['advisory_id']}  {item['published'][:10]}  "
            f"{item['severity'] or '-'}  {item['ecosystems'] or '-'}:{item['packages'] or '-'}"
        )
        print(f"  {item['aliases'] or '-'}  {item['summary']}")
        print(f"  CWE: {item['cwes'] or '-'}")
        if item["references"]:
            print(f"  {item['references'][0]['url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
