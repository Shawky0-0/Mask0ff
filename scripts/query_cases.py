#!/usr/bin/env python3
"""Query the mask0ff public real-case database."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "references" / "cases" / "case-dataset.sqlite3"


def fts_query(text: str) -> str:
    terms = []
    for term in re.findall(r"[A-Za-z0-9_.:/-]+", text):
        normalized = term.strip("._:/-")
        if len(normalized) > 1 and normalized.lower() not in {"the", "and", "for", "with"}:
            terms.append(normalized.replace('"', '""'))
    unique = list(dict.fromkeys(terms))[:20]
    if not unique:
        raise ValueError("query contains no searchable terms")
    return " OR ".join(f'"{term}"' for term in unique)


def metadata(connection: sqlite3.Connection) -> dict[str, str]:
    return dict(connection.execute("SELECT key, value FROM metadata"))


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("query", nargs="?")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--since", help="Minimum published date prefix, for example 2025-01-01")
    parser.add_argument("--cwe", help="Require a CWE token such as CWE-79")
    parser.add_argument("--severity", choices=("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"))
    parser.add_argument("--known-exploited", action="store_true", help="Require CISA KEV enrichment")
    parser.add_argument("--details", action="store_true", help="Include normalized SSVC, KEV, and metric provenance")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--metadata", action="store_true")
    args = parser.parse_args()

    connection = sqlite3.connect(args.database)
    connection.row_factory = sqlite3.Row
    try:
        if args.metadata:
            print(json.dumps(metadata(connection), indent=2))
            return 0
        if not args.query:
            parser.error("query is required unless --metadata is used")
        try:
            query = fts_query(args.query)
        except ValueError as error:
            parser.error(str(error))
        where = ["cases_fts MATCH ?"]
        params: list[object] = [query]
        if args.since:
            where.append("c.published >= ?")
            params.append(args.since)
        if args.cwe:
            where.append("c.cwes LIKE ?")
            params.append(f"%{args.cwe}%")
        if args.severity:
            where.append("c.severity = ?")
            params.append(args.severity)
        if args.known_exploited:
            where.append("c.known_exploited = 1")
        params.append(max(1, min(args.limit, 100)))
        rows = connection.execute(
            f"""
            SELECT c.case_id, c.published, c.updated, c.title, c.summary, c.cna,
                   c.vendors, c.products, c.purls, c.versions, c.cwes, c.severity,
                   c.cvss_score, c.cvss_vector, c.severity_source, c.adp_providers,
                   c.known_exploited, c.references_json, c.metrics_json,
                   c.ssvc_json, c.kev_json,
                   bm25(cases_fts, 0.0, 4.0, 2.5, 0.5, 1.0, 1.5, 2.0, 1.5, 2.0, 0.5) AS rank
            FROM cases_fts
            JOIN cases c ON c.case_id = cases_fts.case_id
            WHERE {' AND '.join(where)}
            ORDER BY rank, c.updated DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    finally:
        connection.close()

    results = []
    for row in rows:
        item = dict(row)
        item["references"] = json.loads(item.pop("references_json"))[:5]
        if args.details:
            item["metrics"] = json.loads(item.pop("metrics_json"))
            item["ssvc"] = json.loads(item.pop("ssvc_json"))
            item["kev"] = json.loads(item.pop("kev_json"))
        else:
            item.pop("metrics_json")
            item.pop("ssvc_json")
            item.pop("kev_json")
        results.append(item)
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for item in results:
            print(
                f"{item['case_id']}  {item['published'][:10]}  "
                f"{item['severity'] or '-'} {item['cvss_score'] or '-'}  "
                f"{item['products'] or item['vendors'] or '-'}"
                f"{'  [CISA KEV]' if item['known_exploited'] else ''}"
            )
            print(f"  {item['title']}")
            print(f"  CWE: {item['cwes'] or '-'}")
            if item["references"]:
                print(f"  {item['references'][0]['url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
