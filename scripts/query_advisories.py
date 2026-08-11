#!/usr/bin/env python3
"""Query the bundled GitHub-reviewed advisory database."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = ROOT / "references" / "cases" / "advisory-dataset.sqlite3"


def fts_query(text: str) -> str:
    terms = []
    for term in re.findall(r"[A-Za-z0-9_.:/@-]+", text):
        normalized = term.strip("._:/@-")
        if len(normalized) > 1 and normalized.lower() not in {"the", "and", "for", "with"}:
            terms.append(normalized.replace('"', '""'))
    unique = list(dict.fromkeys(terms))[:20]
    if not unique:
        raise ValueError("query contains no searchable terms")
    return " OR ".join(f'"{term}"' for term in unique)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("query", nargs="?")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--since")
    parser.add_argument("--ecosystem")
    parser.add_argument("--cwe")
    parser.add_argument("--severity", choices=("LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"))
    parser.add_argument("--include-withdrawn", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--metadata", action="store_true")
    args = parser.parse_args()

    if not args.database.is_file():
        parser.error(f"advisory database is not a file: {args.database}")
    connection = sqlite3.connect(f"file:{args.database.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if args.metadata:
            print(json.dumps(dict(connection.execute("SELECT key, value FROM metadata")), indent=2))
            return 0
        if not args.query:
            parser.error("query is required unless --metadata is used")
        try:
            query = fts_query(args.query)
        except ValueError as error:
            parser.error(str(error))
        where = ["advisories_fts MATCH ?"]
        params: list[object] = [query]
        if not args.include_withdrawn:
            where.append("a.withdrawn = ''")
        if args.since:
            where.append("a.published >= ?")
            params.append(args.since)
        if args.ecosystem:
            where.append("a.ecosystems LIKE ?")
            params.append(f"%{args.ecosystem}%")
        if args.cwe:
            where.append("a.cwes LIKE ?")
            params.append(f"%{args.cwe}%")
        if args.severity:
            where.append("a.severity = ?")
            params.append(args.severity)
        params.append(max(1, min(args.limit, 100)))
        rows = connection.execute(
            f"""
            SELECT a.advisory_id, a.modified, a.published, a.aliases, a.summary,
                   a.details, a.ecosystems, a.packages, a.versions, a.ranges,
                   a.cwes, a.severity, a.cvss_vectors, a.references_json,
                   bm25(advisories_fts, 0.0, 2.0, 4.0, 2.5, 1.0, 2.0, 1.5, 2.0, 1.5) AS rank
            FROM advisories_fts
            JOIN advisories a ON a.advisory_id = advisories_fts.advisory_id
            WHERE {' AND '.join(where)}
            ORDER BY rank, a.modified DESC
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
        results.append(item)
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        for item in results:
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
