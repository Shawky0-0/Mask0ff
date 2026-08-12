#!/usr/bin/env python3
"""Search bundled research libraries without loading whole documents."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEARCH_ROOTS = (ROOT / "references", ROOT / "findings")
SEARCHABLE_SUFFIXES = {".md", ".txt", ".json"}


def search(query: str, limit: int = 12, snippets: int = 3) -> list[tuple[int, Path, list[tuple[int, str]]]]:
    terms = [term.lower() for term in re.findall(r"[\w./:-]+", query) if len(term) > 1]
    if not terms:
        raise ValueError("query must contain searchable terms")

    results: list[tuple[int, Path, list[tuple[int, str]]]] = []
    for search_root in SEARCH_ROOTS:
        if not search_root.is_dir():
            continue
        for path in search_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SEARCHABLE_SUFFIXES:
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            matches: list[tuple[int, str]] = []
            content = "\n".join(lines).lower()
            covered = sum(1 for term in terms if term in content)
            minimum_coverage = 1 if len(terms) < 3 else math.ceil(len(terms) / 2)
            if covered < minimum_coverage:
                continue
            frequency_score = sum(min(content.count(term), 12) for term in terms)
            path_text = path.relative_to(ROOT).as_posix().lower()
            path_score = 25 * sum(1 for term in terms if term in path_text)
            score = covered * 100 + frequency_score + path_score
            for number, line in enumerate(lines, 1):
                lowered = line.lower()
                if any(term in lowered for term in terms) and len(matches) < snippets:
                    matches.append((number, line.strip()[:240]))
            if score:
                results.append((score, path, matches))

    results.sort(key=lambda item: (-item[0], item[1].as_posix()))
    return results[:limit]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("query", help="Words, symbol names, endpoints, or vulnerability terms")
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--snippets", type=int, default=3)
    args = parser.parse_args()

    try:
        results = search(args.query, args.limit, args.snippets)
    except ValueError as error:
        parser.error(str(error))

    for score, path, matches in results:
        print(f"[{score}] {path.relative_to(ROOT).as_posix()}")
        for number, line in matches:
            print(f"  {number}: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
