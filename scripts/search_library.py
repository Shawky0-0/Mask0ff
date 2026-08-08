#!/usr/bin/env python3
"""Search the technique and case libraries without loading whole documents."""

from __future__ import annotations

import argparse
import math
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REFERENCE_ROOT = ROOT / "references"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("query", help="Words, symbol names, endpoints, or vulnerability terms")
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--snippets", type=int, default=3)
    args = parser.parse_args()

    terms = [term.lower() for term in re.findall(r"[\w./:-]+", args.query) if len(term) > 1]
    if not terms:
        parser.error("query must contain searchable terms")

    results: list[tuple[int, Path, list[tuple[int, str]]]] = []
    for path in REFERENCE_ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".json"}:
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
            if any(term in lowered for term in terms):
                if len(matches) < args.snippets:
                    matches.append((number, line.strip()[:240]))
        if score:
            results.append((score, path, matches))

    results.sort(key=lambda item: (-item[0], item[1].as_posix()))
    for score, path, matches in results[: args.limit]:
        print(f"[{score}] {path.relative_to(ROOT).as_posix()}")
        for number, line in matches:
            print(f"  {number}: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
