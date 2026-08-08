#!/usr/bin/env python3
"""Rank the compact current-technique catalog by signal, mode, and surface."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "references" / "techniques" / "current-techniques.json"
TOKEN = re.compile(r"[a-z0-9][a-z0-9.+_-]*")


def tokens(value: str) -> set[str]:
    return set(TOKEN.findall(value.lower()))


def source_map(catalog: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(row.get("id")): row for row in catalog.get("sources", []) if isinstance(row, dict)}


def score(row: dict[str, Any], query: set[str], mode: str | None, surface: str | None) -> float:
    fields = " ".join(
        [
            str(row.get("id", "")),
            str(row.get("title", "")),
            " ".join(str(value) for value in row.get("signals", [])),
            " ".join(str(value) for value in row.get("surfaces", [])),
        ]
    )
    row_tokens = tokens(fields)
    overlap = len(query & row_tokens)
    if query and overlap == 0:
        return -100.0
    value = float(overlap * 10)
    if query and any(" ".join(sorted(query)) in str(row.get("title", "")).lower() for _ in [0]):
        value += 5
    if mode and mode in row.get("modes", []):
        value += 4
    elif mode:
        value -= 20
    if surface and surface in row.get("surfaces", []):
        value += 6
    elif surface:
        value -= 10
    rank = row.get("rank")
    if isinstance(rank, int):
        value += max(0.0, (11 - rank) / 10)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Search provenance-rich current security techniques.")
    parser.add_argument("query", nargs="?", default="")
    parser.add_argument("--mode", choices=("black-box", "gray-box", "white-box", "hybrid"))
    parser.add_argument(
        "--surface",
        choices=(
            "web", "api", "graphql", "websocket", "grpc", "sse", "webhook", "soap",
            "mobile", "desktop", "browser-extension", "cloud", "ci-cd", "source", "ai-agent",
        ),
    )
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--sources", action="store_true", help="Return source registry instead of techniques")
    args = parser.parse_args()
    try:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        if args.sources:
            result = {
                "reviewed_at_utc": catalog.get("reviewed_at_utc"),
                "sources": catalog.get("sources", []),
                "caveat": "Current at the recorded review time only; recheck living sources during a real engagement.",
            }
            print(json.dumps(result, indent=2))
            return 0
        query = tokens(args.query)
        sources = source_map(catalog)
        ranked = []
        for row in catalog.get("techniques", []):
            if not isinstance(row, dict):
                continue
            value = score(row, query, args.mode, args.surface)
            if query and value <= 0:
                continue
            copy = dict(row)
            copy["relevance_score"] = round(value, 2)
            copy["source_details"] = sources.get(str(row.get("source")), {})
            ranked.append(copy)
        ranked.sort(key=lambda item: (-float(item["relevance_score"]), int(item.get("rank", 999)), str(item.get("id"))))
        result = {
            "query": args.query,
            "mode": args.mode,
            "surface": args.surface,
            "reviewed_at_utc": catalog.get("reviewed_at_utc"),
            "matches": ranked[: max(1, min(args.limit, 50))],
            "caveat": "Technique matches are hypotheses, not findings. Use target evidence, controls, clean repeats, and current primary-source review.",
        }
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
