#!/usr/bin/env python3
"""Validate and summarize affected-version evidence without guessing untested ranges."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


VALID_RESULTS = {"safe", "vulnerable", "inconclusive", "not_tested"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    data = json.loads(args.matrix.read_text(encoding="utf-8-sig"))
    errors: list[str] = []
    warnings: list[str] = []
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    for field in ("product", "component", "test_invariant"):
        if not str(data.get(field, "")).strip():
            errors.append(f"{field} is required")
    if data.get("ordering") != "oldest-to-newest":
        errors.append("ordering must be oldest-to-newest")

    releases = data.get("releases", [])
    seen: set[str] = set()
    prior_date = ""
    transitions = []
    prior_result = None
    for index, release in enumerate(releases):
        label = str(release.get("version") or release.get("commit") or "").strip()
        if not label:
            errors.append(f"release {index}: version or commit is required")
            label = f"row-{index}"
        if label in seen:
            errors.append(f"duplicate release label: {label}")
        seen.add(label)
        result = release.get("result")
        if result not in VALID_RESULTS:
            errors.append(f"{label}: invalid result {result!r}")
        evidence = release.get("evidence", [])
        if result in {"safe", "vulnerable"} and not evidence:
            errors.append(f"{label}: {result} requires evidence")
        date = str(release.get("date", ""))
        if prior_date and date and date < prior_date:
            warnings.append(f"date order decreases at {label}")
        if date:
            prior_date = date
        if prior_result and result != prior_result and result in {"safe", "vulnerable"} and prior_result in {"safe", "vulnerable"}:
            transitions.append({"from": prior_result, "to": result, "at": label})
        if result in {"safe", "vulnerable"}:
            prior_result = result

    vulnerable = [str(item.get("version") or item.get("commit")) for item in releases if item.get("result") == "vulnerable"]
    safe = [str(item.get("version") or item.get("commit")) for item in releases if item.get("result") == "safe"]
    unknown = [str(item.get("version") or item.get("commit")) for item in releases if item.get("result") in {"inconclusive", "not_tested"}]
    if not vulnerable:
        warnings.append("no tested vulnerable release")
    if not safe:
        warnings.append("no tested safe release or fix control")
    if unknown:
        warnings.append("untested or inconclusive releases prevent a continuous affected-range claim")

    result = {
        "tested_releases": len(releases),
        "oldest_tested_vulnerable": vulnerable[0] if vulnerable else None,
        "newest_tested_vulnerable": vulnerable[-1] if vulnerable else None,
        "oldest_tested_safe": safe[0] if safe else None,
        "newest_tested_safe": safe[-1] if safe else None,
        "unknown_releases": unknown,
        "transitions": transitions,
        "errors": errors,
        "warnings": warnings,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for key, value in result.items():
            print(f"{key}: {value}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
