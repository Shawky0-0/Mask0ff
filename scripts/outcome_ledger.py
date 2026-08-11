#!/usr/bin/env python3
"""Record submission outcomes, search them as triage prior art, and learn from them."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from triage_review import MANDATORY_REJECTION_TESTS

VERDICTS = {"accepted", "duplicate", "informative", "needs-more-info", "rejected", "pending"}
CLASSIFICATION_SIGNALS = {
    "working-as-designed": "working-as-designed",
    "consent": "explicit-user-or-admin-consent",
    "same-principal": "same-trust-principal",
    "no-attacker-control": "no-attacker-control",
    "equivalent-authority": "equivalent-authority",
    "stale-version": "stale-or-fixed-current-version",
    "functional-correctness": "functional-correctness-only",
    "unrealistic-preconditions": "unrealistic-or-self-imposed-precondition",
    "no-security-contract": "no-security-contract",
    "potential-impact": "potential-impact-only",
    "accepted-risk": "accepted-risk-or-documented-policy",
    "duplicate": "duplicate-or-known-issue",
}
KNOWN_SIGNALS = set(MANDATORY_REJECTION_TESTS) | set(CLASSIFICATION_SIGNALS.values())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_ledger(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"schema_version": 1, "kind": "mask0ff-outcome-ledger", "outcomes": []}
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or not isinstance(value.get("outcomes"), list):
        raise ValueError(f"ledger is not a mask0ff outcome ledger: {path}")
    return value


def save_ledger(path: Path, ledger: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def outcome_entry(args: argparse.Namespace) -> dict[str, Any]:
    signals = []
    for raw in args.signal or []:
        signal = str(raw).strip()
        if signal not in KNOWN_SIGNALS:
            raise ValueError(f"unknown rejection signal {signal!r}; use one of: {', '.join(sorted(KNOWN_SIGNALS))}")
        signals.append(signal)
    entry = {
        "schema_version": 1,
        "id": str(args.report_id).strip(),
        "platform": args.platform,
        "program": args.program,
        "target": args.target or "",
        "vulnerability_class": args.class_name or "",
        "finding_title": args.title or "",
        "verdict": args.verdict,
        "severity": args.severity or "",
        "vendor_reason": args.vendor_reason or "",
        "signals": sorted(set(signals)),
        "submitted_at_utc": args.date or utc_now(),
        "recorded_at_utc": utc_now(),
        "notes": args.notes or "",
    }
    missing = [field for field in ("id", "platform", "program", "verdict") if not entry[field]]
    if missing:
        raise ValueError(f"required fields missing: {', '.join(missing)}")
    if entry["verdict"] not in VERDICTS:
        raise ValueError(f"verdict must be one of: {', '.join(sorted(VERDICTS))}")
    return entry


def record_outcome(args: argparse.Namespace) -> int:
    ledger = load_ledger(args.ledger)
    entry = outcome_entry(args)
    existing = [item for item in ledger["outcomes"] if str(item.get("id", "")).strip() == entry["id"]]
    if existing:
        raise ValueError(f"outcome already recorded: {entry['id']}")
    ledger["outcomes"].append(entry)
    save_ledger(args.ledger, ledger)
    print(json.dumps({"recorded": entry, "total": len(ledger["outcomes"])}, indent=2))
    return 0


def search_outcomes(args: argparse.Namespace) -> int:
    ledger = load_ledger(args.ledger)
    results = []
    for item in ledger["outcomes"]:
        text = " ".join(
            str(item.get(field, "")) for field in ("id", "platform", "program", "target", "vulnerability_class", "finding_title", "vendor_reason")
        ).lower()
        if args.platform and args.platform.lower() not in str(item.get("platform", "")).lower():
            continue
        if args.program and args.program.lower() not in str(item.get("program", "")).lower():
            continue
        if args.class_name and args.class_name.lower() not in str(item.get("vulnerability_class", "")).lower():
            continue
        if args.verdict and args.verdict != item.get("verdict"):
            continue
        if args.query and args.query.lower() not in text:
            continue
        if args.signal and not set(args.signal) & set(item.get("signals", [])):
            continue
        results.append(item)
    results.sort(key=lambda item: str(item.get("submitted_at_utc", "")), reverse=True)
    output = {
        "count": len(results),
        "prior_art_note": "Prior outcomes are triage prior art for J1 and the program threat model; they are not verdicts for the current candidate.",
        "outcomes": results,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


def stats_outcomes(args: argparse.Namespace) -> int:
    ledger = load_ledger(args.ledger)
    outcomes = ledger["outcomes"]
    by_platform: dict[str, dict[str, int]] = {}
    by_program: dict[str, dict[str, int]] = {}
    by_class: dict[str, dict[str, int]] = {}
    for item in outcomes:
        for bucket, key in ((by_platform, "platform"), (by_program, "program"), (by_class, "vulnerability_class")):
            name = str(item.get(key, "")).strip() or "unknown"
            cell = bucket.setdefault(name, {})
            cell[str(item.get("verdict", "pending"))] = cell.get(str(item.get("verdict", "pending")), 0) + 1
    for bucket in (by_platform, by_program, by_class):
        for name, verdicts in bucket.items():
            accepted = verdicts.get("accepted", 0)
            total = sum(verdicts.values())
            bucket[name] = {**verdicts, "total": total, "acceptance_rate": round(accepted / total, 3) if total else 0.0}
    print(
        json.dumps(
            {
                "total_outcomes": len(outcomes),
                "by_platform": by_platform,
                "by_program": by_program,
                "by_class": by_class,
                "note": "Acceptance rates are empirical prior art for platform selection and J1; a low acceptance class is a strong T0 signal, not a ban.",
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def import_outcomes(args: argparse.Namespace) -> int:
    ledger = load_ledger(args.ledger)
    source = json.loads(args.file.read_text(encoding="utf-8-sig"))
    entries = source if isinstance(source, list) else source.get("outcomes", []) if isinstance(source, dict) else []
    if not isinstance(entries, list):
        raise ValueError("import file must be a JSON array of outcomes or a ledger object")
    existing = {str(item.get("id", "")).strip() for item in ledger["outcomes"]}
    added = 0
    for entry in entries:
        if not isinstance(entry, dict) or not str(entry.get("id", "")).strip():
            raise ValueError("imported outcomes must be objects with an id")
        entry_id = str(entry["id"]).strip()
        if entry_id in existing:
            continue
        signals = [str(s) for s in entry.get("signals", []) if str(s) in KNOWN_SIGNALS]
        ledger["outcomes"].append(
            {
                "schema_version": 1,
                "id": entry_id,
                "platform": str(entry.get("platform", "")),
                "program": str(entry.get("program", "")),
                "target": str(entry.get("target", "")),
                "vulnerability_class": str(entry.get("vulnerability_class", "")),
                "finding_title": str(entry.get("finding_title", "")),
                "verdict": entry.get("verdict") if entry.get("verdict") in VERDICTS else "pending",
                "severity": str(entry.get("severity", "")),
                "vendor_reason": str(entry.get("vendor_reason", "")),
                "signals": sorted(set(signals)),
                "submitted_at_utc": str(entry.get("submitted_at_utc", utc_now())),
                "recorded_at_utc": utc_now(),
                "notes": str(entry.get("notes", "")),
            }
        )
        existing.add(entry_id)
        added += 1
    save_ledger(args.ledger, ledger)
    print(json.dumps({"imported": added, "total": len(ledger["outcomes"])}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record and learn from submission outcomes.")
    parser.add_argument("--ledger", type=Path, default=Path("outcome-ledger.json"), help="Ledger path (default: ./outcome-ledger.json)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    record = subparsers.add_parser("record")
    record.add_argument("--report-id", required=True)
    record.add_argument("--platform", required=True)
    record.add_argument("--program", required=True)
    record.add_argument("--target")
    record.add_argument("--class-name", dest="class_name")
    record.add_argument("--title")
    record.add_argument("--verdict", required=True)
    record.add_argument("--severity")
    record.add_argument("--vendor-reason")
    record.add_argument("--signal", action="append", help="Rejection signal id (e.g. working-as-designed, no-attacker-control)")
    record.add_argument("--date")
    record.add_argument("--notes")
    record.set_defaults(handler=record_outcome)

    search = subparsers.add_parser("search")
    search.add_argument("--platform")
    search.add_argument("--program")
    search.add_argument("--class-name", dest="class_name")
    search.add_argument("--verdict")
    search.add_argument("--signal", action="append")
    search.add_argument("query", nargs="?")
    search.set_defaults(handler=search_outcomes)

    stats = subparsers.add_parser("stats")
    stats.set_defaults(handler=stats_outcomes)

    import_out = subparsers.add_parser("import")
    import_out.add_argument("file", type=Path)
    import_out.set_defaults(handler=import_outcomes)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        return int(args.handler(args))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
