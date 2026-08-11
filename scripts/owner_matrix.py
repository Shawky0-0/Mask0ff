#!/usr/bin/env python3
"""Validate an object-ownership matrix for access-control findings."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

OBSERVED_ACCESS = {"granted", "denied", "error"}


def evidence_ids(record: dict[str, Any]) -> set[str]:
    if not isinstance(record, dict):
        return set()
    return {
        str(item.get("id"))
        for item in record.get("evidence", [])
        if isinstance(item, dict) and str(item.get("id", "")).strip()
    }


def validate_matrix(matrix: Any, record: dict[str, Any] | None = None) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    warnings: list[str] = []
    signals: list[dict[str, Any]] = []
    if not isinstance(matrix, dict):
        return ["owner matrix must be a JSON object"], warnings, signals
    if matrix.get("schema_version") != 1 or matrix.get("kind") != "mask0ff-owner-matrix":
        errors.append("owner matrix schema or kind is invalid")
    attacker = str(matrix.get("attacker_account", "")).strip()
    victim = str(matrix.get("victim_account", "")).strip()
    if not attacker or not victim:
        errors.append("attacker_account and victim_account are required")
    elif attacker.casefold() == victim.casefold():
        errors.append("attacker_account and victim_account must be distinct principals")
    known = evidence_ids(record) if record is not None else set()
    entries = matrix.get("entries", [])
    if not isinstance(entries, list):
        errors.append("entries must be a list")
        entries = []
    if not entries:
        warnings.append("owner matrix has no entries; access-control claims need at least one object row")
    seen_objects: set[str] = set()
    for index, entry in enumerate(entries, 1):
        label = f"entry {index}"
        if not isinstance(entry, dict):
            errors.append(f"{label} is not an object")
            continue
        object_id = str(entry.get("object_id", "")).strip()
        if not object_id:
            errors.append(f"{label} requires object_id")
        elif object_id in seen_objects:
            errors.append(f"{label} duplicate object_id: {object_id}")
        seen_objects.add(object_id)
        for field in ("created_by_request", "created_by_account", "owner_account"):
            if not str(entry.get(field, "")).strip():
                errors.append(f"{label} requires {field}")
        expected = entry.get("expected_allowed_accounts")
        if not isinstance(expected, list) or not expected:
            errors.append(f"{label} requires expected_allowed_accounts (which accounts SHOULD access this object)")
            expected_accounts: set[str] = set()
        else:
            expected_accounts = {str(item).strip().casefold() for item in expected if str(item).strip()}
            if not expected_accounts:
                errors.append(f"{label} expected_allowed_accounts must contain at least one non-empty account")
        tested = str(entry.get("tested_account", "")).strip()
        if not tested:
            errors.append(f"{label} requires tested_account")
        observed = str(entry.get("observed_access", "")).strip()
        if observed not in OBSERVED_ACCESS:
            errors.append(f"{label} observed_access must be granted, denied, or error")
        refs = [str(ref) for ref in entry.get("evidence", []) if isinstance(entry.get("evidence"), list)]
        if not refs:
            errors.append(f"{label} requires evidence references")
        unknown = [ref for ref in refs if record is not None and ref not in known]
        if unknown:
            errors.append(f"{label} references unknown evidence ids: {', '.join(unknown)}")
        owner = str(entry.get("owner_account", "")).strip()
        if tested and owner and tested.casefold() == owner.casefold():
            warnings.append(f"{label}: tested account owns the object; accessing an object you own is not broken access control")
        if tested and observed == "granted" and expected_accounts and tested.casefold() not in expected_accounts:
            signals.append(
                {
                    "object_id": object_id,
                    "tested_account": tested,
                    "observed_access": observed,
                    "signal": "access granted to an account outside the expected allowed set",
                    "note": "A candidate, not a verdict: confirm it is not an intended share and that the object was created by a different principal.",
                }
            )
        if tested and observed == "denied" and expected_accounts and tested.casefold() in expected_accounts:
            warnings.append(f"{label}: expected-allowed account was denied; check the baseline is correct")
    return errors, warnings, signals


def load_matrix(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any] | None]:
    matrix = json.loads(args.matrix.read_text(encoding="utf-8-sig"))
    if not isinstance(matrix, dict):
        raise ValueError("owner matrix must be a JSON object")
    record = None
    if args.finding:
        record = json.loads(args.finding.read_text(encoding="utf-8-sig"))
        if not isinstance(record, dict):
            raise ValueError("finding record must be a JSON object")
    return matrix, record


def verify_matrix(args: argparse.Namespace) -> int:
    matrix, record = load_matrix(args)
    errors, warnings, signals = validate_matrix(matrix, record)
    result = {
        "status": "pass" if not errors else "blocked",
        "matrix": str(args.matrix.resolve()),
        "entry_count": len(matrix.get("entries", []) if isinstance(matrix.get("entries"), list) else []),
        "signals": signals,
        "errors": errors,
        "warnings": warnings,
        "caveat": "The matrix proves ownership and expected access; a granted-outside-expected signal is a candidate that still needs C1 controls and the J1 review.",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 1 if errors else 0


def init_matrix(args: argparse.Namespace) -> int:
    template = json.loads((Path(__file__).resolve().parents[1] / "assets" / "evidence-bundle" / "owner-matrix.json").read_text(encoding="utf-8"))
    template["attacker_account"] = args.attacker or ""
    template["victim_account"] = args.victim or ""
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(template, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"path": str(args.output.resolve()), "hint": "Fill entries: object_id, created_by_request, created_by_account, owner_account, expected_allowed_accounts, tested_account, observed_access, evidence."}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the object-ownership matrix for access-control findings.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("output", type=Path)
    init.add_argument("--attacker")
    init.add_argument("--victim")
    init.set_defaults(handler=init_matrix)
    verify = subparsers.add_parser("verify")
    verify.add_argument("matrix", type=Path)
    verify.add_argument("--finding", type=Path, help="Finding-record JSON to cross-check evidence references")
    verify.set_defaults(handler=verify_matrix)
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
