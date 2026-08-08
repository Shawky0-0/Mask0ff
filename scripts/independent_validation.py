#!/usr/bin/env python3
"""Validate a blind, independent challenge review for one finding candidate."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


INDEPENDENCE_MODES = {"separate-agent", "separate-model", "human-review", "independent-tool-replay"}
VERDICTS = {"confirmed", "refuted", "inconclusive"}
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def evidence_map(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id")): item
        for item in record.get("evidence", [])
        if isinstance(item, dict) and str(item.get("id", "")).strip()
    }


def referenced_evidence(review: dict[str, Any]) -> set[str]:
    refs = set(str(item) for item in review.get("independent_reproduction_evidence", []))
    refs.update(str(item) for item in review.get("control_evidence", []))
    for collection in ("alternative_explanations", "chain_review"):
        for item in review.get(collection, []):
            if isinstance(item, dict):
                refs.update(str(ref) for ref in item.get("evidence", []))
    packet = str(review.get("blind_packet_evidence_id", "")).strip()
    if packet:
        refs.add(packet)
    return refs


def validate_review(review: dict[str, Any], record: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    evidence = evidence_map(record)
    if review.get("schema_version") != 1:
        errors.append("review schema_version must be 1")
    if review.get("kind") != "mask0ff-independent-validation":
        errors.append("review kind must be mask0ff-independent-validation")

    discovery_owner = str(review.get("discovery_owner", "")).strip()
    validator_owner = str(review.get("validator_owner", "")).strip()
    if not discovery_owner or not validator_owner:
        errors.append("discovery_owner and validator_owner are required")
    elif discovery_owner.casefold() == validator_owner.casefold():
        errors.append("independent validation cannot be performed by the discovery owner")
    if review.get("independence") not in INDEPENDENCE_MODES:
        errors.append("independence mode is invalid")

    packet_id = str(review.get("blind_packet_evidence_id", "")).strip()
    packet = evidence.get(packet_id)
    if not packet or packet.get("kind") != "validation-packet":
        errors.append("blind_packet_evidence_id must reference validation-packet evidence")
    packet_hash = str(review.get("blind_packet_sha256", "")).strip().lower()
    if not SHA256.fullmatch(packet_hash):
        errors.append("blind_packet_sha256 is missing or malformed")
    elif packet and packet_hash != str(packet.get("sha256", "")).lower():
        errors.append("blind packet SHA-256 does not match the preserved evidence item")

    known = set(evidence)
    all_refs = referenced_evidence(review)
    unknown = sorted(all_refs - known)
    if unknown:
        errors.append(f"independent review references unknown evidence ids: {', '.join(unknown)}")

    discovery_refs: set[str] = set()
    gates = record.get("gates", {}) if isinstance(record.get("gates"), dict) else {}
    for gate in ("P1", "C1", "R1"):
        item = gates.get(gate, {}) if isinstance(gates.get(gate), dict) else {}
        discovery_refs.update(str(ref) for ref in item.get("evidence", []))

    reproduction = {str(item) for item in review.get("independent_reproduction_evidence", [])}
    controls = {str(item) for item in review.get("control_evidence", [])}
    if not reproduction:
        errors.append("independent_reproduction_evidence requires at least one artifact")
    if not controls:
        errors.append("control_evidence requires at least one independently replayed control")
    if reproduction & discovery_refs:
        errors.append("independent reproduction reuses discovery proof/control/run evidence")
    if controls & discovery_refs:
        errors.append("independent controls reuse discovery proof/control/run evidence")
    if reproduction & controls:
        errors.append("independent proof and control evidence must be distinct")

    alternatives = review.get("alternative_explanations")
    if not isinstance(alternatives, list) or not alternatives:
        errors.append("alternative_explanations requires at least one challenged explanation")
        alternatives = []
    for index, item in enumerate(alternatives, 1):
        if not isinstance(item, dict) or not str(item.get("explanation", "")).strip():
            errors.append(f"alternative explanation {index} is incomplete")
            continue
        if item.get("status") not in {"ruled-out", "plausible", "unknown"}:
            errors.append(f"alternative explanation {index} has an invalid status")
        if not item.get("evidence"):
            errors.append(f"alternative explanation {index} has no evidence")

    chain = review.get("chain_review")
    if not isinstance(chain, list) or not chain:
        errors.append("chain_review requires at least one explicit exploit-chain link")
        chain = []
    for index, item in enumerate(chain, 1):
        if not isinstance(item, dict) or not str(item.get("link", "")).strip():
            errors.append(f"chain link {index} is incomplete")
            continue
        if item.get("status") not in {"pass", "fail", "unknown"}:
            errors.append(f"chain link {index} has an invalid status")
        if not item.get("evidence"):
            errors.append(f"chain link {index} has no evidence")

    if not isinstance(review.get("environment_limitations"), list):
        errors.append("environment_limitations must be a list")
    if not str(review.get("duplicate_assessment", "")).strip():
        errors.append("duplicate_assessment is required")
    verdict = str(review.get("verdict", "")).strip()
    if verdict not in VERDICTS:
        errors.append("verdict must be confirmed, refuted, or inconclusive")
    if not str(review.get("reason", "")).strip():
        errors.append("review reason is required")

    if verdict == "confirmed":
        if review.get("scope_rechecked") is not True:
            errors.append("confirmed review did not independently recheck scope")
        if review.get("clean_environment") is not True:
            errors.append("confirmed review did not use a clean environment or fresh state")
        if any(item.get("status") != "ruled-out" for item in alternatives if isinstance(item, dict)):
            errors.append("confirmed review leaves an alternative explanation plausible or unknown")
        if any(item.get("status") != "pass" for item in chain if isinstance(item, dict)):
            errors.append("confirmed review has an incomplete or failed exploit-chain link")
    elif verdict == "inconclusive":
        warnings.append("independent review is inconclusive; X1 must remain pending")

    if errors:
        return "invalid", errors, warnings
    return {"confirmed": "pass", "refuted": "fail", "inconclusive": "pending"}[verdict], errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an independent mask0ff challenge review.")
    parser.add_argument("review", type=Path)
    parser.add_argument("--finding", type=Path, required=True)
    args = parser.parse_args()
    try:
        review = json.loads(args.review.read_text(encoding="utf-8-sig"))
        record = json.loads(args.finding.read_text(encoding="utf-8-sig"))
        status, errors, warnings = validate_review(review, record)
        print(json.dumps({"status": status, "errors": errors, "warnings": warnings}, indent=2))
        return 0 if status == "pass" else 2 if status in {"fail", "pending"} else 1
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
