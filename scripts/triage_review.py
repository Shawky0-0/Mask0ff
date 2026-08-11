#!/usr/bin/env python3
"""Validate an adversarial vendor-triage review before a finding can be reportable."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PREREQUISITE_GATES = ("T1", "V1", "E1", "X1", "I1")

MANDATORY_REJECTION_TESTS = (
    "working-as-designed",
    "explicit-user-or-admin-consent",
    "same-trust-principal",
    "no-attacker-control",
    "equivalent-authority",
    "stale-or-fixed-current-version",
    "functional-correctness-only",
    "unrealistic-or-self-imposed-precondition",
    "no-security-contract",
    "potential-impact-only",
    "accepted-risk-or-documented-policy",
    "duplicate-or-known-issue",
)
VALID_TEST_STATUSES = {"defeated", "applies", "unknown", "not-applicable"}
FINAL_VERDICTS = {"survives", "reject", "needs-more-evidence"}
CLASSIFICATIONS = {
    "security-vulnerability",
    "working-as-designed",
    "hardening",
    "functional-bug",
    "outdated-or-fixed",
    "duplicate-or-known-issue",
    "insufficient-attacker-control",
    "insufficient-security-impact",
    "needs-more-evidence",
}


def evidence_ids(record: Any) -> set[str]:
    if not isinstance(record, dict):
        return set()
    return {
        str(item.get("id"))
        for item in record.get("evidence", [])
        if isinstance(item, dict) and str(item.get("id", "")).strip()
    }


def validate_triage(review: Any, record: Any) -> tuple[str, list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(review, dict):
        return "invalid", ["triage review must be a JSON object"], warnings
    if not isinstance(record, dict):
        return "invalid", ["finding record must be a JSON object"], warnings
    known = evidence_ids(record)

    gates = record.get("gates", {}) if isinstance(record.get("gates"), dict) else {}
    missing_prerequisites = [
        gate for gate in PREREQUISITE_GATES
        if not isinstance(gates.get(gate), dict) or gates.get(gate, {}).get("status") != "pass"
    ]
    if missing_prerequisites:
        errors.append("triage review cannot run as a final J1 decision before prerequisite gates pass: " + ", ".join(missing_prerequisites))

    threat = record.get("threat_model") if isinstance(record.get("threat_model"), dict) else {}
    contract = threat.get("security_contract") if isinstance(threat.get("security_contract"), dict) else {}
    authority = threat.get("authority_delta") if isinstance(threat.get("authority_delta"), dict) else {}
    freshness = record.get("freshness") if isinstance(record.get("freshness"), dict) else {}
    impact = record.get("impact_model") if isinstance(record.get("impact_model"), dict) else {}
    validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}

    if not threat.get("attacker_controls") or not threat.get("attacker_control_evidence"):
        errors.append("triage review requires an evidence-backed attacker-control model in the finding")
    if not threat.get("trust_principals") or not threat.get("trust_model_evidence"):
        errors.append("triage review requires an evidence-backed trust-principal model in the finding")
    if not str(contract.get("statement", "")).strip() or not contract.get("evidence"):
        errors.append("triage review requires an evidence-backed security contract in the finding")
    if freshness.get("status") != "vulnerable" or freshness.get("submission_relevance") not in {"current-vulnerable", "supported-vulnerable"}:
        errors.append("triage review requires current/supported vulnerable-version evidence in the finding")
    if authority.get("boundary_crossed") is not True or authority.get("equivalent_authority_already_held") is not False:
        errors.append("triage review requires a proven non-equivalent authority/protected-property boundary crossing")
    if not impact.get("demonstrated_effects") or not (impact.get("attacker_gain") or impact.get("victim_loss")):
        errors.append("triage review requires a directly demonstrated security impact in the finding")
    if validation.get("verdict") != "confirmed":
        errors.append("triage review requires X1 independent confirmation before a final J1 decision")

    if review.get("schema_version") != 1:
        errors.append("triage review schema_version must be 1")
    if review.get("kind") != "mask0ff-triage-review":
        errors.append("triage review kind must be mask0ff-triage-review")

    if not str(review.get("reviewed_at_utc", "")).strip():
        errors.append("reviewed_at_utc is required")

    reviewer = str(review.get("reviewer_owner", "")).strip()
    discovery = str(review.get("discovery_owner", "")).strip()
    if not reviewer or not discovery:
        errors.append("reviewer_owner and discovery_owner are required")
    elif reviewer.casefold() == discovery.casefold():
        errors.append("triage review must be adversarial and independent of the discovery owner")

    tests = review.get("rejection_tests")
    if not isinstance(tests, list):
        errors.append("rejection_tests must be a list")
        tests = []
    by_id: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(tests, 1):
        if not isinstance(item, dict):
            errors.append(f"rejection test {index} is not an object")
            continue
        test_id = str(item.get("id", "")).strip()
        if not test_id:
            errors.append(f"rejection test {index} has no id")
            continue
        if test_id in by_id:
            errors.append(f"duplicate rejection test id: {test_id}")
            continue
        by_id[test_id] = item
        test_status = item.get("status")
        if test_status not in VALID_TEST_STATUSES:
            errors.append(f"rejection test {test_id} has invalid status {test_status!r}")
        rationale = str(item.get("rationale", "")).strip()
        if not rationale:
            errors.append(f"rejection test {test_id} requires a rationale")
        raw_refs = item.get("evidence", [])
        if not isinstance(raw_refs, list):
            errors.append(f"rejection test {test_id} evidence must be a list")
            raw_refs = []
        refs = {str(ref) for ref in raw_refs}
        unknown = sorted(refs - known)
        if unknown:
            errors.append(f"rejection test {test_id} references unknown evidence ids: {', '.join(unknown)}")
        if test_status == "defeated" and not refs:
            errors.append(f"rejection test {test_id} is defeated without evidence")
        if test_status == "applies" and not refs:
            warnings.append(f"rejection test {test_id} applies but has no evidence; preserve the basis")

    missing = [item for item in MANDATORY_REJECTION_TESTS if item not in by_id]
    if missing:
        errors.append(f"missing mandatory rejection tests: {', '.join(missing)}")

    if review.get("current_version_checked") is not True:
        errors.append("triage review must independently check current/supported version relevance")
    if review.get("security_contract_checked") is not True:
        errors.append("triage review must independently check the alleged security contract")
    if review.get("attacker_control_checked") is not True:
        errors.append("triage review must independently check attacker control")
    if review.get("authority_delta_checked") is not True:
        errors.append("triage review must independently check authority delta or protected-property loss")

    final = str(review.get("final_verdict", "")).strip()
    classification = str(review.get("classification", "")).strip()
    if final not in FINAL_VERDICTS:
        errors.append("final_verdict must be survives, reject, or needs-more-evidence")
    if classification not in CLASSIFICATIONS:
        errors.append("classification is invalid")
    if not str(review.get("reason", "")).strip():
        errors.append("triage review reason is required")

    applicable = [item for item in by_id.values() if item.get("status") == "applies"]
    unknown_tests = [item for item in by_id.values() if item.get("status") == "unknown"]
    if final == "survives":
        if classification != "security-vulnerability":
            errors.append("surviving triage review must classify the candidate as security-vulnerability")
        if applicable:
            errors.append("surviving triage review leaves at least one vendor rejection reason applicable")
        if unknown_tests:
            errors.append("surviving triage review leaves at least one vendor rejection reason unknown")
    elif final == "reject" and classification == "security-vulnerability":
        errors.append("rejected triage review cannot classify the candidate as security-vulnerability")

    if errors:
        return "invalid", errors, warnings
    return {"survives": "pass", "reject": "fail", "needs-more-evidence": "pending"}[final], errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a mask0ff adversarial triage review.")
    parser.add_argument("review", type=Path)
    parser.add_argument("--finding", type=Path, required=True)
    args = parser.parse_args()
    try:
        review = json.loads(args.review.read_text(encoding="utf-8-sig"))
        record = json.loads(args.finding.read_text(encoding="utf-8-sig"))
        status, errors, warnings = validate_triage(review, record)
        print(json.dumps({"status": status, "errors": errors, "warnings": warnings}, indent=2))
        return 0 if status == "pass" else 2 if status in {"fail", "pending"} else 1
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
