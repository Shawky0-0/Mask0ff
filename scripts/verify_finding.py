#!/usr/bin/env python3
"""Validate a finding record and calculate its evidence state."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from independent_validation import INDEPENDENCE_MODES, validate_review


VALID_STATUSES = {"pending", "pass", "fail", "blocked", "not_applicable"}
GATES = ("A0", "A1", "H1", "B1", "P1", "C1", "R1", "X1", "I1", "S1", "V1", "F1", "D1", "Q1")
CORE_VERIFIED = ("A0", "A1", "H1", "B1", "P1", "C1", "R1", "X1", "I1")
APPLICABILITY = ("S1", "V1", "F1")
ASSESSMENT_MODES = {"black-box", "gray-box", "white-box", "hybrid"}
SECRET_KEYS = {
    "password",
    "passwd",
    "token",
    "api_token",
    "api_key",
    "access_token",
    "refresh_token",
    "bearer_token",
    "cookie",
    "session_cookie",
    "secret",
}


def status(record: dict[str, Any], gate: str) -> str:
    return str(record.get("gates", {}).get(gate, {}).get("status", "pending"))


def calculate_state(record: dict[str, Any]) -> str:
    if status(record, "A0") != "pass":
        return "blocked"
    if not all(status(record, gate) == "pass" for gate in ("B1", "P1", "C1")):
        return "candidate"
    if not all(status(record, gate) == "pass" for gate in CORE_VERIFIED):
        return "substantiated"
    if not all(status(record, gate) in {"pass", "not_applicable"} for gate in APPLICABILITY):
        return "verified"
    if status(record, "D1") == "pass" and status(record, "Q1") == "pass":
        return "reportable"
    return "verified"


def calculate_effective_state(record: dict[str, Any], errors: list[str]) -> str:
    """Downgrade invalid authorization evidence even when the stored gate says pass."""
    state = calculate_state(record)
    if status(record, "A0") != "pass":
        return "blocked"
    a0 = record.get("gates", {}).get("A0", {})
    refs = {str(ref) for ref in a0.get("evidence", [])} if isinstance(a0, dict) else set()
    for error in errors:
        if error.startswith("A0") or error.startswith("authorization"):
            return "blocked"
        if any(ref and ref in error for ref in refs):
            return "blocked"
    if state in {"verified", "reportable"} and any(
        error.startswith("X1") or error.startswith("validation") for error in errors
    ):
        return "substantiated"
    return state


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def embedded_secret_fields(value: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() in SECRET_KEYS and child not in (None, "", [], {}):
                errors.append(f"finding record contains forbidden secret material at {child_path}")
            errors.extend(embedded_secret_fields(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(embedded_secret_fields(child, f"{path}[{index}]"))
    return errors


def validate(
    record: dict[str, Any],
    record_path: Path | None = None,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if record.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if record.get("work_mode") not in {"passive", "local-lab", "active-authorized", "unclear"}:
        errors.append("work_mode is invalid")
    if record.get("assessment_mode", "black-box") not in ASSESSMENT_MODES:
        errors.append("assessment_mode is invalid")
    if not str(record.get("title", "")).strip():
        errors.append("title is required")
    errors.extend(embedded_secret_fields(record))

    evidence = record.get("evidence", [])
    evidence_ids: set[str] = set()
    evidence_by_id: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            errors.append(f"evidence item {index} is not an object")
            continue
        evidence_id = str(item.get("id", "")).strip()
        if not evidence_id:
            errors.append(f"evidence item {index} has no id")
            continue
        if evidence_id in evidence_ids:
            errors.append(f"duplicate evidence id {evidence_id!r}")
            continue
        evidence_ids.add(evidence_id)
        evidence_by_id[evidence_id] = item
        if not str(item.get("kind", "")).strip():
            errors.append(f"{evidence_id} has no kind")
        relative = str(item.get("path", "")).strip()
        if not relative:
            errors.append(f"{evidence_id} has no path")
        if record_path is not None and relative:
            base = record_path.resolve().parent
            artifact = (base / relative).resolve()
            try:
                artifact.relative_to(base)
            except ValueError:
                errors.append(f"{evidence_id} path escapes the finding bundle")
                continue
            if not artifact.is_file():
                errors.append(f"{evidence_id} artifact is missing: {relative}")
                continue
            expected_size = item.get("size_bytes")
            if not isinstance(expected_size, int) or expected_size < 0:
                errors.append(f"{evidence_id} has an invalid size_bytes")
            elif artifact.stat().st_size != expected_size:
                errors.append(f"{evidence_id} artifact size mismatch")
            expected_sha = str(item.get("sha256", "")).lower()
            if len(expected_sha) != 64:
                errors.append(f"{evidence_id} has an invalid SHA-256")
            elif file_sha256(artifact) != expected_sha:
                errors.append(f"{evidence_id} artifact SHA-256 mismatch")
    gates = record.get("gates", {})
    for gate in GATES:
        item = gates.get(gate)
        if not isinstance(item, dict):
            errors.append(f"{gate} gate is missing")
            continue
        gate_status = item.get("status")
        if gate_status not in VALID_STATUSES:
            errors.append(f"{gate} has invalid status {gate_status!r}")
            continue
        refs = item.get("evidence", [])
        if gate_status == "pass" and not refs:
            errors.append(f"{gate} passes without evidence references")
        if gate_status == "not_applicable" and not str(item.get("reason", "")).strip():
            errors.append(f"{gate} is not_applicable without a reason")
        for ref in refs:
            if ref not in evidence_ids:
                errors.append(f"{gate} references unknown evidence id {ref!r}")

    a0_refs = gates.get("A0", {}).get("evidence", []) if isinstance(gates.get("A0"), dict) else []
    a0_kinds = {str(evidence_by_id.get(str(ref), {}).get("kind", "")) for ref in a0_refs}
    if status(record, "A0") == "pass":
        mode = record.get("work_mode")
        required = {
            "active-authorized": {"authorization-validation"},
            "local-lab": {"authorization-validation", "local-lab-ownership"},
            "passive": {"authorization-validation", "passive-scope"},
        }.get(str(mode), set())
        if not required:
            errors.append("A0 cannot pass while work_mode is unclear")
        elif not (a0_kinds & required):
            errors.append(f"A0 for {mode} lacks required evidence kind: {', '.join(sorted(required))}")

        if mode == "active-authorized" and record_path is not None:
            authorization = record.get("authorization", {})
            if not isinstance(authorization, dict):
                authorization = {}
            validations = [
                evidence_by_id[str(ref)]
                for ref in a0_refs
                if str(ref) in evidence_by_id
                and evidence_by_id[str(ref)].get("kind") == "authorization-validation"
            ]
            valid_artifact = False
            for item in validations:
                artifact = (record_path.resolve().parent / str(item.get("path", ""))).resolve()
                if not artifact.is_file():
                    continue
                try:
                    validation = json.loads(artifact.read_text(encoding="utf-8-sig"))
                except (OSError, json.JSONDecodeError):
                    continue
                if (
                    validation.get("status") == "pass"
                    and validation.get("target_in_scope") is True
                    and not validation.get("errors")
                    and str(validation.get("receipt_sha256", ""))
                    and validation.get("target") == authorization.get("target")
                    and validation.get("action") == authorization.get("action")
                    and str(validation.get("action_group") or "") == str(authorization.get("action_group") or "")
                    and validation.get("receipt_evidence_id") == authorization.get("receipt_evidence_id")
                    and validation.get("validation_evidence_id") == authorization.get("validation_evidence_id")
                    and validation.get("validation_evidence_id") == item.get("id")
                ):
                    receipt_hashes = {
                        str(evidence_by_id[str(ref)].get("sha256", ""))
                        for ref in a0_refs
                        if str(ref) in evidence_by_id
                        and evidence_by_id[str(ref)].get("kind") == "authorization-receipt"
                    }
                    if validation["receipt_sha256"] in receipt_hashes:
                        valid_artifact = True
                        break
            if not valid_artifact:
                errors.append("A0 lacks a passing validation artifact bound to its authorization receipt")

    if status(record, "C1") == "pass":
        proof_refs = set(gates.get("P1", {}).get("evidence", [])) if isinstance(gates.get("P1"), dict) else set()
        control_refs = set(gates.get("C1", {}).get("evidence", [])) if isinstance(gates.get("C1"), dict) else set()
        if not (control_refs - proof_refs):
            errors.append("C1 lacks control evidence distinct from the proof evidence")

    fingerprint = record.get("fingerprint", {})
    for field in ("component", "entry_point", "controlled_input", "source_sink", "boundary", "primitive", "impact", "fix_invariant"):
        if not fingerprint.get(field):
            warnings.append(f"fingerprint.{field} is empty")
    claims = record.get("claims", [])
    proof_started = any(status(record, gate) == "pass" for gate in ("P1", "C1", "R1", "I1"))
    if not claims:
        if proof_started:
            errors.append("claims list is empty after proof gates have started")
        else:
            warnings.append("claims list is empty")
    for index, claim in enumerate(claims):
        label = f"claim {index + 1}"
        if not isinstance(claim, dict):
            errors.append(f"{label} is not an object")
            continue
        if not str(claim.get("statement", "")).strip():
            errors.append(f"{label} has no statement")
        basis = str(claim.get("basis", "")).strip()
        if basis not in {"observed", "derived", "inferred", "external-source"}:
            errors.append(f"{label} has invalid basis {basis!r}")
        refs = claim.get("evidence", [])
        if not refs:
            errors.append(f"{label} with basis {basis!r} requires evidence")
        for ref in refs:
            if ref not in evidence_ids:
                errors.append(f"{label} references unknown evidence id {ref!r}")

    severity = record.get("severity")
    if severity is not None:
        if not isinstance(severity, dict):
            errors.append("severity must be an object")
        else:
            supplied = any(severity.get(field) not in (None, "", []) for field in ("rating", "cvss_version", "vector", "score"))
            if supplied:
                if not str(severity.get("rationale", "")).strip():
                    errors.append("supplied severity lacks a rationale")
                severity_refs = severity.get("evidence", [])
                if not severity_refs:
                    errors.append("supplied severity lacks evidence references")
                for ref in severity_refs:
                    if ref not in evidence_ids:
                        errors.append(f"severity references unknown evidence id {ref!r}")
                score_value = severity.get("score")
                if score_value not in {None, ""} and (
                    not isinstance(score_value, (int, float)) or isinstance(score_value, bool) or not 0 <= score_value <= 10
                ):
                    errors.append("severity score must be between 0 and 10")

    if status(record, "R1") == "pass":
        runs = record.get("runs", [])
        if not isinstance(runs, list):
            errors.append("runs must be a list")
            runs = []
        if len(runs) < 2:
            errors.append("R1 passes without two recorded runs")
        run_ids: list[str] = []
        evidence_sets: list[tuple[str, ...]] = []
        for index, run in enumerate(runs):
            if not isinstance(run, dict):
                errors.append(f"run {index + 1} is not an object")
                continue
            run_id = str(run.get("id", "")).strip()
            if not run_id:
                errors.append(f"run {index + 1} has no id")
            else:
                run_ids.append(run_id)
            refs = run.get("evidence", [])
            if not refs:
                errors.append(f"run {index + 1} has no evidence")
            else:
                evidence_sets.append(tuple(sorted(str(ref) for ref in refs)))
            for ref in refs:
                if ref not in evidence_ids:
                    errors.append(f"run {index + 1} references unknown evidence id {ref!r}")
        if len(run_ids) != len(set(run_ids)):
            errors.append("R1 run IDs are not unique")
        if len(evidence_sets) >= 2 and len(set(evidence_sets)) < 2:
            errors.append("R1 runs reuse the same evidence set")

    if status(record, "X1") == "pass":
        x1 = gates.get("X1", {}) if isinstance(gates.get("X1"), dict) else {}
        x1_refs = {str(ref) for ref in x1.get("evidence", [])}
        review_refs = {
            ref for ref in x1_refs if str(evidence_by_id.get(ref, {}).get("kind", "")) == "independent-validation"
        }
        if not review_refs:
            errors.append("X1 lacks independent-validation evidence")
        validation = record.get("validation")
        if not isinstance(validation, dict):
            errors.append("validation summary is missing for X1")
            validation = {}
        discovery_owner = str(validation.get("discovery_owner", "")).strip()
        validator_owner = str(validation.get("validator_owner", "")).strip()
        if not discovery_owner or not validator_owner:
            errors.append("validation summary lacks discovery and validator owners")
        elif discovery_owner.casefold() == validator_owner.casefold():
            errors.append("validation summary records self-review instead of independent validation")
        if validation.get("independence") not in INDEPENDENCE_MODES:
            errors.append("validation summary has an invalid independence mode")
        if validation.get("verdict") != "confirmed":
            errors.append("validation summary is not independently confirmed")
        review_id = str(validation.get("review_evidence_id", "")).strip()
        packet_id = str(validation.get("blind_packet_evidence_id", "")).strip()
        reproduction_refs = {str(ref) for ref in validation.get("reproduction_evidence", [])}
        if review_id not in review_refs:
            errors.append("validation review evidence is not bound to X1")
        if str(evidence_by_id.get(packet_id, {}).get("kind", "")) != "validation-packet":
            errors.append("validation summary lacks a preserved blind validation packet")
        if not reproduction_refs or reproduction_refs - evidence_ids:
            errors.append("validation summary lacks known independent reproduction evidence")
        discovery_refs = set()
        for gate in ("P1", "C1", "R1"):
            item = gates.get(gate, {}) if isinstance(gates.get(gate), dict) else {}
            discovery_refs.update(str(ref) for ref in item.get("evidence", []))
        if reproduction_refs & discovery_refs:
            errors.append("validation summary reuses discovery evidence as independent reproduction")
        if record_path is not None and review_id in evidence_by_id:
            review_item = evidence_by_id[review_id]
            review_path = (record_path.resolve().parent / str(review_item.get("path", ""))).resolve()
            try:
                review = json.loads(review_path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError) as error:
                errors.append(f"X1 independent review artifact cannot be read: {error}")
            else:
                review_status, review_errors, _review_warnings = validate_review(review, record)
                if review_status != "pass":
                    errors.append(f"X1 independent review status is {review_status}")
                errors.extend(f"X1 review: {item}" for item in review_errors)
                if str(review.get("validator_owner", "")).strip() != validator_owner:
                    errors.append("validation summary validator does not match the review artifact")
                if str(review.get("blind_packet_evidence_id", "")).strip() != packet_id:
                    errors.append("validation summary packet does not match the review artifact")
    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("finding", type=Path)
    parser.add_argument("--require", choices=("candidate", "substantiated", "verified", "reportable"))
    args = parser.parse_args()

    record = json.loads(args.finding.read_text(encoding="utf-8-sig"))
    errors, warnings = validate(record, args.finding)
    state = calculate_effective_state(record, errors)
    print(json.dumps({"state": state, "errors": errors, "warnings": warnings}, indent=2))
    if errors:
        return 1
    if args.require:
        order = {"blocked": 0, "candidate": 1, "substantiated": 2, "verified": 3, "reportable": 4}
        if order[state] < order[args.require]:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
