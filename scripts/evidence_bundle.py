#!/usr/bin/env python3
"""Create and maintain a hash-verified mask0ff evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from authorization_gate import evaluate
from independent_validation import referenced_evidence, validate_review
from program_profile import validate_profile
from session_profile import validate_session


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "assets" / "evidence-bundle" / "finding-record.json"
VALID_STATUSES = {"pending", "pass", "fail", "blocked", "not_applicable"}


def load_record(bundle: Path) -> tuple[Path, dict[str, Any]]:
    path = bundle / "finding-record.json"
    if not path.is_file():
        raise ValueError(f"finding record is missing: {path}")
    return path, json.loads(path.read_text(encoding="utf-8-sig"))


def save_record(path: Path, record: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def next_evidence_id(record: dict[str, Any]) -> str:
    existing = {str(item.get("id")) for item in record.get("evidence", [])}
    number = 1
    while f"E-{number:03d}" in existing:
        number += 1
    return f"E-{number:03d}"


def evidence_item(
    bundle: Path,
    path: Path,
    *,
    evidence_id: str,
    kind: str,
    observation: str,
    redacted: bool = False,
) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "kind": kind,
        "path": path.relative_to(bundle).as_posix(),
        "sha256": digest(path),
        "size_bytes": path.stat().st_size,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "observation": observation,
        "redacted": redacted,
    }


def init_bundle(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    if bundle.exists() and any(bundle.iterdir()):
        raise ValueError(f"bundle is not empty: {bundle}")
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "raw").mkdir(parents=True, exist_ok=True)
    (bundle / "artifacts" / "redacted").mkdir(parents=True, exist_ok=True)
    record = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    record["title"] = args.title
    record["work_mode"] = args.work_mode
    record["assessment_mode"] = args.assessment_mode
    record["authorization"]["authority"] = args.authority or ""
    record["authorization"]["policy_reference"] = args.policy_reference or ""
    record["authorization"]["in_scope"] = args.scope or []
    path = bundle / "finding-record.json"
    save_record(path, record)
    shutil.copy2(ROOT / "assets" / "evidence-bundle" / "evidence-log.md", bundle / "evidence-log.md")
    shutil.copy2(ROOT / "assets" / "evidence-bundle" / "duplicate-review.md", bundle / "duplicate-review.md")
    shutil.copy2(ROOT / "assets" / "evidence-bundle" / "report.md", bundle / "report.md")
    shutil.copy2(ROOT / "assets" / "evidence-bundle" / "coverage-plan.json", bundle / "coverage-plan.json")
    shutil.copy2(ROOT / "assets" / "evidence-bundle" / "source-map.json", bundle / "source-map.json")
    shutil.copy2(ROOT / "assets" / "evidence-bundle" / "validation-packet.json", bundle / "validation-packet.json")
    shutil.copy2(ROOT / "assets" / "evidence-bundle" / "independent-validation.json", bundle / "independent-validation.json")
    print(path)
    return 0


def add_evidence(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    record_path, record = load_record(bundle)
    source = args.file.resolve()
    if not source.is_file():
        raise ValueError(f"artifact is not a file: {source}")
    evidence_id = next_evidence_id(record)
    destination_dir = bundle / "artifacts" / ("redacted" if args.redacted else "raw")
    destination = destination_dir / f"{evidence_id}-{source.name}"
    shutil.copy2(source, destination)
    item = evidence_item(
        bundle,
        destination,
        evidence_id=evidence_id,
        kind=args.kind,
        observation=args.observation,
        redacted=bool(args.redacted),
    )
    record.setdefault("evidence", []).append(item)
    save_record(record_path, record)
    print(json.dumps(item, indent=2))
    return 0


def authorize_bundle(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    record_path, record = load_record(bundle)
    receipt_source = args.receipt.resolve()
    if not receipt_source.is_file():
        raise ValueError(f"authorization receipt is not a file: {receipt_source}")
    raw = receipt_source.read_bytes()
    receipt = json.loads(raw.decode("utf-8-sig"))

    existing_ids = {str(item.get("id")) for item in record.get("evidence", [])}
    number = 1
    while f"E-{number:03d}" in existing_ids:
        number += 1
    receipt_id = f"E-{number:03d}"
    number += 1
    while f"E-{number:03d}" in existing_ids:
        number += 1
    validation_id = f"E-{number:03d}"
    raw_dir = bundle / "artifacts" / "raw"
    receipt_path = raw_dir / f"{receipt_id}-authorization-receipt.json"
    validation_path = raw_dir / f"{validation_id}-authorization-validation.json"
    shutil.copy2(receipt_source, receipt_path)

    result = evaluate(
        receipt,
        target=args.target,
        action=args.action,
        action_group=args.action_group,
        now_value=args.now,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
    )
    result["receipt_evidence_id"] = receipt_id
    result["validation_evidence_id"] = validation_id
    validation_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    receipt_item = evidence_item(
        bundle,
        receipt_path,
        evidence_id=receipt_id,
        kind="authorization-receipt",
        observation="Supplied authorization receipt preserved for A0 review",
    )
    validation_item = evidence_item(
        bundle,
        validation_path,
        evidence_id=validation_id,
        kind="authorization-validation",
        observation=f"A0 authorization validation status: {result['status']}",
    )
    record.setdefault("evidence", []).extend((receipt_item, validation_item))
    record["authorization"] = {
        "authority": str(receipt.get("authority", "")),
        "program_or_owner": str(receipt.get("program_or_owner", "")),
        "policy_reference": str(receipt.get("policy_reference", "")),
        "in_scope": list(receipt.get("in_scope_targets", [])),
        "out_of_scope": list(receipt.get("out_of_scope_targets", [])),
        "owned_accounts_and_data": list(receipt.get("owned_accounts_and_data", [])),
        "constraints": list(receipt.get("prohibited_actions", [])),
        "receipt_evidence_id": receipt_id,
        "validation_evidence_id": validation_id,
        "target": args.target,
        "action": args.action,
        "action_group": args.action_group or "",
        "status": result["status"],
    }
    record["gates"]["A0"] = {
        "status": "pass" if result["status"] == "pass" else "blocked",
        "evidence": [receipt_id, validation_id],
        "reason": "" if result["status"] == "pass" else "; ".join(result["errors"]),
    }
    save_record(record_path, record)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 2


def bind_profile(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    record_path, record = load_record(bundle)
    source = args.profile.resolve()
    if not source.is_file():
        raise ValueError(f"engagement profile is not a file: {source}")
    profile = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(profile, dict):
        raise ValueError("engagement profile must be a JSON object")
    errors, warnings = validate_profile(profile, target=args.target)
    if errors:
        raise ValueError("; ".join(errors))
    evidence_id = next_evidence_id(record)
    destination = bundle / "artifacts" / "raw" / f"{evidence_id}-engagement-profile.json"
    shutil.copy2(source, destination)
    item = evidence_item(
        bundle,
        destination,
        evidence_id=evidence_id,
        kind="engagement-profile",
        observation=f"Normalized {profile.get('platform')} scope profile for {profile.get('program_or_owner')}",
    )
    record.setdefault("evidence", []).append(item)
    record["assessment_mode"] = profile.get("assessment_mode", record.get("assessment_mode", "black-box"))
    record["engagement"] = {
        "platform": profile.get("platform", ""),
        "program_or_owner": profile.get("program_or_owner", ""),
        "policy_reference": profile.get("policy_reference", ""),
        "profile_evidence_id": evidence_id,
        "profile_sha256": item["sha256"],
    }
    save_record(record_path, record)
    print(json.dumps({"evidence": item, "warnings": warnings, "secret_material_stored": False}, indent=2))
    return 0


def bind_session(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    record_path, record = load_record(bundle)
    source = args.session.resolve()
    if not source.is_file():
        raise ValueError(f"session profile is not a file: {source}")
    profile = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(profile, dict):
        raise ValueError("session profile must be a JSON object")
    errors, warnings, _availability = validate_session(profile)
    if errors:
        raise ValueError("; ".join(errors))
    evidence_id = next_evidence_id(record)
    destination = bundle / "artifacts" / "raw" / f"{evidence_id}-session-profile.json"
    shutil.copy2(source, destination)
    item = evidence_item(
        bundle,
        destination,
        evidence_id=evidence_id,
        kind="session-profile",
        observation=f"Secret-free session reference for role {profile.get('role')}",
    )
    record.setdefault("evidence", []).append(item)
    access = record.setdefault("access", {"session_profiles": [], "secret_material_stored": False})
    sessions = access.setdefault("session_profiles", [])
    sessions.append(
        {
            "label": profile.get("label", ""),
            "role": profile.get("role", ""),
            "tenant": profile.get("tenant", ""),
            "auth_type": profile.get("auth_type", ""),
            "credential_reference_names": sorted(profile.get("credential_references", {}).keys()),
            "evidence_id": evidence_id,
        }
    )
    access["secret_material_stored"] = False
    save_record(record_path, record)
    print(json.dumps({"evidence": item, "session": sessions[-1], "warnings": warnings, "secret_material_stored": False}, indent=2))
    return 0


def set_gate(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    record_path, record = load_record(bundle)
    if args.status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {args.status}")
    if args.gate not in record.get("gates", {}):
        raise ValueError(f"unknown gate: {args.gate}")
    known = {str(item.get("id")) for item in record.get("evidence", [])}
    unknown = sorted(set(args.evidence or []) - known)
    if unknown:
        raise ValueError(f"unknown evidence ids: {', '.join(unknown)}")
    if args.status == "pass" and not args.evidence:
        raise ValueError("a passing gate requires at least one evidence id")
    if args.status == "not_applicable" and not args.reason:
        raise ValueError("not_applicable requires --reason")
    record["gates"][args.gate] = {
        "status": args.status,
        "evidence": args.evidence or [],
        "reason": args.reason or "",
    }
    save_record(record_path, record)
    print(json.dumps(record["gates"][args.gate], indent=2))
    return 0


def bind_challenge(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    record_path, record = load_record(bundle)
    source = args.review.resolve()
    if not source.is_file():
        raise ValueError(f"independent validation review is not a file: {source}")
    review = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(review, dict):
        raise ValueError("independent validation review must be a JSON object")
    review_status, errors, warnings = validate_review(review, record)
    if errors:
        raise ValueError("; ".join(errors))

    evidence_id = next_evidence_id(record)
    destination = bundle / "artifacts" / "raw" / f"{evidence_id}-independent-validation.json"
    shutil.copy2(source, destination)
    item = evidence_item(
        bundle,
        destination,
        evidence_id=evidence_id,
        kind="independent-validation",
        observation=f"Independent X1 challenge verdict: {review.get('verdict')}",
    )
    record.setdefault("evidence", []).append(item)
    reproduction = [str(ref) for ref in review.get("independent_reproduction_evidence", [])]
    record["validation"] = {
        "status": review_status,
        "independence": review.get("independence", ""),
        "discovery_owner": review.get("discovery_owner", ""),
        "validator_owner": review.get("validator_owner", ""),
        "blind_packet_evidence_id": review.get("blind_packet_evidence_id", ""),
        "review_evidence_id": evidence_id,
        "reproduction_evidence": reproduction,
        "verdict": review.get("verdict", ""),
    }
    gate_status = {"pass": "pass", "fail": "fail", "pending": "pending"}[review_status]
    gate_refs = [evidence_id, *sorted(referenced_evidence(review))]
    record["gates"]["X1"] = {
        "status": gate_status,
        "evidence": list(dict.fromkeys(gate_refs)),
        "reason": "" if gate_status == "pass" else str(review.get("reason", "")),
    }
    save_record(record_path, record)
    print(
        json.dumps(
            {
                "status": review_status,
                "evidence": item,
                "validation": record["validation"],
                "gate": record["gates"]["X1"],
                "warnings": warnings,
            },
            indent=2,
        )
    )
    return 0 if review_status == "pass" else 2


def verify_bundle(args: argparse.Namespace) -> int:
    bundle = args.bundle.resolve()
    record_path, record = load_record(bundle)
    errors = []
    seen_ids: set[str] = set()
    tracked_paths: set[str] = set()
    for item in record.get("evidence", []):
        evidence_id = str(item.get("id", ""))
        if not evidence_id:
            errors.append("evidence item has no id")
        elif evidence_id in seen_ids:
            errors.append(f"duplicate evidence id: {evidence_id}")
        seen_ids.add(evidence_id)
        relative = str(item.get("path", ""))
        tracked_paths.add(relative)
        path = (bundle / relative).resolve()
        try:
            path.relative_to(bundle)
        except ValueError:
            errors.append(f"{item.get('id')}: path escapes bundle")
            continue
        if not path.is_file():
            errors.append(f"{item.get('id')}: missing {relative}")
        elif digest(path) != item.get("sha256"):
            errors.append(f"{item.get('id')}: SHA-256 mismatch")
        elif path.stat().st_size != item.get("size_bytes"):
            errors.append(f"{item.get('id')}: size mismatch")

    artifacts_root = bundle / "artifacts"
    untracked = sorted(
        path.relative_to(bundle).as_posix()
        for path in artifacts_root.rglob("*")
        if path.is_file() and path.relative_to(bundle).as_posix() not in tracked_paths
    )
    for relative in untracked:
        errors.append(f"untracked artifact: {relative}")

    from verify_finding import validate

    finding_errors, warnings = validate(record, record_path)
    errors.extend(f"finding: {item}" for item in finding_errors)
    from assess_finding import assess, atomic_write, normalized_now

    assessment = assess(record, record_path, normalized_now(args.now))
    if args.assessment_output:
        atomic_write(args.assessment_output.resolve(), assessment)
    print(
        json.dumps(
            {
                "artifact_count": len(record.get("evidence", [])),
                "untracked_artifacts": untracked,
                "errors": errors,
                "warnings": warnings,
                "assessment": {
                    "verdict": assessment["verdict"],
                    "effective_state": assessment["effective_state"],
                    "scores": assessment["scores"],
                    "decision": assessment["decision"],
                    "continue_investigation": assessment["continue_investigation"],
                    "continuation": assessment["continuation"],
                    "next_gate": assessment["next_gate"],
                    "next_action": assessment["next_action"],
                    "recommendations": assessment["recommendations"],
                },
            },
            indent=2,
        )
    )
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init")
    init.add_argument("bundle", type=Path)
    init.add_argument("--title", required=True)
    init.add_argument("--work-mode", choices=("passive", "local-lab", "active-authorized", "unclear"), default="unclear")
    init.add_argument("--assessment-mode", choices=("black-box", "gray-box", "white-box", "hybrid"), default="black-box")
    init.add_argument("--authority")
    init.add_argument("--policy-reference")
    init.add_argument("--scope", action="append")
    init.set_defaults(handler=init_bundle)

    add = subparsers.add_parser("add")
    add.add_argument("bundle", type=Path)
    add.add_argument("file", type=Path)
    add.add_argument("--kind", required=True)
    add.add_argument("--observation", required=True)
    add.add_argument("--redacted", action="store_true")
    add.set_defaults(handler=add_evidence)

    authorize = subparsers.add_parser("authorize")
    authorize.add_argument("bundle", type=Path)
    authorize.add_argument("receipt", type=Path)
    authorize.add_argument("--target", required=True)
    authorize.add_argument("--action", required=True)
    authorize.add_argument("--action-group", help="Allowed group such as authenticated-testing or source-review")
    authorize.add_argument("--now", help="ISO-8601 time override for deterministic evaluation")
    authorize.set_defaults(handler=authorize_bundle)

    profile = subparsers.add_parser("profile")
    profile.add_argument("bundle", type=Path)
    profile.add_argument("profile", type=Path)
    profile.add_argument("--target")
    profile.set_defaults(handler=bind_profile)

    session = subparsers.add_parser("session")
    session.add_argument("bundle", type=Path)
    session.add_argument("session", type=Path)
    session.set_defaults(handler=bind_session)

    gate = subparsers.add_parser("gate")
    gate.add_argument("bundle", type=Path)
    gate.add_argument("gate")
    gate.add_argument("status")
    gate.add_argument("--evidence", action="append")
    gate.add_argument("--reason")
    gate.set_defaults(handler=set_gate)

    challenge = subparsers.add_parser("challenge")
    challenge.add_argument("bundle", type=Path)
    challenge.add_argument("review", type=Path)
    challenge.set_defaults(handler=bind_challenge)

    verify = subparsers.add_parser("verify")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--assessment-output", type=Path)
    verify.add_argument("--now", help="ISO-8601 time override for deterministic assessment")
    verify.set_defaults(handler=verify_bundle)
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
