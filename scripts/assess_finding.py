#!/usr/bin/env python3
"""Produce a calibrated evidence assessment and next safe action for one finding."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "scripts"))
from verify_finding import (  # noqa: E402
    APPLICABILITY,
    GATES,
    calculate_effective_state,
    file_sha256,
    status,
    validate,
)


GATE_WEIGHTS = {
    "A0": 10,
    "A1": 5,
    "H1": 5,
    "B1": 10,
    "P1": 20,
    "C1": 15,
    "R1": 15,
    "I1": 10,
    "S1": 3,
    "V1": 2,
    "F1": 2,
    "D1": 2,
    "Q1": 1,
}
STATE_CAPS = {"blocked": 15, "candidate": 39, "substantiated": 69, "verified": 89, "reportable": 100}
NEXT_ACTIONS = {
    "A0": "Preserve and validate exact authorization for the target and proposed action; remain passive until it passes.",
    "A1": "Map assets, roles, objects, states, attacker control, and trust boundaries from evidence.",
    "H1": "Write one falsifiable boundary-failure hypothesis tied to an observed signal.",
    "B1": "Capture the secure or intended baseline before changing one variable.",
    "P1": "Run the minimum safe controlled proof with owned accounts, synthetic data, or a local lab.",
    "C1": "Add negative, differential, wrong-role, intended-behavior, and patched controls as applicable.",
    "R1": "Repeat from clean state and preserve a second distinct run artifact.",
    "I1": "Separate observed impact from bounded inference and record preconditions and blast radius.",
    "S1": "Trace the root cause or record a calibrated black-box root-cause hypothesis.",
    "V1": "Test or source-trace the affected version and configuration range.",
    "F1": "Verify that the proposed invariant-level fix prevents the effect without breaking the legitimate path.",
    "D1": "Record source status, search both public datasets and current primary sources, then compare exact root cause and path.",
    "Q1": "Redact secrets, map every report claim to evidence, lint the report, and calibrate severity.",
}


def normalized_now(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    candidate = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def artifact_metrics(record: dict[str, Any], record_path: Path) -> tuple[set[str], dict[str, Any]]:
    base = record_path.resolve().parent
    items = record.get("evidence", [])
    valid_ids: set[str] = set()
    details = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            details.append({"id": None, "valid": False, "reasons": ["not-an-object"]})
            continue
        evidence_id = str(item.get("id", "")).strip()
        reasons = []
        relative = str(item.get("path", "")).strip()
        artifact = (base / relative).resolve() if relative else None
        if not evidence_id:
            reasons.append("missing-id")
        if not str(item.get("kind", "")).strip():
            reasons.append("missing-kind")
        if artifact is None:
            reasons.append("missing-path")
        else:
            try:
                artifact.relative_to(base)
            except ValueError:
                reasons.append("path-escape")
            else:
                if not artifact.is_file():
                    reasons.append("missing-file")
                else:
                    expected_size = item.get("size_bytes")
                    if not isinstance(expected_size, int) or artifact.stat().st_size != expected_size:
                        reasons.append("size-mismatch")
                    expected_sha = str(item.get("sha256", "")).lower()
                    if len(expected_sha) != 64 or file_sha256(artifact) != expected_sha:
                        reasons.append("sha256-mismatch")
        valid = bool(evidence_id) and not reasons
        if valid:
            valid_ids.add(evidence_id)
        details.append({"id": evidence_id or None, "kind": item.get("kind"), "valid": valid, "reasons": reasons})
    total = len(details)
    return valid_ids, {
        "total": total,
        "valid": len(valid_ids),
        "integrity_ratio": round(len(valid_ids) / total, 4) if total else 0.0,
        "items": details,
    }


def claim_metrics(record: dict[str, Any], valid_ids: set[str]) -> dict[str, Any]:
    claims = record.get("claims", [])
    details = []
    supported = 0
    for index, claim in enumerate(claims if isinstance(claims, list) else [], 1):
        if not isinstance(claim, dict):
            details.append({"index": index, "supported": False, "reasons": ["not-an-object"]})
            continue
        refs = {str(ref) for ref in claim.get("evidence", [])}
        reasons = []
        if not str(claim.get("statement", "")).strip():
            reasons.append("missing-statement")
        if claim.get("basis") not in {"observed", "derived", "inferred", "external-source"}:
            reasons.append("invalid-basis")
        if not refs:
            reasons.append("no-evidence")
        if refs - valid_ids:
            reasons.append("invalid-evidence-reference")
        is_supported = not reasons
        supported += int(is_supported)
        details.append(
            {
                "index": index,
                "basis": claim.get("basis"),
                "evidence": sorted(refs),
                "supported": is_supported,
                "reasons": reasons,
            }
        )
    total = len(details)
    return {
        "total": total,
        "supported": supported,
        "support_ratio": round(supported / total, 4) if total else 0.0,
        "items": details,
    }


def control_ratio(record: dict[str, Any], valid_ids: set[str]) -> tuple[float, dict[str, Any]]:
    gates = record.get("gates", {})
    proof_refs = set(gates.get("P1", {}).get("evidence", [])) & valid_ids
    control_refs = set(gates.get("C1", {}).get("evidence", [])) & valid_ids
    distinct = control_refs - proof_refs
    if status(record, "C1") != "pass" or not control_refs:
        ratio = 0.0
    elif distinct:
        ratio = 1.0
    else:
        ratio = 0.4
    return ratio, {
        "proof_evidence": sorted(proof_refs),
        "control_evidence": sorted(control_refs),
        "distinct_control_evidence": sorted(distinct),
        "independence_ratio": ratio,
    }


def repeat_ratio(record: dict[str, Any], valid_ids: set[str]) -> tuple[float, dict[str, Any]]:
    runs = record.get("runs", [])
    valid_runs = []
    for run in runs if isinstance(runs, list) else []:
        if not isinstance(run, dict) or not str(run.get("id", "")).strip():
            continue
        refs = {str(ref) for ref in run.get("evidence", [])}
        if refs and not (refs - valid_ids):
            valid_runs.append({"id": str(run["id"]), "evidence": refs})
    distinct_ids = {item["id"] for item in valid_runs}
    evidence_sets = {tuple(sorted(item["evidence"])) for item in valid_runs}
    if status(record, "R1") != "pass" or len(valid_runs) < 2 or len(distinct_ids) < 2:
        ratio = 0.0
    elif len(evidence_sets) >= 2:
        ratio = 1.0
    else:
        ratio = 0.4
    return ratio, {
        "recorded_runs": len(runs) if isinstance(runs, list) else 0,
        "valid_runs": len(valid_runs),
        "distinct_run_ids": len(distinct_ids),
        "distinct_evidence_sets": len(evidence_sets),
        "independence_ratio": ratio,
    }


def error_affects_gate(error: str, gate: str, refs: set[str]) -> bool:
    return error.startswith(gate) or any(ref and ref in error for ref in refs)


def band(score: int) -> str:
    if score < 20:
        return "insufficient-evidence"
    if score < 40:
        return "weak"
    if score < 60:
        return "moderate"
    if score < 80:
        return "strong"
    if score < 95:
        return "verified"
    return "reportable-quality"


def assess(record: dict[str, Any], record_path: Path, assessed_at: str) -> dict[str, Any]:
    errors, warnings = validate(record, record_path)
    effective_state = calculate_effective_state(record, errors)
    valid_ids, evidence = artifact_metrics(record, record_path)
    claims = claim_metrics(record, valid_ids)
    controls_ratio, controls = control_ratio(record, valid_ids)
    repeats_ratio, repeats = repeat_ratio(record, valid_ids)

    gate_rows = []
    gate_score = 0
    gates = record.get("gates", {})
    for gate in GATES:
        item = gates.get(gate, {}) if isinstance(gates, dict) else {}
        gate_status = status(record, gate)
        refs = {str(ref) for ref in item.get("evidence", [])} if isinstance(item, dict) else set()
        structurally_complete = gate_status == "pass" or (
            gate_status == "not_applicable" and gate in APPLICABILITY and str(item.get("reason", "")).strip()
        )
        invalidated = any(error_affects_gate(error, gate, refs) for error in errors)
        awarded = GATE_WEIGHTS[gate] if structurally_complete and not invalidated else 0
        gate_score += awarded
        gate_rows.append(
            {
                "gate": gate,
                "status": gate_status,
                "weight": GATE_WEIGHTS[gate],
                "awarded": awarded,
                "evidence": sorted(refs),
                "invalidated": invalidated,
            }
        )

    integrity_component = 40 * evidence["integrity_ratio"]
    claim_component = 20 * claims["support_ratio"]
    control_component = 20 * controls_ratio
    repeat_component = 20 * repeats_ratio
    evidence_quality = round(integrity_component + claim_component + control_component + repeat_component)
    raw_score = round(0.70 * gate_score + 0.30 * evidence_quality)
    score = min(raw_score, STATE_CAPS[effective_state])

    a0_refs = {
        str(ref)
        for ref in (gates.get("A0", {}).get("evidence", []) if isinstance(gates, dict) else [])
    }
    authorization_error = any(
        error.startswith("A0") or error.startswith("authorization") or any(ref and ref in error for ref in a0_refs)
        for error in errors
    )
    if authorization_error:
        score = min(score, 10)
    elif errors:
        score = min(score, 29)

    failed_gates = [gate for gate in GATES if status(record, gate) == "fail"]
    refuting_failure = next((gate for gate in ("H1", "P1", "C1", "R1") if gate in failed_gates), None)
    if authorization_error or effective_state == "blocked":
        verdict = "blocked"
    elif errors:
        verdict = "invalid-record"
    elif refuting_failure:
        verdict = "refuted-or-not-reproducible"
    else:
        verdict = effective_state

    if verdict == "blocked":
        decision = "Stop active testing. Continue only passive analysis or an owned local reproduction until A0 is repaired."
        continue_investigation = False
        next_gate = "A0"
        continuation = {
            "continue_work": True,
            "continue_technical_testing": False,
            "mode": "passive-or-owned-local-only",
            "terminal_for_current_hypothesis": True,
            "safe_alternatives": ["passive artifact review", "owned local reproduction", "request exact authorization input"],
        }
    elif verdict == "invalid-record":
        decision = "Repair the evidence record before drawing a vulnerability conclusion."
        continue_investigation = True
        next_gate = next((row["gate"] for row in gate_rows if row["invalidated"]), None)
        continuation = {
            "continue_work": True,
            "continue_technical_testing": False,
            "mode": "repair-and-reverify-record",
            "terminal_for_current_hypothesis": False,
            "safe_alternatives": ["repair evidence paths and hashes", "restore missing artifacts", "rerun validation"],
        }
    elif verdict == "refuted-or-not-reproducible":
        decision = "Record the current hypothesis as refuted or non-reproducible; preserve the evidence and pivot only from a new observed signal."
        continue_investigation = False
        next_gate = refuting_failure
        continuation = {
            "continue_work": True,
            "continue_technical_testing": False,
            "mode": "record-refutation-and-review-new-signals",
            "terminal_for_current_hypothesis": True,
            "safe_alternatives": ["record the failed hypothesis", "review remaining observed signals", "create one new falsifiable hypothesis only if evidence supports it"],
        }
    elif effective_state == "reportable":
        decision = "Stop technical escalation. Finalize redaction and submit through the authorized disclosure channel."
        continue_investigation = False
        next_gate = None
        continuation = {
            "continue_work": True,
            "continue_technical_testing": False,
            "mode": "reporting-only",
            "terminal_for_current_hypothesis": True,
            "safe_alternatives": ["final redaction", "report lint", "submission preparation", "respond to triage with bounded evidence"],
        }
    elif effective_state == "verified":
        decision = "Do not escalate impact further. Complete duplicate review and report quality only."
        continue_investigation = True
        next_gate = next((gate for gate in ("S1", "V1", "F1", "D1", "Q1") if status(record, gate) not in {"pass", "not_applicable"}), None)
        continuation = {
            "continue_work": True,
            "continue_technical_testing": False,
            "mode": "analysis-and-reporting-only",
            "terminal_for_current_hypothesis": False,
            "safe_alternatives": ["root-cause trace", "version and fix analysis", "duplicate review", "report quality review"],
        }
    else:
        next_gate = next((gate for gate in GATES if status(record, gate) not in {"pass", "not_applicable"}), None)
        decision = NEXT_ACTIONS.get(next_gate, "Preserve the current evidence and select the next falsifiable, safe step.")
        continue_investigation = True
        continuation = {
            "continue_work": True,
            "continue_technical_testing": True,
            "mode": "evidence-production-within-scope",
            "terminal_for_current_hypothesis": False,
            "safe_alternatives": [decision],
        }

    recommendations = []
    if errors:
        recommendations.extend(f"Fix validation error: {error}" for error in errors[:5])
    if next_gate and next_gate in NEXT_ACTIONS:
        recommendations.append(NEXT_ACTIONS[next_gate])
    if controls_ratio < 1.0 and status(record, "P1") == "pass":
        recommendations.append("Use control evidence distinct from the proof artifact to reduce false-positive risk.")
    if repeats_ratio < 1.0 and status(record, "R1") == "pass":
        recommendations.append("Use distinct run IDs and distinct clean-run artifacts for reproducibility.")
    if claims["support_ratio"] < 1.0:
        recommendations.append("Bind every observed, derived, inferred, and external claim to valid evidence IDs.")
    recommendations = list(dict.fromkeys(recommendations))[:8]

    if status(record, "I1") != "pass" or effective_state not in {"verified", "reportable"}:
        severity = {
            "status": "defer",
            "recommendation": "Do not assign severity yet; first prove and bound observed impact and preconditions.",
        }
    else:
        severity_record = record.get("severity") if isinstance(record.get("severity"), dict) else {}
        supplied = {
            key: value
            for key, value in severity_record.items()
            if value not in (None, "", [])
        }
        severity = {
            "status": "review-supplied-vector" if supplied else "ready-for-scoring",
            "supplied": supplied,
            "recommendation": "Calculate or review CVSS from demonstrated impact and preconditions; validation confidence is not severity.",
        }

    if verdict in {"blocked", "invalid-record", "refuted-or-not-reproducible"}:
        false_positive_risk = "not-assessable" if verdict == "blocked" else "high"
    elif effective_state == "candidate":
        false_positive_risk = "high"
    elif effective_state == "substantiated":
        false_positive_risk = "medium"
    else:
        false_positive_risk = "low" if evidence_quality >= 80 else "medium"

    return {
        "schema_version": 1,
        "assessed_at_utc": assessed_at,
        "finding": str(record_path.resolve()),
        "title": record.get("title"),
        "verdict": verdict,
        "effective_state": effective_state,
        "scores": {
            "validation_confidence": score,
            "confidence_band": band(score),
            "gate_completion": gate_score,
            "evidence_quality": evidence_quality,
            "false_positive_risk": false_positive_risk,
            "score_is_severity": False,
        },
        "score_components": {
            "artifact_integrity": round(integrity_component),
            "claim_support": round(claim_component),
            "control_independence": round(control_component),
            "repeat_independence": round(repeat_component),
        },
        "gates": gate_rows,
        "evidence": evidence,
        "claims": claims,
        "controls": controls,
        "repeats": repeats,
        "decision": decision,
        "continue_investigation": continue_investigation,
        "continuation": continuation,
        "next_gate": next_gate,
        "next_action": NEXT_ACTIONS.get(next_gate) if next_gate else None,
        "recommendations": recommendations,
        "severity": severity,
        "duplicate_review": {
            "status": "complete" if status(record, "D1") == "pass" else "required",
            "recommendation": NEXT_ACTIONS["D1"] if status(record, "D1") != "pass" else "Preserve the D1 comparison and residual internal-duplicate risk.",
        },
        "persistence_policy": {
            "continue_until": "reportable, evidence-refuted, authorization/safety-blocked, or a required external decision is identified",
            "same_action_failure_limit": 2,
            "same_blocker_turn_limit": 3,
            "on_no_progress": "change method, reduce to passive/local proof, or mark blocked with the exact missing input; never repeat indefinitely",
        },
        "errors": errors,
        "warnings": warnings,
        "calibration": "This score summarizes evidence completeness and reliability. It does not prove objective truth, novelty, exploitability, or severity by itself.",
    }


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("finding", type=Path, help="Finding-record JSON")
    parser.add_argument("--output", type=Path, help="Atomically write the assessment JSON")
    parser.add_argument("--minimum-score", type=int, choices=range(0, 101), metavar="0-100")
    parser.add_argument("--now", help="ISO-8601 time override for deterministic evaluation")
    args = parser.parse_args()

    finding = args.finding.resolve()
    record = json.loads(finding.read_text(encoding="utf-8-sig"))
    payload = assess(record, finding, normalized_now(args.now))
    if args.output:
        atomic_write(args.output.resolve(), payload)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if args.minimum_score is not None and payload["scores"]["validation_confidence"] < args.minimum_score:
        return 2
    return 1 if payload["verdict"] in {"blocked", "invalid-record"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
