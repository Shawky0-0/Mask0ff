#!/usr/bin/env python3
"""Triage a vulnerability report: scope, claims, evidence, impact, severity, duplicates, verdict."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from authorization_gate import evaluate as evaluate_authorization  # noqa: E402
from assess_finding import assess, normalized_now  # noqa: E402
from duplicate_check import (  # noqa: E402
    DEFAULT_ADVISORY_DATABASE,
    DEFAULT_CASES,
    DEFAULT_DATABASE,
    advisory_matches,
    compare,
    public_matches,
)
from program_profile import validate_profile  # noqa: E402
from verify_finding import validate as validate_finding  # noqa: E402

ATTACKER_CONTROL_PATTERNS = [
    re.compile(r"(?<!not )(?<!no )(?<!without )(?<!no )attacker-controlled", re.I),
    re.compile(r"\b(attacker can|attacker controls|unauthenticated attacker|third[- ]party attacker|adversary|arbitrary user)\b", re.I),
]
NO_ATTACKER_PATTERNS = [
    re.compile(r"\b(no attacker|not attacker-controlled|not a security vulnerability|outside .{0,20} threat model|no security boundary|no third party|no adversary|no untrusted party)\b", re.I),
]
SAME_PRINCIPAL_PATTERNS = [
    re.compile(r"\b(same trust principal|same server|own server|own app|self[- ]inflicted|operator[- ]selected|application developer|working as designed|intentional|by design|documented behavior)\b", re.I),
]
CROSS_PRINCIPAL_PATTERNS = [
    re.compile(r"\b(cross[- ]tenant|cross[- ]user|cross[- ]server|another user|different principal|third[- ]party host|unauthorized access)\b", re.I),
]

IMPACT_PROOF_PATTERNS = [
    re.compile(r"\buid=\d+(?:\([^)]+\))?"),
    re.compile(r"\broot:x:0:0:"),
    re.compile(r"\bHTTP/\d(?:\.\d)?\s+[1-5]\d\d\b", re.I),
    re.compile(r"\b(?:command|observed|actual)\s+output\s*[:=]\s*(?!not\b|none\b|missing\b|unavailable\b)\S", re.I),
    re.compile(r"```[\s\S]{0,600}?(uid=\d+|root:x:0:0:|HTTP/\d(?:\.\d)?\s+[1-5]\d\d|Content-Type\s*:)", re.I),
    re.compile(r"callback (received|hit|fired)|pingback", re.I),
    re.compile(r"\bresponse (?:body|content)\s*[:=]\s*(?!not\b|none\b|missing\b|unavailable\b)\S", re.I),
]
CLAIM_ONLY_PATTERNS = [
    re.compile(
        r"\b(we believe|likely|probably|might|could|should|potentially|assumed|in theory|untested|"
        r"may allow|can lead|suggests|appears to)\b",
        re.I,
    )
]
REQUIRED_SECTIONS = ("steps to reproduce", "expected", "observed", "impact")


def report_analysis(report: str) -> dict[str, Any]:
    body = report.lower()
    missing = [section for section in REQUIRED_SECTIONS if section not in body]
    has_reproduction = bool(re.search(r"(^|\n)\s*\d+[.)]", report) or "reproduce" in body)
    demonstrated = any(pattern.search(report) for pattern in IMPACT_PROOF_PATTERNS)
    claimed = any(pattern.search(report) for pattern in CLAIM_ONLY_PATTERNS)
    if demonstrated:
        impact = "demonstrated"
    elif claimed:
        impact = "claimed-only"
    else:
        impact = "absent"
    return {
        "missing_sections": missing,
        "has_reproduction_steps": has_reproduction,
        "impact": impact,
        "impact_notes": {
            "demonstrated": bool(demonstrated),
            "hedged_language": bool(claimed),
        },
    }


def threat_model_check(report: str, report_result: dict[str, Any]) -> dict[str, Any]:
    attacker_claimed = any(pattern.search(report) for pattern in ATTACKER_CONTROL_PATTERNS)
    attacker_disclaimed = any(pattern.search(report) for pattern in NO_ATTACKER_PATTERNS)
    same_principal = any(pattern.search(report) for pattern in SAME_PRINCIPAL_PATTERNS)
    cross_principal = any(pattern.search(report) for pattern in CROSS_PRINCIPAL_PATTERNS)
    impact_demonstrated = report_result["impact"] == "demonstrated"
    if attacker_disclaimed and not attacker_claimed:
        status = "fail"
    elif same_principal and not cross_principal and not attacker_claimed:
        status = "fail"
    elif not attacker_claimed and not impact_demonstrated:
        status = "fail"
    elif not attacker_claimed or same_principal:
        status = "review"
    else:
        status = "pass"
    return {
        "status": status,
        "attacker_control": {
            "claimed": attacker_claimed,
            "disclaimed": attacker_disclaimed,
        },
        "boundary": {
            "cross_principal": cross_principal,
            "same_principal": same_principal,
        },
        "impact_demonstrated": impact_demonstrated,
        "reason": {
            "fail": "no attacker-controlled source or no cross-principal security boundary per the report's own statements; likely functional or working-as-designed",
            "review": "threat model is unclear: attacker control or boundary is not established; research the vendor threat model before any acceptance",
            "pass": "attacker-controlled source and cross-principal boundary are claimed",
        }[status],
    }


def program_threat_model_check(report: str, model: dict[str, Any] | None) -> dict[str, Any]:
    if not model:
        return {"status": "not-checked", "reason": "no program threat model supplied"}
    body = report.lower()
    excluded = {str(item).lower() for item in model.get("excluded_classes", [])}
    designs = {str(item.get("behavior", "")).lower() for item in model.get("documented_design_behaviors", []) if isinstance(item, dict)}
    accepted = {str(item).lower() for item in model.get("accepted_classes", [])}
    boundaries = {str(item).lower() for item in model.get("security_boundary_classes", [])}
    matched = [term for term in excluded | designs | accepted | boundaries if term and term in body]
    if any(term in excluded | designs for term in matched):
        return {
            "status": "fail",
            "reason": "the report matches an excluded class or documented working-as-designed behavior for this program",
            "matched_terms": matched,
        }
    if any(term in accepted | boundaries for term in matched):
        return {
            "status": "pass",
            "reason": "the report matches a recorded security-boundary class or a class with historical acceptance for this program",
            "matched_terms": matched,
        }
    return {
        "status": "review",
        "reason": "no prior art match in the program threat model; research the vendor threat model before acceptance",
        "matched_terms": matched,
    }


def scope_check(
    args: argparse.Namespace,
) -> dict[str, Any]:
    if not args.target:
        return {"status": "not-checked", "reason": "no target supplied"}
    errors: list[str] = []
    warnings: list[str] = []
    if args.profile:
        profile = json.loads(args.profile.read_text(encoding="utf-8-sig"))
        errors, warnings = validate_profile(profile, target=args.target, action_group=args.action_group)
    if args.authorization:
        receipt = json.loads(args.authorization.read_text(encoding="utf-8-sig"))
        result = evaluate_authorization(
            receipt,
            target=args.target,
            action=args.action,
            action_group=args.action_group,
            now_value=args.now,
        )
        errors.extend(result["errors"])
        warnings.extend(result["warnings"])
    status = "blocked" if errors else ("in-scope" if args.profile or args.authorization else "not-checked")
    return {"status": status, "errors": errors, "warnings": warnings}


def evidence_check(finding: Path) -> dict[str, Any]:
    record = json.loads(finding.read_text(encoding="utf-8-sig"))
    errors, warnings = validate_finding(record, finding)
    assessment = assess(record, finding, normalized_now(None))
    return {
        "status": "invalid" if errors else "pass",
        "verdict": assessment["verdict"],
        "validation_confidence": assessment["scores"]["validation_confidence"],
        "effective_state": assessment["effective_state"],
        "errors": errors,
        "warnings": warnings,
    }


def severity_check(record: dict[str, Any] | None, report: str) -> dict[str, Any]:
    score = None
    rating = ""
    vector = ""
    if record and isinstance(record.get("severity"), dict):
        raw_score = record["severity"].get("score")
        if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool) and 0 <= raw_score <= 10:
            score = float(raw_score)
        rating = str(record["severity"].get("rating", "")).upper()
    if score is None:
        vector_match = re.search(r"\bCVSS[:=]?\s*(3\.\d[/ ]+AV:[^\s]+)", report, re.I)
        if vector_match:
            vector = vector_match.group(1)
        rating_match = re.search(r"\b(critical|high|medium|low)\b", report, re.I)
        if rating_match:
            text = rating_match.group(1).lower()
            if text == "critical":
                rating = "CRITICAL"
            elif text == "high":
                rating = "HIGH"
            elif text == "medium":
                rating = "MEDIUM"
            elif text == "low":
                rating = "LOW"
    if score is not None:
        if score >= 9.0:
            band = "critical"
        elif score >= 7.0:
            band = "high"
        elif score >= 4.0:
            band = "medium"
        else:
            band = "low"
        rating = band.upper()
        return {"status": "scored", "score": score, "band": band, "rating": rating, "vector": vector}
    if rating:
        return {"status": "rated", "score": None, "band": rating.lower(), "rating": rating, "vector": vector}
    return {
        "status": "vector-provided" if vector else "requires-reviewer-scoring",
        "score": None,
        "band": "unknown",
        "rating": "",
        "vector": vector,
    }


def duplicate_check(args: argparse.Namespace, record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {"status": "not-checked", "reason": "no finding record supplied"}
    candidate = record.get("fingerprint", record)
    cases = json.loads(args.cases.read_text(encoding="utf-8-sig"))["cases"]
    ranked = sorted((compare(candidate, case) for case in cases), key=lambda item: -item[0])
    local_top = ranked[0] if ranked else (0.0, {})
    public = public_matches(args.database, candidate, 5)
    advisory = advisory_matches(args.advisory_database, candidate, 5)
    possible = local_top[0] >= 0.5 or any(item.get("fingerprint_overlap", 0) >= 0.5 for item in public + advisory)
    return {
        "status": "possible-duplicate" if possible else "no-strong-match",
        "top_local_score": round(local_top[0], 4) if ranked else None,
        "public_leads": [item["case_id"] for item in public[:3]],
        "advisory_leads": [item["advisory_id"] for item in advisory[:3]],
    }


def verdict(
    report_result: dict[str, Any],
    scope: dict[str, Any],
    evidence: dict[str, Any],
    duplicate: dict[str, Any],
    threat_model: dict[str, Any],
    program_threat_model: dict[str, Any] | None = None,
) -> tuple[str, str]:
    if scope["status"] == "blocked":
        return "rejected", "out-of-scope-or-not-authorized"
    if threat_model["status"] == "fail":
        return "rejected", "no-attacker-controlled-impact-or-boundary"
    if evidence["status"] == "invalid":
        return "rejected", "invalid-evidence"
    if report_result["missing_sections"] or not report_result["has_reproduction_steps"]:
        return "needs-more-info", "incomplete-report"
    if report_result["impact"] == "absent":
        return "needs-more-info", "impact-not-demonstrated"
    if report_result["impact"] == "claimed-only":
        return "needs-more-info", "impact-asserted-not-demonstrated"
    if scope["status"] != "in-scope":
        return "needs-more-info", "scope-not-verified"
    if evidence["status"] != "pass":
        return "needs-more-info", "evidence-bundle-required"
    if evidence.get("effective_state") not in {"verified", "reportable"}:
        return "needs-more-info", "finding-not-independently-verified"
    if threat_model["status"] == "review":
        return "needs-more-info", "threat-model-clarity-required"
    if program_threat_model and program_threat_model.get("status") == "fail":
        return "rejected", "program-threat-model-exclusion"
    if not program_threat_model or program_threat_model.get("status") != "pass":
        return "needs-more-info", "program-threat-model-review-required"
    if duplicate["status"] == "possible-duplicate":
        return "possible-duplicate", "strong-prior-art-match"
    return "accepted", "evidence-and-impact-satisfied"


def triage(args: argparse.Namespace) -> dict[str, Any]:
    report = args.report.read_text(encoding="utf-8-sig")
    report_result = report_analysis(report)
    threat_model = threat_model_check(report, report_result)
    program_model = None
    if args.threat_model:
        program_model = json.loads(args.threat_model.read_text(encoding="utf-8-sig"))
    program_model_check = program_threat_model_check(report, program_model)
    if threat_model["status"] == "pass" and program_model_check["status"] == "fail":
        threat_model = {
            "status": "fail",
            "reason": program_model_check["reason"],
            "attacker_control": threat_model["attacker_control"],
            "boundary": threat_model["boundary"],
            "impact_demonstrated": threat_model["impact_demonstrated"],
            "program_model": program_model_check,
        }
    scope = scope_check(args)
    record = None
    evidence = {"status": "not-provided", "verdict": "", "validation_confidence": None, "effective_state": "", "errors": [], "warnings": []}
    if args.finding:
        evidence = evidence_check(args.finding)
        record = json.loads(args.finding.read_text(encoding="utf-8-sig"))
    severity = severity_check(record, report)
    duplicate = duplicate_check(args, record)
    final_verdict, reason = verdict(report_result, scope, evidence, duplicate, threat_model, program_model_check)

    if final_verdict == "accepted" and severity["band"] != "unknown":
        priority = severity["band"]
    elif final_verdict == "accepted":
        priority = "unknown"
    else:
        priority = "none"

    return {
        "schema_version": 1,
        "triaged_at_utc": normalized_now(None),
        "report": str(args.report.resolve()),
        "final_verdict": final_verdict,
        "reason": reason,
        "scope": scope,
        "report_quality": report_result,
        "threat_model": threat_model,
        "program_threat_model": program_model_check,
        "evidence": evidence,
        "severity": severity,
        "duplicate": duplicate,
        "priority": priority,
        "next_action": {
            "accepted": "Escalate to fix/response; prepare disclosure per program rules.",
            "needs-more-info": "Return the report with the exact missing evidence: reproduction steps, expected/observed behavior, or demonstrated impact (command output, file contents, captured response).",
            "possible-duplicate": "Compare root cause, reachable path, affected versions, and fix against the listed leads before deciding.",
            "rejected": "Record the rejection reason; respond to the reporter with the specific deficiency.",
            "blocked": "Resolve the scope or authorization gap before any triage decision.",
        }.get(final_verdict, ""),
        "caveat": "Triage verdicts are decision aids from the supplied evidence; severity and priority require reviewer calibration under program rules.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Triage a vulnerability report like a triager, not a finder.")
    parser.add_argument("report", type=Path, help="Markdown report to triage")
    parser.add_argument("--finding", type=Path, help="Finding-record JSON (evidence/impact/duplicate checks)")
    parser.add_argument("--profile", type=Path, help="Engagement profile JSON (scope check)")
    parser.add_argument("--authorization", type=Path, help="Authorization receipt JSON (scope check)")
    parser.add_argument("--threat-model", type=Path, help="Program threat-model JSON (excluded classes, documented design, prior triage decisions)")
    parser.add_argument("--target", help="Claimed target for scope checks")
    parser.add_argument("--action", help="Claimed action for authorization check")
    parser.add_argument("--action-group", help="Broad normal-testing group")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--advisory-database", type=Path, default=DEFAULT_ADVISORY_DATABASE)
    parser.add_argument("--now", help="ISO-8601 time override")
    parser.add_argument("--output", type=Path, help="Atomically write the triage verdict JSON")
    args = parser.parse_args()

    if not args.report.is_file():
        print(f"ERROR: report is not a file: {args.report}", file=sys.stderr)
        return 1
    try:
        result = triage(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    if args.output:
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temporary.replace(args.output)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return {
        "accepted": 0,
        "possible-duplicate": 2,
        "needs-more-info": 2,
        "rejected": 3,
        "blocked": 4,
    }[result["final_verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
