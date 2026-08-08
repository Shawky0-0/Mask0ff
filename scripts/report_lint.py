#!/usr/bin/env python3
"""Lint a vulnerability report against its finding record and evidence claims."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from redact_artifact import PATTERNS  # noqa: E402
from verify_finding import calculate_effective_state, validate  # noqa: E402


REQUIRED_HEADINGS = {
    "summary",
    "affected asset and range",
    "preconditions",
    "steps to reproduce",
    "evidence and controls",
    "expected behavior",
    "observed behavior",
    "impact",
    "root cause",
    "recommended remediation",
    "duplicate review",
    "verification status",
    "safety statement",
}
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("finding", type=Path)
    parser.add_argument("--require-reportable", action="store_true")
    args = parser.parse_args()

    report = args.report.read_text(encoding="utf-8-sig")
    record = json.loads(args.finding.read_text(encoding="utf-8-sig"))
    errors, warnings = validate(record, args.finding)
    state = calculate_effective_state(record, errors)

    headings = {
        match.group(1).strip().lower()
        for match in re.finditer(r"(?m)^##\s+(.+?)\s*$", report)
    }
    for heading in sorted(REQUIRED_HEADINGS - headings):
        errors.append(f"missing report heading: {heading}")
    if re.search(r"\[(?!E-\d{3,}\])[^\]\n]{2,80}\]", report):
        message = "report may still contain bracketed template placeholders"
        (errors if args.require_reportable else warnings).append(message)
    if len(re.findall(r"(?m)^\d+\.\s+", report)) < 2:
        errors.append("steps to reproduce needs at least two numbered steps")

    known_evidence = {str(item.get("id")) for item in record.get("evidence", [])}
    report_evidence = set(re.findall(r"\bE-\d{3,}\b", report))
    for evidence_id in sorted(report_evidence - known_evidence):
        errors.append(f"report references unknown evidence id: {evidence_id}")
    if known_evidence and not report_evidence:
        message = "report cites no evidence IDs"
        (errors if args.require_reportable else warnings).append(message)
    for index, claim in enumerate(record.get("claims", []), 1):
        if not isinstance(claim, dict):
            continue
        refs = {str(item) for item in claim.get("evidence", [])}
        if refs and not (refs & report_evidence):
            message = f"report cites no supporting evidence for claim {index}"
            if args.require_reportable:
                errors.append(message)
            else:
                warnings.append(message)
    if args.require_reportable:
        validation = record.get("validation") if isinstance(record.get("validation"), dict) else {}
        review_id = str(validation.get("review_evidence_id", "")).strip()
        packet_id = str(validation.get("blind_packet_evidence_id", "")).strip()
        for evidence_id, label in ((review_id, "independent X1 review"), (packet_id, "blind validation packet")):
            if evidence_id and evidence_id not in report_evidence:
                errors.append(f"report cites no {label} evidence id: {evidence_id}")
    for name, pattern, _replacement in PATTERNS:
        if any("<REDACTED" not in match.group(0) for match in pattern.finditer(report)):
            errors.append(f"possible unredacted secret: {name}")
    if args.require_reportable and state != "reportable":
        errors.append(f"finding state is {state}, not reportable")

    result = {
        "state": state,
        "known_evidence": len(known_evidence),
        "cited_evidence": sorted(report_evidence),
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(result, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
