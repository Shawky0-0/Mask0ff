#!/usr/bin/env python3
"""Run deterministic mask0ff state, duplicate, and dataset evaluations."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import threading
import time
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from assess_finding import assess  # noqa: E402
from authorization_gate import evaluate as evaluate_authorization  # noqa: E402
from duplicate_check import advisory_matches, compare  # noqa: E402
from plan_engagement import merged_lanes  # noqa: E402
from program_profile import checked_hackerone_url, import_bugcrowd, import_hackerone, validate_profile  # noqa: E402
from query_techniques import score as technique_score, tokens as technique_tokens  # noqa: E402
from race_condition import (  # noqa: E402
    build_plan as build_race_plan,
    execute as execute_race,
    validate_config as validate_race_config,
)
from redact_artifact import PATTERNS  # noqa: E402
from session_profile import validate_session  # noqa: E402
from security_graph import validate_graph as validate_security_graph  # noqa: E402
from tool_inventory import build_strategy  # noqa: E402
from triage_report import (  # noqa: E402
    program_threat_model_check,
    report_analysis,
    severity_check as triage_severity_check,
    verdict as triage_verdict,
)
from triage_review import MANDATORY_REJECTION_TESTS, validate_triage  # noqa: E402
from verify_finding import calculate_effective_state, calculate_state, validate  # noqa: E402
from weird_surface import evidence_confidence as weird_evidence_confidence  # noqa: E402


def scenario_record(template: dict, scenario: dict) -> dict:
    record = deepcopy(template)
    record["title"] = scenario["id"]
    record["work_mode"] = scenario["work_mode"]
    evidence_kind = {
        "active-authorized": "authorization-validation",
        "local-lab": "local-lab-ownership",
        "passive": "passive-scope",
    }.get(scenario["work_mode"], "eval")
    record["evidence"] = [
        {"id": "E-001", "kind": evidence_kind, "path": "none", "sha256": "", "observation": "synthetic eval"}
    ]
    record["claims"] = [{"statement": "eval", "basis": "observed", "evidence": ["E-001"]}]
    record["fingerprint"] = {
        "product": "eval",
        "component": "eval component",
        "entry_point": "eval entry",
        "controlled_input": "eval input",
        "source_sink": "eval source to sink",
        "preconditions": ["eval"],
        "boundary": "eval boundary",
        "primitive": "eval primitive",
        "impact": "eval impact",
        "affected_versions": "eval-current",
        "fix_invariant": "eval fix"
    }
    record["threat_model"] = {
        "attacker_actor": "external eval attacker",
        "victim_actor": "eval victim",
        "attacker_principal": "low-authority-eval-principal",
        "victim_principal": "higher-authority-eval-service",
        "attacker_controls": ["synthetic eval input"],
        "attacker_control_evidence": ["E-001"],
        "attacker_does_not_control": ["victim service policy"],
        "required_victim_actions": ["process attacker input"],
        "required_admin_actions": [],
        "trust_principals": ["low-authority-eval-principal", "higher-authority-eval-service"],
        "trust_model_evidence": ["E-001"],
        "security_contract": {
            "statement": "Low-authority eval input must not gain the protected eval capability.",
            "basis": "documented",
            "evidence": ["E-001"],
        },
        "consent_analysis": {
            "explicit_authorization_required": False,
            "explicit_authorization_present": False,
            "authorized_actor": "",
            "outcome": "not-applicable",
            "evidence": [],
        },
        "authority_delta": {
            "before": ["submit eval input"],
            "after": ["submit eval input", "invoke protected eval capability"],
            "gained": ["invoke protected eval capability"],
            "equivalent_authority_already_held": False,
            "protected_property": "eval authorization boundary",
            "boundary_crossed": True,
            "evidence": ["E-001"],
        },
    }
    record["freshness"] = {
        "checked_at_utc": "2026-08-10T00:00:00Z",
        "tested_version_or_revision": "eval-current",
        "current_supported_version_or_revision": "eval-current",
        "status": "vulnerable",
        "submission_relevance": "current-vulnerable",
        "evidence": ["E-001"],
    }
    record["impact_model"] = {
        "demonstrated_effects": ["protected eval capability reached"],
        "bounded_inferences": [],
        "attacker_gain": ["invoke protected eval capability"],
        "victim_loss": ["authorization boundary"],
        "preconditions": ["synthetic eval precondition"],
        "blast_radius": "single synthetic eval object",
        "counterfactual_if_fixed": "attacker cannot invoke the protected eval capability",
        "evidence": ["E-001"],
    }
    for gate in scenario.get("pass", []):
        record["gates"][gate] = {"status": "pass", "evidence": ["E-001"], "reason": ""}
    if any(gate in scenario.get("pass", []) for gate in ("C1", "R1")):
        record["evidence"].append(
            {"id": "E-002", "kind": "runtime-repeat", "path": "none-2", "sha256": "", "observation": "second synthetic eval"}
        )
    if "C1" in scenario.get("pass", []):
        record["gates"]["C1"]["evidence"] = ["E-002"]
    if "R1" in scenario.get("pass", []):
        record["gates"]["R1"]["evidence"] = ["E-001", "E-002"]
        record["runs"] = [
            {"id": "run-1", "evidence": ["E-001"]},
            {"id": "run-2", "evidence": ["E-002"]},
        ]
    if "X1" in scenario.get("pass", []):
        record["evidence"].extend(
            [
                {"id": "E-003", "kind": "independent-validation", "path": "none-3", "sha256": "", "observation": "synthetic independent review"},
                {"id": "E-004", "kind": "independent-reproduction", "path": "none-4", "sha256": "", "observation": "synthetic independent reproduction"},
                {"id": "E-005", "kind": "validation-packet", "path": "none-5", "sha256": "", "observation": "synthetic blind packet"},
            ]
        )
        record["gates"]["X1"] = {"status": "pass", "evidence": ["E-003", "E-004", "E-005"], "reason": ""}
        record["validation"] = {
            "status": "pass",
            "independence": "separate-agent",
            "discovery_owner": "discovery-eval",
            "validator_owner": "validator-eval",
            "blind_packet_evidence_id": "E-005",
            "review_evidence_id": "E-003",
            "reproduction_evidence": ["E-004"],
            "verdict": "confirmed",
        }
    if "J1" in scenario.get("pass", []):
        record["evidence"].append(
            {"id": "E-006", "kind": "triage-review", "path": "none-6", "sha256": "", "observation": "synthetic adversarial triage review"}
        )
        record["gates"]["J1"] = {"status": "pass", "evidence": ["E-006"], "reason": ""}
        record["classification"] = {"status": "security-vulnerability", "reason": "synthetic eval", "evidence": ["E-001", "E-006"]}
        record["triage"] = {
            "status": "pass",
            "discovery_owner": "discovery-eval",
            "reviewer_owner": "triager-eval",
            "review_evidence_id": "E-006",
            "verdict": "survives",
            "classification": "security-vulnerability",
        }
    for gate in scenario.get("not_applicable", []):
        record["gates"][gate] = {"status": "not_applicable", "evidence": [], "reason": "eval reason"}
    for gate in scenario.get("clear_evidence_for", []):
        record["gates"][gate]["evidence"] = []
    for gate in scenario.get("clear_reason_for", []):
        record["gates"][gate]["reason"] = ""
    for gate in scenario.get("unknown_evidence_for", []):
        record["gates"][gate]["evidence"] = ["E-UNKNOWN"]
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-dataset", action="store_true")
    parser.add_argument("--minimum-cases", type=int, default=10001)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--advisory-database", type=Path)
    parser.add_argument("--minimum-advisories", type=int, default=30000)
    args = parser.parse_args()

    template = json.loads((ROOT / "assets" / "evidence-bundle" / "finding-record.json").read_text(encoding="utf-8"))
    scenarios = json.loads((ROOT / "evals" / "scenarios.json").read_text(encoding="utf-8"))["scenarios"]
    failures = []
    for scenario in scenarios:
        record = scenario_record(template, scenario)
        errors, _ = validate(record)
        state = calculate_state(record)
        if state != scenario["expected_state"] or len(errors) != scenario["expected_errors"]:
            failures.append(
                f"{scenario['id']}: state={state} errors={len(errors)} "
                f"expected_state={scenario['expected_state']} expected_errors={scenario['expected_errors']}"
            )

    cases = json.loads((ROOT / "references" / "cases" / "cases.json").read_text(encoding="utf-8"))["cases"]
    exact_score, _ = compare(cases[3]["fingerprint"], cases[3])
    unrelated_score, _ = compare(cases[3]["fingerprint"], cases[0])
    if exact_score != 1.0:
        failures.append(f"exact duplicate analogy score is {exact_score}, expected 1.0")
    if unrelated_score >= 0.2:
        failures.append(f"unrelated analogy score is {unrelated_score}, expected below 0.2")

    consent_record = scenario_record(
        template,
        {"id": "consent-regression", "work_mode": "local-lab", "pass": ["A0", "T1"], "not_applicable": []},
    )
    consent_record["threat_model"]["consent_analysis"] = {
        "explicit_authorization_required": True,
        "explicit_authorization_present": True,
        "authorized_actor": "administrator",
        "outcome": "not-authorized-by-consent",
        "evidence": ["E-001"],
    }
    consent_errors, _ = validate(consent_record)
    if not any("explicitly authorized" in error for error in consent_errors):
        failures.append("T1 regression accepts explicitly authorized behavior as an attacker bypass")

    same_authority_record = scenario_record(
        template,
        {"id": "same-authority-regression", "work_mode": "local-lab", "pass": ["A0", "E1"], "not_applicable": []},
    )
    same_authority_record["threat_model"]["authority_delta"]["equivalent_authority_already_held"] = True
    same_authority_errors, _ = validate(same_authority_record)
    if not any("did not already hold equivalent authority" in error for error in same_authority_errors):
        failures.append("E1 regression accepts equivalent pre-existing authority as escalation")

    stale_record = scenario_record(
        template,
        {"id": "stale-version-regression", "work_mode": "local-lab", "pass": ["A0", "V1"], "not_applicable": []},
    )
    stale_record["freshness"]["status"] = "safe"
    stale_record["freshness"]["submission_relevance"] = "historical-only"
    stale_errors, _ = validate(stale_record)
    if not any("freshness.status=vulnerable" in error for error in stale_errors):
        failures.append("V1 regression accepts a current-safe/historical-only candidate")

    no_attacker_record = scenario_record(
        template,
        {"id": "no-attacker-control-regression", "work_mode": "local-lab", "pass": ["A0", "T1"], "not_applicable": []},
    )
    no_attacker_record["threat_model"]["attacker_controls"] = []
    no_attacker_errors, _ = validate(no_attacker_record)
    if not any("concrete attacker-controlled" in error for error in no_attacker_errors):
        failures.append("T1 regression accepts a candidate with no attacker-controlled input")

    triage_record = scenario_record(
        template,
        {"id": "triage-regression", "work_mode": "local-lab", "pass": ["A0", "T1", "V1", "E1", "X1", "I1"], "not_applicable": []},
    )

    def triage_fixture(applies: str | None = None, final: str = "survives", classification: str = "security-vulnerability") -> dict:
        return {
            "schema_version": 1,
            "kind": "mask0ff-triage-review",
            "candidate_id": "triage-regression",
            "discovery_owner": "discovery-eval",
            "reviewer_owner": "triager-eval",
            "reviewed_at_utc": "2026-08-10T00:00:00Z",
            "current_version_checked": True,
            "security_contract_checked": True,
            "attacker_control_checked": True,
            "authority_delta_checked": True,
            "rejection_tests": [
                {
                    "id": test_id,
                    "status": "applies" if test_id == applies else "defeated",
                    "rationale": "synthetic triage regression",
                    "evidence": ["E-001"],
                }
                for test_id in MANDATORY_REJECTION_TESTS
            ],
            "final_verdict": final,
            "classification": classification,
            "reason": "synthetic triage regression",
        }

    surviving_status, surviving_errors, _ = validate_triage(triage_fixture(), triage_record)
    if surviving_status != "pass" or surviving_errors:
        failures.append(f"J1 triage regression rejects a fully defeated candidate: {surviving_errors}")

    rejected_status, rejected_errors, _ = validate_triage(
        triage_fixture(applies="no-attacker-control", final="reject", classification="insufficient-attacker-control"),
        triage_record,
    )
    if rejected_status != "fail" or rejected_errors:
        failures.append("J1 triage regression does not fail an applicable vendor rejection")

    surviving_with_applies, _, _ = validate_triage(
        triage_fixture(applies="working-as-designed"),
        triage_record,
    )
    if surviving_with_applies != "invalid":
        failures.append("J1 triage regression accepts a survives verdict with an applicable rejection reason")

    generic_id_report = """## Steps to Reproduce
1. Change the ID parameter.
## Expected
The request should fail.
## Observed
The response could potentially expose another record.
## Impact
The ID may allow unauthorized access, but no response body was captured.
"""
    if report_analysis(generic_id_report)["impact"] != "claimed-only":
        failures.append("triage report treats a generic ID mention and hedged impact as demonstrated evidence")

    vector_result = triage_severity_check(None, "Severity: CVSS 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    if vector_result["status"] != "vector-provided" or not vector_result["vector"].startswith("3.1/AV:N"):
        failures.append("triage severity does not preserve an unscored CVSS vector for reviewer calibration")

    no_scope_verdict = triage_verdict(
        {"missing_sections": [], "has_reproduction_steps": True, "impact": "demonstrated"},
        {"status": "not-checked"},
        {"status": "not-provided"},
        {"status": "no-strong-match"},
        {"status": "pass"},
        {"status": "pass"},
    )
    if no_scope_verdict != ("needs-more-info", "scope-not-verified"):
        failures.append("triage report accepts a finding without verified scope")

    candidate_evidence_verdict = triage_verdict(
        {"missing_sections": [], "has_reproduction_steps": True, "impact": "demonstrated"},
        {"status": "in-scope"},
        {"status": "pass", "effective_state": "candidate"},
        {"status": "no-strong-match"},
        {"status": "pass"},
        {"status": "pass"},
    )
    if candidate_evidence_verdict != ("needs-more-info", "finding-not-independently-verified"):
        failures.append("triage report accepts a syntactically valid but unverified finding record")

    boundary_model_result = program_threat_model_check(
        "Cross-tenant authorization bypass",
        {
            "security_boundary_classes": ["cross-tenant authorization"],
            "excluded_classes": [],
            "documented_design_behaviors": [],
            "accepted_classes": [],
        },
    )
    if boundary_model_result["status"] != "pass":
        failures.append("triage report ignores a program threat model's declared security-boundary classes")

    old_gate_confidence = weird_evidence_confidence(
        {"gates": {gate: {"status": "pass"} for gate in ("A1", "H1", "B1", "P1", "C1", "R1", "X1", "I1", "D1")}}
    )
    if old_gate_confidence["confidence"] >= 1.0 or not {"T1", "E1", "V1", "J1"}.issubset(old_gate_confidence["missing"]):
        failures.append("weird-surface evidence confidence ignores the mandatory threat, authority, freshness, or triage gates")

    graph_errors, _graph_warnings = validate_security_graph([])
    if "security graph must be a JSON object" not in graph_errors:
        failures.append("security graph validator crashes on or accepts a non-object document")

    malformed_review_status, malformed_review_errors, _malformed_review_warnings = validate_triage([], {})
    if malformed_review_status != "invalid" or "triage review must be a JSON object" not in malformed_review_errors:
        failures.append("triage review validator crashes on or accepts a non-object document")

    real_world = json.loads((ROOT / "evals" / "real-world-outcomes.json").read_text(encoding="utf-8"))["cases"]

    def apply_patch(record: dict[str, Any], patch: dict[str, Any]) -> None:
        for dotted, value in patch.items():
            target = record
            parts = dotted.split(".")
            for part in parts[:-1]:
                if not isinstance(target.get(part), dict):
                    target[part] = {}
                target = target[part]
            target[parts[-1]] = value

    for case in real_world:
        case_record = scenario_record(
            template,
            {"id": case["id"], "work_mode": "local-lab", "pass": case["gate_requirements"], "not_applicable": []},
        )
        apply_patch(case_record, case["record_patch"])
        gate_errors, _ = validate(case_record)
        missing_errors = [expected for expected in case["expected_gate_errors"] if not any(expected in error for error in gate_errors)]
        if missing_errors:
            failures.append(f"real-world case {case['id']} no longer rejected by the verifier: missing {missing_errors}")

        triage_prerequisite_record = scenario_record(
            template,
            {"id": case["id"] + "-j1", "work_mode": "local-lab", "pass": ["A0", "T1", "V1", "E1", "X1", "I1"], "not_applicable": []},
        )
        review = triage_fixture(
            applies=case["triage_review"]["applies"],
            final=case["triage_review"]["final"],
            classification=case["triage_review"]["classification"],
        )
        review_status, review_errors, _ = validate_triage(review, triage_prerequisite_record)
        if review_status != case["triage_review"]["expected_status"] or review_errors:
            failures.append(
                f"real-world case {case['id']} triage review did not reject as expected: status={review_status} errors={review_errors}"
            )

    adversarial = scenario_record(
        template,
        {
            "id": "adversarial-authorization",
            "work_mode": "active-authorized",
            "pass": ["A0"],
            "not_applicable": [],
        },
    )
    adversarial["evidence"][0]["kind"] = "runtime-log"
    auth_errors, _ = validate(adversarial)
    if not any("A0" in error and "evidence kind" in error for error in auth_errors):
        failures.append("active A0 accepts generic evidence instead of authorization validation")
    if calculate_effective_state(adversarial, auth_errors) != "blocked":
        failures.append("invalid A0 evidence does not force effective state to blocked")

    claim_record = scenario_record(
        template,
        {
            "id": "adversarial-claim",
            "work_mode": "local-lab",
            "pass": ["A0", "A1", "H1", "B1", "P1"],
            "not_applicable": [],
        },
    )
    claim_record["claims"][0]["evidence"] = ["E-UNKNOWN"]
    claim_errors, _ = validate(claim_record)
    if not any("claim" in error and "unknown evidence" in error for error in claim_errors):
        failures.append("claim validation accepts an unknown evidence reference")

    inferred_record = scenario_record(
        template,
        {
            "id": "adversarial-inferred-claim",
            "work_mode": "local-lab",
            "pass": ["A0", "A1", "H1", "B1", "P1"],
            "not_applicable": [],
        },
    )
    inferred_record["claims"] = [{"statement": "inferred impact", "basis": "inferred", "evidence": []}]
    inferred_errors, _ = validate(inferred_record)
    if not any("basis 'inferred' requires evidence" in error for error in inferred_errors):
        failures.append("inferred claim validation accepts no supporting evidence")

    secret_sample = "\n".join(
        (
            "Authorization: Bearer secret-value",
            "X-API-Key: header-value",
            "password='secret words'",
            "AKIA1234567890ABCDEF",
            "ghp_abcdefghijklmnopqrstuvwxyz123456",
        )
    )
    redacted = secret_sample
    for _name, pattern, replacement in PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    if any(value in redacted for value in ("secret-value", "header-value", "secret words", "AKIA1234567890ABCDEF", "ghp_abcdefghijklmnopqrstuvwxyz123456")):
        failures.append("redaction regression leaked a known secret fixture")

    hackerone_fixture = {
        "data": [
            {
                "id": "101",
                "type": "structured-scope",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "*.example.test",
                    "eligible_for_submission": True,
                    "eligible_for_bounty": True,
                    "max_severity": "critical",
                    "instruction": "researcher accounts only",
                },
            },
            {
                "id": "102",
                "type": "structured-scope",
                "attributes": {
                    "asset_type": "URL",
                    "asset_identifier": "excluded.example.test",
                    "eligible_for_submission": False,
                    "eligible_for_bounty": False,
                },
            },
        ]
    }
    imported_scope, imported_exclusions = import_hackerone(hackerone_fixture)
    dynamic_profile = {
        "schema_version": 1,
        "kind": "mask0ff-engagement-profile",
        "platform": "hackerone",
        "program_or_owner": "eval-program",
        "policy_reference": "https://example.test/policy",
        "assessment_mode": "hybrid",
        "work_mode": "active-authorized",
        "scope": imported_scope,
        "out_of_scope": imported_exclusions,
        "allowed_action_groups": ["standard-safe-testing", "authenticated-testing", "source-review"],
        "prohibited_actions": ["denial-of-service"],
        "owned_accounts_and_data": ["two researcher-owned accounts and synthetic objects"],
    }
    profile_errors, _profile_warnings = validate_profile(
        dynamic_profile, target="api.example.test", action_group="authenticated-testing"
    )
    excluded_errors, _excluded_warnings = validate_profile(dynamic_profile, target="excluded.example.test")
    if profile_errors or len(imported_scope) != 1 or len(imported_exclusions) != 1:
        failures.append(f"HackerOne scope import/profile validation failed: {profile_errors}")
    if not any("out of scope" in error for error in excluded_errors):
        failures.append("normalized platform profile does not enforce explicit exclusions")

    bugcrowd_fixture = {
        "data": [{"id": "program-1", "type": "programs", "attributes": {"code": "eval"}}],
        "included": [
            {
                "id": "target-1",
                "type": "targets",
                "attributes": {"name": "api.bugcrowd.example", "category": "website"},
            }
        ],
    }
    bugcrowd_scope, bugcrowd_exclusions = import_bugcrowd(bugcrowd_fixture)
    if len(bugcrowd_scope) != 1 or bugcrowd_scope[0]["identifier"] != "api.bugcrowd.example" or bugcrowd_exclusions:
        failures.append("Bugcrowd target export import regression")
    try:
        checked_hackerone_url("https://attacker.example/redirected-scope")
        failures.append("HackerOne synchronizer accepted pagination outside api.hackerone.com")
    except ValueError:
        pass

    authorization_fixture = {
        "authority": "hackerone program",
        "program_or_owner": "eval-program",
        "policy_reference": "https://example.test/policy",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "in_scope_targets": ["*.example.test"],
        "out_of_scope_targets": ["excluded.example.test"],
        "allowed_actions": ["standard-safe-testing"],
        "allowed_action_groups": ["authenticated-testing"],
        "prohibited_actions": ["denial-of-service"],
        "owned_accounts_and_data": ["researcher account"],
        "evidence": [{"kind": "engagement-profile", "sha256": "0" * 64}],
    }
    grouped_authorization = evaluate_authorization(
        authorization_fixture,
        target="api.example.test",
        action="authorization-differential",
        action_group="authenticated-testing",
        now_value="2026-08-02T00:00:00Z",
    )
    prohibited_authorization = evaluate_authorization(
        authorization_fixture,
        target="api.example.test",
        action="denial-of-service",
        action_group="authenticated-testing",
        now_value="2026-08-02T00:00:00Z",
    )
    if grouped_authorization["status"] != "pass":
        failures.append(f"broad normal-testing authorization group was rejected: {grouped_authorization['errors']}")
    if prohibited_authorization["status"] != "blocked":
        failures.append("explicitly prohibited action passed through an allowed normal-testing group")

    session_fixture = {
        "schema_version": 1,
        "kind": "mask0ff-session-profile",
        "label": "member-a",
        "base_url": "https://api.example.test",
        "role": "member",
        "tenant": "tenant-a",
        "auth_type": "password",
        "credential_references": {"username_env": "MASK0FF_USER_A", "secret_env": "MASK0FF_PASS_A"},
        "browser_profile": "",
    }
    session_errors, _session_warnings, _availability = validate_session(session_fixture)
    leaked_session = deepcopy(session_fixture)
    leaked_session["password"] = "must-not-be-stored"
    leaked_errors, _leaked_warnings, _leaked_availability = validate_session(leaked_session)
    if session_errors:
        failures.append(f"secret-free session profile was rejected: {session_errors}")
    if not any("plaintext secret" in error for error in leaked_errors):
        failures.append("session profile accepted embedded plaintext credential material")
    expired_session = deepcopy(session_fixture)
    expired_session["expires_at_utc"] = "2026-01-01T00:00:00Z"
    expired_errors, _expired_warnings, _expired_availability = validate_session(
        expired_session, now_value="2026-08-02T00:00:00Z"
    )
    if not any("expired" in error for error in expired_errors):
        failures.append("expired authenticated session profile was accepted")

    secret_record = scenario_record(
        template,
        {
            "id": "finding-secret-regression",
            "work_mode": "local-lab",
            "pass": ["A0"],
            "not_applicable": [],
        },
    )
    secret_record.setdefault("access", {})["password"] = "must-not-be-stored"
    secret_record_errors, _secret_record_warnings = validate(secret_record)
    if not any("forbidden secret material" in error for error in secret_record_errors):
        failures.append("finding verifier accepted embedded plaintext credential material")

    if not any(item["id"] == "authorization-matrix" for item in merged_lanes("black-box")):
        failures.append("black-box plan lacks authorization-matrix lane")
    if not any(item["id"] == "environment-toolchain" for item in merged_lanes("black-box")):
        failures.append("engagement plan lacks environment/toolchain inventory lane")
    if not any(item["id"] == "prior-art-method-mining" for item in merged_lanes("white-box")):
        failures.append("engagement plan lacks prior-art method-mining lane")
    if not any(item["id"] == "source-dataflow" for item in merged_lanes("white-box")):
        failures.append("white-box plan lacks source-dataflow lane")
    hybrid_lane_ids = [item["id"] for item in merged_lanes("hybrid")]
    if len(hybrid_lane_ids) != len(set(hybrid_lane_ids)) or "source-dataflow" not in hybrid_lane_ids:
        failures.append("hybrid plan does not merge black/gray/white lanes deterministically")

    installed = {"rg", "subfinder", "httpx", "katana", "ffuf", "semgrep", "slither", "forge"}
    tool_strategy = build_strategy(
        "hybrid",
        ["web", "web3"],
        ["remote code execution"],
        "large-scope",
        which_func=lambda name: f"/tools/{name}" if name in installed else None,
    )
    tool_stage_ids = {item["id"] for item in tool_strategy["stages"]}
    if not {"passive-enumeration", "endpoint-and-client-map", "focused-fuzzing", "source-and-dependency-analysis", "web3-invariant-analysis"} <= tool_stage_ids:
        failures.append(f"tool strategy omitted required research stages: {sorted(tool_stage_ids)}")
    if "role_and_tenant" not in tool_strategy["correlation_keys"] or tool_strategy["inventory"]["available_count"] < len(installed):
        failures.append("tool strategy does not preserve cross-tool correlation or installed-tool inventory")

    race_tools = {"python", "curl", "burpsuite", "turbo-intruder", "h2spacex"}
    race_strategy = build_strategy(
        "black-box",
        ["api"],
        ["race condition idempotency TOCTOU"],
        "single-target",
        which_func=lambda name: f"/tools/{name}" if name in race_tools else None,
    )
    race_stage = next((item for item in race_strategy["stages"] if item["id"] == "race-state-analysis"), None)
    race_groups = {item["group"] for item in race_stage.get("tool_groups", [])} if race_stage else set()
    if race_stage is None or "race-delivery" not in race_groups or "race_method" not in race_strategy:
        failures.append("race focus does not route to dedicated delivery, state-analysis, and method guidance")

    race_plan = build_race_plan(
        work_mode="local-lab",
        assessment_mode="hybrid",
        surface="api",
        protocol="http2",
        pattern="state-machine",
        max_concurrency=2,
        max_attempts=2,
    )
    phase_ids = [item["id"] for item in race_plan["phases"]]
    delivery_actions = next(item["actions"] for item in race_plan["phases"] if item["id"] == "bounded-synchronization")
    if phase_ids[:2] != ["model-invariant", "sequential-benchmark"] or not any("single-packet" in item for item in delivery_actions):
        failures.append("race planner does not require invariant modeling, sequential benchmarking, and HTTP/2 single-packet delivery")

    race_config = json.loads((ROOT / "assets" / "evidence-bundle" / "race-run-config.json").read_text(encoding="utf-8"))
    race_errors, race_warnings, _race_authorization = validate_race_config(race_config)
    if race_errors or race_warnings:
        failures.append(f"local race-run template is not execution-ready: errors={race_errors} warnings={race_warnings}")
    remote_local_config = deepcopy(race_config)
    remote_local_config["target"] = "api.example.test"
    for spec in remote_local_config["reset_requests"] + remote_local_config["requests"] + remote_local_config["state_checks"]:
        spec["url"] = spec["url"].replace("127.0.0.1:8080", "api.example.test")
    remote_local_errors, _warnings, _authorization = validate_race_config(remote_local_config)
    if not any("loopback" in error for error in remote_local_errors):
        failures.append("local-lab race runner accepts a non-loopback target")
    secret_race_config = deepcopy(race_config)
    secret_race_config["requests"][0]["headers"]["Authorization"] = "must-not-be-stored"
    secret_race_errors, _warnings, _authorization = validate_race_config(secret_race_config)
    if not any("sensitive header" in error for error in secret_race_errors):
        failures.append("race runner accepts stored authorization material")
    unbounded_race_config = deepcopy(race_config)
    unbounded_race_config["requests"][0]["copies"] = 1000
    unbounded_race_errors, _warnings, _authorization = validate_race_config(unbounded_race_config)
    if not any("copies" in error or "hard cap" in error for error in unbounded_race_errors):
        failures.append("race runner accepts unbounded concurrency")
    over_limit_race_config = deepcopy(race_config)
    over_limit_race_config["requests"][0]["copies"] = 3
    over_limit_race_errors, _warnings, _authorization = validate_race_config(over_limit_race_config)
    if not any("configured limit" in error for error in over_limit_race_errors):
        failures.append("race runner exceeds the engagement-configured concurrency limit")

    authorized_race_config = deepcopy(remote_local_config)
    authorized_race_config["work_mode"] = "active-authorized"
    authorized_race_config["action_group"] = "authenticated-testing"
    authorization_fixture_hash = hashlib.sha256(
        json.dumps(authorization_fixture, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    authorized_race_errors, _warnings, authorized_race_result = validate_race_config(
        authorized_race_config,
        authorization_fixture,
        "2026-08-02T00:00:00Z",
        authorization_fixture_hash,
    )
    if authorized_race_errors or not authorized_race_result or authorized_race_result["status"] != "pass":
        failures.append(f"bounded race runner rejected a valid target-bound authorization: {authorized_race_errors}")
    prohibited_race_authorization = deepcopy(authorization_fixture)
    prohibited_race_authorization["prohibited_actions"].append("race-condition-testing")
    prohibited_race_authorization_hash = hashlib.sha256(
        json.dumps(prohibited_race_authorization, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    prohibited_race_errors, _warnings, _authorization = validate_race_config(
        authorized_race_config,
        prohibited_race_authorization,
        "2026-08-02T00:00:00Z",
        prohibited_race_authorization_hash,
    )
    if not any("explicitly prohibits" in error for error in prohibited_race_errors):
        failures.append("race runner ignores an explicit race-testing prohibition")

    race_state = {"value": 0}
    race_fixture_control = {"reset_count": 0}
    race_transition_barrier = threading.Barrier(2)

    class RaceFixtureHandler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/reset":
                race_state["value"] = 0
                race_fixture_control["reset_count"] += 1
            elif self.path == "/transition":
                value = race_state["value"]
                if race_fixture_control["reset_count"] > 2:
                    race_transition_barrier.wait(timeout=2)
                else:
                    time.sleep(0.01)
                race_state["value"] = value + 1
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def do_GET(self) -> None:  # noqa: N802
            if self.path != "/state":
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps(race_state, sort_keys=True).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    race_server = ThreadingHTTPServer(("127.0.0.1", 0), RaceFixtureHandler)
    race_server_thread = threading.Thread(target=race_server.serve_forever, daemon=True)
    race_server_thread.start()
    try:
        executable_race_config = deepcopy(race_config)
        fixture_base = f"http://127.0.0.1:{race_server.server_address[1]}"
        executable_race_config["reset_requests"][0]["url"] = fixture_base + "/reset"
        executable_race_config["requests"][0]["url"] = fixture_base + "/transition"
        executable_race_config["state_checks"][0]["url"] = fixture_base + "/state"
        live_race_errors, live_race_warnings, live_race_authorization = validate_race_config(executable_race_config)
        live_race_result = execute_race(executable_race_config, live_race_warnings, live_race_authorization)
        if (
            live_race_errors
            or not live_race_result["signals"]["baseline_is_stable"]
            or not live_race_result["signals"]["concurrent_state_differs_from_baseline"]
            or any(
                not run["reset"] or not run["pre_state"] or not run["state_checks"]
                for run in live_race_result["baseline_runs"] + live_race_result["concurrent_runs"]
            )
        ):
            failures.append("bounded local race runner failed to distinguish stable sequential state from a synchronized lost update")
    finally:
        race_server.shutdown()
        race_server.server_close()
        race_server_thread.join(timeout=2)

    self_review = scenario_record(
        template,
        {
            "id": "self-review-x1",
            "work_mode": "local-lab",
            "pass": ["A0", "A1", "H1", "B1", "P1", "C1", "R1", "X1", "I1"],
            "not_applicable": [],
        },
    )
    self_review["validation"]["validator_owner"] = self_review["validation"]["discovery_owner"]
    self_review_errors, _self_review_warnings = validate(self_review)
    if not any("self-review" in error for error in self_review_errors):
        failures.append("X1 accepts self-review by the discovery owner")
    if calculate_effective_state(self_review, self_review_errors) != "substantiated":
        failures.append("invalid X1 self-review is not capped at substantiated")

    technique_catalog = json.loads(
        (ROOT / "references" / "techniques" / "current-techniques.json").read_text(encoding="utf-8")
    )
    current_techniques = technique_catalog.get("techniques", [])
    orm_query = technique_tokens("ORM relation filter leak")
    ranked_current = sorted(
        current_techniques,
        key=lambda row: -technique_score(row, orm_query, "white-box", "source"),
    )
    if len(current_techniques) < 25 or not ranked_current or ranked_current[0].get("id") != "PS-2025-02":
        actual = ranked_current[0].get("id") if ranked_current else "none"
        failures.append(f"current-technique catalog/ranking regression: count={len(current_techniques)} top={actual}")
    if not all(
        row.get("source") and row.get("safe_validation") and row.get("modes") and row.get("signals")
        for row in current_techniques
    ):
        failures.append("current-technique catalog has entries without provenance, routing, or safe validation")
    race_query = technique_tokens("race condition idempotency TOCTOU")
    ranked_races = sorted(
        current_techniques,
        key=lambda row: -technique_score(row, race_query, "black-box", "api"),
    )
    if not ranked_races or ranked_races[0].get("id") != "PS-RACE-STATE-MACHINE":
        actual = ranked_races[0].get("id") if ranked_races else "none"
        failures.append(f"race technique routing regression: top={actual}")
    unrelated_race_score = technique_score(
        next(row for row in current_techniques if row.get("id") == "PS-2025-01"),
        race_query,
        "black-box",
        "api",
    )
    if unrelated_race_score > 0:
        failures.append("race technique query still promotes unrelated mode/surface-only matches")

    database = args.database.resolve() if args.database else ROOT / "references" / "cases" / "case-dataset.sqlite3"
    dataset_count = 0
    if database.is_file():
        connection = sqlite3.connect(database)
        try:
            dataset_count = int(connection.execute("SELECT count(*) FROM cases").fetchone()[0])
            fts_count = int(connection.execute("SELECT count(*) FROM cases_fts").fetchone()[0])
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            distinct_count = int(connection.execute("SELECT count(DISTINCT case_id) FROM cases").fetchone()[0])
            empty_summaries = int(connection.execute("SELECT count(*) FROM cases WHERE trim(summary) = ''").fetchone()[0])
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            source_revision = str(metadata.get("source_revision", ""))
            invalid_ids = int(connection.execute("SELECT count(*) FROM cases WHERE case_id NOT GLOB 'CVE-[0-9][0-9][0-9][0-9]-*'").fetchone()[0])
            invalid_hashes = int(connection.execute("SELECT count(*) FROM cases WHERE length(source_sha256) != 64").fetchone()[0])
            enriched = int(connection.execute("SELECT count(*) FROM cases WHERE adp_providers != ''").fetchone()[0])
            sourced_severity = int(connection.execute("SELECT count(*) FROM cases WHERE severity != '' AND severity_source != ''").fetchone()[0])
            severity_count = int(connection.execute("SELECT count(*) FROM cases WHERE severity != ''").fetchone()[0])
        finally:
            connection.close()
        if dataset_count != fts_count:
            failures.append(f"case/FTS count mismatch: {dataset_count} != {fts_count}")
        if integrity != "ok":
            failures.append(f"SQLite integrity check failed: {integrity}")
        if distinct_count != dataset_count:
            failures.append(f"duplicate case IDs: distinct={distinct_count} total={dataset_count}")
        if empty_summaries:
            failures.append(f"dataset has {empty_summaries} empty summaries")
        if not source_revision or source_revision == "unknown":
            failures.append("dataset source revision is missing")
        if metadata.get("schema_version") != "2":
            failures.append(f"dataset schema is {metadata.get('schema_version')!r}, expected '2'")
        if "CNA plus CVE Program" not in metadata.get("containers", ""):
            failures.append("dataset metadata does not declare Program/ADP container ingestion")
        if invalid_ids:
            failures.append(f"dataset has {invalid_ids} malformed CVE IDs")
        if invalid_hashes:
            failures.append(f"dataset has {invalid_hashes} malformed source hashes")
        if enriched == 0:
            failures.append("dataset has no ADP-enriched cases")
        if sourced_severity != severity_count:
            failures.append("dataset has severity values without metric provenance")
    elif args.require_dataset:
        failures.append("case-dataset.sqlite3 is missing")
    if args.require_dataset and dataset_count < args.minimum_cases:
        failures.append(f"dataset has {dataset_count} cases, requires {args.minimum_cases}")

    advisory_database = (
        args.advisory_database.resolve()
        if args.advisory_database
        else ROOT / "references" / "cases" / "advisory-dataset.sqlite3"
    )
    advisory_count = 0
    if advisory_database.is_file():
        connection = sqlite3.connect(advisory_database)
        try:
            advisory_count = int(connection.execute("SELECT count(*) FROM advisories").fetchone()[0])
            advisory_fts_count = int(connection.execute("SELECT count(*) FROM advisories_fts").fetchone()[0])
            advisory_integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            advisory_distinct = int(connection.execute("SELECT count(DISTINCT advisory_id) FROM advisories").fetchone()[0])
            advisory_metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            advisory_invalid_ids = int(
                connection.execute("SELECT count(*) FROM advisories WHERE advisory_id NOT GLOB 'GHSA-????-????-????'").fetchone()[0]
            )
            advisory_invalid_hashes = int(
                connection.execute("SELECT count(*) FROM advisories WHERE length(source_sha256) != 64").fetchone()[0]
            )
            advisory_empty_packages = int(
                connection.execute("SELECT count(*) FROM advisories WHERE trim(packages) = ''").fetchone()[0]
            )
        finally:
            connection.close()
        if advisory_count != advisory_fts_count:
            failures.append(f"advisory/FTS count mismatch: {advisory_count} != {advisory_fts_count}")
        if advisory_integrity != "ok":
            failures.append(f"advisory SQLite integrity check failed: {advisory_integrity}")
        if advisory_distinct != advisory_count:
            failures.append(f"duplicate advisory IDs: distinct={advisory_distinct} total={advisory_count}")
        if advisory_invalid_ids:
            failures.append(f"advisory dataset has {advisory_invalid_ids} malformed GHSA IDs")
        if advisory_invalid_hashes:
            failures.append(f"advisory dataset has {advisory_invalid_hashes} malformed source hashes")
        if advisory_empty_packages:
            failures.append(f"advisory dataset has {advisory_empty_packages} empty package names")
        if advisory_metadata.get("schema_version") != "1":
            failures.append(f"advisory schema is {advisory_metadata.get('schema_version')!r}, expected '1'")
        if advisory_metadata.get("source_license") != "CC-BY-4.0":
            failures.append("advisory dataset license provenance is missing")
        if advisory_metadata.get("source_revision") in {None, "", "unknown"}:
            failures.append("advisory dataset source revision is missing")
        source_archive_hash = advisory_metadata.get("source_sha256", "")
        if len(source_archive_hash) != 64 or any(char not in "0123456789abcdef" for char in source_archive_hash.lower()):
            failures.append("advisory dataset source archive hash is missing or malformed")

        ranking_fixture = {
            "component": "Django debug toolbar SQL panel",
            "entry_point": "raw_sql explain form",
            "source_sink": "form input to database SQL execution",
            "primitive": "SQL injection",
            "impact": "database confidentiality and integrity",
            "boundary": "unauthenticated web request to database",
            "fix_invariant": "never execute attacker-controlled SQL",
        }
        advisory_leads = advisory_matches(advisory_database, ranking_fixture, 10)
        if not advisory_leads or advisory_leads[0]["advisory_id"] != "GHSA-pghf-347x-c2gj":
            actual = advisory_leads[0]["advisory_id"] if advisory_leads else "none"
            failures.append(f"advisory ranking regression: top lead is {actual}")
    elif args.require_dataset:
        failures.append("advisory-dataset.sqlite3 is missing")
    if args.require_dataset and advisory_count < args.minimum_advisories:
        failures.append(f"advisory dataset has {advisory_count} cases, requires {args.minimum_advisories}")

    assessment_fixture = ROOT / "evals" / "fixtures" / "reportable-bundle" / "finding-record.json"
    assessment_record = json.loads(assessment_fixture.read_text(encoding="utf-8"))
    reportable_assessment = assess(assessment_record, assessment_fixture, "2026-08-02T15:00:00+00:00")
    if (
        reportable_assessment["verdict"] != "reportable"
        or reportable_assessment["scores"]["validation_confidence"] != 100
        or reportable_assessment["scores"]["evidence_quality"] != 100
        or reportable_assessment["continue_investigation"] is not False
        or reportable_assessment["continuation"]["continue_work"] is not True
        or reportable_assessment["continuation"]["mode"] != "reporting-then-resume-sweep"
    ):
        failures.append("reportable assessment fixture does not produce a calibrated terminal 100 score")

    candidate_assessment_record = deepcopy(assessment_record)
    for gate in ("B1", "P1", "C1", "R1", "I1", "E1", "S1", "V1", "F1", "J1", "D1", "Q1"):
        candidate_assessment_record["gates"][gate] = {"status": "pending", "evidence": [], "reason": ""}
    candidate_assessment_record["runs"] = []
    candidate_assessment = assess(candidate_assessment_record, assessment_fixture, "2026-08-02T15:00:00+00:00")
    if (
        candidate_assessment["verdict"] != "candidate"
        or candidate_assessment["scores"]["validation_confidence"] > 39
        or candidate_assessment["next_gate"] != "B1"
        or candidate_assessment["continue_investigation"] is not True
        or candidate_assessment["continuation"]["continue_technical_testing"] is not True
        or candidate_assessment["severity"]["status"] != "defer"
    ):
        failures.append("candidate assessment does not enforce its score cap and next-gate recommendation")

    substantiated_record = deepcopy(assessment_record)
    for gate in ("R1", "I1", "E1", "S1", "V1", "F1", "J1", "D1", "Q1"):
        substantiated_record["gates"][gate] = {"status": "pending", "evidence": [], "reason": ""}
    substantiated_record["runs"] = []
    substantiated_assessment = assess(substantiated_record, assessment_fixture, "2026-08-02T15:00:00+00:00")
    if (
        substantiated_assessment["verdict"] != "substantiated"
        or substantiated_assessment["scores"]["validation_confidence"] > 69
        or substantiated_assessment["next_gate"] != "R1"
        or substantiated_assessment["scores"]["false_positive_risk"] != "medium"
    ):
        failures.append("substantiated assessment does not enforce its score cap and R1 recommendation")

    verified_record = deepcopy(assessment_record)
    for gate in ("S1", "V1", "F1", "J1", "D1", "Q1"):
        verified_record["gates"][gate] = {"status": "pending", "evidence": [], "reason": ""}
    verified_assessment = assess(verified_record, assessment_fixture, "2026-08-02T15:00:00+00:00")
    if (
        verified_assessment["verdict"] != "verified"
        or verified_assessment["scores"]["validation_confidence"] > 89
        or verified_assessment["next_gate"] != "S1"
        or verified_assessment["continuation"]["continue_technical_testing"] is not False
        or verified_assessment["severity"]["status"] != "ready-for-scoring"
    ):
        failures.append("verified assessment does not stop escalation and enforce its score cap")

    blocked_assessment_record = deepcopy(candidate_assessment_record)
    blocked_assessment_record["work_mode"] = "unclear"
    blocked_assessment_record["gates"]["A0"] = {"status": "pending", "evidence": [], "reason": ""}
    blocked_assessment = assess(blocked_assessment_record, assessment_fixture, "2026-08-02T15:00:00+00:00")
    if (
        blocked_assessment["verdict"] != "blocked"
        or blocked_assessment["scores"]["validation_confidence"] > 15
        or blocked_assessment["continue_investigation"] is not False
        or blocked_assessment["continuation"]["continue_work"] is not True
        or blocked_assessment["continuation"]["continue_technical_testing"] is not False
    ):
        failures.append("blocked assessment does not stop active continuation and cap its score")

    repeated_evidence_record = deepcopy(assessment_record)
    repeated_evidence_record["runs"][1]["evidence"] = ["E-001"]
    repeated_assessment = assess(repeated_evidence_record, assessment_fixture, "2026-08-02T15:00:00+00:00")
    if (
        repeated_assessment["verdict"] != "invalid-record"
        or repeated_assessment["scores"]["validation_confidence"] > 29
        or not any("reuse the same evidence set" in error for error in repeated_assessment["errors"])
    ):
        failures.append("repeat-independence assessment accepts two runs backed by the same artifact")

    repeated_control_record = deepcopy(assessment_record)
    repeated_control_record["gates"]["C1"]["evidence"] = ["E-001"]
    repeated_control_assessment = assess(repeated_control_record, assessment_fixture, "2026-08-02T15:00:00+00:00")
    if (
        repeated_control_assessment["verdict"] != "invalid-record"
        or repeated_control_assessment["scores"]["validation_confidence"] > 29
        or not any("control evidence distinct" in error for error in repeated_control_assessment["errors"])
    ):
        failures.append("control-independence assessment accepts a control backed only by proof evidence")

    bad_severity_record = deepcopy(assessment_record)
    bad_severity_record["severity"] = {
        "rating": "HIGH",
        "cvss_version": "4.0",
        "vector": "",
        "score": 11,
        "rationale": "",
        "evidence": [],
    }
    bad_severity_errors, _ = validate(bad_severity_record, assessment_fixture)
    if (
        not any("severity lacks a rationale" in error for error in bad_severity_errors)
        or not any("severity requires evidence references" in error for error in bad_severity_errors)
        or not any("severity score must be between 0 and 10" in error for error in bad_severity_errors)
    ):
        failures.append("severity validation accepts an unsupported or out-of-range score")

    from outcome_ledger import KNOWN_SIGNALS, import_outcomes, load_ledger, save_ledger, search_outcomes, stats_outcomes

    import io

    ledger_path = ROOT / "outcome-ledger.eval.json"
    ledger = load_ledger(ledger_path)
    ledger["outcomes"] = [
        {
            "schema_version": 1,
            "id": "eval-1",
            "platform": "bugcrowd",
            "program": "eval-program",
            "target": "api.example.test",
            "vulnerability_class": "idor",
            "finding_title": "eval IDOR",
            "verdict": "accepted",
            "severity": "HIGH",
            "vendor_reason": "confirmed",
            "signals": [],
            "submitted_at_utc": "2026-08-01T00:00:00Z",
            "recorded_at_utc": "2026-08-01T00:00:00Z",
            "notes": "",
        },
        {
            "schema_version": 1,
            "id": "eval-2",
            "platform": "bugcrowd",
            "program": "eval-program",
            "target": "api.example.test",
            "vulnerability_class": "ato",
            "finding_title": "eval ATO",
            "verdict": "informative",
            "severity": "",
            "vendor_reason": "working as designed",
            "signals": ["working-as-designed"],
            "submitted_at_utc": "2026-08-02T00:00:00Z",
            "recorded_at_utc": "2026-08-02T00:00:00Z",
            "notes": "",
        },
    ]
    save_ledger(ledger_path, ledger)
    ledger = load_ledger(ledger_path)
    if len(ledger["outcomes"]) != 2:
        failures.append("outcome ledger roundtrip lost entries")
    ato_search_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        search_outcomes(
            argparse.Namespace(ledger=ledger_path, platform=None, program=None, class_name="ato", verdict=None, signal=None, query=None)
        )
        ato_search_text = sys.stdout.getvalue()
    finally:
        sys.stdout = ato_search_stdout
    if "eval-2" not in ato_search_text:
        failures.append("outcome ledger search by class did not return the ATO match")

    stats_parser = argparse.Namespace(ledger=ledger_path)
    stats_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        stats_outcomes(stats_parser)
        stats_text = sys.stdout.getvalue()
    finally:
        sys.stdout = stats_stdout
    stats_data = json.loads(stats_text)
    if stats_data["by_program"]["eval-program"]["acceptance_rate"] != 0.5:
        failures.append("outcome ledger stats acceptance rate is incorrect")
    if stats_data["by_class"]["ato"]["acceptance_rate"] != 0.0:
        failures.append("outcome ledger stats does not expose low-acceptance classes as T0 prior art")

    integer_id = 7
    ledger["outcomes"].append({"id": integer_id})
    save_ledger(ledger_path, ledger)
    import_path = ROOT / "outcome-import.eval.json"
    import_path.write_text(json.dumps([{"id": integer_id, "platform": "eval", "program": "eval"}]), encoding="utf-8")
    import_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        import_outcomes(argparse.Namespace(ledger=ledger_path, file=import_path))
    finally:
        sys.stdout = import_stdout
    imported_ledger = load_ledger(ledger_path)
    if sum(1 for item in imported_ledger["outcomes"] if str(item.get("id")) == str(integer_id)) != 1:
        failures.append("outcome ledger import duplicates an existing numeric report id")
    import_path.unlink(missing_ok=True)
    ledger_path.unlink(missing_ok=True)

    from owner_matrix import validate_matrix as validate_owner_matrix

    valid_matrix = {
        "schema_version": 1,
        "kind": "mask0ff-owner-matrix",
        "attacker_account": "attacker-eval",
        "victim_account": "victim-eval",
        "entries": [
            {
                "object_id": "obj-1",
                "created_by_request": "POST /api/objects (victim-eval)",
                "created_by_account": "victim-eval",
                "owner_account": "victim-eval",
                "expected_allowed_accounts": ["victim-eval"],
                "tested_account": "attacker-eval",
                "observed_access": "granted",
                "evidence": ["E-001"],
            }
        ],
    }
    matrix_errors, matrix_warnings, matrix_signals = validate_owner_matrix(valid_matrix)
    if matrix_errors or not matrix_signals:
        failures.append(f"owner matrix rejects a valid cross-account grant: {matrix_errors}")
    case_normalized = deepcopy(valid_matrix)
    case_normalized["entries"][0]["expected_allowed_accounts"] = ["ATTACKER-EVAL"]
    case_normalized["entries"][0]["tested_account"] = "attacker-eval"
    _case_errors, _case_warnings, case_signals = validate_owner_matrix(case_normalized)
    if case_signals:
        failures.append("owner matrix treats account-name casing as an authorization boundary")
    self_owned = deepcopy(valid_matrix)
    self_owned["entries"][0]["tested_account"] = "victim-eval"
    self_owned_errors, self_owned_warnings, _signals = validate_owner_matrix(self_owned)
    if not any("accessing an object you own is not broken access control" in warning for warning in self_owned_warnings):
        failures.append("owner matrix does not warn on self-owned object access")
    same_principal_matrix = deepcopy(valid_matrix)
    same_principal_matrix["victim_account"] = "attacker-eval"
    sp_errors, _sp_warnings, _signals = validate_owner_matrix(same_principal_matrix)
    if not any("must be distinct principals" in error for error in sp_errors):
        failures.append("owner matrix accepts identical attacker and victim accounts")

    from report_lint import FORBIDDEN_ATTACKER_PREREQUISITES

    tools_in_steps = (
        "## Steps to Reproduce\n1. Install the test harness and adb\n2. Run the PoC through mitmproxy\n"
        "3. Observe root access granted\n## Impact\nFull compromise"
    )
    if not any(pattern.search(tools_in_steps) for pattern in FORBIDDEN_ATTACKER_PREREQUISITES):
        failures.append("report-lint prerequisite detector missed adb/mitm/root access in reproduction steps")
    clean_steps = "## Steps to Reproduce\n1. Login as attacker account\n2. GET /api/objects/123\n3. Observe the victim-owned object in the response\n## Impact\nCross-account read"
    if any(pattern.search(clean_steps) for pattern in FORBIDDEN_ATTACKER_PREREQUISITES):
        failures.append("report-lint prerequisite detector false-positives on a realistic attacker reproduction")

    result = {
        "state_scenarios": len(scenarios),
        "agent_scenarios": len(json.loads((ROOT / "evals" / "agent-scenarios.json").read_text(encoding="utf-8"))["scenarios"]),
        "exact_analogy_score": exact_score,
        "unrelated_analogy_score": unrelated_score,
        "dataset_count": dataset_count,
        "advisory_count": advisory_count,
        "assessment_scenarios": 8,
        "dynamic_profile_scenarios": 11,
        "current_technique_count": len(current_techniques),
        "race_workflow_scenarios": 12,
        "database_integrity": "ok" if database.is_file() and not any("SQLite integrity" in item for item in failures) else "failed-or-missing",
        "advisory_database_integrity": "ok" if advisory_database.is_file() and not any("advisory SQLite integrity" in item for item in failures) else "failed-or-missing",
        "failures": failures,
    }
    print(json.dumps(result, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
