#!/usr/bin/env python3
"""Score a candidate by ZDE-style semantic-route priority: weird-surface score + evidence confidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from duplicate_check import DEFAULT_CASES, compare, tokens  # noqa: E402

SEMANTIC_ROLES = {
    "RAW_DATA": ["raw", "input", "body", "parameter", "request", "query string"],
    "STORED_DATA": ["database", "db ", "stored", "persist", "cache", "queue", "message", "stream", "record", "row", "collection"],
    "METADATA": ["metadata", "filename", "branch", "title", "label", "name field", "header", "tag", "attribute", "property"],
    "PATH_COMPONENT": ["path", "directory", "file name", "filename", "url path", "route"],
    "FILESYSTEM_OBJECT": ["file", "upload", "attachment", "artifact", "archive", "zip", "tar"],
    "TEMPLATE_DATA": ["template", "render", "markdown", "html", "jinja", "handlebars"],
    "EXPRESSION": ["expression", "spel", "eval", "grok", "regex", "formula"],
    "CONFIGURATION": ["config", "yaml", "json", "toml", "ini", "setting", "flag", "env var", "environment variable"],
    "GENERATED_CONFIGURATION": ["generated", "synthesized", "auto-generated", "provisioned", "baked"],
    "COMMAND_ARGUMENT": ["command", "shell", "argument", "arg", "parameter to", "exec"],
    "MODULE_IDENTIFIER": ["module", "import", "plugin", "class name", "type name", "loader", "reflect"],
    "WORKFLOW_INSTRUCTION": ["workflow", "ci", "action", "pipeline", "job step", "script step"],
    "TOOL_ARGUMENT": ["tool", "function call", "mcp", "agent", "api call"],
    "BUILD_INSTRUCTION": ["build", "dockerfile", "makefile", "compile", "package"],
    "AUTHORIZATION_INPUT": ["permission", "role", "tenant", "acl", "allowlist", "policy"],
}

WSS_WEIGHTS = {
    "C": 0.18,
    "M": 0.15,
    "X": 0.12,
    "P": 0.11,
    "G": 0.10,
    "D": 0.10,
    "I": 0.08,
    "A": 0.07,
    "F": 0.05,
    "N": 0.04,
}

PRIVILEGE_WORDS = ["privileged", "admin", "root", "worker", "runner", "service account", "internal", "server-side", "background", "cron"]
DEFERRED_WORDS = ["async", "asynchronous", "queue", "worker", "job", "scheduled", "cron", "deferred", "eventual", "webhook", "retry", "second-order", "stored"]
INTERPRETER_WORDS = ["template", "eval", "exec", "shell", "expression", "loader", "class resolution", "instantiate", "interpreter", "renderer", "spel", "ssti", "rce"]
FALLBACK_WORDS = ["fallback", "default", "unknown type", "auto-detect", "autodetect", "legacy", "compat", "retry", "error handler", "recovery", "migration"]
LOW_ATTENTION_WORDS = ["scripts", "tools", "build", "packaging", "release", "migration", "converter", "adapter", "legacy", "compat", "import", "export", "backup", "restore", "sanitizer", "preview", "thumbnail", "generator"]
GRAMMAR_WORDS = ["grammar", "parser", "parse", "encoding", "decode", "escape", "quoting", "validator", "format", "serialize", "deserialize", "delimiter", "charset", "canonical"]
AUTH_BOUNDARY_WORDS = ["unauthenticated", "anonymous", "no auth", "missing auth", "wrong role", "wrong tenant", "any user", "attacker-controlled"]

NOVELTY_EXEMPT = {"eval", "exec", "shell", "rce", "sqli", "xss", "ssrf", "injection"}
EVIDENCE_GATES = ("A1", "T1", "H1", "B1", "P1", "C1", "R1", "E1", "X1", "I1", "V1", "J1", "D1")


def role_matches(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    return [keyword for keyword in keywords if keyword in lowered]


def detected_transitions(text: str) -> list[dict[str, str]]:
    hits: dict[str, list[str]] = {}
    for role, keywords in SEMANTIC_ROLES.items():
        matched = role_matches(text, keywords)
        if matched:
            hits[role] = matched
    transitions = []
    for source_role in ("RAW_DATA", "STORED_DATA", "METADATA", "PATH_COMPONENT", "FILESYSTEM_OBJECT"):
        if source_role not in hits:
            continue
        for target_role in (
            "TEMPLATE_DATA",
            "EXPRESSION",
            "CONFIGURATION",
            "GENERATED_CONFIGURATION",
            "COMMAND_ARGUMENT",
            "MODULE_IDENTIFIER",
            "WORKFLOW_INSTRUCTION",
            "TOOL_ARGUMENT",
            "BUILD_INSTRUCTION",
        ):
            if target_role in hits and target_role != source_role:
                transitions.append({"from": source_role, "to": target_role, "keywords": hits[target_role][:2]})
    return transitions


def factor(text: str, words: list[str]) -> float:
    lowered = text.lower()
    return 1.0 if any(word in lowered for word in words) else 0.0


def weird_surface_score(text: str) -> tuple[float, dict[str, float]]:
    lowered = text.lower()
    scores = {
        "C": 1.0 if any(word in lowered for word in AUTH_BOUNDARY_WORDS) or "attacker" in lowered else 0.6,
        "M": 1.0 if detected_transitions(text) else 0.0,
        "X": 0.7 if any(word in lowered for word in ("store", "persist", "save", "write", "insert")) else 0.0,
        "P": factor(text, PRIVILEGE_WORDS),
        "G": factor(text, GRAMMAR_WORDS),
        "D": factor(text, DEFERRED_WORDS),
        "I": factor(text, INTERPRETER_WORDS),
        "A": factor(text, LOW_ATTENTION_WORDS),
        "F": factor(text, FALLBACK_WORDS),
        "N": 0.5,
    }
    weighted = sum(WSS_WEIGHTS[key] * scores[key] for key in WSS_WEIGHTS)
    return round(100 * weighted, 1), scores


def novelty(candidate: dict[str, Any], cases_path: Path) -> tuple[float, str]:
    cases = json.loads(cases_path.read_text(encoding="utf-8-sig"))["cases"]
    candidate_text = " ".join(
        str(candidate.get(field, "")) for field in ("component", "entry_point", "source_sink", "primitive", "impact")
    ).lower()
    candidate_tokens = {t for t in tokens(candidate_text) if t not in NOVELTY_EXEMPT}
    if not candidate_tokens:
        return 0.0, "no-comparable-corpus"
    best = 0.0
    best_id = ""
    for case in cases:
        case_text = " ".join(
            str(case.get(field, "")) for field in ("title", "summary", "component", "primitive", "impact")
        )
        overlap = len(candidate_tokens & tokens(case_text)) / len(candidate_tokens | tokens(case_text))
        if overlap > best:
            best = overlap
            best_id = str(case.get("id", ""))
    return round(1.0 - best, 3), best_id


def evidence_confidence(record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {"confidence": 0.0, "basis": "no-finding-record"}
    gates = record.get("gates", {}) if isinstance(record.get("gates"), dict) else {}
    passed = [gate for gate in EVIDENCE_GATES if isinstance(gates.get(gate), dict) and gates[gate].get("status") == "pass"]
    missing = [gate for gate in EVIDENCE_GATES if gate not in passed]
    fraction = len(passed) / len(EVIDENCE_GATES)
    return {
        "confidence": round(fraction, 3),
        "basis": "finding-record-gates",
        "passed": passed,
        "missing": missing,
    }


def run(candidate: dict[str, Any], record: dict[str, Any] | None, cases_path: Path) -> dict[str, Any]:
    text = json.dumps(candidate, ensure_ascii=False)
    transitions = detected_transitions(text)
    wss, factors = weird_surface_score(text)
    novelty_value, nearest = novelty(candidate, cases_path)
    ec = evidence_confidence(record)
    factors["N"] = novelty_value
    weighted = sum(WSS_WEIGHTS[key] * factors[key] for key in WSS_WEIGHTS)
    wss = round(100 * weighted, 1)
    final_priority = round(wss * ec["confidence"], 1)
    return {
        "schema_version": 1,
        "weird_surface_score": wss,
        "evidence_confidence": ec,
        "final_priority": final_priority,
        "factors": {key: round(value, 3) for key, value in factors.items()},
        "semantic_transitions": transitions,
        "novelty": {"value": novelty_value, "nearest_case": nearest},
        "interpretation": {
            "wss": "search priority, not severity",
            "priority": "final_priority ranks candidates; evidence outranks model confidence",
            "high_value_route": bool(transitions and factors["I"]),
        },
        "route_summary": (
            "Unexpected route to an old primitive: "
            + " -> ".join(f"{t['from']}->{t['to']}" for t in transitions[:3])
            if transitions
            else "no explicit semantic transition detected"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a candidate by ZDE-style weird-surface and evidence priority.")
    parser.add_argument("--candidate", type=Path, help="JSON object with fingerprint fields (component, entry_point, source_sink, primitive, impact, boundary)")
    parser.add_argument("--finding", type=Path, help="Finding-record JSON to derive evidence confidence")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        candidate: dict[str, Any] = {}
        record: dict[str, Any] | None = None
        if args.candidate:
            value = json.loads(args.candidate.read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict):
                raise ValueError("candidate JSON must be an object")
            candidate_value = value.get("fingerprint", value)
            if not isinstance(candidate_value, dict):
                raise ValueError("candidate fingerprint must be an object")
            candidate = candidate_value
        if args.finding:
            value = json.loads(args.finding.read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict):
                raise ValueError("finding record must be an object")
            record = value
            candidate_value = value.get("fingerprint", {})
            if not isinstance(candidate_value, dict):
                raise ValueError("finding fingerprint must be an object")
            candidate = candidate_value
        if not candidate:
            parser.error("a --candidate or --finding with a non-empty fingerprint is required")
        result = run(candidate, record, args.cases)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
