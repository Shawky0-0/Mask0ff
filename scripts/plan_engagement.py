#!/usr/bin/env python3
"""Build a mode-aware research plan from scope and secret-free session profiles."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from program_profile import validate_profile
from session_profile import validate_session


MODE_LANES: dict[str, list[dict[str, Any]]] = {
    "black-box": [
        {"id": "surface-map", "priority": 1, "goal": "Map only in-scope hosts, APIs, clients, roles, objects, and state transitions from observable behavior."},
        {"id": "baseline-differential", "priority": 2, "goal": "Capture unauthenticated and authenticated baselines, then change one variable at a time."},
        {"id": "authorization-matrix", "priority": 3, "goal": "Compare researcher-owned roles, tenants, and objects for horizontal and vertical boundary failures."},
        {"id": "workflow-integrity", "priority": 4, "goal": "Model multi-step business invariants, replay boundaries, and safe concurrency hypotheses."},
        {"id": "protocol-client", "priority": 5, "goal": "Inspect browser, API, cache, proxy, and protocol interpretation boundaries relevant to observed signals."},
    ],
    "gray-box": [
        {"id": "artifact-guided-map", "priority": 1, "goal": "Use supplied schemas, documentation, traffic, and test accounts to map reachable trust boundaries."},
        {"id": "role-object-differential", "priority": 2, "goal": "Compare owned roles, tenants, and object ownership with clean sessions and synthetic canaries."},
        {"id": "schema-implementation-gap", "priority": 3, "goal": "Test differences between documented contracts and observed validation, authorization, and error behavior."},
        {"id": "workflow-integrity", "priority": 4, "goal": "Trace business invariants across API, UI, asynchronous jobs, and integrations."},
        {"id": "local-or-staging-control", "priority": 5, "goal": "Prefer staging or local controls when production proof would exceed minimum-safe evidence."},
    ],
    "white-box": [
        {"id": "architecture-trust-map", "priority": 1, "goal": "Identify entry points, identities, policy checks, data stores, queues, integrations, and trust-boundary transitions."},
        {"id": "source-dataflow", "priority": 2, "goal": "Trace controlled sources through transforms and guards to security-sensitive sinks."},
        {"id": "variant-analysis", "priority": 3, "goal": "Search sibling call sites and incomplete-fix variants using the root-cause invariant, not only the original payload."},
        {"id": "test-first-reproduction", "priority": 4, "goal": "Create a focused local regression test or harness before any production validation."},
        {"id": "patch-differential", "priority": 5, "goal": "Confirm the fix invariant with vulnerable/patched or guard-present/guard-absent controls."},
    ],
}

SURFACE_HINTS = {
    "web": ["browser/server parsing differences", "session and authorization boundaries", "cache and proxy behavior"],
    "api": ["object/function/property authorization", "inventory drift", "unsafe downstream API consumption"],
    "graphql": ["field-level authorization", "resolver batching and aliases", "schema/documentation gaps"],
    "websocket": ["handshake/session binding", "message-level authorization", "cross-channel state confusion"],
    "mobile": ["backend API trust", "deep-link and WebView boundaries", "local secret and certificate assumptions"],
    "desktop": ["custom protocol and update boundaries", "local IPC and file handling", "embedded browser and backend API trust"],
    "browser-extension": ["message sender validation", "host permissions and content-script boundaries", "native messaging and update integrity"],
    "cloud": ["identity and tenant boundaries", "metadata and callback controls", "configuration and supply-chain paths"],
    "grpc": ["method-level authorization", "metadata and reflection exposure", "protobuf presence/default interpretation"],
    "sse": ["stream authorization and reconnect state", "event data separation", "cache and proxy handling"],
    "webhook": ["signature and replay controls", "redirect and SSRF boundaries", "event ordering and tenant binding"],
    "soap": ["WSDL and generated-client trust", "XML parser controls", "proxy and endpoint override behavior"],
    "ci-cd": ["workflow identity and permissions", "untrusted build inputs", "artifact provenance and deployment mapping"],
    "source": ["dataflow", "variant analysis", "dependency and build integrity"],
    "ai-agent": ["tool authorization", "prompt/data trust separation", "approval and consequential-field visibility"],
}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def merged_lanes(mode: str) -> list[dict[str, Any]]:
    if mode != "hybrid":
        return [dict(item) for item in MODE_LANES[mode]]
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for current_mode in ("black-box", "gray-box", "white-box"):
        for item in MODE_LANES[current_mode]:
            if item["id"] in seen:
                continue
            seen.add(item["id"])
            copy = dict(item)
            copy["priority"] = len(output) + 1
            output.append(copy)
    return output


def build_plan(args: argparse.Namespace) -> int:
    profile_path = args.profile.resolve()
    profile = load_object(profile_path)
    profile_errors, profile_warnings = validate_profile(profile, target=args.target)
    if profile_errors:
        raise ValueError("; ".join(profile_errors))
    sessions: list[dict[str, Any]] = []
    session_warnings: list[str] = []
    for session_path in args.session or []:
        session = load_object(session_path.resolve())
        errors, warnings, _availability = validate_session(session)
        if errors:
            raise ValueError(f"{session_path}: {'; '.join(errors)}")
        sessions.append(
            {
                "label": session.get("label"),
                "role": session.get("role"),
                "tenant": session.get("tenant"),
                "auth_type": session.get("auth_type"),
                "credential_reference_names": sorted(session.get("credential_references", {}).keys()),
            }
        )
        session_warnings.extend(warnings)
    assessment_mode = profile["assessment_mode"]
    lanes = merged_lanes(assessment_mode)
    if args.signal:
        for lane in lanes:
            lane["signal"] = args.signal
    surfaces = args.surface or []
    plan = {
        "schema_version": 1,
        "program_or_owner": profile["program_or_owner"],
        "platform": profile["platform"],
        "work_mode": profile["work_mode"],
        "assessment_mode": assessment_mode,
        "target": args.target,
        "target_in_scope": True if args.target else None,
        "scope_count": len(profile.get("scope", [])),
        "access": {
            "authenticated_sessions": len(sessions),
            "sessions": sessions,
            "secret_material_in_plan": False,
        },
        "surfaces": [
            {"name": surface, "focus": SURFACE_HINTS.get(surface, ["map observed trust boundaries before selecting tests"])}
            for surface in surfaces
        ],
        "lanes": lanes,
        "dynamic_recommendations": [],
        "evidence_requirements": [
            "preserve an unmodified baseline",
            "use researcher-owned accounts or synthetic data",
            "run negative and intended-behavior controls",
            "repeat in a clean state with distinct evidence",
            "assess after each material gate or evidence change",
        ],
        "warnings": profile_warnings + session_warnings,
    }
    recommendations = plan["dynamic_recommendations"]
    if not sessions and assessment_mode in {"black-box", "gray-box", "hybrid"}:
        recommendations.append("Start with the unauthenticated baseline. If registration or login is required, accept user-supplied researcher credentials through a secret-free session profile or an already signed-in browser session.")
    if len(sessions) == 1:
        recommendations.append("Add a second researcher-owned role, tenant, or object owner when authorization or workflow differentials are relevant.")
    if len({(str(item.get('role')), str(item.get('tenant'))) for item in sessions}) >= 2:
        recommendations.append("Prioritize role/tenant/object matrices because distinct controlled principals are available.")
    if assessment_mode in {"white-box", "hybrid"}:
        recommendations.append("Record repository revision, build command, test command, reachable deployment version, and source-to-runtime mapping before claiming affected production code.")
    if args.signal:
        recommendations.append("Turn the supplied signal into one falsifiable hypothesis; do not spray unrelated technique families.")
    if args.output:
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temporary.replace(output)
    print(json.dumps(plan, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a black-, gray-, white-, or hybrid-box engagement plan.")
    parser.add_argument("profile", type=Path)
    parser.add_argument("--session", type=Path, action="append")
    parser.add_argument("--target")
    parser.add_argument("--surface", choices=sorted(SURFACE_HINTS), action="append")
    parser.add_argument("--signal")
    parser.add_argument("--output", type=Path)
    return parser


def main() -> int:
    try:
        return build_plan(build_parser().parse_args())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
