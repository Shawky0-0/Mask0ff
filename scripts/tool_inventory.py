#!/usr/bin/env python3
"""Inventory research tools and build a capability-led engagement pipeline."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
from collections.abc import Callable
from typing import Any


TOOL_GROUPS: dict[str, dict[str, Any]] = {
    "workspace": {
        "purpose": "Normalize, search, transform, deduplicate, and preserve evidence.",
        "binaries": ["rg", "jq", "yq", "python3", "python", "git"],
        "interaction": "local",
    },
    "passive-discovery": {
        "purpose": "Collect passive DNS, certificate, archive, and public asset leads.",
        "binaries": ["subfinder", "amass", "assetfinder", "findomain", "gau", "waybackurls"],
        "interaction": "passive-or-low-impact",
    },
    "dns-and-service-mapping": {
        "purpose": "Resolve controlled host lists and identify reachable services.",
        "binaries": ["dnsx", "massdns", "dig", "host", "httpx", "naabu", "nmap"],
        "interaction": "active-authorized",
    },
    "endpoint-discovery": {
        "purpose": "Crawl applications, JavaScript, archives, and content paths into endpoint candidates.",
        "binaries": ["katana", "hakrawler", "gospider", "feroxbuster", "ffuf", "dirsearch"],
        "interaction": "active-authorized",
    },
    "request-fuzzing": {
        "purpose": "Mutate one bounded request dimension and preserve structured response differentials.",
        "binaries": ["ffuf", "wfuzz", "radamsa", "arjun", "boofuzz"],
        "interaction": "active-authorized-rate-limited",
    },
    "scanner-leads": {
        "purpose": "Generate versioned template or rule matches that remain unverified leads.",
        "binaries": ["nuclei", "nikto", "dalfox", "sqlmap"],
        "interaction": "active-authorized-lead-only",
    },
    "browser-and-proxy": {
        "purpose": "Capture authenticated flows, browser execution, DOM behavior, and transport differences.",
        "binaries": ["mitmproxy", "mitmdump", "zap.sh", "chromium", "google-chrome", "playwright"],
        "interaction": "controlled-session",
    },
    "api-protocols": {
        "purpose": "Inspect structured APIs and alternate transports without flattening protocol semantics.",
        "binaries": ["curl", "jq", "grpcurl", "websocat", "wscat", "openssl"],
        "interaction": "active-authorized",
    },
    "source-analysis": {
        "purpose": "Search sources and sinks, run rule/dataflow analysis, and inspect dependency reachability.",
        "binaries": ["rg", "semgrep", "codeql", "trivy", "syft", "osv-scanner"],
        "interaction": "local-or-repository",
    },
    "runtime-lab": {
        "purpose": "Observe process, filesystem, network, and container behavior in an owned environment.",
        "binaries": ["strace", "ltrace", "tcpdump", "docker", "podman", "gdb", "rr"],
        "interaction": "local-lab",
    },
    "race-delivery": {
        "purpose": "Deliver bounded synchronized request groups and correlate them with authoritative state.",
        "binaries": [
            "burpsuite", "BurpSuiteCommunity", "turbo-intruder", "raceocat", "h2spacex",
            "python3", "python", "go", "curl",
        ],
        "interaction": "local-lab-or-explicitly-authorized-bounded",
    },
    "cloud-and-infrastructure": {
        "purpose": "Map identities, configuration, deployment boundaries, and cloud-native resources.",
        "binaries": ["aws", "az", "gcloud", "kubectl", "helm", "terraform", "trivy", "nmap"],
        "interaction": "authorized-account-or-local",
    },
    "web3": {
        "purpose": "Analyze contracts and protocol invariants with static, fuzz, invariant, and local-chain tools.",
        "binaries": ["slither", "echidna-test", "medusa", "forge", "cast", "anvil", "myth", "solana", "anchor"],
        "interaction": "local-lab-or-authorized-fork",
    },
}


STAGES: list[dict[str, Any]] = [
    {
        "id": "scope-normalization",
        "groups": ["workspace"],
        "purpose": "Convert scope, exclusions, rate limits, and supplied assets into a canonical allowlist before collection.",
        "output": ["asset", "asset_type", "scope_status", "source", "captured_at"],
    },
    {
        "id": "passive-enumeration",
        "groups": ["passive-discovery"],
        "purpose": "Collect passive leads, retain provenance, and deduplicate without assuming ownership or reachability.",
        "output": ["hostname_or_url", "source", "first_seen", "scope_status"],
    },
    {
        "id": "resolution-and-service-map",
        "groups": ["dns-and-service-mapping"],
        "purpose": "Resolve only allowlisted candidates and correlate host, IP, port, protocol, certificate, and technology signals.",
        "output": ["host", "ip", "port", "protocol", "status", "technology", "scope_status"],
    },
    {
        "id": "endpoint-and-client-map",
        "groups": ["endpoint-discovery", "browser-and-proxy", "api-protocols"],
        "purpose": "Merge crawled paths, JavaScript references, schemas, archives, proxy traffic, and alternate transports.",
        "output": ["url", "method", "parameter", "content_type", "role", "source", "response_signature"],
    },
    {
        "id": "focused-fuzzing",
        "groups": ["request-fuzzing", "scanner-leads"],
        "purpose": "Fuzz one hypothesis-relevant dimension under explicit budgets; treat scanner matches as leads only.",
        "output": ["request_id", "mutation", "baseline_signature", "response_signature", "delta", "tool_version"],
    },
    {
        "id": "race-state-analysis",
        "groups": ["race-delivery", "api-protocols", "runtime-lab"],
        "purpose": "Model one state invariant, benchmark sequential behavior, select a protocol-correct synchronization primitive, and compare bounded attempts with authoritative final state.",
        "output": [
            "transition_id", "attempt_id", "lane_id", "actor", "object", "state_before_hash",
            "delivery_primitive", "negotiated_protocol", "monotonic_timing", "response_signature",
            "downstream_event", "state_after_hash", "invariant_result", "reset_evidence",
        ],
    },
    {
        "id": "source-and-dependency-analysis",
        "groups": ["source-analysis"],
        "purpose": "Trace reachable sources, transformations, guards, sinks, sibling call sites, versions, and fix invariants.",
        "output": ["revision", "entry_point", "source", "guard", "sink", "call_path", "variant", "test_id"],
    },
    {
        "id": "runtime-local-proof",
        "groups": ["runtime-lab"],
        "purpose": "Confirm a candidate in an owned lab with process-level evidence and minimum-safe markers.",
        "output": ["run_id", "revision", "environment", "input", "observed_effect", "artifact_hash"],
    },
    {
        "id": "infrastructure-correlation",
        "groups": ["cloud-and-infrastructure"],
        "purpose": "Relate external assets to identities, routes, workloads, secrets boundaries, and deployment configuration.",
        "output": ["resource", "identity", "tenant", "network_boundary", "configuration", "evidence"],
    },
    {
        "id": "web3-invariant-analysis",
        "groups": ["web3"],
        "purpose": "Combine static findings with stateful fuzzing, invariant tests, role analysis, and local/forked execution.",
        "output": ["chain", "contract", "function", "actor", "state_before", "state_after", "invariant", "trace"],
    },
]


WEB_SURFACES = {"web", "api", "graphql", "websocket", "mobile", "desktop", "browser-extension", "sse", "webhook", "soap"}
INFRA_SURFACES = {"cloud", "infrastructure", "kubernetes", "serverless", "ci-cd"}
WEB3_SURFACES = {"web3", "evm", "solana"}
FUZZ_FOCUS = {"rce", "remote code execution", "sql injection", "sqli", "xss", "ssrf", "deserialization", "race", "fuzz"}
RACE_FOCUS = {
    "race", "race condition", "toctou", "time-of-check", "time of check", "double spend",
    "double-spend", "idempotency", "concurrent", "concurrency", "atomicity", "limit overrun",
}


def inventory(which_func: Callable[[str], str | None] = shutil.which) -> dict[str, Any]:
    groups: dict[str, Any] = {}
    for group, definition in TOOL_GROUPS.items():
        available = []
        for binary in definition["binaries"]:
            path = which_func(binary)
            if path:
                available.append({"name": binary, "path": path})
        groups[group] = {
            "purpose": definition["purpose"],
            "interaction": definition["interaction"],
            "available": available,
            "missing_examples": [item for item in definition["binaries"] if item not in {tool["name"] for tool in available}],
        }
    return {
        "platform": platform.platform(),
        "groups": groups,
        "available_count": sum(len(group["available"]) for group in groups.values()),
    }


def relevant_stage_ids(assessment_mode: str, surfaces: list[str], focuses: list[str]) -> set[str]:
    surface_set = {item.lower() for item in surfaces}
    focus_text = " ".join(focuses).lower()
    selected = {"scope-normalization"}
    if assessment_mode in {"black-box", "gray-box", "hybrid"}:
        selected.add("passive-enumeration")
    if surface_set & (WEB_SURFACES | INFRA_SURFACES) or assessment_mode in {"black-box", "gray-box", "hybrid"}:
        selected.add("resolution-and-service-map")
    if surface_set & WEB_SURFACES:
        selected.add("endpoint-and-client-map")
    if any(token in focus_text for token in FUZZ_FOCUS) or surface_set & WEB_SURFACES:
        selected.add("focused-fuzzing")
    if any(token in focus_text for token in RACE_FOCUS):
        selected.add("race-state-analysis")
    if assessment_mode in {"white-box", "hybrid"} or "source" in surface_set:
        selected.update({"source-and-dependency-analysis", "runtime-local-proof"})
    if surface_set & INFRA_SURFACES:
        selected.add("infrastructure-correlation")
    if surface_set & WEB3_SURFACES or any(token in focus_text for token in ("web3", "smart contract", "blockchain", "defi")):
        selected.update({"source-and-dependency-analysis", "runtime-local-proof", "web3-invariant-analysis"})
    return selected


def build_strategy(
    assessment_mode: str,
    surfaces: list[str] | None = None,
    focuses: list[str] | None = None,
    scale: str = "adaptive",
    which_func: Callable[[str], str | None] = shutil.which,
) -> dict[str, Any]:
    surfaces = surfaces or []
    focuses = focuses or []
    detected = inventory(which_func)
    selected_ids = relevant_stage_ids(assessment_mode, surfaces, focuses)
    stages = []
    for stage in STAGES:
        if stage["id"] not in selected_ids:
            continue
        tool_groups = []
        for group_name in stage["groups"]:
            group = detected["groups"][group_name]
            tool_groups.append(
                {
                    "group": group_name,
                    "interaction": group["interaction"],
                    "available_tools": [item["name"] for item in group["available"]],
                    "fallback": "Use an equivalent installed tool or a small auditable local script; do not invent results.",
                }
            )
        stages.append({**stage, "tool_groups": tool_groups})
    strategy = {
        "schema_version": 1,
        "assessment_mode": assessment_mode,
        "surfaces": surfaces,
        "focuses": focuses,
        "scale": scale,
        "inventory": detected,
        "stages": stages,
        "correlation_keys": [
            "scope_status",
            "host",
            "ip",
            "port",
            "url",
            "method",
            "parameter",
            "protocol",
            "technology_and_version",
            "role_and_tenant",
            "object_and_state",
            "source_symbol",
            "run_id",
        ],
        "execution_rules": [
            "Filter every stage through the canonical scope allowlist and preserve provenance.",
            "Record exact command, configuration, tool version, timestamp, exit status, and raw output path.",
            "Prefer structured JSON, JSONL, CSV, or stable line output; normalize before joining datasets.",
            "Deduplicate before active probing and checkpoint large scopes so failed stages can resume safely.",
            "Honor program rate limits and concurrency limits; low impact does not mean unlimited volume.",
            "Treat scanner and fuzzer output as signals until baseline, controls, reproduction, and impact gates pass.",
            "Correlate independent sources before prioritizing; never let one noisy tool define the target model.",
        ],
    }
    if "race-state-analysis" in selected_ids:
        strategy["race_method"] = {
            "sequence": [
                "name the actor/object/state invariant and reset procedure",
                "run two clean sequential baselines",
                "fingerprint the negotiated protocol and session-lock behavior",
                "select HTTP/2 single-packet, HTTP/1.1 last-byte, protocol-aware, or deterministic local delivery",
                "run bounded synchronized attempts while preserving lane ordering and monotonic timing",
                "wait for asynchronous completion and query authoritative final state",
                "run retry, session, idempotency, jitter, and eventual-consistency controls",
                "repeat from clean state and hand a blind packet to independent X1 validation",
            ],
            "built_in_runner": "mask0ff race run",
            "runner_limitations": "The built-in barrier-http1 runner is preliminary evidence only; it is not wire-level single-packet or last-byte synchronization.",
            "verdict_rule": "Response or timing variation is a lead; require a repeatable authoritative-state invariant violation.",
        }
    return strategy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inventory installed security-research tools and build a staged workflow.")
    parser.add_argument("--assessment-mode", choices=("black-box", "gray-box", "white-box", "hybrid"), default="black-box")
    parser.add_argument("--surface", action="append", default=[])
    parser.add_argument("--focus", action="append", default=[])
    parser.add_argument("--scale", choices=("adaptive", "single-target", "multi-asset", "large-scope"), default="adaptive")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    print(json.dumps(build_strategy(args.assessment_mode, args.surface, args.focus, args.scale), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
