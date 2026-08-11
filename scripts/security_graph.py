#!/usr/bin/env python3
"""Validate and rank semantic-security paths in a compact Architecture Security Graph."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

SENSITIVE_ROLES = {
    "TEMPLATE_SOURCE", "EXPRESSION", "CONFIGURATION", "GENERATED_CONFIGURATION",
    "COMMAND_ARGUMENT", "COMMAND_PROGRAM", "MODULE_IDENTIFIER", "CLASS_IDENTIFIER",
    "PLUGIN_DESCRIPTOR", "BUILD_INSTRUCTION", "WORKFLOW_INSTRUCTION", "TOOL_ARGUMENT",
    "AUTHORIZATION_INPUT", "IDENTITY_REFERENCE", "CAPABILITY_HANDLE", "EXECUTABLE_ARTIFACT",
    "OBJECT_IDENTIFIER", "RESOURCE_OWNERSHIP", "TENANT_IDENTIFIER", "SESSION_BINDING",
    "QUERY_STRUCTURE", "GRAPHQL_SELECTION", "NETWORK_DESTINATION", "CACHE_KEY",
    "PROTOCOL_STATE", "STATE_TRANSITION", "HTML_CONTEXT", "DOM_SCRIPT_CONTEXT",
}


def validate_graph(data: Any) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(data, dict):
        return ["security graph must be a JSON object"], warnings
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    nodes = data.get("nodes", [])
    edges = data.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return ["nodes and edges must be lists"], warnings
    node_ids: set[str] = set()
    for index, node in enumerate(nodes, 1):
        if not isinstance(node, dict):
            errors.append(f"node {index} is not an object")
            continue
        node_id = str(node.get("id", "")).strip()
        if not node_id:
            errors.append(f"node {index} has no id")
            continue
        if node_id in node_ids:
            errors.append(f"duplicate node id: {node_id}")
        node_ids.add(node_id)
        if not str(node.get("kind", "")).strip():
            errors.append(f"node {node_id} has no kind")
        if not str(node.get("semantic_role", "")).strip():
            warnings.append(f"node {node_id} has no semantic_role")
    edge_ids: set[str] = set()
    for index, edge in enumerate(edges, 1):
        if not isinstance(edge, dict):
            errors.append(f"edge {index} is not an object")
            continue
        edge_id = str(edge.get("id", "")).strip()
        if not edge_id:
            errors.append(f"edge {index} has no id")
            continue
        if edge_id in edge_ids:
            errors.append(f"duplicate edge id: {edge_id}")
        edge_ids.add(edge_id)
        if str(edge.get("from", "")) not in node_ids or str(edge.get("to", "")) not in node_ids:
            errors.append(f"edge {edge_id} references an unknown node")
        if not str(edge.get("operation", "")).strip():
            errors.append(f"edge {edge_id} has no operation")
    return errors, warnings


def edge_score(edge: dict[str, Any]) -> int:
    score = 0
    transition = edge.get("semantic_transition") if isinstance(edge.get("semantic_transition"), dict) else {}
    if transition and transition.get("from") != transition.get("to"):
        score += 3
        if str(transition.get("to", "")) in SENSITIVE_ROLES:
            score += 4
    grammar = edge.get("grammar_transition") if isinstance(edge.get("grammar_transition"), dict) else {}
    if grammar and grammar.get("from") and grammar.get("to") and grammar.get("from") != grammar.get("to"):
        score += 3
    if edge.get("persistent") is True:
        score += 2
    if edge.get("identity_change") is True:
        score += 4
    if edge.get("capability_gain"):
        score += 5
    if str(edge.get("operation", "")).upper() in {"FALLBACK", "RECOVERY", "AUTO_DETECT", "RESTORE", "GENERATE", "REINTERPRET"}:
        score += 2
    return score


def candidate_paths(data: dict[str, Any], max_depth: int = 8, top: int = 20) -> list[dict[str, Any]]:
    nodes = {str(node["id"]): node for node in data.get("nodes", []) if isinstance(node, dict) and node.get("id")}
    adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in data.get("edges", []):
        if isinstance(edge, dict) and str(edge.get("from", "")) in nodes and str(edge.get("to", "")) in nodes:
            adjacency[str(edge["from"])].append(edge)

    sources = [node_id for node_id, node in nodes.items() if node.get("attacker_influence") is True]
    results: list[dict[str, Any]] = []
    for source in sources:
        queue = deque([(source, [], 0)])
        seen: dict[tuple[str, int], int] = {}
        while queue:
            current, path, score = queue.popleft()
            if len(path) >= max_depth:
                continue
            for edge in adjacency.get(current, []):
                nxt = str(edge["to"])
                new_path = [*path, str(edge.get("id"))]
                new_score = score + edge_score(edge)
                node = nodes[nxt]
                terminal = bool(node.get("execution_capable") or node.get("sensitive_capability") or str(node.get("semantic_role", "")) in SENSITIVE_ROLES)
                if terminal and new_score > 0:
                    results.append({
                        "source": source,
                        "sink": nxt,
                        "score": new_score,
                        "edges": new_path,
                        "sink_role": node.get("semantic_role"),
                        "sink_principal": node.get("principal"),
                    })
                key = (nxt, len(new_path))
                if seen.get(key, -1) >= new_score:
                    continue
                seen[key] = new_score
                queue.append((nxt, new_path, new_score))
    results.sort(key=lambda item: (-int(item["score"]), len(item["edges"]), str(item["source"]), str(item["sink"])))
    return results[:top]


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate or query a mask0ff Architecture Security Graph.")
    parser.add_argument("graph", type=Path)
    parser.add_argument("--candidates", action="store_true")
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--top", type=int, default=20)
    args = parser.parse_args()
    try:
        data = json.loads(args.graph.read_text(encoding="utf-8-sig"))
        errors, warnings = validate_graph(data)
        result: dict[str, Any] = {"errors": errors, "warnings": warnings}
        if args.candidates and not errors:
            result["candidates"] = candidate_paths(data, max_depth=min(32, max(1, args.max_depth)), top=min(200, max(1, args.top)))
        print(json.dumps(result, indent=2))
        return 1 if errors else 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
