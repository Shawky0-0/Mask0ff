#!/usr/bin/env python3
"""Plan and execute bounded race-condition experiments with evidence-safe output."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from authorization_gate import evaluate as evaluate_authorization


MAX_LANES = 10
MAX_ATTEMPTS = 5
MAX_BASELINE_RUNS = 5
MAX_TOTAL_REQUESTS = 100
MAX_BODY_BYTES = 65536
MAX_RESPONSE_BYTES = 262144
TOOL_VERSION = "1.0"
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
PATTERNS = {
    "limit-overrun",
    "single-endpoint",
    "multi-endpoint",
    "partial-construction",
    "asynchronous-job",
    "toctou",
    "state-machine",
}
PROTOCOLS = {"auto", "http2", "http1", "websocket", "grpc", "local"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def url_host(value: str) -> str:
    return (urlsplit(value).hostname or "").lower()


def is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def as_bounded_int(data: dict[str, Any], field: str, default: int, minimum: int, maximum: int, errors: list[str]) -> int:
    raw = data.get(field, default)
    if isinstance(raw, bool) or not isinstance(raw, int):
        errors.append(f"{field} must be an integer")
        return default
    if raw < minimum or raw > maximum:
        errors.append(f"{field} must be between {minimum} and {maximum}")
    return raw


def request_copies(spec: dict[str, Any], errors: list[str], label: str) -> int:
    copies = spec.get("copies", 1)
    if isinstance(copies, bool) or not isinstance(copies, int) or copies < 1 or copies > MAX_LANES:
        errors.append(f"{label}.copies must be between 1 and {MAX_LANES}")
        return 1
    return copies


def validate_request_spec(spec: Any, label: str, errors: list[str]) -> None:
    if not isinstance(spec, dict):
        errors.append(f"{label} must be an object")
        return
    if not str(spec.get("id", "")).strip():
        errors.append(f"{label}.id is required")
    method = str(spec.get("method", "GET")).upper()
    if method not in ALLOWED_METHODS:
        errors.append(f"{label}.method is unsupported: {method}")
    raw_url = str(spec.get("url", ""))
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        errors.append(f"{label}.url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        errors.append(f"{label}.url must not contain credentials")
    headers = spec.get("headers", {})
    if not isinstance(headers, dict):
        errors.append(f"{label}.headers must be an object")
    else:
        for name in headers:
            if str(name).lower().strip() in SENSITIVE_HEADERS:
                errors.append(f"{label}.headers must not store sensitive header {name}; use header_env")
    header_env = spec.get("header_env", {})
    if not isinstance(header_env, dict):
        errors.append(f"{label}.header_env must be an object")
    else:
        for name, env_name in header_env.items():
            if not str(name).strip() or not ENV_NAME.fullmatch(str(env_name)):
                errors.append(f"{label}.header_env contains an invalid header or environment-variable name")
            elif str(env_name) not in os.environ:
                errors.append(f"{label}.header_env references unavailable environment variable {env_name}")
    body = spec.get("body", "")
    if not isinstance(body, str):
        errors.append(f"{label}.body must be a string")
    elif len(body.encode("utf-8")) > MAX_BODY_BYTES:
        errors.append(f"{label}.body exceeds {MAX_BODY_BYTES} bytes")
    expected_statuses = spec.get("expected_statuses", [200])
    if (
        not isinstance(expected_statuses, list)
        or not expected_statuses
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 100 or item > 599 for item in expected_statuses)
    ):
        errors.append(f"{label}.expected_statuses must be a non-empty array of HTTP status codes")


def expanded_requests(data: dict[str, Any]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for spec in data.get("requests", []):
        if not isinstance(spec, dict):
            continue
        copies = spec.get("copies", 1)
        copies = copies if isinstance(copies, int) and not isinstance(copies, bool) else 1
        for index in range(max(1, copies)):
            lane = dict(spec)
            lane["lane_id"] = f"{spec.get('id', 'request')}#{index + 1}"
            expanded.append(lane)
    return expanded


def validate_config(
    data: dict[str, Any],
    authorization: dict[str, Any] | None = None,
    now_value: str | None = None,
    authorization_sha256: str | None = None,
) -> tuple[list[str], list[str], dict[str, Any] | None]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(data, dict):
        errors.append("config must be a JSON object")
        return errors, warnings, None
    if not isinstance(authorization, (dict, type(None))):
        errors.append("authorization must be a JSON object")
        authorization = None
    if data.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if data.get("kind") != "mask0ff-race-run-config":
        errors.append("kind must be mask0ff-race-run-config")
    work_mode = str(data.get("work_mode", ""))
    if work_mode not in {"local-lab", "active-authorized"}:
        errors.append("work_mode must be local-lab or active-authorized")
    if str(data.get("delivery", "barrier-http1")) != "barrier-http1":
        errors.append("the built-in runner supports only barrier-http1; use the plan command for wire-level HTTP/2 or last-byte synchronization")

    baseline_runs = as_bounded_int(data, "baseline_runs", 2, 1, MAX_BASELINE_RUNS, errors)
    attempts = as_bounded_int(data, "attempts", 2, 1, MAX_ATTEMPTS, errors)
    timeout = data.get("timeout_seconds", 10)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= float(timeout) <= 30:
        errors.append("timeout_seconds must be between 0.1 and 30")

    requests = data.get("requests", [])
    if not isinstance(requests, list) or not requests:
        errors.append("requests must contain at least one request specification")
        requests = []
    lane_count = 0
    for index, spec in enumerate(requests):
        label = f"requests[{index}]"
        validate_request_spec(spec, label, errors)
        if isinstance(spec, dict):
            lane_count += request_copies(spec, errors, label)
    request_ids = [str(spec.get("id", "")) for spec in requests if isinstance(spec, dict)]
    if len(request_ids) != len(set(request_ids)):
        errors.append("request specification IDs must be unique")
    if lane_count < 2:
        errors.append("the concurrent group must contain at least two lanes")
    if lane_count > MAX_LANES:
        errors.append(f"the concurrent group exceeds the hard cap of {MAX_LANES} lanes")
    configured_limit = data.get("configured_concurrency_limit", 2 if work_mode == "local-lab" else None)
    if isinstance(configured_limit, bool) or not isinstance(configured_limit, int):
        errors.append("configured_concurrency_limit must be recorded as an integer")
    elif configured_limit < 2 or configured_limit > MAX_LANES:
        errors.append(f"configured_concurrency_limit must be between 2 and {MAX_LANES}")
    elif lane_count > configured_limit:
        errors.append(f"the concurrent group has {lane_count} lanes but the configured limit is {configured_limit}")

    reset_requests = data.get("reset_requests", [])
    if not isinstance(reset_requests, list):
        errors.append("reset_requests must be an array")
        reset_requests = []
    if not reset_requests:
        warnings.append("no reset request is configured; clean state must be established and evidenced outside the runner")
        if work_mode == "active-authorized":
            errors.append("active-authorized execution requires an explicit reset request")
    for index, spec in enumerate(reset_requests):
        validate_request_spec(spec, f"reset_requests[{index}]", errors)

    state_checks = data.get("state_checks", [])
    if not isinstance(state_checks, list):
        errors.append("state_checks must be an array")
        state_checks = []
    if not state_checks:
        warnings.append("no authoritative state check is configured; response-only anomalies cannot prove a race")
        if work_mode == "active-authorized":
            errors.append("active-authorized execution requires an authoritative state check")
    for index, spec in enumerate(state_checks):
        validate_request_spec(spec, f"state_checks[{index}]", errors)

    group_count = baseline_runs + attempts
    total = group_count * (lane_count + len(reset_requests) + (2 * len(state_checks)))
    if total > MAX_TOTAL_REQUESTS:
        errors.append(f"planned request count {total} exceeds the hard cap of {MAX_TOTAL_REQUESTS}")

    all_specs = [item for item in requests + reset_requests + state_checks if isinstance(item, dict)]
    hosts = {url_host(str(item.get("url", ""))) for item in all_specs if item.get("url")}
    target = str(data.get("target", "")).lower().strip()
    if not target:
        errors.append("target is required")
    elif hosts and hosts != {target}:
        errors.append(f"all request hosts must exactly match target {target}")

    authorization_result = None
    if work_mode == "local-lab":
        if target and not is_loopback(target):
            errors.append("local-lab execution is restricted to loopback targets")
    elif work_mode == "active-authorized":
        if authorization is None:
            errors.append("active-authorized execution requires an authorization receipt")
        else:
            if not authorization_sha256 or not SHA256.fullmatch(authorization_sha256):
                errors.append("active-authorized execution requires the SHA-256 of the preserved authorization receipt")
            prohibited_text = " ".join(str(item).lower().replace("-", " ") for item in authorization.get("prohibited_actions", []))
            if any(term in prohibited_text for term in ("race condition", "race testing", "concurrency testing")):
                errors.append("authorization explicitly prohibits race or concurrency testing")
            action_group = str(data.get("action_group", "standard-safe-testing"))
            authorization_result = evaluate_authorization(
                authorization,
                target=target,
                action="bounded-race-testing",
                action_group=action_group,
                now_value=now_value,
                receipt_sha256=authorization_sha256,
            )
            if authorization_result["status"] != "pass":
                errors.extend(f"authorization: {item}" for item in authorization_result["errors"])

    return errors, warnings, authorization_result


def build_plan(
    *,
    work_mode: str,
    assessment_mode: str,
    surface: str,
    protocol: str,
    pattern: str,
    max_concurrency: int,
    max_attempts: int,
) -> dict[str, Any]:
    delivery = {
        "http2": ["Burp Repeater parallel group", "Turbo Intruder BURP2 single-packet gate"],
        "http1": ["HTTP/1.1 last-byte synchronization", "built-in barrier runner for preliminary low-jitter evidence"],
        "websocket": ["protocol-aware WebSocket client with a start barrier", "server event and authoritative-state correlation"],
        "grpc": ["protocol-aware concurrent RPC client", "server trace and datastore-state correlation"],
        "local": ["deterministic scheduler or inserted barrier", "debugger, transaction hook, fault injection, or thread sanitizer"],
        "auto": ["fingerprint negotiated transport first", "select HTTP/2 single-packet, HTTP/1.1 last-byte, or a protocol-aware local harness"],
    }[protocol]
    return {
        "schema_version": 1,
        "kind": "mask0ff-race-plan",
        "tool": {"name": "mask0ff race", "version": TOOL_VERSION},
        "work_mode": work_mode,
        "assessment_mode": assessment_mode,
        "surface": surface,
        "protocol": protocol,
        "pattern": pattern,
        "limits": {
            "requested_max_concurrency": max_concurrency,
            "requested_max_attempts": max_attempts,
            "runner_hard_concurrency_cap": MAX_LANES,
            "runner_hard_attempt_cap": MAX_ATTEMPTS,
            "runner_hard_total_request_cap": MAX_TOTAL_REQUESTS,
        },
        "phases": [
            {
                "id": "model-invariant",
                "actions": [
                    "Name the actor, object, authoritative state, one-time or bounded invariant, and irreversible side effect.",
                    "Map checks, writes, locks, idempotency keys, caches, queues, retries, rollback, and hidden sub-states.",
                    "Mine comparable reports and fixes; extract the failed state assumption instead of copying payloads.",
                ],
            },
            {
                "id": "sequential-benchmark",
                "actions": [
                    "Run the exact request group sequentially at least twice from clean synthetic state.",
                    "Measure endpoint-specific latency, connection setup, session locking, retries, and asynchronous completion.",
                    "Record pre-state, every response, downstream events, and final authoritative state.",
                ],
            },
            {
                "id": "bounded-synchronization",
                "actions": delivery,
                "caveat": "A thread barrier is not a wire-level single-packet or last-byte synchronization primitive.",
            },
            {
                "id": "discriminating-controls",
                "actions": [
                    "Compare sequential versus concurrent runs while changing only delivery timing.",
                    "Test fresh versus shared sessions, unique versus reused idempotency keys, and completed versus pending jobs.",
                    "Repeat from clean state and distinguish network jitter, client retries, proxy behavior, and eventual consistency.",
                ],
            },
            {
                "id": "proof-and-handoff",
                "actions": [
                    "Minimize the request group and stop at the smallest owned-data invariant violation.",
                    "Preserve request ordering, timestamps, response hashes, events, and authoritative final state.",
                    "Hand a blind packet and fresh-state prerequisites to an independent X1 validator.",
                ],
            },
        ],
        "required_artifacts": [
            "authorization and explicit concurrency/rate limits",
            "state-machine and collision hypothesis",
            "two clean sequential baselines",
            "bounded synchronized attempts",
            "authoritative pre-state and final-state observations",
            "negative and differential controls",
            "request/event ordering with monotonic timing",
            "independent fresh-state reproduction or X1 pending",
        ],
        "stop_conditions": [
            "scope or session becomes invalid",
            "unexpected load, resource exhaustion, third-party effect, or data exposure occurs",
            "the program prohibits race, concurrency, stress, or the required protocol technique",
            "minimum-safe proof is reached",
        ],
        "verdict_rule": "Timing or response variation is a clue only. Require a repeatable authoritative-state invariant violation and independent validation before verification.",
    }


def resolve_headers(spec: dict[str, Any]) -> dict[str, str]:
    headers = {str(name): str(value) for name, value in spec.get("headers", {}).items()}
    for name, env_name in spec.get("header_env", {}).items():
        value = os.environ.get(str(env_name))
        if value is None:
            raise ValueError(f"required environment variable is unavailable for header {name}")
        headers[str(name)] = value
    return headers


def request_result(spec: dict[str, Any], *, phase: str, run_id: str, barrier: threading.Barrier | None, timeout: float) -> dict[str, Any]:
    body = str(spec.get("body", "")).encode("utf-8")
    headers = resolve_headers(spec)
    request = Request(str(spec["url"]), data=body or None, headers=headers, method=str(spec.get("method", "GET")).upper())
    opener = build_opener(NoRedirect())
    if barrier is not None:
        barrier.wait(timeout=timeout)
    started_utc = utc_now()
    started = time.perf_counter_ns()
    status: int | None = None
    response_body = b""
    truncated = False
    error_kind = ""
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        status = int(error.code)
        response_body = error.read(MAX_RESPONSE_BYTES + 1)
    except (URLError, TimeoutError, OSError) as error:
        error_kind = type(error).__name__
    if len(response_body) > MAX_RESPONSE_BYTES:
        response_body = response_body[:MAX_RESPONSE_BYTES]
        truncated = True
    ended = time.perf_counter_ns()
    finished_utc = utc_now()
    return {
        "phase": phase,
        "run_id": run_id,
        "lane_id": str(spec.get("lane_id", spec.get("id", "request"))),
        "request_id": str(spec.get("id", "request")),
        "method": str(spec.get("method", "GET")).upper(),
        "url": safe_url(str(spec["url"])),
        "query_sha256": sha256_bytes(urlsplit(str(spec["url"])).query.encode("utf-8")),
        "request_body_sha256": sha256_bytes(body),
        "request_header_names": sorted(headers),
        "started_at_utc": started_utc,
        "finished_at_utc": finished_utc,
        "started_monotonic_ns": started,
        "duration_ms": round((ended - started) / 1_000_000, 3),
        "status": status,
        "response_body_sha256": sha256_bytes(response_body),
        "response_bytes": len(response_body),
        "response_truncated": truncated,
        "error_kind": error_kind,
        "expected_statuses": spec.get("expected_statuses", [200]),
        "expected_status_match": status in spec.get("expected_statuses", [200]),
    }


def run_state_checks(specs: list[dict[str, Any]], phase: str, run_id: str, timeout: float) -> list[dict[str, Any]]:
    return [request_result(spec, phase=phase, run_id=run_id, barrier=None, timeout=timeout) for spec in specs]


def signature(rows: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    return sorted((row["request_id"], row["status"], row["response_body_sha256"], row["error_kind"]) for row in rows)


def execute(
    data: dict[str, Any],
    warnings: list[str],
    authorization_result: dict[str, Any] | None,
    config_sha256: str | None = None,
) -> dict[str, Any]:
    timeout = float(data.get("timeout_seconds", 10))
    lanes = expanded_requests(data)
    reset_requests = [dict(item) for item in data.get("reset_requests", [])]
    state_checks = [dict(item) for item in data.get("state_checks", [])]
    baseline_runs: list[dict[str, Any]] = []
    concurrent_runs: list[dict[str, Any]] = []

    for index in range(int(data.get("baseline_runs", 2))):
        run_id = f"baseline-{index + 1}"
        reset_rows = run_state_checks(reset_requests, "reset", run_id, timeout)
        if any(not row["expected_status_match"] for row in reset_rows):
            raise ValueError(f"reset failed for {run_id}; no transition requests were sent")
        pre_state = run_state_checks(state_checks, "pre-state", run_id, timeout)
        rows = [request_result(spec, phase="sequential", run_id=run_id, barrier=None, timeout=timeout) for spec in lanes]
        baseline_runs.append({"run_id": run_id, "reset": reset_rows, "pre_state": pre_state, "requests": rows, "state_checks": run_state_checks(state_checks, "post-state", run_id, timeout)})

    for index in range(int(data.get("attempts", 2))):
        run_id = f"concurrent-{index + 1}"
        reset_rows = run_state_checks(reset_requests, "reset", run_id, timeout)
        if any(not row["expected_status_match"] for row in reset_rows):
            raise ValueError(f"reset failed for {run_id}; no transition requests were sent")
        pre_state = run_state_checks(state_checks, "pre-state", run_id, timeout)
        barrier = threading.Barrier(len(lanes) + 1)
        with ThreadPoolExecutor(max_workers=len(lanes)) as executor:
            futures = [
                executor.submit(request_result, spec, phase="concurrent", run_id=run_id, barrier=barrier, timeout=timeout)
                for spec in lanes
            ]
            barrier.wait(timeout=timeout)
            rows = [future.result(timeout=timeout + 5) for future in futures]
        concurrent_runs.append({"run_id": run_id, "reset": reset_rows, "pre_state": pre_state, "requests": rows, "state_checks": run_state_checks(state_checks, "post-state", run_id, timeout)})

    baseline_signatures = [signature(run["requests"]) for run in baseline_runs]
    concurrent_signatures = [signature(run["requests"]) for run in concurrent_runs]
    baseline_state = [signature(run["state_checks"]) for run in baseline_runs]
    concurrent_state = [signature(run["state_checks"]) for run in concurrent_runs]
    signals = {
        "baseline_is_stable": len({json.dumps(item) for item in baseline_signatures}) == 1,
        "concurrent_response_differs_from_baseline": any(item not in baseline_signatures for item in concurrent_signatures),
        "concurrent_state_differs_from_baseline": bool(state_checks) and any(item not in baseline_state for item in concurrent_state),
        "request_errors_observed": any(
            row["error_kind"]
            for run in baseline_runs + concurrent_runs
            for row in run["reset"] + run["pre_state"] + run["requests"] + run["state_checks"]
        ),
    }
    return {
        "schema_version": 1,
        "kind": "mask0ff-race-run",
        "tool": {"name": "mask0ff race", "version": TOOL_VERSION},
        "created_at_utc": utc_now(),
        "config_sha256": config_sha256 or sha256_bytes(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ),
        "work_mode": data["work_mode"],
        "target": data["target"],
        "delivery": "barrier-http1",
        "delivery_caveat": "Thread-barrier release reduces client scheduling skew but is not HTTP/2 single-packet or HTTP/1.1 last-byte synchronization.",
        "limits": {
            "lanes": len(lanes),
            "baseline_runs": len(baseline_runs),
            "concurrent_attempts": len(concurrent_runs),
            "timeout_seconds": timeout,
            "configured_concurrency_limit": data.get("configured_concurrency_limit", 2),
        },
        "request_specs": [
            {
                "id": spec.get("id"),
                "method": str(spec.get("method", "GET")).upper(),
                "url": safe_url(str(spec.get("url", ""))),
                "copies": spec.get("copies", 1),
                "header_names": sorted(set(spec.get("headers", {})) | set(spec.get("header_env", {}))),
                "body_sha256": sha256_bytes(str(spec.get("body", "")).encode("utf-8")),
            }
            for spec in data["requests"]
        ],
        "authorization": authorization_result,
        "warnings": warnings,
        "baseline_runs": baseline_runs,
        "concurrent_runs": concurrent_runs,
        "signals": signals,
        "verdict": "lead-only",
        "verdict_reason": "The runner records delivery and state differentials. It does not establish the business invariant, root cause, impact, clean repeat, or independent X1 validation.",
    }


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.new")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(path)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Plan or run bounded race-condition experiments.")
    commands = root.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="Build a protocol-aware, evidence-first race test plan without network access")
    plan.add_argument("--work-mode", choices=("local-lab", "active-authorized"), default="local-lab")
    plan.add_argument("--assessment-mode", choices=("black-box", "gray-box", "white-box", "hybrid"), default="black-box")
    plan.add_argument("--surface", choices=("web", "api", "graphql", "websocket", "grpc", "source"), default="api")
    plan.add_argument("--protocol", choices=sorted(PROTOCOLS), default="auto")
    plan.add_argument("--pattern", choices=sorted(PATTERNS), default="state-machine")
    plan.add_argument("--max-concurrency", type=int, default=2)
    plan.add_argument("--max-attempts", type=int, default=2)

    run = commands.add_parser("run", help="Run a low-volume HTTP/1.x barrier experiment from a reviewed JSON config")
    run.add_argument("config", type=Path)
    run.add_argument("--authorization", type=Path)
    run.add_argument("--now", help="ISO-8601 override for deterministic authorization validation")
    run.add_argument("--output", type=Path)
    run.add_argument("--dry-run", action="store_true", help="Validate and summarize without network requests")
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "plan":
        if not 2 <= args.max_concurrency <= MAX_LANES or not 1 <= args.max_attempts <= MAX_ATTEMPTS:
            print(f"ERROR: limits exceed hard caps (concurrency {MAX_LANES}, attempts {MAX_ATTEMPTS})", file=sys.stderr)
            return 2
        print(json.dumps(build_plan(
            work_mode=args.work_mode,
            assessment_mode=args.assessment_mode,
            surface=args.surface,
            protocol=args.protocol,
            pattern=args.pattern,
            max_concurrency=args.max_concurrency,
            max_attempts=args.max_attempts,
        ), indent=2))
        return 0

    try:
        config_raw = args.config.read_bytes()
        config_sha256 = sha256_bytes(config_raw)
        data = json.loads(config_raw.decode("utf-8-sig"))
        authorization = None
        authorization_sha256 = None
        if args.authorization:
            authorization_raw = args.authorization.read_bytes()
            authorization = json.loads(authorization_raw.decode("utf-8-sig"))
            authorization_sha256 = sha256_bytes(authorization_raw)
        errors, warnings, authorization_result = validate_config(data, authorization, args.now, authorization_sha256)
        if errors:
            print(json.dumps({"status": "blocked", "errors": errors, "warnings": warnings}, indent=2), file=sys.stderr)
            return 2
        if args.dry_run:
            result = {
                "status": "ready",
                "tool": {"name": "mask0ff race", "version": TOOL_VERSION},
                "config_sha256": config_sha256,
                "network_requests_sent": 0,
                "target": data["target"],
                "lanes": len(expanded_requests(data)),
                "configured_concurrency_limit": data.get("configured_concurrency_limit", 2),
                "baseline_runs": data.get("baseline_runs", 2),
                "attempts": data.get("attempts", 2),
                "state_checks": len(data.get("state_checks", [])),
                "reset_requests": len(data.get("reset_requests", [])),
                "warnings": warnings,
                "authorization": authorization_result,
            }
        else:
            result = execute(data, warnings, authorization_result, config_sha256)
        if args.output:
            atomic_write(args.output.resolve(), result)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, KeyError, threading.BrokenBarrierError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
