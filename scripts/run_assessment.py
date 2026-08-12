#!/usr/bin/env python3
"""Run one scenario against one authorised target, in a sandbox, and write the bundle.

The order is the design, not an implementation detail. A0 runs FIRST on the receipt: a
refusal creates no container, sends no request and writes no bundle. Then the sandbox is
created, which also opens the usage ledger, so the clock starts before the first request.
Every step runs inside that sandbox, the caps are checked between steps, and EVERY STEP
WRITES ITS OWN ARTIFACT FILE. The proof artifact and the control artifact are two files
with two sha256 values, because one transcript holding both cannot show that the refusal
and the success were separate observations. The bundle is written through
evidence_bundle.py, never by hand here. The sandbox is destroyed either way.

THE SCENARIO FILE is where everything product specific lives. validate_scenario in this
file is the authority on its shape, and it is the only one: a field list written here as
well would drift away from the code that enforces it. Read that function.

WHAT A CONTROL AND A PROOF MUST DECLARE, checked before anything runs. A control step
must declare expect.status_in and none of those statuses may be 2xx, because a route that
answers with success did not refuse. A control may not expect the marker in its body. A
proof step must declare expect.status_in with 2xx statuses only, and must declare
expect.body_contains_marker true, because a status alone is never proof. A scenario that
cannot express a refusal and a service is rejected rather than run.

THE VERDICT, and it is judged on what was observed, not only on the scenario's own
expectations. "bypassable" needs every control step to have refused (a non 2xx status,
no marker in the body, and its own expectations met) AND every proof step to have been
served (a 2xx status, a body of more than zero bytes, the marker present, and its own
expectations met). "not_bypassable" means the controls refused and the proof did not go
through. Everything else is "inconclusive": a control that did not refuse, a step that
errored, or a proof and a control that are the same response bytes. An ungated file
served to an anonymous caller is not a finding, so with no refusing control there is
nothing to conclude, and a run that reaches no conclusion never reports a pass.

TWO CHECKS THIS RUNNER MAKES ON TOP OF A0, because A0 is upstream and unchanged. First,
the scenario's action must be named in the receipt's allowed_actions. An action nobody
wrote down is not authorised by belonging to an allowed group. Second, scope is matched
with the port included: an entry naming a port authorises that port only, and an entry
naming no port authorises the scheme's default port only.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import secrets
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import authorization_gate

ROOT = Path(__file__).resolve().parents[1]
SANDBOX_SCRIPT = ROOT / "scripts" / "sandbox.py"
USAGE_SCRIPT = ROOT / "scripts" / "usage_tracker.py"
BUNDLE_SCRIPT = ROOT / "scripts" / "evidence_bundle.py"

SCHEMA_VERSION = 1
DEFAULT_NETWORK = "mask0ff-internal"
STEP_KINDS = ("discovery", "control", "proof")
ALLOWED_METHODS = ("GET", "HEAD")
REQUEST_TIMEOUT_SECONDS = 20
EXPECT_KEYS = ("status_in", "body_contains_marker", "min_bytes", "header_present", "header_absent")
STEP_KEYS = ("id", "kind", "method", "path", "url_from_step", "url_index", "headers",
             "collect_json_field", "collect_must_contain", "expect", "note")

RUN_FAILED_EXIT_CODE, AUTHORIZATION_BLOCKED_EXIT_CODE, USAGE_BREACH_EXIT_CODE = 1, 2, 3
INTERNAL_ERROR_EXIT_CODE = 4
SCRIPT_FAILURE_CODE = 125


def is_success(status: Any) -> bool:
    """True only for a 2xx. A redirect is not a served document and neither is an error."""
    return isinstance(status, int) and 200 <= status < 300


class RunError(Exception):
    """A refusal or a broken input. Always reported, never guessed around."""


class RunStop(Exception):
    """A deliberate early exit, carrying the summary to print and the code to exit with.

    It exists so the stages below can refuse without also owning the printing. main is the
    only place that prints and the only place that returns an exit code, so there is one
    place to read when asking what this script does on a refusal."""

    def __init__(self, payload: dict[str, Any], code: int) -> None:
        super().__init__(str(payload.get("error") or payload.get("status", "")))
        self.payload = payload
        self.code = code


@dataclass(frozen=True)
class RunContext:
    """What is fixed for the whole run: the sandbox job, where it writes, and what it seeks.

    Every field is settled once before the first step and never changes, so passing this
    one record beats threading six arguments through every step."""

    job: str
    workdir: Path
    base: str
    marker: str
    argv_dir: Path
    artifact_dir: Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def run_engine(script: Path, arguments: list[str]) -> tuple[int, dict[str, Any] | None, str]:
    """Call one of the engine's own scripts and hand back its JSON if it printed any."""
    completed = subprocess.run(
        [sys.executable, str(script), *arguments],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
    )
    payload = None
    try:
        parsed = json.loads(completed.stdout)
        payload = parsed if isinstance(parsed, dict) else None
    except ValueError:
        payload = None
    return completed.returncode, payload, (completed.stderr or completed.stdout).strip()[:800]


def load_json_file(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise RunError(f"{label} is not a file: {path}")
    try:
        data = json.loads(path.read_bytes().decode("utf-8-sig"))
    except ValueError as error:
        raise RunError(f"{label} is not valid JSON: {path}: {error}") from error
    if not isinstance(data, dict):
        raise RunError(f"{label} must be a JSON object: {path}")
    return data


def declared_statuses(step_id: str, expect: dict[str, Any]) -> list[int]:
    raw = expect.get("status_in")
    if not isinstance(raw, list) or not raw:
        raise RunError(f"step {step_id}: expect.status_in must be a non empty list of HTTP status numbers")
    try:
        return [int(item) for item in raw]
    except (TypeError, ValueError) as error:
        raise RunError(f"step {step_id}: expect.status_in holds something that is not a status number: {error}") from error


def validate_expect(step_id: str, kind: str, expect: dict[str, Any]) -> None:
    """A control has to be able to fail as a refusal, and a proof has to be able to fail
    as a served document. An empty expectation block is met by anything, so a scenario
    that declares nothing could report a finding without ever observing one."""
    if kind == "control":
        statuses = declared_statuses(step_id, expect)
        if any(is_success(item) for item in statuses):
            raise RunError(f"step {step_id}: a control step cannot expect a 2xx status. A route that answers "
                           "with success did not refuse, so it gates nothing and the proof would mean nothing.")
        if expect.get("body_contains_marker") is True:
            raise RunError(f"step {step_id}: a control step cannot expect the marker in its body. A control that "
                           "hands over the protected content is not a refusal.")
    if kind == "proof":
        statuses = declared_statuses(step_id, expect)
        if not all(is_success(item) for item in statuses):
            raise RunError(f"step {step_id}: a proof step can only expect a 2xx status. A redirect or an error is "
                           "not a served document.")
        if expect.get("body_contains_marker") is not True:
            raise RunError(f"step {step_id}: a proof step must declare expect.body_contains_marker true. A status "
                           "alone is never proof, the marker in the body is what makes it evidence.")


def validate_scenario(scenario: dict[str, Any]) -> None:
    for field in ("id", "title", "action", "marker"):
        if not str(scenario.get(field, "")).strip():
            raise RunError(f"scenario field is required and must not be empty: {field}")
    steps = scenario.get("steps")
    if not isinstance(steps, list) or not steps:
        raise RunError("scenario must carry a non empty 'steps' list")

    seen: set[str] = set()
    kinds: list[str] = []
    for position, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            raise RunError(f"step {position} is not an object")
        if sorted(set(step) - set(STEP_KEYS)):
            raise RunError(f"step {position} has unknown keys: {', '.join(sorted(set(step) - set(STEP_KEYS)))}")
        step_id = str(step.get("id", "")).strip()
        if not step_id or step_id in seen:
            raise RunError(f"step {position} needs an id, and every id must be unique: {step_id!r}")
        seen.add(step_id)
        if str(step.get("kind", "")) not in STEP_KINDS:
            raise RunError(f"step {step_id}: kind must be one of {', '.join(STEP_KINDS)}")
        kinds.append(str(step["kind"]))
        if str(step.get("method", "GET")).upper() not in ALLOWED_METHODS:
            raise RunError(f"step {step_id}: this runner sends {' and '.join(ALLOWED_METHODS)} only, it is read only")
        path, source_step = step.get("path"), step.get("url_from_step")
        if bool(path) == bool(source_step):
            raise RunError(f"step {step_id}: give exactly one of 'path' or 'url_from_step'")
        if path is not None and "://" in str(path):
            raise RunError(f"step {step_id}: 'path' is a path, not a URL. The host comes from --target, always.")
        if path is not None and not str(path).startswith("/"):
            raise RunError(f"step {step_id}: 'path' must start with '/'")
        if source_step is not None and str(source_step) not in seen:
            raise RunError(f"step {step_id}: url_from_step names a step that is not earlier: {source_step}")
        if not isinstance(step.get("headers") or {}, dict):
            raise RunError(f"step {step_id}: 'headers' must be an object")
        expect = step.get("expect") or {}
        if not isinstance(expect, dict):
            raise RunError(f"step {step_id}: 'expect' must be an object")
        if sorted(set(expect) - set(EXPECT_KEYS)):
            raise RunError(f"step {step_id}: unknown expectation keys: {', '.join(sorted(set(expect) - set(EXPECT_KEYS)))}")
        validate_expect(step_id, str(step["kind"]), expect)

    if "control" not in kinds:
        raise RunError("scenario has no control step. Without one the proof means nothing, because a "
                       "file that was never gated is not a finding.")
    if "proof" not in kinds:
        raise RunError("scenario has no proof step, so it can never demonstrate anything")


def base_of(target: str) -> str:
    parts = urlsplit(target if "://" in target else f"http://{target}")
    if not parts.netloc:
        raise RunError(f"target has no host: {target}")
    return urlunsplit((parts.scheme or "http", parts.netloc, "", "", ""))


def same_host(first: str, second: str) -> bool:
    return urlsplit(first).netloc.lower() == urlsplit(second).netloc.lower()


def host_and_port(target: str) -> tuple[str, str, str]:
    """The target's host, the port it actually speaks to, and the port its scheme
    defaults to. The scheme default is what a scope entry that names no port means."""
    parts = urlsplit(target if "://" in target else f"http://{target}")
    try:
        port = parts.port
    except ValueError as error:
        raise RunError(f"target has an unreadable port: {target}: {error}") from error
    scheme_default = "443" if parts.scheme == "https" else "80"
    return (parts.hostname or "").lower(), str(port or scheme_default), scheme_default


def entry_patterns(entry: str, default_port: str) -> tuple[str, str]:
    """A scope entry read as a host pattern and a port pattern. An entry that names no
    port covers the default port only, so a receipt cannot silently cover every port."""
    text = str(entry).strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if text.count(":") == 1:
        host, _, port = text.rpartition(":")
        return host, (port or default_port)
    return text, default_port  # no port, or an IPv6 literal this runner will not guess at


def runner_authorization(receipt: dict[str, Any], target: str, action: str) -> dict[str, Any]:
    """The runner's own gate, on top of A0. A0 lives upstream and is not edited here, so
    the two rules it does not enforce are enforced here instead: the port is part of the
    scope, and an action nobody wrote down is not authorised by an allowed group."""
    host, port, scheme_default = host_and_port(target)

    def in_scope(entry: str) -> bool:
        host_pattern, port_pattern = entry_patterns(entry, scheme_default)
        return fnmatch.fnmatchcase(host, host_pattern) and fnmatch.fnmatchcase(port, port_pattern)

    def out_of_scope(entry: str) -> bool:
        # Exclusions are read broadly on purpose. A host named as forbidden is forbidden
        # on every port, because the safe direction of error here is to refuse.
        return (fnmatch.fnmatchcase(host, entry_patterns(entry, "*")[0])
                or fnmatch.fnmatchcase(f"{host}:{port}", str(entry).strip().lower()))

    errors: list[str] = []
    matched_in = [entry for entry in receipt.get("in_scope_targets", []) or [] if in_scope(entry)]
    matched_out = [entry for entry in receipt.get("out_of_scope_targets", []) or [] if out_of_scope(entry)]
    if matched_out:
        errors.append(f"the receipt puts this host out of scope: {', '.join(matched_out)}")
    if not matched_in:
        errors.append(f"no in scope entry names host {host} on port {port}. An entry with no port covers the "
                      "default port only, so a bare host does not authorise every port on it.")
    named = {str(item).lower().strip() for item in receipt.get("allowed_actions", []) or []}
    action_named = action.lower().strip() in named
    if not action_named:
        errors.append(f"the action {action!r} is not named in the receipt's allowed_actions. Belonging to an "
                      "allowed action group is not enough, because an unstated action was never permitted.")
    return {
        "status": "pass" if not errors else "blocked",
        "target_host": host, "target_port": port,
        "matched_in_scope_entries": matched_in, "matched_out_of_scope_entries": matched_out,
        "action": action, "action_named_in_allowed_actions": action_named,
        "errors": errors,
        "rule": ("This runner checks scope with the port included and requires the exact action to be named in "
                 "allowed_actions. A0 upstream does neither, so a pass there is necessary and not sufficient."),
    }


def collect_values(node: Any, key: str, found: list[str]) -> list[str]:
    """Pull every string value stored under this key, anywhere in the JSON."""
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key and isinstance(value, str):
                found.append(value)
            else:
                collect_values(value, key, found)
    elif isinstance(node, list):
        for item in node:
            collect_values(item, key, found)
    return found


def split_response(raw: bytes) -> tuple[list[str], bytes]:
    """Separate the header blocks curl printed from the body bytes that followed."""
    blocks: list[str] = []
    rest = raw
    while rest.startswith(b"HTTP/"):
        marker = rest.find(b"\r\n\r\n")
        if marker == -1:
            blocks.append(rest.decode("utf-8", errors="replace"))
            return blocks, b""
        blocks.append(rest[:marker].decode("utf-8", errors="replace"))
        rest = rest[marker + 4:]
    return blocks, rest


def parse_headers(block: str) -> tuple[int | None, list[str]]:
    lines = [line for line in block.replace("\r\n", "\n").split("\n") if line.strip()]
    if not lines:
        return None, []
    pieces = lines[0].split()
    status = int(pieces[1]) if len(pieces) >= 2 and pieces[1].isdigit() else None
    return status, lines[1:]


def check_expectations(expect: dict[str, Any], observed: dict[str, Any]) -> list[str]:
    """Return the reasons this step did not meet its expectations. Empty means met."""
    failures: list[str] = []
    if "status_in" in expect:
        allowed = [int(item) for item in expect["status_in"]]
        if observed["status"] not in allowed:
            failures.append(f"status {observed['status']} is not one of {allowed}")
    if "body_contains_marker" in expect and observed["marker_in_body"] is not bool(expect["body_contains_marker"]):
        failures.append(f"marker present is {observed['marker_in_body']}, expected {bool(expect['body_contains_marker'])}")
    if "min_bytes" in expect and observed["body_bytes"] < int(expect["min_bytes"]):
        failures.append(f"body is {observed['body_bytes']} bytes, expected at least {expect['min_bytes']}")
    present = {line.split(":", 1)[0].strip().lower() for line in observed["headers"] if ":" in line}
    failures.extend(f"header is missing: {name}" for name in expect.get("header_present", []) if str(name).lower() not in present)
    failures.extend(f"header should not be there: {name}" for name in expect.get("header_absent", []) if str(name).lower() in present)
    return failures


def build_url(step: dict[str, Any], base: str, collected: dict[str, list[str]]) -> tuple[str, dict[str, Any]]:
    """Work out the one URL this step fetches, and never leave the authorised host."""
    origin: dict[str, Any] = {"source": "scenario_path"}
    if step.get("path") is not None:
        url = base + str(step["path"])
    else:
        source_id, index = str(step["url_from_step"]), int(step.get("url_index", 0))
        values = collected.get(source_id, [])
        if index >= len(values):
            raise RunError(f"step {step['id']}: step {source_id} collected {len(values)} URLs, so index {index} does not exist")
        parts = urlsplit(values[index])
        url = base + parts.path + (f"?{parts.query}" if parts.query else "")
        origin = {
            "source": "collected_from_step", "from_step": source_id, "index": index,
            "as_published_by_the_target": values[index],
            "rewritten_onto_target": not same_host(values[index], base),
            "rewrite_reason": ("Only the path is reused. The host always comes from --target, because a "
                               "response is not allowed to send this tool at a host A0 did not clear."),
        }
    if not same_host(url, base):
        raise RunError(f"refusing to request a host outside the authorised target: {url}")
    return url, origin


def curl_argv(method: str, url: str, headers: dict[str, Any]) -> list[str]:
    argv = ["curl", "-s", "-i", "--max-time", str(REQUEST_TIMEOUT_SECONDS)]
    if method == "HEAD":
        argv.append("--head")
    for name, value in headers.items():
        argv.extend(["-H", f"{name}: {value}"])
    argv.append(url)
    return argv


def write_artifact(path: Path, step: dict[str, Any], url: str, argv: list[str], raw: bytes) -> tuple[str, str]:
    """One file per step. The header says what was asked, then the answer verbatim.

    Two digests come back and they are not interchangeable. The first covers the file on
    disk, header included, and the header carries the step id and the capture time, so two
    steps can never share it. The second covers the response bytes alone, and that is the
    only one that can answer whether two steps saw the same thing."""
    header = (
        f"mask0ff run artifact\nstep: {step['id']}\nkind: {step['kind']}\n"
        f"request: {str(step.get('method', 'GET')).upper()} {url}\n"
        f"command: {json.dumps(argv, ensure_ascii=False)}\ncaptured_at_utc: {utc_now()}\n"
        f"note: everything below the line is the response exactly as the container received it.\n"
        f"{'-' * 72}\n"
    ).encode("utf-8")
    path.write_bytes(header + raw)
    return hashlib.sha256(header + raw).hexdigest(), hashlib.sha256(raw).hexdigest()


def execute_step(step: dict[str, Any], context: RunContext,
                 collected: dict[str, list[str]], position: int) -> dict[str, Any]:
    url, origin = build_url(step, context.base, collected)
    method = str(step.get("method", "GET")).upper()
    argv = curl_argv(method, url, step.get("headers") or {})

    # The command goes to sandbox exec in a file, never as trailing arguments. cmd.exe
    # rewrites an argument list before Python ever sees it, and that defect is on the record.
    argv_path = context.argv_dir / f"{position:02d}-{step['id']}.argv.json"
    argv_path.write_text(json.dumps(argv, ensure_ascii=False), encoding="utf-8")
    code, payload, error_text = run_engine(
        SANDBOX_SCRIPT, ["exec", "--job", context.job, "--workdir", str(context.workdir),
                         "--argv-file", str(argv_path)])

    result: dict[str, Any] = {
        "step": step["id"], "kind": step["kind"], "method": method, "url": url, "url_origin": origin,
        "note": step.get("note", ""), "sandbox_status": (payload or {}).get("status", "no_json_from_sandbox"),
        "command_exit_code": (payload or {}).get("exit_code"), "sandbox_exit_code": code,
    }
    if payload is None:
        return {**result, "state": "error", "error": error_text or "the sandbox printed nothing"}
    if payload.get("status") == "refused_usage_cap":
        return {**result, "state": "refused_usage_cap", "breached_fields": payload.get("breached_fields", []),
                "error": "the job hit a usage cap, so this step never ran"}
    if payload.get("status") != "ran":
        return {**result, "state": "error", "error": f"the sandbox reported status {payload.get('status')!r}"}

    raw = Path(str(payload["stdout_path"])).read_bytes()
    artifact_path = context.artifact_dir / f"{position:02d}-{step['id']}-{step['kind']}.txt"
    result["artifact_path"] = str(artifact_path)
    result["artifact_sha256"], result["response_sha256"] = write_artifact(artifact_path, step, url, argv, raw)
    result["transcript_from_sandbox"] = str(payload["stdout_path"])

    blocks, body = split_response(raw)
    if not blocks:
        return {**result, "state": "error", "captured_bytes": len(raw),
                "error": "no HTTP response was captured. The request did not reach the target, or curl failed."}

    status, headers = parse_headers(blocks[-1])
    # The body digest is what tells two steps apart. The whole response will not do it:
    # a Date header changes every second, so two fetches of one file look different when
    # they are the same document. The body is the document.
    result["body_sha256"] = hashlib.sha256(body).hexdigest()
    observed = {"status": status, "headers": headers, "body_bytes": len(body),
                "marker_in_body": context.marker.encode("utf-8") in body}
    if step.get("collect_json_field"):
        values: list[str] = []
        try:
            values = collect_values(json.loads(body.decode("utf-8", errors="replace")),
                                    str(step["collect_json_field"]), [])
        except ValueError:
            result["collect_error"] = "the body is not JSON, so nothing could be collected from it"
        if step.get("collect_must_contain"):
            values = [item for item in values if str(step["collect_must_contain"]) in item]
        collected[str(step["id"])] = values
        result["collected"] = values
    failures = check_expectations(step.get("expect") or {}, observed)
    return {**result, "observed": observed, "expectations": step.get("expect") or {},
            "expectation_failures": failures, "expectations_met": not failures, "state": "ran"}


def control_failures(item: dict[str, Any]) -> list[str]:
    """Why this control step is not a refusal. Empty means it refused."""
    reasons = list(item.get("expectation_failures") or [])
    observed = item.get("observed") or {}
    status = observed.get("status")
    if status is None:
        reasons.append("no HTTP status was captured, so nothing can be said about the gate")
    elif is_success(status):
        reasons.append(f"status {status} is a success, so this route answered the anonymous caller instead of refusing")
    if observed.get("marker_in_body"):
        reasons.append("the body carries the marker, so this route served the protected content rather than refusing it")
    return reasons


def proof_failures(item: dict[str, Any]) -> list[str]:
    """Why this proof step is not a served document. Empty means it was served."""
    reasons = list(item.get("expectation_failures") or [])
    observed = item.get("observed") or {}
    status = observed.get("status")
    if status is None:
        reasons.append("no HTTP status was captured, so nothing was shown to be served")
    elif not is_success(status):
        reasons.append(f"status {status} is not a served document, it is a redirect or a refusal")
    if int(observed.get("body_bytes") or 0) <= 0:
        reasons.append("the body is zero bytes, so nothing was handed over")
    if not observed.get("marker_in_body"):
        reasons.append("the body does not carry the marker, so this is not the protected document")
    return reasons


def evaluate_gates(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Judge the control and the proof on what was observed, not on the scenario's word.

    Each gate comes back as True (it held), False (it did not) or None (unknown, because
    a step of that kind never ran). The reasons are the concrete observations, so nothing
    downstream has to invent a cause."""
    gates: dict[str, dict[str, Any]] = {}
    for kind, checker, claim in (
        ("control", control_failures, "every control step refused the anonymous caller"),
        ("proof", proof_failures, "every proof step served the marked body to the anonymous caller"),
    ):
        items = [item for item in results if item.get("kind") == kind]
        observations = [
            f"step {item.get('step')} answered status {(item.get('observed') or {}).get('status')}, "
            f"{(item.get('observed') or {}).get('body_bytes')} body bytes, marker present "
            f"{(item.get('observed') or {}).get('marker_in_body')}"
            for item in items if item.get("state") == "ran"
        ]
        if not items:
            gates[kind] = {"state": None, "claim": claim, "observations": observations,
                           "reasons": [f"the run has no {kind} step"]}
            continue
        broken = [item for item in items if item.get("state") != "ran"]
        if broken:
            gates[kind] = {"state": None, "claim": claim, "observations": observations, "reasons": [
                f"step {item.get('step')} did not run ({item.get('state')}): {item.get('error', '')}".strip()
                for item in broken]}
            continue
        reasons = [f"step {item['step']}: {reason}" for item in items for reason in checker(item)]
        gates[kind] = {"state": not reasons, "claim": claim, "observations": observations, "reasons": reasons}
    return gates


def decide_verdict(results: list[dict[str, Any]]) -> dict[str, Any]:
    gates = evaluate_gates(results)
    control, proof = gates["control"], gates["proof"]
    base = {"gates": gates}
    broken = [item for item in results if item.get("state") != "ran"]
    if broken:
        return {**base, "verdict": "inconclusive", "reason": "at least one step did not run: "
                + ", ".join(f"{item.get('step')} ({item.get('state')})" for item in broken)}
    controls = [item for item in results if item["kind"] == "control"]
    proofs = [item for item in results if item["kind"] == "proof"]
    if not controls or not proofs:
        return {**base, "verdict": "inconclusive", "reason": "the run has no control step or no proof step"}
    shared = ({item.get("body_sha256") for item in controls}
              & {item.get("body_sha256") for item in proofs}) - {None}
    if shared:
        return {**base, "verdict": "inconclusive", "reason": "a proof step and a control step received the same "
                f"body bytes (sha256 {sorted(shared)[0][:16]}), so they are one observation reported twice, "
                "not a refusal and a service"}

    if control["state"] is not True:
        return {**base, "verdict": "inconclusive", "control_refused": False,
                "proof_served": proof["state"] is True,
                "reason": "the control did not refuse (" + "; ".join(control["reasons"])
                + "), so nothing is gated and an anonymous fetch proves nothing"}
    if proof["state"] is True:
        return {**base, "verdict": "bypassable", "control_refused": True, "proof_served": True,
                "reason": "the control refused the anonymous caller (" + "; ".join(control["observations"])
                + ") and the proof served the marked body to that same caller ("
                + "; ".join(proof["observations"]) + ")"}
    return {**base, "verdict": "not_bypassable", "control_refused": True, "proof_served": False,
            "reason": "the control refused, and the proof did not go through ("
            + "; ".join(proof["reasons"]) + ")"}


def bundle_call(arguments: list[str], label: str) -> dict[str, Any] | None:
    code, payload, error_text = run_engine(BUNDLE_SCRIPT, arguments)
    if code != 0:
        raise RunError(f"evidence_bundle {label} failed: {error_text}")
    return payload


def gate_reason(detail: dict[str, Any]) -> str:
    """The sentence a gate is stored with, built from what was observed rather than from a
    fixed string. A canned failure reason can name a cause that did not happen."""
    if detail.get("state") is True:
        return f"{detail.get('claim', '')}: {'; '.join(detail.get('observations') or [])}"
    return "; ".join(detail.get("reasons") or []) or "the run established nothing about this gate"


def set_gate(bundle: Path, gate: str, detail: dict[str, Any], ids: list[str], reason_prefix: str = "") -> None:
    """Write one gate into the record through the engine. A gate with no evidence is not
    written at all, because a status with nothing behind it is a claim, not a record."""
    if not ids:
        return
    status = {True: "pass", False: "fail"}.get(detail.get("state"), "pending")
    arguments = ["gate", str(bundle), gate, status, "--reason", reason_prefix + gate_reason(detail)]
    for item_id in ids:
        arguments.extend(["--evidence", item_id])
    bundle_call(arguments, f"gate {gate}")


def write_bundle(bundle: Path, *, receipt: Path, scenario_path: Path, scenario: dict[str, Any],
                 target: str, work_mode: str, results: list[dict[str, Any]], verdict: dict[str, Any]) -> dict[str, Any]:
    bundle_call(["init", str(bundle), "--title", str(scenario["title"]), "--work-mode", work_mode,
                 "--assessment-mode", "black-box"], "init")
    authorize = ["authorize", str(bundle), str(receipt), "--target", target, "--action", str(scenario["action"])]
    if scenario.get("action_group"):
        authorize.extend(["--action-group", str(scenario["action_group"])])
    bundle_call(authorize, "authorize")

    def add(path: Path, kind: str, observation: str) -> str:
        item = bundle_call(["add", str(bundle), str(path), "--kind", kind, "--observation", observation], "add")
        if not item or "id" not in item:
            raise RunError(f"evidence_bundle add printed no evidence id for {path}")
        return str(item["id"])

    scenario_evidence = add(scenario_path, "scenario-definition",
                            f"The scenario this run replayed, id {scenario['id']}, unchanged.")
    per_step: dict[str, str] = {}
    for item in results:
        if not item.get("artifact_path"):
            continue
        observed = item.get("observed") or {}
        per_step[item["step"]] = add(
            Path(item["artifact_path"]), f"http-transcript-{item['kind']}",
            f"Step {item['step']} ({item['kind']}): {item['method']} {item['url']} answered status "
            f"{observed.get('status')}, {observed.get('body_bytes')} body bytes, marker present "
            f"{observed.get('marker_in_body')}.")

    proof_ids = [per_step[item["step"]] for item in results if item["kind"] == "proof" and item["step"] in per_step]
    control_ids = [per_step[item["step"]] for item in results if item["kind"] == "control" and item["step"] in per_step]
    # The gate status and its reason both come from what was observed. A fixed failure
    # string can name a cause that did not happen, and a reason beside its own evidence
    # is exactly where a second reader is entitled to trust the words.
    gates = verdict.get("gates") or {}
    control_detail = gates.get("control") or {}
    set_gate(bundle, "C1", control_detail, control_ids)
    set_gate(bundle, "P1", gates.get("proof") or {}, proof_ids)

    # B1, the baseline. Added 2026-08-12. Without it the record can never leave the
    # candidate state, because calculate_state wants B1, P1 and C1 together.
    #
    # The control observation IS the baseline here, and that is stated rather than hidden:
    # the same request establishes normal behaviour (the product refuses an anonymous
    # caller on its own route) and rules out the boring explanation (that the document was
    # never gated at all). One observation, two jobs. If a scenario ever needs a baseline
    # that is not its control, it gets its own step and this changes.
    set_gate(bundle, "B1", control_detail, control_ids,
             "Baseline, captured by the control step and shared with C1 deliberately. ")

    # CLAIMS. Added 2026-08-12. The engine rejects a record that has proof gates and no
    # claims, and it is right to: a finding is a statement plus its backing, and gates
    # alone are backing with nothing asserted.
    #
    # Written straight into the record because evidence_bundle.py has no claims
    # subcommand. Every other write in this file goes through the engine. This one cannot,
    # and saying so is better than a silent exception to the rule.
    #
    # One claim per gate that actually observed something, and the statement is built from
    # what was observed rather than from what the scenario hoped for. basis is "observed"
    # because each one is a direct reading of a preserved artifact.
    claims: list[dict[str, Any]] = []
    for label, ids, detail in (("proof", proof_ids, gates.get("proof") or {}),
                               ("control", control_ids, control_detail)):
        if not ids:
            continue
        observations = "; ".join(detail.get("observations") or detail.get("reasons") or [])
        statement = str(detail.get("claim") or f"the {label} step ran").strip()
        if observations:
            statement = f"{statement}. Observed: {observations}"
        if detail.get("state") is not True:
            statement = f"NOT ESTABLISHED. {statement}"
        claims.append({"statement": statement, "basis": "observed", "evidence": list(ids)})
    if claims:
        record_path = bundle / "finding-record.json"
        record = json.loads(record_path.read_text(encoding="utf-8-sig"))
        record["claims"] = claims
        temporary = record_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temporary.replace(record_path)

    return {"scenario_evidence_id": scenario_evidence, "evidence_ids_by_step": per_step,
            "proof_evidence_ids": proof_ids, "control_evidence_ids": control_ids,
            "baseline_evidence_ids": control_ids, "claims_written": len(claims)}


def check_gate_separation(bundle: Path, results: list[dict[str, Any]]) -> dict[str, Any]:
    """Read the record back and prove P1 and C1 do not lean on the same observation.

    Three digests are reported and only the body digest is a test. The file digest covers
    the artifact on disk, and that file carries a header holding its own step id and
    capture time, so two steps can never collide there. The response digest is barely
    better: a Date header moves every second, so two fetches of one file look different
    when they are the same document. The body digest covers the document alone, so two
    steps that saw the same content collide on it. The other two are kept for a reader to
    inspect, never to decide on."""
    record = json.loads((bundle / "finding-record.json").read_text(encoding="utf-8-sig"))
    gates = record.get("gates", {})
    proof = [str(item) for item in gates.get("P1", {}).get("evidence", [])]
    control = [str(item) for item in gates.get("C1", {}).get("evidence", [])]
    digests = {str(item.get("id")): str(item.get("sha256")) for item in record.get("evidence", [])}
    shared_ids = sorted(set(proof) & set(control))

    def digest_of(kind: str, field: str) -> list[str]:
        return sorted({str(item[field]) for item in results
                       if item.get("kind") == kind and item.get(field)})

    proof_bodies, control_bodies = digest_of("proof", "body_sha256"), digest_of("control", "body_sha256")
    shared_bodies = sorted(set(proof_bodies) & set(control_bodies))
    return {
        "p1_evidence": proof, "c1_evidence": control, "shared_evidence_ids": shared_ids,
        "p1_file_sha256": sorted({digests.get(item) for item in proof}),
        "c1_file_sha256": sorted({digests.get(item) for item in control}),
        "p1_response_sha256": digest_of("proof", "response_sha256"),
        "c1_response_sha256": digest_of("control", "response_sha256"),
        "p1_body_sha256": proof_bodies, "c1_body_sha256": control_bodies,
        "shared_body_sha256": shared_bodies,
        "proof_and_control_are_separate_observations": bool(proof_bodies) and bool(control_bodies)
        and not shared_bodies,
        "note": ("The engine's own independent_validation refuses a record where the proof and the control rest "
                 "on the same evidence. This is that rule, applied to this run. The one check here is "
                 "proof_and_control_are_separate_observations, which compares the body digests. The file and "
                 "response digests above it are reported for inspection only."),
    }


def usage_command(command: str, job: str, workdir: Path) -> tuple[int, dict[str, Any]]:
    code, payload, error_text = run_engine(USAGE_SCRIPT, [command, "--job", job, "--workdir", str(workdir)])
    return code, payload or {"available": False, "error": error_text or f"usage {command} exited {code}"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one scenario against one authorised target inside a sandbox and write the evidence bundle.")
    parser.add_argument("--target", required=True, help="Base URL of the application under test. Every request goes here.")
    parser.add_argument("--scope", required=True, type=Path, help="Authorization receipt. A0 checks it before anything runs.")
    parser.add_argument("--scenario", required=True, type=Path, help="Scenario file holding the steps.")
    parser.add_argument("--bundle", required=True, type=Path, help="New, empty directory for the evidence bundle.")
    parser.add_argument("--network", default=DEFAULT_NETWORK, help=f"Docker network for the sandbox. Default: {DEFAULT_NETWORK}")
    parser.add_argument("--job", help="Job id. Defaults to a fresh one. The container is always mask0ff-job-<id>.")
    parser.add_argument("--workdir", type=Path, help="Where job records go. Default: a jobs folder beside the bundle.")
    parser.add_argument("--image", help="Container image for the sandbox. Defaults to the sandbox's own default.")
    parser.add_argument("--max-calls", help="Tool call cap for this job, passed to the sandbox.")
    parser.add_argument("--max-seconds", help="Wall clock cap in seconds, passed to the sandbox.")
    parser.add_argument("--max-usd", help="Cost cap in US dollars, passed to the sandbox.")
    parser.add_argument("--work-mode", choices=("passive", "local-lab", "active-authorized", "unclear"),
                        default="active-authorized", help="Recorded in the bundle. Default: active-authorized.")
    # --now was removed 2026-08-12: a time override must never be able to widen authorisation.
    return parser


def main() -> int:
    args = build_parser().parse_args()
    started = utc_now()
    try:
        scenario = load_json_file(args.scenario.resolve(), "scenario")
        validate_scenario(scenario)
        receipt_path = args.scope.resolve()
        receipt = load_json_file(receipt_path, "authorization receipt")
        raw_receipt = receipt_path.read_bytes()
    except RunError as error:
        emit({"schema_version": SCHEMA_VERSION, "status": "error", "verdict": "inconclusive",
              "error": str(error), "ran_anything": False})
        return SCRIPT_FAILURE_CODE

    # A0 FIRST. Nothing exists yet: no container, no bundle, no request.
    #
    # --now IS DELIBERATELY NOT PASSED HERE, and this is a fix for a real defect found
    # 2026-08-12. It used to be. An expired receipt plus --now set to a date inside its
    # window made the gate pass, created a container and sent three real requests, while
    # the run's own summary said "authorization: pass" and never mentioned that the clock
    # had been moved. A debug flag must never be able to widen authorisation. So the gate
    # always reads the real clock, and the override is recorded below either way, because
    # an override nobody can see is the same as no record at all.
    authorization = authorization_gate.evaluate(
        receipt, target=args.target, action=str(scenario["action"]),
        action_group=str(scenario.get("action_group") or "") or None,
        now_value=None, receipt_sha256=hashlib.sha256(raw_receipt).hexdigest())
    # There was a --now flag here until 2026-08-12. It is gone, and it is not coming back:
    # a time override must never be able to widen authorisation, and this one did. An expired
    # receipt plus --now inside its window made this gate pass, created a container and sent
    # three real requests, while the run's own summary said "authorization: pass" and never
    # mentioned the clock had moved. It was not forwarded to evidence_bundle either, because
    # that script re-validating against the real clock is what caught the expired receipt.
    try:
        runner_gate = runner_authorization(receipt, args.target, str(scenario["action"]))
    except RunError as error:
        runner_gate = {"status": "blocked", "errors": [str(error)]}
    if authorization["status"] != "pass" or runner_gate["status"] != "pass":
        emit({"schema_version": SCHEMA_VERSION, "status": "blocked_by_authorization", "verdict": "inconclusive",
              "target": args.target, "scenario": scenario["id"], "authorization": authorization,
              "runner_authorization": runner_gate, "ran_anything": False,
              "blocked_by": ([] if authorization["status"] == "pass" else ["A0"])
              + ([] if runner_gate["status"] == "pass" else ["runner_scope_and_action"]),
              "note": ("Authorisation refused, so this stopped before anything happened. No container was "
                       "created, no request was sent and no bundle was written. This is a structural stop, "
                       "not a warning. A0 is the upstream gate. The runner gate is the extra one this script "
                       "makes: the port is part of the scope, and the action itself must be named in "
                       "allowed_actions rather than carried in by an allowed group.")})
        return AUTHORIZATION_BLOCKED_EXIT_CODE

    bundle = args.bundle.resolve()
    if bundle.exists() and any(bundle.iterdir()):
        emit({"schema_version": SCHEMA_VERSION, "status": "error", "verdict": "inconclusive",
              "error": f"bundle directory is not empty: {bundle}", "ran_anything": False})
        return SCRIPT_FAILURE_CODE

    job = args.job or f"run{secrets.token_hex(4)}"
    workdir = (args.workdir or bundle.parent / f"{bundle.name}-jobs").resolve()
    argv_dir = workdir / job / "runner" / "argv"
    artifact_dir = workdir / job / "runner" / "artifacts"

    create = ["create", "--job", job, "--workdir", str(workdir), "--network", args.network]
    if args.image:
        create.extend(["--image", args.image])
    for flag, value in (("--max-calls", args.max_calls), ("--max-seconds", args.max_seconds), ("--max-usd", args.max_usd)):
        if value is not None:
            create.extend([flag, str(value)])
    code, created, error_text = run_engine(SANDBOX_SCRIPT, create)
    if code != 0 or not created or created.get("status") != "created":
        emit({"schema_version": SCHEMA_VERSION, "status": "error", "verdict": "inconclusive", "job": job,
              "error": f"sandbox create failed: {error_text}", "ran_anything": False})
        return SCRIPT_FAILURE_CODE

    collected: dict[str, list[str]] = {}
    results: list[dict[str, Any]] = []
    cap_checks: list[dict[str, Any]] = []
    stopped_on_cap = False
    fatal: str | None = None
    verdict: dict[str, Any] = {"verdict": "inconclusive", "reason": "the run did not get far enough to judge"}
    bundle_info: dict[str, Any] = {}
    separation: dict[str, Any] = {}
    bundle_error: str | None = None

    # From here to the finally, the container exists. Everything that can raise lives
    # inside this block, including the two mkdir calls, because a crash between creating
    # the container and entering a guard leaks the container and the teardown promise in
    # the docstring at the top of this file would be a lie.
    try:
        try:
            argv_dir.mkdir(parents=True, exist_ok=True)
            artifact_dir.mkdir(parents=True, exist_ok=True)
            context = RunContext(job=job, workdir=workdir, base=base_of(args.target),
                                 marker=str(scenario["marker"]), argv_dir=argv_dir, artifact_dir=artifact_dir)
            for position, step in enumerate(scenario["steps"], start=1):
                try:
                    result = execute_step(step, context, collected, position)
                except RunError as error:
                    result = {"step": step.get("id"), "kind": step.get("kind"), "state": "error", "error": str(error)}
                results.append(result)
                if result.get("state") == "refused_usage_cap":
                    stopped_on_cap = True
                    break
                check_code, check_payload = usage_command("check", job, workdir)
                cap_checks.append({"after_step": result.get("step"), "exit_code": check_code,
                                   "status": check_payload.get("status", "unknown"),
                                   "totals": check_payload.get("totals"),
                                   "breached_fields": check_payload.get("breached_fields", [])})
                if check_code != 0:
                    stopped_on_cap = True
                    break
        except Exception as error:  # noqa: BLE001 - the sandbox still has to come down
            fatal = f"{type(error).__name__}: {error}"

        verdict = decide_verdict(results)
        cause = fatal or ("the run stopped because a usage cap was breached" if stopped_on_cap else None)
        if cause:
            # The gates are downgraded to unknown rather than dropped. A gate that looked
            # satisfied on a run that never finished is not a fact, but what was seen
            # before the run broke is still worth carrying into the record.
            verdict = {"verdict": "inconclusive", "reason": cause, "gates": {
                name: {**detail, "state": None,
                       "reasons": [f"the run did not finish: {cause}", *(detail.get("reasons") or [])]}
                for name, detail in (verdict.get("gates") or {}).items()}}

        try:
            bundle_info = write_bundle(bundle, receipt=receipt_path, scenario_path=args.scenario.resolve(),
                                       scenario=scenario, target=args.target, work_mode=args.work_mode,
                                       results=results, verdict=verdict)
            separation = check_gate_separation(bundle, results)
        except Exception as error:  # noqa: BLE001 - any failure here is a bundle failure, not a silent one
            bundle_error = f"{type(error).__name__}: {error}"
    except Exception as error:  # noqa: BLE001 - nothing gets out of here without a summary
        fatal = fatal or f"{type(error).__name__}: {error}"
        verdict = {"verdict": "inconclusive", "reason": fatal}
    finally:
        _, usage = usage_command("report", job, workdir)
        destroy_code, destroyed, destroy_error = run_engine(
            SANDBOX_SCRIPT, ["destroy", "--job", job, "--workdir", str(workdir)])

    ran = [item for item in results if item.get("state") == "ran"]
    all_met = len(ran) == len(scenario["steps"]) and all(item.get("expectations_met") for item in ran)
    completed = (all_met and verdict["verdict"] == "bypassable" and not fatal
                 and not bundle_error and not stopped_on_cap
                 # Only the body digests are checked, and that is the whole check. The file
                 # digest comparison that used to sit beside this was removed on 2026-08-12:
                 # each artifact file carries its own step id and capture time in its header,
                 # so two steps can never collide on it and the comparison could not fail.
                 # A condition that cannot fail is not a condition.
                 and separation.get("proof_and_control_are_separate_observations") is True)

    emit({
        "schema_version": SCHEMA_VERSION,
        "status": "completed" if completed else "failed",
        "verdict": verdict["verdict"],
        "verdict_reason": verdict.get("reason", ""),
        "scenario": {"id": scenario["id"], "title": scenario["title"], "file": str(args.scenario.resolve())},
        "target": args.target,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "authorization": {"status": authorization["status"], "authority": authorization["authority"],
                          "policy_reference": authorization["policy_reference"],
                          "receipt_sha256": authorization["receipt_sha256"],
                          "warnings": authorization["warnings"]},
        "runner_authorization": runner_gate,
        "job": job,
        "container": created.get("container_name"),
        "network": args.network,
        "sandbox_egress": created.get("egress"),
        "steps": results,
        "cap_checks_between_steps": cap_checks,
        "stopped_on_usage_cap": stopped_on_cap,
        "bundle": str(bundle),
        "bundle_error": bundle_error,
        "bundle_evidence": bundle_info,
        "proof_and_control_separation": separation,
        "cost": usage,
        "teardown": {"exit_code": destroy_code, "status": (destroyed or {}).get("status", "unknown"),
                     "removed": (destroyed or {}).get("removed"),
                     "error": (destroyed or {}).get("error") or (destroy_error if destroy_code != 0 else None)},
        "fatal_error": fatal,
        "gate_detail": verdict.get("gates", {}),
        "exit_code_note": ("0 only when every step ran, every expectation held, the control was observed to "
                           "refuse, the proof was observed to serve the marked body, the two rest on different "
                           "response bytes and the verdict is bypassable. 1 when the run finished and reached no "
                           "such conclusion. 2 when authorisation refused, either A0 or this runner's own scope "
                           "and action check. 3 when a usage cap stopped it. 4 when the run itself broke, which "
                           "is not the same as a clean negative, and the sandbox was still torn down."),
    })
    if stopped_on_cap:
        return USAGE_BREACH_EXIT_CODE
    if fatal:
        return INTERNAL_ERROR_EXIT_CODE
    return 0 if completed else RUN_FAILED_EXIT_CODE


if __name__ == "__main__":
    raise SystemExit(main())
