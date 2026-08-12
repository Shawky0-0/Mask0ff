#!/usr/bin/env python3
"""Connected command router for the mask0ff research workflow."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

# cmd.exe reinterprets these before any program sees them. An ampersand or a pipe
# ends the command and starts a new one on the Windows host. A caret is cmd.exe's
# own escape character and is eaten with no error. Angle brackets redirect. All of
# them change the command silently, which is the failure this router refuses to pass on.
CMD_METACHARACTERS = "&|^<>"
WRAPPER_NAME = "mask0ff.cmd"
CANARY_FLAG = "--mask0ff-wrapper-end="
MANGLED_EXIT_CODE = 126


COMMANDS = {
    "advisories": "query_advisories.py",
    "assess": "assess_finding.py",
    "auth": "authorization_gate.py",
    "audit": "audit_corpus.py",
    "bundle": "evidence_bundle.py",
    "cases": "query_cases.py",
    "duplicate": "duplicate_check.py",
    "finding": "verify_finding.py",
    "graph": "security_graph.py",
    "integrity": "verify_integrity.py",
    "challenge": "independent_validation.py",
    "opencode": "validate_opencode.py",
    "outcome": "outcome_ledger.py",
    "owner-matrix": "owner_matrix.py",
    "plan": "plan_engagement.py",
    "profile": "program_profile.py",
    "race": "race_condition.py",
    "report": "report_lint.py",
    "run": "run_assessment.py",
    "redact": "redact_artifact.py",
    "sandbox": "sandbox.py",
    "search": "search_library.py",
    "session": "session_profile.py",
    "sources": "source_status.py",
    "techniques": "query_techniques.py",
    "toolbox": "tool_inventory.py",
    "triage": "triage_report.py",
    "triage-review": "triage_review.py",
    "update-advisories": "update_advisory_db.py",
    "update-cases": "update_case_db.py",
    "usage": "usage_tracker.py",
    "versions": "version_matrix.py",
    "weird": "weird_surface.py",
}


def wrapper_line_check(arguments: list[str]) -> dict[str, object] | None:
    """Report whether cmd.exe altered the command line before Python saw it.

    Returns None when there is nothing to check, which is every path that does not
    go through the Windows .cmd wrapper. Two independent detectors run, because
    neither catches everything on its own.

    The canary is the stronger one. The wrapper puts a one time token at the end of
    the line, after the user's arguments. If it arrives whole and last, the line
    reached Python in one piece. If it was swallowed into the argument before it, or
    is missing, then cmd.exe and the C runtime disagreed about where a quoted word
    ended, which is the same disagreement that lets an ampersand or a pipe escape.

    The raw line check is the second. MASK0FF_RAW_CMDLINE holds the command line as
    cmd.exe received it, before it reinterpreted anything, so characters it is about
    to act on are visible there even when the argument list looks reasonable. It has
    a blind spot: a pipe gives each side its own process and its own shortened line,
    so the pipe itself never appears. That is what the canary is for.
    """
    token = os.environ.get("MASK0FF_WRAPPER_TOKEN")
    raw = os.environ.get("MASK0FF_RAW_CMDLINE")
    if not token and not raw:
        return None

    canary_intact = True
    if token:
        expected = f"{CANARY_FLAG}{token}"
        canary_intact = bool(arguments) and arguments[-1] == expected

    index = raw.lower().rfind(WRAPPER_NAME) if raw else -1
    tail = raw[index + len(WRAPPER_NAME):] if (raw and index != -1) else (raw or "")
    found = sorted({character for character in tail if character in CMD_METACHARACTERS})
    return {
        "raw_command_line": raw,
        "argument_text": tail,
        "wrapper_located_in_line": index != -1,
        "metacharacters_found": found,
        "canary_intact": canary_intact,
        "arguments_after_canary_removed": arguments[:-1] if (token and canary_intact) else arguments,
    }


def refuse_mangled_line(report: dict[str, object]) -> int:
    """Stop before dispatching, and tell the wrapper to end cmd.exe outright."""
    # The marker tells the wrapper to end cmd.exe outright rather than return to it.
    # Only do that when the raw line shows this cmd.exe was started to run the wrapper
    # and nothing else. At an interactive prompt that is not true, and ending cmd.exe
    # would close the operator's window.
    marker = os.environ.get("MASK0FF_MANGLE_MARKER")
    if marker and report["wrapper_located_in_line"]:
        try:
            Path(marker).write_text("mangled\n", encoding="utf-8")
        except OSError:
            pass
    reasons = []
    if not report["canary_intact"]:
        reasons.append("wrapper_canary_missing_or_absorbed")
    if report["metacharacters_found"]:
        reasons.append("cmd_metacharacter_in_wrapper_command_line")
    payload = {
        "schema_version": 1,
        "status": "refused",
        "reasons": reasons,
        "canary_intact": report["canary_intact"],
        "metacharacters_found": report["metacharacters_found"],
        "argument_text_as_typed": report["argument_text"],
        "argument_text_as_received": sys.argv[1:],
        "explanation": (
            "cmd.exe rewrites these characters before Python is started. An ampersand or a pipe "
            "splits the line and runs the rest on this Windows machine, outside every container. "
            "A caret is deleted. Nothing was run inside any container."
        ),
        "residual_risk": (
            "With an ampersand the rest of the line has not run yet and the wrapper ends cmd.exe "
            "before it can. With a pipe the other side of the pipe was already started by cmd.exe "
            "in its own process, so it runs whatever it was given and its exit code is the one the "
            "caller sees. No .cmd file can prevent that. Do not put a pipe in a wrapper argument."
        ),
        "what_to_do": (
            "For 'sandbox exec', pass the command as base64 with --argv-b64, or in a file with "
            "--argv-file. Those carry no characters cmd.exe reacts to. For any other command, "
            "call scripts/mask0ff.py with Python directly."
        ),
    }
    rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    # When the caller put a pipe in an argument, our stdout is that pipe and the
    # far end is whatever cmd.exe started, which is not reading. Writing there
    # fails. The refusal has to survive that, so it goes to stderr as well.
    try:
        sys.stdout.write(rendered + "\n")
        sys.stdout.flush()
        delivered = True
    except OSError:
        delivered = False
        try:
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
        except OSError:
            pass
    print("ERROR: refusing to run, cmd.exe altered the command line. Nothing was executed.", file=sys.stderr)
    if not delivered:
        print(rendered, file=sys.stderr)
    return MANGLED_EXIT_CODE


def main() -> int:
    arguments = sys.argv[1:]
    report = wrapper_line_check(arguments)
    if report is not None:
        if not report["canary_intact"] or report["metacharacters_found"]:
            return refuse_mangled_line(report)
        sys.argv = [sys.argv[0], *report["arguments_after_canary_removed"]]
    parser = argparse.ArgumentParser(
        description="Route mask0ff scope, session, planning, evidence, research, verification, and reporting commands."
    )
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = [sys.executable, str(SCRIPTS / COMMANDS[args.command]), *args.arguments]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
