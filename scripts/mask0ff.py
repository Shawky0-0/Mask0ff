#!/usr/bin/env python3
"""Connected command router for the mask0ff research workflow."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


COMMANDS = {
    "advisories": "query_advisories.py",
    "assess": "assess_finding.py",
    "auth": "authorization_gate.py",
    "audit": "audit_corpus.py",
    "bundle": "evidence_bundle.py",
    "cases": "query_cases.py",
    "duplicate": "duplicate_check.py",
    "finding": "verify_finding.py",
    "integrity": "verify_integrity.py",
    "challenge": "independent_validation.py",
    "opencode": "validate_opencode.py",
    "plan": "plan_engagement.py",
    "profile": "program_profile.py",
    "race": "race_condition.py",
    "report": "report_lint.py",
    "redact": "redact_artifact.py",
    "search": "search_library.py",
    "session": "session_profile.py",
    "sources": "source_status.py",
    "techniques": "query_techniques.py",
    "toolbox": "tool_inventory.py",
    "update-advisories": "update_advisory_db.py",
    "update-cases": "update_case_db.py",
    "versions": "version_matrix.py",
}


def main() -> int:
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
