#!/usr/bin/env python3
"""Compare bundled research dataset revisions with official upstream HEADs."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    {
        "name": "CVE List V5",
        "database": ROOT / "references" / "cases" / "case-dataset.sqlite3",
        "url": "https://github.com/CVEProject/cvelistV5.git",
    },
    {
        "name": "GitHub Advisory Database",
        "database": ROOT / "references" / "cases" / "advisory-dataset.sqlite3",
        "url": "https://github.com/github/advisory-database.git",
    },
)


def resolve_git(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    discovered = shutil.which("git")
    if discovered:
        return discovered
    profile = os.environ.get("USERPROFILE")
    if profile:
        bundled = (
            Path(profile)
            / ".cache"
            / "codex-runtimes"
            / "codex-primary-runtime"
            / "dependencies"
            / "native"
            / "git"
            / "cmd"
            / "git.exe"
        )
        if bundled.is_file():
            return str(bundled)
    return None


def database_metadata(path: Path) -> tuple[dict[str, str], str]:
    if not path.is_file():
        return {}, "missing"
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        finally:
            connection.close()
        return metadata, integrity
    except sqlite3.Error as error:
        return {}, f"error: {error}"


def remote_head(git: str, url: str, timeout: float) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(
            [git, "ls-remote", url, "HEAD"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(1.0, timeout),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, str(error)
    if result.returncode:
        return None, result.stderr.strip() or f"git exited {result.returncode}"
    fields = result.stdout.strip().split()
    if not fields or len(fields[0]) != 40:
        return None, "upstream returned no valid HEAD revision"
    return fields[0].lower(), None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git", help="Git executable; auto-detected by default")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-source network timeout in seconds")
    parser.add_argument("--offline", action="store_true", help="Inspect local provenance without network access")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    git = resolve_git(args.git)
    results = []
    for source in SOURCES:
        metadata, integrity = database_metadata(source["database"])
        local_revision = metadata.get("source_revision")
        remote_revision = None
        error = None
        if not args.offline:
            if git:
                remote_revision, error = remote_head(git, source["url"], args.timeout)
            else:
                error = "Git executable not found"

        if integrity != "ok":
            status = "invalid" if integrity != "missing" else "missing"
        elif args.offline:
            status = "offline"
        elif error:
            status = "unknown"
        elif local_revision == remote_revision:
            status = "current"
        else:
            status = "update-available"
        results.append(
            {
                "name": source["name"],
                "database": str(source["database"]),
                "source_url": source["url"],
                "status": status,
                "integrity": integrity,
                "local_revision": local_revision,
                "remote_revision": remote_revision,
                "record_count": metadata.get("record_count"),
                "generated_at_utc": metadata.get("generated_at_utc"),
                "source_license": metadata.get("source_license"),
                "source_terms": metadata.get("source_terms"),
                "source_sha256": metadata.get("source_sha256"),
                "error": error,
            }
        )

    payload = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "network_used": not args.offline,
        "sources": results,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for item in results:
            print(f"{item['status']:16} {item['name']}")
            print(f"  local:  {item['local_revision'] or '-'}")
            print(f"  remote: {item['remote_revision'] or '-'}")
            print(f"  records: {item['record_count'] or '-'}  integrity: {item['integrity']}")
            if item["error"]:
                print(f"  check error: {item['error']}")
    return 1 if any(item["status"] in {"invalid", "missing"} for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
