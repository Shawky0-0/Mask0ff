#!/usr/bin/env python3
"""Refresh official CVE sources and transactionally replace the case database."""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATABASE = ROOT / "references" / "cases" / "case-dataset.sqlite3"


def run(command: list[str]) -> None:
    result = subprocess.run(command, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}")


def capture(command: list[str]) -> str:
    result = subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"command failed: {' '.join(command)}")
    return result.stdout.strip()


def validate_database(path: Path, minimum: int, expected_revision: str) -> int:
    connection = sqlite3.connect(path)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        count = int(connection.execute("SELECT count(*) FROM cases").fetchone()[0])
        fts = int(connection.execute("SELECT count(*) FROM cases_fts").fetchone()[0])
        distinct = int(connection.execute("SELECT count(DISTINCT case_id) FROM cases").fetchone()[0])
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    finally:
        connection.close()
    if integrity != "ok" or count < minimum or count != fts or count != distinct:
        raise RuntimeError(
            f"database verification failed: integrity={integrity} cases={count} fts={fts} distinct={distinct}"
        )
    if metadata.get("schema_version") != "2":
        raise RuntimeError(f"unexpected database schema: {metadata.get('schema_version')!r}")
    if metadata.get("source_revision") != expected_revision:
        raise RuntimeError("database source revision does not match the checked-out source")
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path, help="Local checkout of CVEProject/cvelistV5")
    parser.add_argument("--years", nargs="+", help="Source years; default is current and previous year")
    parser.add_argument("--year", action="append", help="Backward-compatible repeatable single-year option")
    parser.add_argument("--git", default="git")
    parser.add_argument("--pull", action="store_true", help="Run an explicit fast-forward-only network update")
    parser.add_argument("--limit", type=int, default=12500)
    parser.add_argument("--minimum", type=int, default=10001)
    parser.add_argument("--sort-by", choices=("published", "updated"), default="published")
    args = parser.parse_args()

    repo = args.repo.resolve()
    if not (repo / ".git").exists():
        parser.error(f"not a Git checkout: {repo}")
    git = [args.git, "-c", f"safe.directory={repo}", "-C", str(repo)]
    remote = capture([*git, "remote", "get-url", "origin"])
    normalized = remote.lower().removesuffix(".git")
    if normalized not in {
        "https://github.com/cveproject/cvelistv5",
        "git@github.com:cveproject/cvelistv5",
    }:
        parser.error(f"unexpected origin: {remote}")
    dirty = capture([*git, "status", "--porcelain", "--untracked-files=normal"])
    if dirty:
        parser.error("source checkout has tracked or untracked changes; use a clean official checkout")
    if args.pull:
        run([*git, "pull", "--ff-only"])
    dirty = capture([*git, "status", "--porcelain", "--untracked-files=normal"])
    if dirty:
        parser.error("source checkout became dirty during update")
    revision = capture([*git, "rev-parse", "HEAD"])

    current_year = datetime.now(timezone.utc).year
    years = args.year or args.years or [str(current_year), str(current_year - 1)]
    years = list(dict.fromkeys(str(year) for year in years))
    sources = [repo / "cves" / year for year in years]
    missing = [str(source) for source in sources if not source.is_dir()]
    if missing:
        parser.error(f"year directories are missing: {', '.join(missing)}")

    temporary = DATABASE.with_name(".case-dataset.sqlite3.new")
    rollback = DATABASE.with_name(".case-dataset.sqlite3.rollback")
    if temporary.exists() or rollback.exists():
        raise RuntimeError(
            f"stale transaction file exists; inspect before retrying: {temporary if temporary.exists() else rollback}"
        )

    build_command = [
        sys.executable,
        str(ROOT / "scripts" / "build_case_db.py"),
        *(str(source) for source in sources),
        "--output",
        str(temporary),
        "--limit",
        str(args.limit),
        "--minimum",
        str(args.minimum),
        "--source-revision",
        revision,
        "--sort-by",
        args.sort_by,
    ]
    run(build_command)
    count = validate_database(temporary, args.minimum, revision)
    run(
        [
            sys.executable,
            str(ROOT / "evals" / "run_evals.py"),
            "--require-dataset",
            "--minimum-cases",
            str(args.minimum),
            "--database",
            str(temporary),
        ]
    )

    if DATABASE.exists():
        shutil.copy2(DATABASE, rollback)
    try:
        os.replace(temporary, DATABASE)
        run([sys.executable, str(ROOT / "scripts" / "build_manifest.py")])
        run([sys.executable, str(ROOT / "evals" / "run_evals.py"), "--require-dataset"])
        run([sys.executable, str(ROOT / "scripts" / "verify_integrity.py")])
    except Exception:
        if rollback.exists():
            os.replace(rollback, DATABASE)
            run([sys.executable, str(ROOT / "scripts" / "build_manifest.py")])
        raise
    finally:
        if temporary.exists():
            temporary.unlink()
    if rollback.exists():
        rollback.unlink()

    print(f"Updated {DATABASE} with {count} cases from {revision} using years {', '.join(years)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
