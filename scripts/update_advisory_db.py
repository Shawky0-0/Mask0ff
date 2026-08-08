#!/usr/bin/env python3
"""Transactionally build and replace the GitHub-reviewed advisory database."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATABASE = ROOT / "references" / "cases" / "advisory-dataset.sqlite3"


def run(command: list[str]) -> None:
    result = subprocess.run(command, check=False)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_archive(path: Path, minimum: int, expected_revision: str) -> int:
    try:
        with zipfile.ZipFile(path) as archive:
            reviewed_names = [
                name
                for name in archive.namelist()
                if "/advisories/github-reviewed/" in name and name.endswith(".json")
            ]
            count = len(reviewed_names)
            roots = {name.split("/", 1)[0] for name in reviewed_names}
            if count < minimum:
                raise RuntimeError(f"archive has only {count} reviewed advisories; requires {minimum}")
            expected_root = f"advisory-database-{expected_revision}"
            if roots != {expected_root}:
                raise RuntimeError(f"archive root {sorted(roots)!r} does not match declared revision {expected_revision}")
            bad = archive.testzip()
            if bad:
                raise RuntimeError(f"archive CRC failure: {bad}")
    except zipfile.BadZipFile as error:
        raise RuntimeError(f"invalid advisory ZIP: {error}") from error
    return count


def validate_database(path: Path, minimum: int, expected_revision: str) -> int:
    connection = sqlite3.connect(path)
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        count = int(connection.execute("SELECT count(*) FROM advisories").fetchone()[0])
        fts = int(connection.execute("SELECT count(*) FROM advisories_fts").fetchone()[0])
        distinct = int(connection.execute("SELECT count(DISTINCT advisory_id) FROM advisories").fetchone()[0])
        invalid_hashes = int(
            connection.execute("SELECT count(*) FROM advisories WHERE length(source_sha256) != 64").fetchone()[0]
        )
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
    finally:
        connection.close()
    if integrity != "ok" or count < minimum or count != fts or count != distinct or invalid_hashes:
        raise RuntimeError(
            "database verification failed: "
            f"integrity={integrity} advisories={count} fts={fts} distinct={distinct} invalid_hashes={invalid_hashes}"
        )
    if metadata.get("schema_version") != "1":
        raise RuntimeError(f"unexpected database schema: {metadata.get('schema_version')!r}")
    if metadata.get("source_revision") != expected_revision:
        raise RuntimeError("database source revision does not match the declared source")
    if metadata.get("source_license") != "CC-BY-4.0":
        raise RuntimeError("database source license provenance is missing")
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path, help="Pinned GitHub Advisory Database ZIP archive")
    parser.add_argument("--source-revision", required=True, help="Full 40-character upstream Git revision")
    parser.add_argument("--archive-sha256", help="Expected SHA-256 for the supplied archive")
    parser.add_argument("--minimum", type=int, default=30000)
    args = parser.parse_args()

    archive = args.archive.resolve()
    revision = args.source_revision.lower()
    if not archive.is_file():
        parser.error(f"archive is missing: {archive}")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        parser.error("--source-revision must be a full 40-character hexadecimal Git revision")
    actual_sha256 = sha256_file(archive)
    if args.archive_sha256 and actual_sha256.lower() != args.archive_sha256.lower():
        raise RuntimeError(
            f"archive SHA-256 mismatch: expected {args.archive_sha256.lower()}, got {actual_sha256.lower()}"
        )
    reviewed_count = validate_archive(archive, args.minimum, revision)

    temporary = DATABASE.with_name(".advisory-dataset.sqlite3.new")
    rollback = DATABASE.with_name(".advisory-dataset.sqlite3.rollback")
    if temporary.exists() or rollback.exists():
        raise RuntimeError(
            f"stale transaction file exists; inspect before retrying: {temporary if temporary.exists() else rollback}"
        )

    run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_advisory_db.py"),
            str(archive),
            "--output",
            str(temporary),
            "--minimum",
            str(args.minimum),
            "--source-revision",
            revision,
            "--source-sha256",
            actual_sha256,
        ]
    )
    count = validate_database(temporary, args.minimum, revision)
    run(
        [
            sys.executable,
            str(ROOT / "evals" / "run_evals.py"),
            "--require-dataset",
            "--minimum-advisories",
            str(args.minimum),
            "--advisory-database",
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

    print(
        f"Updated {DATABASE} with {count} advisories from {revision}; "
        f"archive had {reviewed_count} reviewed JSON files and SHA-256 {actual_sha256}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
