#!/usr/bin/env python3
"""Build a searchable SQLite database from GitHub-reviewed OSV advisories."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sqlite3
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "references" / "cases" / "advisory-dataset.sqlite3"


def unique_join(values: Iterable[str]) -> str:
    return " | ".join(sorted({value.strip() for value in values if value and value.strip()}))


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    modified: str
    published: str
    withdrawn: str
    aliases: str
    summary: str
    details: str
    ecosystems: str
    packages: str
    versions: str
    ranges: str
    cwes: str
    severity: str
    cvss_vectors: str
    references_json: str
    affected_json: str
    source_path: str
    source_sha256: str


def range_statement(item: dict[str, Any]) -> str:
    range_type = str(item.get("type", "")).strip()
    repository = str(item.get("repo", "")).strip()
    events = []
    for event in item.get("events", []) or []:
        if not isinstance(event, dict):
            continue
        events.extend(f"{key}={value}" for key, value in event.items() if value is not None)
    return " ".join(part for part in (range_type, repository, ",".join(events)) if part)


def parse_advisory_bytes(raw: bytes, source_path: str) -> Advisory | None:
    try:
        record = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    database = record.get("database_specific", {}) or {}
    if database.get("github_reviewed") is not True:
        return None
    advisory_id = str(record.get("id", "")).strip()
    if not advisory_id.startswith("GHSA-"):
        return None
    affected = record.get("affected", []) or []
    severity_entries = record.get("severity", []) or []
    return Advisory(
        advisory_id=advisory_id,
        modified=str(record.get("modified", "")),
        published=str(record.get("published", "")),
        withdrawn=str(record.get("withdrawn", "") or ""),
        aliases=unique_join(str(value) for value in record.get("aliases", []) or []),
        summary=str(record.get("summary", "")).strip(),
        details=str(record.get("details", "")).strip(),
        ecosystems=unique_join(
            str((item.get("package", {}) or {}).get("ecosystem", ""))
            for item in affected
            if isinstance(item, dict)
        ),
        packages=unique_join(
            str((item.get("package", {}) or {}).get("name", ""))
            for item in affected
            if isinstance(item, dict)
        ),
        versions=unique_join(
            str(version)
            for item in affected
            if isinstance(item, dict)
            for version in (item.get("versions", []) or [])
        ),
        ranges=unique_join(
            range_statement(value)
            for item in affected
            if isinstance(item, dict)
            for value in (item.get("ranges", []) or [])
            if isinstance(value, dict)
        ),
        cwes=unique_join(str(value) for value in database.get("cwe_ids", []) or []),
        severity=str(database.get("severity", "")).upper(),
        cvss_vectors=unique_join(
            f"{item.get('type', '')}:{item.get('score', '')}"
            for item in severity_entries
            if isinstance(item, dict)
        ),
        references_json=json.dumps(record.get("references", []) or [], ensure_ascii=False, separators=(",", ":")),
        affected_json=json.dumps(affected, ensure_ascii=False, separators=(",", ":")),
        source_path=source_path,
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )


def parse_advisory(path: Path, source_root: Path) -> Advisory | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    return parse_advisory_bytes(raw, path.relative_to(source_root).as_posix())


def create_database(output: Path, advisories: list[Advisory], metadata: dict[str, str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    connection = sqlite3.connect(output)
    try:
        connection.executescript(
            """
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE advisories (
                advisory_id TEXT PRIMARY KEY,
                modified TEXT NOT NULL,
                published TEXT NOT NULL,
                withdrawn TEXT NOT NULL,
                aliases TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL,
                ecosystems TEXT NOT NULL,
                packages TEXT NOT NULL,
                versions TEXT NOT NULL,
                ranges TEXT NOT NULL,
                cwes TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_vectors TEXT NOT NULL,
                references_json TEXT NOT NULL,
                affected_json TEXT NOT NULL,
                source_path TEXT NOT NULL,
                source_sha256 TEXT NOT NULL
            );
            CREATE INDEX advisories_modified_idx ON advisories(modified DESC);
            CREATE INDEX advisories_published_idx ON advisories(published DESC);
            CREATE INDEX advisories_severity_idx ON advisories(severity);
            CREATE VIRTUAL TABLE advisories_fts USING fts5(
                advisory_id UNINDEXED,
                aliases,
                summary,
                details,
                ecosystems,
                packages,
                versions,
                ranges,
                cwes,
                tokenize='porter unicode61'
            );
            """
        )
        connection.executemany("INSERT INTO metadata(key, value) VALUES(?, ?)", sorted(metadata.items()))
        connection.executemany(
            "INSERT INTO advisories VALUES(" + ",".join("?" for _ in Advisory.__dataclass_fields__) + ")",
            [tuple(item.__dict__.values()) for item in advisories],
        )
        connection.executemany(
            "INSERT INTO advisories_fts VALUES(?,?,?,?,?,?,?,?,?)",
            [
                (
                    item.advisory_id,
                    item.aliases,
                    item.summary,
                    item.details,
                    item.ecosystems,
                    item.packages,
                    item.versions,
                    item.ranges,
                    item.cwes,
                )
                for item in advisories
            ],
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="GitHub-reviewed directory or pinned GitHub Advisory Database ZIP")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--minimum", type=int, default=30000)
    parser.add_argument("--source-revision", default="unknown")
    parser.add_argument("--source-sha256", default="unknown", help="SHA-256 of the pinned source archive, when used")
    parser.add_argument("--workers", type=int, default=min(32, max(4, (os.cpu_count() or 4) * 2)))
    args = parser.parse_args()

    if args.source_sha256 != "unknown" and not re.fullmatch(r"[0-9a-fA-F]{64}", args.source_sha256):
        parser.error("--source-sha256 must be a 64-character hexadecimal digest or 'unknown'")

    source = args.source.resolve()
    if source.is_file() and source.suffix.lower() == ".zip":
        with zipfile.ZipFile(source) as archive:
            entries = sorted(
                (
                    info
                    for info in archive.infolist()
                    if "/advisories/github-reviewed/" in info.filename and info.filename.endswith(".json")
                ),
                key=lambda info: info.filename,
            )
            advisories = []
            for info in entries:
                item = parse_advisory_bytes(archive.read(info), info.filename)
                if item is not None:
                    advisories.append(item)
    elif source.is_dir():
        paths = sorted(source.rglob("*.json"))
        workers = max(1, min(args.workers, 64))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            parsed = executor.map(lambda path: parse_advisory(path, source), paths, chunksize=64)
            advisories = [item for item in parsed if item is not None]
    else:
        parser.error(f"source directory or ZIP is missing: {source}")
    advisories.sort(key=lambda item: (item.modified, item.published, item.advisory_id), reverse=True)
    if len(advisories) < args.minimum:
        print(f"ERROR: only {len(advisories)} reviewed advisories; need at least {args.minimum}")
        return 1
    metadata = {
        "schema_version": "1",
        "source_name": "GitHub Advisory Database",
        "source_url": "https://github.com/github/advisory-database",
        "source_revision": args.source_revision,
        "source_sha256": args.source_sha256.lower(),
        "source_license": "CC-BY-4.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "record_count": str(len(advisories)),
        "newest_modified": advisories[0].modified,
        "oldest_published": min(item.published for item in advisories if item.published),
        "selection": "all GitHub-reviewed OSV advisories in supplied source tree",
    }
    create_database(args.output.resolve(), advisories, metadata)
    print(json.dumps({**metadata, "output": str(args.output.resolve())}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
