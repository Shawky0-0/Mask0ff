#!/usr/bin/env python3
"""Build a provenance-rich searchable database from official CVE JSON 5 records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "references" / "cases" / "case-dataset.sqlite3"
METRIC_PRIORITY = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")


@dataclass(frozen=True)
class Case:
    case_id: str
    published: str
    updated: str
    title: str
    summary: str
    cna: str
    vendors: str
    products: str
    purls: str
    versions: str
    cwes: str
    severity: str
    cvss_score: float | None
    cvss_vector: str
    severity_source: str
    adp_providers: str
    known_exploited: int
    references_json: str
    affected_json: str
    metrics_json: str
    ssvc_json: str
    kev_json: str
    source_path: str
    source_sha256: str


def first_english(items: Iterable[dict[str, Any]], key: str = "value") -> str:
    candidates = list(items or [])
    for item in candidates:
        if str(item.get("lang", "")).lower().startswith("en") and item.get(key):
            return str(item[key]).strip()
    for item in candidates:
        if item.get(key):
            return str(item[key]).strip()
    return ""


def unique_join(values: Iterable[str]) -> str:
    return " | ".join(sorted({value.strip() for value in values if value and value.strip()}))


def provider_name(container: dict[str, Any], fallback: str) -> str:
    provider = container.get("providerMetadata", {}) or {}
    return str(provider.get("shortName") or provider.get("orgId") or fallback)


def all_containers(record: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    containers = record.get("containers", {}) or {}
    result: list[tuple[str, dict[str, Any]]] = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        result.append(("CNA", cna))
    for index, adp in enumerate(containers.get("adp", []) or [], 1):
        if isinstance(adp, dict):
            result.append((provider_name(adp, f"ADP-{index}"), adp))
    return result


def metric_records(containers: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for source, container in containers:
        for metric in container.get("metrics", []) or []:
            if isinstance(metric, dict):
                result.append({"source": source, "metric": metric})
    return result


def parse_metric(metrics: list[dict[str, Any]]) -> tuple[str, float | None, str, str]:
    for key in METRIC_PRIORITY:
        candidates: list[tuple[int, str, dict[str, Any]]] = []
        for entry in metrics:
            value = entry["metric"].get(key)
            if not isinstance(value, dict):
                continue
            source = str(entry["source"])
            source_rank = 0 if source == "CNA" else 1
            candidates.append((source_rank, source, value))
        if not candidates:
            continue
        _rank, source, value = sorted(candidates, key=lambda item: (item[0], item[1]))[0]
        severity = str(value.get("baseSeverity", "")).upper()
        score = value.get("baseScore")
        vector = str(value.get("vectorString", ""))
        try:
            parsed_score = float(score) if score is not None else None
        except (TypeError, ValueError):
            parsed_score = None
        return severity, parsed_score, vector, source
    return "", None, "", ""


def cwes_from(container: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for problem in container.get("problemTypes", []) or []:
        for description in problem.get("descriptions", []) or []:
            if description.get("cweId"):
                cwes.append(str(description["cweId"]))
            elif description.get("description"):
                cwes.append(str(description["description"]))
    return cwes


def reference_records(containers: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    references: list[dict[str, Any]] = []
    for source, container in containers:
        for item in container.get("references", []) or []:
            url = str(item.get("url", "")).strip()
            if not url or url in seen:
                continue
            seen.add(url)
            references.append({"url": url, "tags": item.get("tags", []) or [], "source": source})
    return references


def version_statement(version: dict[str, Any]) -> str:
    parts = [str(version.get("version", "")).strip()]
    if version.get("lessThan"):
        parts.append(f"< {version['lessThan']}")
    if version.get("lessThanOrEqual"):
        parts.append(f"<= {version['lessThanOrEqual']}")
    if version.get("status"):
        parts.append(f"[{version['status']}]")
    return " ".join(part for part in parts if part)


def other_metrics(metrics: list[dict[str, Any]], wanted: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for entry in metrics:
        other = entry["metric"].get("other")
        if not isinstance(other, dict):
            continue
        metric_type = str(other.get("type", "")).lower()
        if wanted == "ssvc" and metric_type == "ssvc":
            result.append({"source": entry["source"], **other})
        elif wanted == "kev" and ("kev" in metric_type or "known exploited" in metric_type):
            result.append({"source": entry["source"], **other})
    return result


def parse_case(path: Path, source_root: Path) -> Case | None:
    raw = path.read_bytes()
    try:
        record = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None

    meta = record.get("cveMetadata", {}) or {}
    case_id = str(meta.get("cveId", "")).strip()
    if not case_id or str(meta.get("state", "")).upper() != "PUBLISHED":
        return None

    containers = all_containers(record)
    if not containers:
        return None
    cna = containers[0][1]
    summary = first_english(cna.get("descriptions", []) or [])
    if not summary:
        return None
    title_value = cna.get("title", "")
    title = first_english(title_value if isinstance(title_value, list) else [])
    if not title:
        title = str(title_value).strip() or summary.split(".", 1)[0][:180]

    affected = cna.get("affected", []) or []
    vendors = unique_join(str(item.get("vendor", "")) for item in affected)
    products = unique_join(str(item.get("product", "")) for item in affected)
    purls = unique_join(
        str(item.get("packageURL", ""))
        for item in affected
        if isinstance(item, dict)
    )
    versions = unique_join(
        version_statement(version)
        for item in affected
        for version in (item.get("versions", []) or [])
        if isinstance(version, dict)
    )
    cwes = unique_join(
        cwe
        for _source, container in containers
        for cwe in cwes_from(container)
    )
    metrics = metric_records(containers)
    severity, score, vector, severity_source = parse_metric(metrics)
    ssvc = other_metrics(metrics, "ssvc")
    kev = other_metrics(metrics, "kev")
    providers = unique_join(source for source, _container in containers[1:])
    references = reference_records(containers)

    return Case(
        case_id=case_id,
        published=str(meta.get("datePublished", "")),
        updated=str(meta.get("dateUpdated", "")),
        title=title,
        summary=summary,
        cna=provider_name(cna, "CNA"),
        vendors=vendors,
        products=products,
        purls=purls,
        versions=versions,
        cwes=cwes,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        severity_source=severity_source,
        adp_providers=providers,
        known_exploited=1 if kev else 0,
        references_json=json.dumps(references, ensure_ascii=False, separators=(",", ":")),
        affected_json=json.dumps(affected, ensure_ascii=False, separators=(",", ":")),
        metrics_json=json.dumps(metrics, ensure_ascii=False, separators=(",", ":")),
        ssvc_json=json.dumps(ssvc, ensure_ascii=False, separators=(",", ":")),
        kev_json=json.dumps(kev, ensure_ascii=False, separators=(",", ":")),
        source_path=path.relative_to(source_root).as_posix(),
        source_sha256=hashlib.sha256(raw).hexdigest(),
    )


def date_key(case: Case, sort_by: str) -> tuple[str, str, str]:
    if sort_by == "updated":
        return (case.updated or case.published, case.published, case.case_id)
    return (case.published, case.updated or case.published, case.case_id)


def create_database(output: Path, cases: list[Case], metadata: dict[str, str]) -> None:
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
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY,
                published TEXT NOT NULL,
                updated TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                cna TEXT NOT NULL,
                vendors TEXT NOT NULL,
                products TEXT NOT NULL,
                purls TEXT NOT NULL,
                versions TEXT NOT NULL,
                cwes TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL,
                cvss_vector TEXT NOT NULL,
                severity_source TEXT NOT NULL,
                adp_providers TEXT NOT NULL,
                known_exploited INTEGER NOT NULL CHECK(known_exploited IN (0,1)),
                references_json TEXT NOT NULL,
                affected_json TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                ssvc_json TEXT NOT NULL,
                kev_json TEXT NOT NULL,
                source_path TEXT NOT NULL,
                source_sha256 TEXT NOT NULL
            );
            CREATE INDEX cases_published_idx ON cases(published DESC);
            CREATE INDEX cases_updated_idx ON cases(updated DESC);
            CREATE INDEX cases_severity_idx ON cases(severity);
            CREATE INDEX cases_kev_idx ON cases(known_exploited);
            CREATE VIRTUAL TABLE cases_fts USING fts5(
                case_id UNINDEXED,
                title,
                summary,
                cna,
                vendors,
                products,
                purls,
                versions,
                cwes,
                adp_providers,
                tokenize='porter unicode61'
            );
            """
        )
        connection.executemany("INSERT INTO metadata(key, value) VALUES(?, ?)", sorted(metadata.items()))
        rows = [tuple(case.__dict__.values()) for case in cases]
        connection.executemany(
            "INSERT INTO cases VALUES(" + ",".join("?" for _ in Case.__dataclass_fields__) + ")",
            rows,
        )
        connection.executemany(
            "INSERT INTO cases_fts VALUES(?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    case.case_id,
                    case.title,
                    case.summary,
                    case.cna,
                    case.vendors,
                    case.products,
                    case.purls,
                    case.versions,
                    case.cwes,
                    case.adp_providers,
                )
                for case in cases
            ],
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sources", nargs="+", type=Path, help="One or more directories containing official CVE JSON 5 files")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=12500, help="Newest records to retain")
    parser.add_argument("--minimum", type=int, default=10001, help="Fail if fewer records are available")
    parser.add_argument("--sort-by", choices=("published", "updated"), default="published")
    parser.add_argument("--source-revision", default="unknown")
    parser.add_argument("--source-url", default="https://github.com/CVEProject/cvelistV5")
    args = parser.parse_args()

    sources = [source.resolve() for source in args.sources]
    missing = [str(source) for source in sources if not source.is_dir()]
    if missing:
        parser.error(f"source directories are missing: {', '.join(missing)}")
    source_root = Path(os.path.commonpath([str(source) for source in sources]))
    paths = sorted({path for source in sources for path in source.rglob("CVE-*.json")})
    cases = [case for path in paths if (case := parse_case(path, source_root)) is not None]
    cases.sort(key=lambda case: date_key(case, args.sort_by), reverse=True)
    cases = cases[: args.limit]
    if len(cases) < args.minimum:
        print(f"ERROR: only {len(cases)} usable published cases; need at least {args.minimum}")
        return 1

    metadata = {
        "schema_version": "2",
        "source_name": "CVE List V5",
        "source_url": args.source_url,
        "source_revision": args.source_revision,
        "source_license": "CVE Program Terms of Use",
        "source_terms": "https://www.cve.org/Legal/TermsOfUse",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "record_count": str(len(cases)),
        "newest_published": max(case.published for case in cases),
        "oldest_published": min(case.published for case in cases),
        "newest_updated": max(case.updated or case.published for case in cases),
        "oldest_updated": min(case.updated or case.published for case in cases),
        "selection": f"newest {len(cases)} records by {args.sort_by} timestamp from {len(sources)} supplied source tree(s)",
        "containers": "CNA plus CVE Program and all available ADP enrichment containers",
    }
    create_database(args.output.resolve(), cases, metadata)
    print(json.dumps({**metadata, "output": str(args.output.resolve())}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
