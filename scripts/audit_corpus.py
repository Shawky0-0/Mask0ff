#!/usr/bin/env python3
"""Audit and optionally normalize textual skill assets without touching binary datasets."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
TEXT_EXTENSIONS = {
    ".cmd",
    ".css",
    ".csv",
    ".html",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".toml",
    ".tsv",
    ".txt",
    ".yaml",
    ".yml",
}
CITATION = re.compile("\ue200cite\ue202.*?\ue201", re.DOTALL)
CITATION_MARKERS = {"\ue200", "\ue201", "\ue202"}
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
ALLOWED_CONTROLS = {"\t", "\n", "\r"}


def text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in TEXT_EXTENSIONS:
            yield path


def atomic_write(path: Path, text: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def normalize_corruption(text: str) -> tuple[str, dict[str, int]]:
    counts = {
        "citation_sequences": len(CITATION.findall(text)),
        "citation_markers": sum(text.count(marker) for marker in CITATION_MARKERS),
        "nul": text.count("\x00"),
        "controls": sum(1 for char in text if (ord(char) < 32 or ord(char) == 127) and char not in ALLOWED_CONTROLS),
    }
    text = CITATION.sub("[citation unavailable in inherited source]", text)
    for marker in CITATION_MARKERS:
        text = text.replace(marker, "")
    output = []
    for char in text:
        codepoint = ord(char)
        if char == "\x00":
            output.append(r"\x00")
        elif (codepoint < 32 or codepoint == 127) and char not in ALLOWED_CONTROLS:
            output.append(f"\\x{codepoint:02x}")
        else:
            output.append(char)
    return "".join(output), counts


def broken_links(path: Path, text: str, root: Path) -> list[str]:
    results = []
    prose_lines = []
    fence = None
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        marker = stripped[:3]
        if marker in {"```", "~~~"}:
            if fence is None:
                fence = marker
            elif fence == marker:
                fence = None
            prose_lines.append("\n" if line.endswith("\n") else "")
        elif fence is None:
            prose_lines.append(line)
        else:
            prose_lines.append("\n" if line.endswith("\n") else "")
    prose = re.sub(r"`[^`\n]*`", "", "".join(prose_lines))
    for raw_target in MARKDOWN_LINK.findall(prose):
        target = raw_target.strip().strip("<>").split(maxsplit=1)[0]
        if not target or target.startswith("#") or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target):
            continue
        target_path = unquote(target.split("#", 1)[0]).replace("/", os.sep)
        if not target_path:
            continue
        resolved = (path.parent / target_path).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            results.append(f"escapes skill root: {target}")
            continue
        if not resolved.exists():
            results.append(target)
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--fix-artifacts", action="store_true", help="Escape corrupt controls and replace broken citation markers")
    parser.add_argument("--fail-on-issues", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    files = list(text_files(root))
    findings = []
    fixed_files = []
    totals = {
        "decode_errors": 0,
        "nul": 0,
        "controls": 0,
        "citation_sequences": 0,
        "citation_markers": 0,
        "private_use": 0,
        "broken_links": 0,
        "large_text_files": 0,
    }
    for path in files:
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            totals["decode_errors"] += 1
            findings.append({"file": str(path.relative_to(root)), "decode_error": str(error)})
            continue
        normalized, corruption = normalize_corruption(text)
        for key, value in corruption.items():
            totals[key] += value
        private_use = sum(1 for char in text if 0xE000 <= ord(char) <= 0xF8FF)
        totals["private_use"] += private_use
        links = broken_links(path, normalized if args.fix_artifacts else text, root) if path.suffix.lower() == ".md" else []
        totals["broken_links"] += len(links)
        if len(raw) >= 1024 * 1024:
            totals["large_text_files"] += 1
        if any(corruption.values()) or private_use or links or len(raw) >= 1024 * 1024:
            findings.append(
                {
                    "file": str(path.relative_to(root)),
                    **corruption,
                    "private_use": private_use,
                    "broken_links": links,
                    "bytes": len(raw),
                }
            )
        if args.fix_artifacts and normalized != text:
            atomic_write(path, normalized)
            fixed_files.append(str(path.relative_to(root)))

    payload = {
        "root": str(root),
        "text_files": len(files),
        "totals": totals,
        "fixed_files": fixed_files,
        "findings": findings,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(payload["totals"], indent=2))
        if fixed_files:
            print(f"fixed {len(fixed_files)} files")
        for item in findings:
            print(item["file"])

    blocking = sum(
        totals[key]
        for key in ("decode_errors", "nul", "controls", "citation_sequences", "citation_markers", "broken_links")
    )
    return 1 if args.fail_on_issues and blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
