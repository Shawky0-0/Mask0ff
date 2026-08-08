#!/usr/bin/env python3
"""Verify the mask0ff corpus against MANIFEST.sha256."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def actual_files() -> set[str]:
    result: set[str] = set()
    for path in ROOT.rglob("*"):
        if not path.is_file() or path == MANIFEST:
            continue
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        result.add(path.relative_to(ROOT).as_posix())
    return result


def main() -> int:
    if not MANIFEST.exists():
        print("ERROR: MANIFEST.sha256 is missing")
        return 1

    expected: dict[str, str] = {}
    malformed: list[str] = []
    for number, line in enumerate(MANIFEST.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            digest, relative = line.split("  ", 1)
        except ValueError:
            malformed.append(f"line {number}: {line}")
            continue
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            malformed.append(f"line {number}: invalid digest")
            continue
        expected[relative] = digest.lower()

    missing: list[str] = []
    mismatched: list[str] = []
    for relative, digest in expected.items():
        path = ROOT / Path(relative)
        if not path.is_file():
            missing.append(relative)
        elif sha256(path) != digest:
            mismatched.append(relative)

    extras = sorted(actual_files() - set(expected))
    print(
        f"manifest={len(expected)} malformed={len(malformed)} "
        f"missing={len(missing)} mismatched={len(mismatched)} extras={len(extras)}"
    )
    for label, values in (
        ("MALFORMED", malformed),
        ("MISSING", missing),
        ("MISMATCH", mismatched),
        ("EXTRA", extras),
    ):
        for value in values:
            print(f"{label}: {value}")
    return 1 if any((malformed, missing, mismatched, extras)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
