#!/usr/bin/env python3
"""Build a deterministic SHA-256 manifest for the mask0ff skill."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
TRANSACTION_SUFFIXES = (".new", ".rollback")


def tracked_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path == MANIFEST:
            continue
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        # Database updaters deliberately keep recoverable transaction copies
        # while the replacement is evaluated. They are runtime state, not
        # distributable skill content, and must never enter the stable manifest.
        if path.name.startswith(".") and path.name.endswith(TRANSACTION_SUFFIXES):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(ROOT).as_posix())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    lines = [f"{sha256(path)}  {path.relative_to(ROOT).as_posix()}" for path in tracked_files()]
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {MANIFEST} with {len(lines)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
