#!/usr/bin/env python3
"""Build a deterministic SHA-256 manifest for the mask0ff skill."""

from __future__ import annotations

import hashlib
from pathlib import Path

from audit_corpus import GitBlobReader, is_text_path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
TRANSACTION_SUFFIXES = (".new", ".rollback")


def tracked_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path == MANIFEST or ".git" in path.parts:
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


def file_bytes(path: Path, reader: GitBlobReader) -> bytes:
    if is_text_path(path):
        return reader.read(path)[0]
    return path.read_bytes()


def main() -> int:
    reader = GitBlobReader(ROOT)
    try:
        lines = [
            f"{hashlib.sha256(file_bytes(path, reader)).hexdigest()}  {path.relative_to(ROOT).as_posix()}"
            for path in tracked_files()
        ]
    finally:
        reader.close()
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {MANIFEST} with {len(lines)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
