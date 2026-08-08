#!/usr/bin/env python3
"""Build deterministic Codex and OpenCode mask0ff ZIP distributions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath


EXCLUDED_PARTS = {"__pycache__", ".git", ".pytest_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".tmp"}
SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def files(root: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in root.rglob("*")
            if path.is_file()
            and not any(part in EXCLUDED_PARTS for part in path.parts)
            and path.suffix.lower() not in EXCLUDED_SUFFIXES
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def write_zip(path: Path, entries: list[tuple[Path, PurePosixPath]]) -> None:
    if path.exists():
        raise ValueError(f"refusing to overwrite existing package: {path}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source, destination in entries:
            info = zipfile.ZipInfo(destination.as_posix(), date_time=(2026, 8, 2, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if source.suffix.lower() in {".sh", ".py"} else 0o644
            info.external_attr = mode << 16
            archive.writestr(info, source.read_bytes())
    temporary.replace(path)


def validate_skill_identity(skill: Path) -> None:
    skill_file = skill / "SKILL.md"
    if not skill_file.is_file():
        raise ValueError("SKILL.md is missing")
    text = skill_file.read_text(encoding="utf-8-sig")
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md frontmatter is missing")
    match = re.search(r"^name:\s*([^\r\n]+)$", text, re.MULTILINE)
    if not match:
        raise ValueError("SKILL.md name is missing")
    name = match.group(1).strip().strip('"\'')
    if name != "mask0ff" or not SKILL_NAME.fullmatch(name):
        raise ValueError(f"unexpected skill identity: {name!r}; expected 'mask0ff'")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create separately installable Codex and OpenCode packages.")
    parser.add_argument("skill", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--version", default="v4")
    args = parser.parse_args()
    try:
        skill = args.skill.resolve()
        output_dir = args.output_dir.resolve()
        validate_skill_identity(skill)
        opencode_agent = skill / "assets" / "opencode" / "agents" / "mask0ff.md"
        opencode_config = skill / "assets" / "opencode" / "opencode.json"
        if not opencode_agent.is_file() or not opencode_config.is_file():
            raise ValueError("OpenCode adapter assets are missing")
        json.loads(opencode_config.read_text(encoding="utf-8"))
        output_dir.mkdir(parents=True, exist_ok=True)
        skill_files = files(skill)
        codex_path = output_dir / f"mask0ff-codex-{args.version}.zip"
        opencode_path = output_dir / f"mask0ff-opencode-{args.version}.zip"
        codex_entries = [
            (source, PurePosixPath("mask0ff") / source.relative_to(skill).as_posix())
            for source in skill_files
        ]
        opencode_entries = [
            (source, PurePosixPath(".opencode/skills/mask0ff") / source.relative_to(skill).as_posix())
            for source in skill_files
        ]
        opencode_entries.extend(
            [
                (opencode_agent, PurePosixPath(".opencode/agents/mask0ff.md")),
                (opencode_config, PurePosixPath("opencode.json")),
            ]
        )
        write_zip(codex_path, codex_entries)
        write_zip(opencode_path, opencode_entries)
        result = {"skill_files": len(skill_files), "packages": []}
        for kind, path in (("codex", codex_path), ("opencode", opencode_path)):
            sha256 = digest(path)
            sha_path = path.with_suffix(path.suffix + ".sha256")
            sha_path.write_text(f"{sha256}  {path.name}\n", encoding="ascii")
            result["packages"].append(
                {
                    "kind": kind,
                    "path": str(path),
                    "bytes": path.stat().st_size,
                    "sha256": sha256,
                    "sha256_file": str(sha_path),
                }
            )
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
