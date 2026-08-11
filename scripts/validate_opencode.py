#!/usr/bin/env python3
"""Validate an extracted OpenCode mask0ff distribution."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def frontmatter(text: str) -> str:
    normalized = text.replace("\r\n", "\n")
    if not normalized.startswith("---\n"):
        raise ValueError("Markdown frontmatter is missing")
    end = normalized.find("\n---\n", 4)
    if end < 0:
        raise ValueError("Markdown frontmatter is not closed")
    return normalized[4:end]


def scalar(block: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}:\s*(.+?)\s*$", block, re.MULTILINE)
    return match.group(1).strip().strip('"\'') if match else ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Check OpenCode skill discovery and primary-agent adapter files.")
    parser.add_argument("root", type=Path, help="Extracted package root containing .opencode")
    args = parser.parse_args()
    try:
        root = args.root.resolve()
        skill = root / ".opencode" / "skills" / "mask0ff"
        skill_file = skill / "SKILL.md"
        agent_file = root / ".opencode" / "agents" / "mask0ff.md"
        config_file = root / "opencode.json"
        errors: list[str] = []
        if not skill_file.is_file():
            errors.append(".opencode/skills/mask0ff/SKILL.md is missing")
        else:
            skill_frontmatter = frontmatter(skill_file.read_text(encoding="utf-8-sig"))
            name = scalar(skill_frontmatter, "name")
            description = scalar(skill_frontmatter, "description")
            if name != "mask0ff" or not NAME.fullmatch(name):
                errors.append("OpenCode skill name is invalid or does not match its directory")
            if not 1 <= len(description) <= 1024:
                errors.append("OpenCode skill description length is invalid")
        if not agent_file.is_file():
            errors.append(".opencode/agents/mask0ff.md is missing")
        else:
            agent_text = agent_file.read_text(encoding="utf-8-sig")
            agent_frontmatter = frontmatter(agent_text)
            if not scalar(agent_frontmatter, "description"):
                errors.append("OpenCode agent description is missing")
            if scalar(agent_frontmatter, "mode") != "primary":
                errors.append("OpenCode mask0ff agent must use mode: primary")
            if "maxSteps:" in agent_frontmatter:
                errors.append("deprecated OpenCode maxSteps field is present")
            for required in ("bash: allow", "webfetch: allow", "websearch: allow", "mask0ff"):
                if required not in agent_frontmatter:
                    errors.append(f"OpenCode agent frontmatter lacks {required!r}")
        if not config_file.is_file():
            errors.append("opencode.json is missing")
            config = {}
        else:
            try:
                config = json.loads(config_file.read_text(encoding="utf-8-sig"))
            except json.JSONDecodeError:
                errors.append("opencode.json is not valid JSON")
                config = {}
            if not isinstance(config, dict):
                errors.append("opencode.json must be a JSON object")
                config = {}
            if config.get("$schema") != "https://opencode.ai/config.json":
                errors.append("opencode.json schema URL is invalid")
            permissions = config.get("permission")
            globally_allowed = permissions == "allow"
            skill_allowed = (
                isinstance(permissions, dict)
                and isinstance(permissions.get("skill"), dict)
                and permissions["skill"].get("mask0ff") == "allow"
            )
            if not globally_allowed and not skill_allowed:
                errors.append("opencode.json does not allow the mask0ff skill")
        cache_files = [
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and (path.suffix.lower() in {".pyc", ".pyo"} or "__pycache__" in path.parts)
        ]
        if cache_files:
            errors.append(f"package contains Python cache files: {len(cache_files)}")
        result = {
            "status": "pass" if not errors else "fail",
            "root": str(root),
            "skill": str(skill),
            "agent": str(agent_file),
            "config": str(config_file),
            "cache_files": cache_files,
            "errors": errors,
        }
        print(json.dumps(result, indent=2))
        return 1 if errors else 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
