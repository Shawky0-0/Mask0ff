#!/usr/bin/env python3
"""Create secret-free references to authenticated research sessions."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AUTH_TYPES = {"password", "bearer", "api-key", "cookie", "oauth", "browser-session", "client-certificate"}
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FORBIDDEN_KEYS = {
    "password",
    "passwd",
    "token",
    "api_token",
    "api_key",
    "access_token",
    "refresh_token",
    "bearer_token",
    "cookie",
    "session_cookie",
    "secret",
    "value",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def secret_field_errors(value: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() in FORBIDDEN_KEYS and child not in (None, "", [], {}):
                errors.append(f"plaintext secret field is forbidden: {child_path}")
            errors.extend(secret_field_errors(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(secret_field_errors(child, f"{path}[{index}]"))
    return errors


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_session(
    profile: dict[str, Any], *, check_environment: bool = False, now_value: str | None = None
) -> tuple[list[str], list[str], dict[str, bool]]:
    errors: list[str] = []
    warnings: list[str] = []
    availability: dict[str, bool] = {}
    if profile.get("schema_version") != 1 or profile.get("kind") != "mask0ff-session-profile":
        errors.append("session schema or kind is invalid")
    if profile.get("auth_type") not in AUTH_TYPES:
        errors.append("auth_type is invalid")
    for field in ("label", "base_url", "role"):
        if not str(profile.get(field, "")).strip():
            errors.append(f"{field} is required")
    references = profile.get("credential_references", {})
    if not isinstance(references, dict):
        errors.append("credential_references must be an object")
        references = {}
    for label, env_name in references.items():
        name = str(env_name).strip()
        if not name or not ENV_NAME.fullmatch(name):
            errors.append(f"credential reference {label} is not a valid environment-variable name")
            continue
        if check_environment:
            availability[label] = name in os.environ and bool(os.environ[name])
            if not availability[label]:
                warnings.append(f"credential reference {label} is not available in this process")
    if profile.get("auth_type") in {"password", "bearer", "api-key", "cookie", "oauth", "client-certificate"} and not references:
        errors.append("this auth_type requires at least one environment-variable reference")
    if profile.get("auth_type") == "password" and "secret_env" not in references:
        errors.append("password auth requires credential_references.secret_env")
    if profile.get("auth_type") == "browser-session" and not str(profile.get("browser_profile", "")).strip():
        warnings.append("browser-session has no browser_profile label; bind it to the active signed-in browser session at runtime")
    expires_at = str(profile.get("expires_at_utc", "")).strip()
    if expires_at:
        try:
            now = parse_time(now_value) if now_value else datetime.now(timezone.utc)
            if now > parse_time(expires_at):
                errors.append("session profile is expired; refresh the runtime session and create a new reference")
        except ValueError as error:
            errors.append(f"invalid expires_at_utc: {error}")
    errors.extend(secret_field_errors(profile))
    return errors, warnings, availability


def create_session(args: argparse.Namespace) -> int:
    references = {
        key: value
        for key, value in {
            "username_env": args.username_env,
            "secret_env": args.secret_env,
            "token_env": args.token_env,
            "cookie_env": args.cookie_env,
            "header_env": args.header_env,
            "certificate_env": args.certificate_env,
        }.items()
        if value
    }
    profile = {
        "schema_version": 1,
        "kind": "mask0ff-session-profile",
        "label": args.label,
        "base_url": args.base_url,
        "role": args.role,
        "tenant": args.tenant or "",
        "auth_type": args.auth_type,
        "credential_references": references,
        "browser_profile": args.browser_profile or "",
        "scope_profile": str(args.scope_profile.resolve()) if args.scope_profile else "",
        "created_at_utc": args.created_at or utc_now(),
        "expires_at_utc": args.expires_at or "",
        "storage_policy": "references-only-no-secret-material",
        "notes": args.notes or "",
    }
    errors, warnings, _availability = validate_session(profile)
    if errors:
        raise ValueError("; ".join(errors))
    atomic_write(args.output.resolve(), profile)
    print(
        json.dumps(
            {
                "path": str(args.output.resolve()),
                "label": profile["label"],
                "auth_type": profile["auth_type"],
                "credential_reference_names": sorted(references),
                "secret_material_stored": False,
                "warnings": warnings,
            },
            indent=2,
        )
    )
    return 0


def verify_session(args: argparse.Namespace) -> int:
    path = args.profile.resolve()
    profile = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(profile, dict):
        raise ValueError("session profile must be a JSON object")
    errors, warnings, availability = validate_session(
        profile, check_environment=args.check_environment, now_value=args.now
    )
    result = {
        "status": "pass" if not errors else "blocked",
        "profile": str(path),
        "label": profile.get("label"),
        "role": profile.get("role"),
        "tenant": profile.get("tenant"),
        "auth_type": profile.get("auth_type"),
        "credential_references": sorted(profile.get("credential_references", {}).keys()) if isinstance(profile.get("credential_references"), dict) else [],
        "environment_available": availability,
        "secret_material_stored": False,
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(result, indent=2))
    return 1 if errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reference passwords, tokens, cookies, and browser sessions without storing their values."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("output", type=Path)
    init.add_argument("--label", required=True)
    init.add_argument("--base-url", required=True)
    init.add_argument("--role", required=True)
    init.add_argument("--tenant")
    init.add_argument("--auth-type", choices=sorted(AUTH_TYPES), required=True)
    init.add_argument("--username-env")
    init.add_argument("--secret-env")
    init.add_argument("--token-env")
    init.add_argument("--cookie-env")
    init.add_argument("--header-env")
    init.add_argument("--certificate-env")
    init.add_argument("--browser-profile")
    init.add_argument("--scope-profile", type=Path)
    init.add_argument("--created-at")
    init.add_argument("--expires-at")
    init.add_argument("--notes")
    init.set_defaults(handler=create_session)

    verify = subparsers.add_parser("verify")
    verify.add_argument("profile", type=Path)
    verify.add_argument("--check-environment", action="store_true")
    verify.add_argument("--now", help="ISO-8601 time override for deterministic expiration checks")
    verify.set_defaults(handler=verify_session)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        return int(args.handler(args))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
