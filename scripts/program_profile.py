#!/usr/bin/env python3
"""Create, import, and validate normalized bug-bounty engagement profiles."""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlparse
from urllib.request import Request, urlopen


PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack", "private", "owner", "generic"}
ASSESSMENT_MODES = {"black-box", "gray-box", "white-box", "hybrid"}
WORK_MODES = {"passive", "local-lab", "active-authorized", "unclear"}
DEFAULT_ALLOWED_GROUPS = [
    "passive-recon",
    "standard-safe-testing",
    "authenticated-testing",
    "source-review",
    "local-reproduction",
]
DEFAULT_PROHIBITED = [
    "denial-of-service",
    "credential-attacks",
    "social-engineering",
    "persistence",
    "third-party-data-access",
    "destructive-production-actions",
    "bulk-extraction",
    "stealth-or-log-removal",
]
SECRET_KEYS = {
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
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def atomic_write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def target_values(target: str) -> set[str]:
    clean = target.strip().lower()
    values = {clean}
    parsed = urlparse(clean if "://" in clean else f"https://{clean}")
    if parsed.hostname:
        values.add(parsed.hostname.lower())
    return values


def target_matches(target: str, pattern: str) -> bool:
    normalized = pattern.strip().lower()
    if not normalized:
        return False
    pattern_values = {normalized}
    parsed = urlparse(normalized if "://" in normalized else f"https://{normalized}")
    if parsed.hostname:
        pattern_values.add(parsed.hostname.lower())
    return any(
        fnmatch.fnmatchcase(value, candidate)
        for value in target_values(target)
        for candidate in pattern_values
    )


def scope_item(
    identifier: str,
    *,
    asset_type: str = "OTHER",
    eligible_for_submission: bool = True,
    eligible_for_bounty: bool | None = None,
    max_severity: str = "",
    instruction: str = "",
    source_id: str = "",
) -> dict[str, Any]:
    return {
        "identifier": identifier.strip(),
        "asset_type": asset_type or "OTHER",
        "eligible_for_submission": bool(eligible_for_submission),
        "eligible_for_bounty": eligible_for_bounty,
        "max_severity": max_severity or "",
        "instruction": instruction or "",
        "source_id": source_id or "",
    }


def base_profile(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "mask0ff-engagement-profile",
        "platform": args.platform,
        "program_or_owner": args.program,
        "policy_reference": args.policy_reference,
        "captured_at_utc": args.captured_at or utc_now(),
        "assessment_mode": args.assessment_mode,
        "work_mode": args.work_mode,
        "authorization_model": "platform-program" if args.platform not in {"owner", "private", "generic"} else "owner-supplied",
        "scope": [],
        "out_of_scope": [],
        "allowed_action_groups": list(args.allowed_group or DEFAULT_ALLOWED_GROUPS),
        "prohibited_actions": list(args.prohibited or DEFAULT_PROHIBITED),
        "rate_limits": list(args.rate_limit or []),
        "testing_windows": list(args.testing_window or []),
        "data_handling_rules": list(args.data_rule or []),
        "owned_accounts_and_data": list(args.owned_resource or []),
        "source": {},
        "notes": args.notes or "",
    }


def create_profile(args: argparse.Namespace) -> int:
    profile = base_profile(args)
    profile["scope"] = [scope_item(value) for value in args.scope or []]
    profile["out_of_scope"] = [scope_item(value, eligible_for_submission=False) for value in args.out_of_scope or []]
    if args.source:
        profile["source"] = {"type": "user-supplied-reference", "reference": args.source}
    errors, warnings = validate_profile(profile)
    if errors:
        raise ValueError("; ".join(errors))
    atomic_write(args.output.resolve(), profile)
    print(json.dumps({"path": str(args.output.resolve()), "warnings": warnings, "profile": profile}, indent=2))
    return 0


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def iter_resources(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if "type" in value and ("attributes" in value or "id" in value):
            yield value
        for child in value.values():
            yield from iter_resources(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_resources(child)


def import_hackerone(data: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    included: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    rows = data.get("data", []) if isinstance(data, dict) else []
    if not isinstance(rows, list):
        rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        attributes = row.get("attributes", {})
        if not isinstance(attributes, dict):
            continue
        identifier = str(attributes.get("asset_identifier", "")).strip()
        if not identifier:
            continue
        item = scope_item(
            identifier,
            asset_type=str(attributes.get("asset_type", "OTHER")),
            eligible_for_submission=bool(attributes.get("eligible_for_submission", False)),
            eligible_for_bounty=attributes.get("eligible_for_bounty") if isinstance(attributes.get("eligible_for_bounty"), bool) else None,
            max_severity=str(attributes.get("max_severity", "")),
            instruction=str(attributes.get("instruction", "")),
            source_id=str(row.get("id", "")),
        )
        (included if item["eligible_for_submission"] else excluded).append(item)
    return included, excluded


def import_bugcrowd(data: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    included: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in iter_resources(data):
        resource_type = str(row.get("type", "")).lower().replace("_", "-")
        if resource_type not in {"target", "targets"}:
            continue
        attributes = row.get("attributes", {})
        if not isinstance(attributes, dict):
            continue
        identifier = str(
            attributes.get("name")
            or attributes.get("uri")
            or attributes.get("target")
            or attributes.get("identifier")
            or ""
        ).strip()
        if not identifier or identifier in seen:
            continue
        seen.add(identifier)
        included.append(
            scope_item(
                identifier,
                asset_type=str(attributes.get("category") or attributes.get("type") or "OTHER"),
                eligible_for_submission=True,
                eligible_for_bounty=None,
                instruction=str(attributes.get("description") or attributes.get("instructions") or ""),
                source_id=str(row.get("id", "")),
            )
        )
    return included, []


def import_generic(data: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(data, dict):
        return [], []
    included = [scope_item(str(value)) for value in data.get("in_scope_targets", []) if str(value).strip()]
    excluded = [
        scope_item(str(value), eligible_for_submission=False)
        for value in data.get("out_of_scope_targets", [])
        if str(value).strip()
    ]
    if not included and isinstance(data.get("scope"), list):
        for row in data["scope"]:
            if isinstance(row, dict) and str(row.get("identifier", "")).strip():
                item = scope_item(
                    str(row["identifier"]),
                    asset_type=str(row.get("asset_type", "OTHER")),
                    eligible_for_submission=bool(row.get("eligible_for_submission", True)),
                    eligible_for_bounty=row.get("eligible_for_bounty") if isinstance(row.get("eligible_for_bounty"), bool) else None,
                    max_severity=str(row.get("max_severity", "")),
                    instruction=str(row.get("instruction", "")),
                    source_id=str(row.get("source_id", "")),
                )
                (included if item["eligible_for_submission"] else excluded).append(item)
    return included, excluded


def import_profile(args: argparse.Namespace) -> int:
    source = args.input.resolve()
    data = load_json(source)
    profile = base_profile(args)
    if args.platform == "hackerone":
        included, excluded = import_hackerone(data)
    elif args.platform == "bugcrowd":
        included, excluded = import_bugcrowd(data)
    else:
        included, excluded = import_generic(data)
        if isinstance(data, dict):
            if data.get("allowed_action_groups"):
                profile["allowed_action_groups"] = list(data["allowed_action_groups"])
            if data.get("prohibited_actions"):
                profile["prohibited_actions"] = list(data["prohibited_actions"])
            if data.get("rate_limits"):
                profile["rate_limits"] = list(data["rate_limits"])
            if data.get("owned_accounts_and_data") and not profile.get("owned_accounts_and_data"):
                profile["owned_accounts_and_data"] = list(data["owned_accounts_and_data"])
    for exclusions_path in args.exclusions or []:
        exclusions_data = load_json(exclusions_path.resolve())
        if args.platform == "hackerone" and isinstance(exclusions_data, dict):
            for row in exclusions_data.get("data", []):
                if not isinstance(row, dict):
                    continue
                attributes = row.get("attributes", {})
                label = str(attributes.get("details") or attributes.get("category") or "").strip()
                if label:
                    excluded.append(scope_item(label, asset_type="POLICY_EXCLUSION", eligible_for_submission=False, source_id=str(row.get("id", ""))))
        else:
            _more_included, more_excluded = import_generic(exclusions_data)
            excluded.extend(more_excluded)
    profile["scope"] = included
    profile["out_of_scope"] = excluded
    profile["source"] = {
        "type": f"{args.platform}-export",
        "path": str(source),
        "sha256": digest(source),
        "imported_at_utc": utc_now(),
    }
    errors, warnings = validate_profile(profile)
    if errors:
        raise ValueError("; ".join(errors))
    atomic_write(args.output.resolve(), profile)
    print(
        json.dumps(
            {
                "path": str(args.output.resolve()),
                "in_scope_count": len(included),
                "out_of_scope_count": len(excluded),
                "warnings": warnings,
            },
            indent=2,
        )
    )
    return 0


def checked_hackerone_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "api.hackerone.com" or parsed.port not in (None, 443):
        raise ValueError(f"refusing non-HackerOne API pagination URL: {value}")
    return value


def fetch_pages(url: str, headers: dict[str, str], timeout: int) -> dict[str, Any]:
    current = checked_hackerone_url(url)
    rows: list[Any] = []
    page_count = 0
    while current:
        page_count += 1
        if page_count > 200:
            raise ValueError("HackerOne API pagination exceeded 200 pages")
        request = Request(current, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=timeout) as response:
                final_url = checked_hackerone_url(response.geturl())
                page = json.loads(response.read().decode("utf-8-sig"))
        except HTTPError as error:
            raise ValueError(f"HackerOne API returned HTTP {error.code}") from error
        except URLError as error:
            raise ValueError(f"HackerOne API request failed: {error.reason}") from error
        if not isinstance(page, dict) or not isinstance(page.get("data", []), list):
            raise ValueError("HackerOne API response does not contain a data array")
        rows.extend(page.get("data", []))
        next_url = page.get("links", {}).get("next") if isinstance(page.get("links"), dict) else None
        current = checked_hackerone_url(urljoin(final_url, str(next_url))) if next_url else ""
    return {"data": rows, "page_count": page_count}


def sync_hackerone(args: argparse.Namespace) -> int:
    username = os.environ.get(args.username_env, "")
    token = os.environ.get(args.token_env, "")
    if not username or not token:
        raise ValueError("HackerOne API username/token environment references are not available")
    encoded = base64.b64encode(f"{username}:{token}".encode("utf-8")).decode("ascii")
    headers = {"Accept": "application/json", "Authorization": f"Basic {encoded}", "User-Agent": "mask0ff-scope-sync/1"}
    handle = quote(args.program, safe="")
    base = f"https://api.hackerone.com/v1/hackers/programs/{handle}"
    scopes = fetch_pages(f"{base}/structured_scopes", headers, args.timeout)
    exclusions = fetch_pages(f"{base}/scope_exclusions", headers, args.timeout)
    raw_capture = {
        "schema_version": 1,
        "platform": "hackerone",
        "program": args.program,
        "fetched_at_utc": utc_now(),
        "endpoints": [f"{base}/structured_scopes", f"{base}/scope_exclusions"],
        "structured_scopes": scopes,
        "scope_exclusions": exclusions,
    }
    raw_path = args.raw_output.resolve()
    atomic_write(raw_path, raw_capture)
    profile = base_profile(args)
    included, excluded = import_hackerone(scopes)
    for row in exclusions.get("data", []):
        if not isinstance(row, dict):
            continue
        attributes = row.get("attributes", {})
        if not isinstance(attributes, dict):
            continue
        label = str(attributes.get("details") or attributes.get("category") or "").strip()
        if label:
            excluded.append(
                scope_item(
                    label,
                    asset_type="POLICY_EXCLUSION",
                    eligible_for_submission=False,
                    source_id=str(row.get("id", "")),
                )
            )
    profile["scope"] = included
    profile["out_of_scope"] = excluded
    profile["source"] = {
        "type": "hackerone-live-api",
        "path": str(raw_path),
        "sha256": digest(raw_path),
        "imported_at_utc": utc_now(),
        "documentation": "https://api.hackerone.com/hacker-resources/",
    }
    errors, warnings = validate_profile(profile)
    if errors:
        raise ValueError("; ".join(errors))
    atomic_write(args.output.resolve(), profile)
    print(
        json.dumps(
            {
                "path": str(args.output.resolve()),
                "raw_capture": str(raw_path),
                "in_scope_count": len(included),
                "out_of_scope_or_policy_count": len(excluded),
                "pages": scopes["page_count"] + exclusions["page_count"],
                "credential_values_logged": False,
                "warnings": warnings,
            },
            indent=2,
        )
    )
    return 0


def find_embedded_secret(value: Any, path: str = "") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() in SECRET_KEYS and child not in (None, "", [], {}):
                errors.append(f"embedded secret field is forbidden: {child_path}")
            errors.extend(find_embedded_secret(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(find_embedded_secret(child, f"{path}[{index}]"))
    return errors


def validate_profile(
    profile: dict[str, Any], *, target: str | None = None, action_group: str | None = None,
    action: str | None = None,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if profile.get("schema_version") != 1 or profile.get("kind") != "mask0ff-engagement-profile":
        errors.append("profile schema or kind is invalid")
    if profile.get("platform") not in PLATFORMS:
        errors.append("platform is invalid")
    if profile.get("assessment_mode") not in ASSESSMENT_MODES:
        errors.append("assessment_mode is invalid")
    if profile.get("work_mode") not in WORK_MODES:
        errors.append("work_mode is invalid")
    for field in ("program_or_owner", "policy_reference"):
        if not str(profile.get(field, "")).strip():
            errors.append(f"{field} is required")
    scope = profile.get("scope", [])
    if not isinstance(scope, list) or not scope:
        errors.append("scope must contain at least one target")
    else:
        identifiers = [str(row.get("identifier", "")).strip() for row in scope if isinstance(row, dict)]
        if not all(identifiers) or len(identifiers) != len(scope):
            errors.append("every scope item requires an identifier")
        if len(set(identifiers)) != len(identifiers):
            errors.append("scope contains duplicate identifiers")
    allowed_groups = {str(value).strip() for value in profile.get("allowed_action_groups", [])}
    if not allowed_groups:
        errors.append("allowed_action_groups must not be empty")
    if not profile.get("prohibited_actions"):
        warnings.append("prohibited_actions is empty; mask0ff default high-risk boundaries still apply")
    if not profile.get("owned_accounts_and_data") and profile.get("assessment_mode") in {"gray-box", "hybrid"}:
        warnings.append("no researcher-owned account or synthetic-data resource is recorded yet")
    errors.extend(find_embedded_secret(profile))
    if target:
        explicit_exclusions = [
            str(row.get("identifier", ""))
            for row in profile.get("out_of_scope", [])
            if isinstance(row, dict)
        ]
        in_scope = [
            str(row.get("identifier", ""))
            for row in scope
            if isinstance(row, dict) and row.get("eligible_for_submission", True)
        ]
        if any(target_matches(target, pattern) for pattern in explicit_exclusions):
            errors.append(f"target is explicitly out of scope: {target}")
        elif not any(target_matches(target, pattern) for pattern in in_scope):
            errors.append(f"target does not match imported scope: {target}")
    if action_group and action_group not in allowed_groups:
        errors.append(f"action group is not allowed by the profile: {action_group}")
    if action and action.strip().lower() in {
        str(value).strip().lower() for value in profile.get("prohibited_actions", [])
    }:
        errors.append(f"action is explicitly prohibited by the profile: {action}")
    return errors, warnings


def verify_profile(args: argparse.Namespace) -> int:
    path = args.profile.resolve()
    profile = load_json(path)
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object")
    errors, warnings = validate_profile(
        profile, target=args.target, action_group=args.action_group, action=args.action
    )
    result = {
        "status": "pass" if not errors else "blocked",
        "profile": str(path),
        "sha256": digest(path),
        "platform": profile.get("platform"),
        "program_or_owner": profile.get("program_or_owner"),
        "assessment_mode": profile.get("assessment_mode"),
        "target": args.target,
        "target_in_scope": None if not args.target else not any("target" in error for error in errors),
        "action_group": args.action_group,
        "action": args.action,
        "errors": errors,
        "warnings": warnings,
        "secret_material_stored": False,
    }
    print(json.dumps(result, indent=2))
    return 1 if errors else 0


def export_authorization(args: argparse.Namespace) -> int:
    profile_path = args.profile.resolve()
    profile = load_json(profile_path)
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object")
    errors, warnings = validate_profile(profile)
    if errors:
        raise ValueError("; ".join(errors))
    receipt = {
        "schema_version": 2,
        "authority": f"{profile['platform']} program or asset owner",
        "program_or_owner": profile["program_or_owner"],
        "policy_reference": profile["policy_reference"],
        "valid_from": args.valid_from or "",
        "valid_until": args.valid_until or "",
        "in_scope_targets": [
            row["identifier"]
            for row in profile["scope"]
            if isinstance(row, dict) and row.get("eligible_for_submission", True)
        ],
        "out_of_scope_targets": [
            row["identifier"] for row in profile.get("out_of_scope", []) if isinstance(row, dict)
        ],
        "allowed_actions": list(args.allowed_action or ["standard-safe-testing"]),
        "allowed_action_groups": list(profile.get("allowed_action_groups", [])),
        "prohibited_actions": list(profile.get("prohibited_actions", DEFAULT_PROHIBITED)),
        "rate_limits": list(profile.get("rate_limits", [])),
        "owned_accounts_and_data": list(profile.get("owned_accounts_and_data", [])),
        "evidence": [
            {
                "kind": "engagement-profile",
                "sha256": digest(profile_path),
                "source": profile.get("source", {}),
            }
        ],
        "notes": "Generated from a normalized platform/owner profile. It contains no credentials or tokens.",
    }
    atomic_write(args.output.resolve(), receipt)
    print(json.dumps({"path": str(args.output.resolve()), "warnings": warnings, "receipt": receipt}, indent=2))
    return 0


def compare_profiles(args: argparse.Namespace) -> int:
    old_path = args.old.resolve()
    new_path = args.new.resolve()
    old = load_json(old_path)
    new = load_json(new_path)
    if not isinstance(old, dict) or not isinstance(new, dict):
        raise ValueError("both profiles must be JSON objects")
    for label, profile in (("old", old), ("new", new)):
        errors, _warnings = validate_profile(profile)
        if errors:
            raise ValueError(f"{label} profile is invalid: {'; '.join(errors)}")

    def identifiers(profile: dict[str, Any], field: str) -> set[str]:
        return {
            str(row.get("identifier", "")).strip()
            for row in profile.get(field, [])
            if isinstance(row, dict) and str(row.get("identifier", "")).strip()
        }

    old_scope = identifiers(old, "scope")
    new_scope = identifiers(new, "scope")
    old_excluded = identifiers(old, "out_of_scope")
    new_excluded = identifiers(new, "out_of_scope")
    old_groups = {str(value) for value in old.get("allowed_action_groups", [])}
    new_groups = {str(value) for value in new.get("allowed_action_groups", [])}
    old_prohibited = {str(value) for value in old.get("prohibited_actions", [])}
    new_prohibited = {str(value) for value in new.get("prohibited_actions", [])}
    result = {
        "old_profile": str(old_path),
        "new_profile": str(new_path),
        "old_sha256": digest(old_path),
        "new_sha256": digest(new_path),
        "added_scope": sorted(new_scope - old_scope),
        "removed_scope": sorted(old_scope - new_scope),
        "added_exclusions": sorted(new_excluded - old_excluded),
        "removed_exclusions": sorted(old_excluded - new_excluded),
        "added_action_groups": sorted(new_groups - old_groups),
        "removed_action_groups": sorted(old_groups - new_groups),
        "added_prohibited_actions": sorted(new_prohibited - old_prohibited),
        "removed_prohibited_actions": sorted(old_prohibited - new_prohibited),
        "assessment_mode_changed": old.get("assessment_mode") != new.get("assessment_mode"),
        "policy_reference_changed": old.get("policy_reference") != new.get("policy_reference"),
    }
    material_keys = (
        "added_scope",
        "removed_scope",
        "added_exclusions",
        "removed_exclusions",
        "added_action_groups",
        "removed_action_groups",
        "added_prohibited_actions",
        "removed_prohibited_actions",
    )
    result["material_scope_or_policy_change"] = any(result[key] for key in material_keys) or result["policy_reference_changed"]
    result["requires_new_a0_binding"] = result["material_scope_or_policy_change"]
    print(json.dumps(result, indent=2))
    return 0


def add_common(parser: argparse.ArgumentParser, *, include_platform: bool = True) -> None:
    if include_platform:
        parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--policy-reference", required=True)
    parser.add_argument("--assessment-mode", choices=sorted(ASSESSMENT_MODES), default="black-box")
    parser.add_argument("--work-mode", choices=sorted(WORK_MODES), default="active-authorized")
    parser.add_argument("--captured-at", help="ISO-8601 time for deterministic imports")
    parser.add_argument("--allowed-group", action="append")
    parser.add_argument("--prohibited", action="append")
    parser.add_argument("--rate-limit", action="append")
    parser.add_argument("--testing-window", action="append")
    parser.add_argument("--data-rule", action="append")
    parser.add_argument("--owned-resource", action="append")
    parser.add_argument("--notes")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize program scope without storing credentials.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create a profile from supplied program details.")
    init.add_argument("output", type=Path)
    add_common(init)
    init.add_argument("--scope", action="append")
    init.add_argument("--out-of-scope", action="append")
    init.add_argument("--source")
    init.set_defaults(handler=create_profile)

    imported = subparsers.add_parser("import", help="Import a platform JSON export or generic receipt.")
    imported.add_argument("input", type=Path)
    imported.add_argument("output", type=Path)
    add_common(imported)
    imported.add_argument("--exclusions", type=Path, action="append")
    imported.set_defaults(handler=import_profile)

    sync = subparsers.add_parser(
        "sync-hackerone",
        help="Fetch current official HackerOne scope using API credentials referenced by environment-variable name.",
    )
    sync.add_argument("output", type=Path)
    add_common(sync, include_platform=False)
    sync.set_defaults(platform="hackerone")
    sync.add_argument("--username-env", required=True)
    sync.add_argument("--token-env", required=True)
    sync.add_argument("--raw-output", type=Path, required=True)
    sync.add_argument("--timeout", type=int, default=30)
    sync.set_defaults(handler=sync_hackerone)

    verify = subparsers.add_parser("verify", help="Validate a normalized profile and optional target/action group.")
    verify.add_argument("profile", type=Path)
    verify.add_argument("--target")
    verify.add_argument("--action-group")
    verify.add_argument("--action")
    verify.set_defaults(handler=verify_profile)

    export = subparsers.add_parser("export-authorization", help="Create an A0 receipt from a normalized profile.")
    export.add_argument("profile", type=Path)
    export.add_argument("output", type=Path)
    export.add_argument("--allowed-action", action="append")
    export.add_argument("--valid-from")
    export.add_argument("--valid-until")
    export.set_defaults(handler=export_authorization)

    diff = subparsers.add_parser("diff", help="Compare two captured program profiles for scope or policy changes.")
    diff.add_argument("old", type=Path)
    diff.add_argument("new", type=Path)
    diff.set_defaults(handler=compare_profiles)
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
