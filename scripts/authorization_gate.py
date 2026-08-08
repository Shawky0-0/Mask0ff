#!/usr/bin/env python3
"""Validate explicit authorization context before active security testing."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def parse_date(value: str) -> datetime | None:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def target_values(target: str) -> set[str]:
    values = {target.lower().strip()}
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.hostname:
        values.add(parsed.hostname.lower())
    return values


def matches(target: str, patterns: list[str]) -> bool:
    values = target_values(target)
    return any(fnmatch.fnmatchcase(value, pattern.lower().strip()) for value in values for pattern in patterns)


def evaluate(
    data: dict[str, Any],
    *,
    target: str | None,
    action: str | None,
    action_group: str | None = None,
    now_value: str | None = None,
    receipt_sha256: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    evaluation_time = datetime.now(timezone.utc)
    for field in ("authority", "program_or_owner", "policy_reference"):
        if not str(data.get(field, "")).strip():
            errors.append(f"{field} is required")
    for field in ("in_scope_targets", "owned_accounts_and_data", "evidence"):
        if not data.get(field):
            errors.append(f"{field} must not be empty")
    if not data.get("allowed_actions") and not data.get("allowed_action_groups"):
        errors.append("allowed_actions or allowed_action_groups must not be empty")
    if not data.get("prohibited_actions"):
        warnings.append("prohibited_actions is empty; unstated destructive actions still default to prohibited")

    try:
        start = parse_date(str(data.get("valid_from", "")))
        end = parse_date(str(data.get("valid_until", "")))
        now = parse_date(now_value) if now_value else evaluation_time
        if now is not None:
            evaluation_time = now
        if start and now and now < start:
            errors.append("authorization window has not started")
        if end and now and now > end:
            errors.append("authorization window has expired")
        if start and end and start > end:
            errors.append("valid_from is later than valid_until")
        if not start or not end:
            warnings.append("authorization window is incomplete")
    except ValueError as error:
        errors.append(f"invalid authorization date: {error}")

    target_in_scope = None
    if target:
        excluded = matches(target, list(data.get("out_of_scope_targets", [])))
        included = matches(target, list(data.get("in_scope_targets", [])))
        target_in_scope = included and not excluded
        if excluded:
            errors.append(f"target is explicitly out of scope: {target}")
        elif not included:
            errors.append(f"target does not match in-scope patterns: {target}")
    allowed = {str(item).lower().strip() for item in data.get("allowed_actions", [])}
    allowed_groups = {str(item).lower().strip() for item in data.get("allowed_action_groups", [])}
    prohibited = {str(item).lower().strip() for item in data.get("prohibited_actions", [])}
    normalized_action = action.lower().strip() if action else ""
    normalized_group = action_group.lower().strip() if action_group else ""
    if normalized_action in prohibited:
        errors.append(f"action is explicitly prohibited: {action}")
    elif normalized_group in prohibited:
        errors.append(f"action group is explicitly prohibited: {action_group}")
    elif normalized_action or normalized_group:
        exact_allowed = normalized_action and normalized_action in allowed
        group_allowed = normalized_group and normalized_group in allowed_groups
        if not exact_allowed and not group_allowed:
            label = action_group or action
            errors.append(f"action or action group is not allowed: {label}")

    return {
        "schema_version": 1,
        "status": "pass" if not errors else "blocked",
        "validated_at_utc": evaluation_time.isoformat(),
        "authority": str(data.get("authority", "")),
        "program_or_owner": str(data.get("program_or_owner", "")),
        "policy_reference": str(data.get("policy_reference", "")),
        "receipt_sha256": receipt_sha256,
        "target": target,
        "target_in_scope": target_in_scope,
        "action": action,
        "action_group": action_group,
        "errors": errors,
        "warnings": warnings,
        "caveat": "This validates the supplied receipt structure and scope match; the parent must still assess authenticity and program rules."
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--action")
    parser.add_argument("--action-group", help="Broad normal-testing group imported from a program profile")
    parser.add_argument("--now", help="ISO-8601 time override for deterministic evaluation")
    args = parser.parse_args()

    raw = args.receipt.read_bytes()
    data = json.loads(raw.decode("utf-8-sig"))
    result = evaluate(
        data,
        target=args.target,
        action=args.action,
        action_group=args.action_group,
        now_value=args.now,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
    )
    print(json.dumps(result, indent=2))
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
