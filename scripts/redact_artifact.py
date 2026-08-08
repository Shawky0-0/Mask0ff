#!/usr/bin/env python3
"""Create a redacted evidence copy without modifying the original artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


PATTERNS = [
    ("authorization", re.compile(r"(?im)^((?:proxy-)?authorization\s*:\s*)(?:bearer|token|basic)\s+\S+"), r"\1<REDACTED>"),
    ("cookie", re.compile(r"(?im)^(cookie|set-cookie)\s*:\s*[^\r\n]+"), r"\1: <REDACTED>"),
    ("api_header", re.compile(r"(?im)^((?:x-)?(?:api[-_]key|auth[-_]token|access[-_]token|private[-_]token)\s*:\s*)[^\r\n]+"), r"\1<REDACTED>"),
    (
        "named_secret",
        re.compile(
            r'(?i)(["\']?(?:password|passwd|secret|client_secret|api[-_]?key|access[-_]?token|refresh[-_]?token|private[-_]?token|secret[-_]?key|session[-_]?token)["\']?\s*[:=]\s*)(?:"[^"]*"|\'[^\']*\'|[^&\s,}]+)'
        ),
        r"\1<REDACTED>",
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "<REDACTED-JWT>"),
    ("url_password", re.compile(r"(?i)(https?://[^:/@\s]+:)[^@/\s]+@"), r"\1<REDACTED>@"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<REDACTED-AWS-ACCESS-KEY>"),
    ("github_token", re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,255}\b"), "<REDACTED-GITHUB-TOKEN>"),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,255}\b"), "<REDACTED-GITLAB-TOKEN>"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"), "<REDACTED-SLACK-TOKEN>"),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,255}\b"), "<REDACTED-STRIPE-KEY>"),
    ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,50}\b"), "<REDACTED-GOOGLE-API-KEY>"),
    ("private_key", re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.DOTALL), "<REDACTED-PRIVATE-KEY>"),
]
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--redact-emails", action="store_true")
    parser.add_argument("--force-text", action="store_true", help="Allow lossy decoding of a binary-looking input")
    args = parser.parse_args()

    source = args.input.resolve()
    output = args.output.resolve()
    if source == output:
        parser.error("output must differ from input")
    raw = source.read_bytes()
    if b"\x00" in raw and not args.force_text:
        parser.error("input appears binary; refuse lossy text redaction without --force-text")
    text = raw.decode("utf-8-sig", errors="replace")
    counts: dict[str, int] = {}
    for name, pattern, replacement in PATTERNS:
        text, count = pattern.subn(replacement, text)
        counts[name] = count
    if args.redact_emails:
        text, count = EMAIL.subn("<REDACTED-EMAIL>", text)
        counts["email"] = count
    redacted = text.encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_bytes(redacted)
    temporary.replace(output)
    metadata = {
        "input": str(source),
        "output": str(output),
        "input_sha256": sha256(raw),
        "output_sha256": sha256(redacted),
        "replacements": counts,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    sidecar = output.with_suffix(output.suffix + ".redaction.json")
    sidecar.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
