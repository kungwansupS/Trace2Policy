from __future__ import annotations

import re
from typing import Any

ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|credential|password|private[_-]?key|secret|token)"
    r"\b\s*[:=]\s*['\"]?[^'\"\s,;]+"
)
AWS_ACCESS_KEY_RE = re.compile(r"\bA[KS]IA[0-9A-Z]{16}\b")
BEARER_SECRET_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
GITHUB_TOKEN_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_secret_text(value: str) -> str:
    redacted = PRIVATE_KEY_RE.sub("[REDACTED_SECRET]", value)
    redacted = BEARER_SECRET_RE.sub("Bearer [REDACTED_SECRET]", redacted)
    redacted = GITHUB_TOKEN_RE.sub("[REDACTED_SECRET]", redacted)
    redacted = AWS_ACCESS_KEY_RE.sub("[REDACTED_SECRET]", redacted)
    return ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group(1)}=[REDACTED_SECRET]", redacted)


def redact_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secret_text(value)
    if isinstance(value, list):
        return [redact_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_json_value(item) for key, item in value.items()}
    return value
