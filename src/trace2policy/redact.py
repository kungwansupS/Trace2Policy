from __future__ import annotations

import re

ASSIGNMENT_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|authorization|credential|password|private[_-]?key|secret|token)"
    r"\b\s*[:=]\s*['\"]?[^'\"\s,;]+"
)
BEARER_SECRET_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_secret_text(value: str) -> str:
    redacted = PRIVATE_KEY_RE.sub("[REDACTED_SECRET]", value)
    redacted = BEARER_SECRET_RE.sub("Bearer [REDACTED_SECRET]", redacted)
    return ASSIGNMENT_SECRET_RE.sub(lambda match: f"{match.group(1)}=[REDACTED_SECRET]", redacted)
