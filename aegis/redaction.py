"""Secret redaction for text crossing the machine boundary.

Applied only to data bound for the remote reasoner. Narrow by design: it
strips high-value secrets, not everything that looks opaque. Long base64 blobs
are LEFT INTACT because an encoded PowerShell payload *is* the evidence -
scrubbing it would destroy the signal that makes the alert interpretable.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*", re.I), "Bearer [REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "[REDACTED_JWT]"),
    (re.compile(r"\bsk-[A-Za-z0-9\-]{20,}"), "[REDACTED_API_KEY]"),
    (
        re.compile(r"\b(pass(word)?|pwd|secret|api[_-]?key|token)\s*[=:]\s*\S+", re.I),
        r"\1=[REDACTED]",
    ),
]


def redact(text: str) -> str:
    """Strip known secret shapes from text. Idempotent and side-effect free."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def prepare_raw_log(text: str, *, max_chars: int) -> str:
    """Redact then truncate. A log line past ~2k chars is almost always noise."""
    cleaned = redact(text)
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars] + f"\n…[truncated {len(cleaned) - max_chars} chars]"
