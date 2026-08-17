"""Conservative secret and local-identity redaction for exported data."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

REDACTED = "<REDACTED>"
HOME = "<HOME>"

_SENSITIVE_KEYS = {
    "apikey",
    "authorization",
    "authtoken",
    "awssecretaccesskey",
    "clientsecret",
    "cookie",
    "password",
    "privatekey",
    "refreshtoken",
    "secret",
    "secretkey",
    "sessioncookie",
    "token",
    "accesstoken",
}

_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), f"Bearer {REDACTED}"),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"), REDACTED),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"), REDACTED),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        REDACTED,
    ),
    ("email", re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])"), REDACTED),
    ("mac_home", re.compile(r"/Users/[^/\s\"']+"), HOME),
    ("linux_home", re.compile(r"/home/[^/\s\"']+"), HOME),
    ("windows_home", re.compile(r"(?i)[A-Z]:\\Users\\[^\\\s\"']+"), HOME),
)


@dataclass
class RedactionReport:
    """Counts redactions without retaining the original sensitive values."""

    counts: Counter[str] = field(default_factory=Counter)

    @property
    def total(self) -> int:
        """Return the total number of replacements."""
        return sum(self.counts.values())

    def as_dict(self) -> dict[str, Any]:
        """Return a stable JSON-compatible report."""
        return {"total": self.total, "counts": dict(sorted(self.counts.items()))}


def _normalized_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def redact_text(text: str, report: RedactionReport) -> str:
    """Redact known credential, identity, and home-directory patterns."""
    result = text
    for category, pattern, replacement in _TEXT_PATTERNS:
        result, count = pattern.subn(replacement, result)
        if count:
            report.counts[category] += count
    return result


def redact_value(value: Any, report: RedactionReport) -> Any:
    """Recursively redact JSON-compatible data."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in value.items():
            if _normalized_key(key) in _SENSITIVE_KEYS:
                redacted[str(key)] = REDACTED
                report.counts["sensitive_key"] += 1
            else:
                redacted[str(key)] = redact_value(child, report)
        return redacted
    if isinstance(value, list):
        return [redact_value(child, report) for child in value]
    if isinstance(value, str):
        return redact_text(value, report)
    return value
