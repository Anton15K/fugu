"""Secret-safe CLI messages, independent of the audit engine."""
from __future__ import annotations

from typing import Sequence


class CliError(Exception):
    """A categorized, authored message safe to show instead of raw exceptions."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def redact(text: str, secrets: Sequence[str] = ()) -> str:
    """Remove known runtime credentials while retaining synthetic canary evidence."""
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text
