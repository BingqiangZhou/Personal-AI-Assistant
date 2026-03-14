"""Shared status extraction helpers for transcription services."""

from __future__ import annotations

from typing import Any


def status_value(status: Any) -> str:
    """Extract string value from status enum or object.

    Args:
        status: Status enum or object with .value attribute

    Returns:
        String representation of the status

    """
    if status is None:
        return "unknown"
    return status.value if hasattr(status, "value") else str(status)
