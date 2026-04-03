"""SettingsProvider protocol for reading system settings.

This protocol decouples consumers (subscription/podcast domains) from
the admin domain's SystemSettings model, allowing clean domain boundaries.
"""

from typing import Any, Protocol

from sqlalchemy.ext.asyncio import AsyncSession


class SettingsProvider(Protocol):
    """Protocol for reading system settings from any backend store."""

    async def get_setting(self, db: AsyncSession, key: str) -> dict[str, Any] | None:
        """Return the full JSON value for *key*, or ``None`` if absent."""
        ...

    async def get_setting_value(
        self,
        db: AsyncSession,
        key: str,
        default: Any = None,
    ) -> Any:
        """Return a specific nested value or *default* when the key is missing."""
        ...
