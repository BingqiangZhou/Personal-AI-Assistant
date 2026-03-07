"""User API dependency providers."""

from app.core.providers import get_authentication_service, get_current_user


__all__ = ["get_authentication_service", "get_current_user"]