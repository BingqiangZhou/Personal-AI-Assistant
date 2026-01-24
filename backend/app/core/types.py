"""
Common type aliases used across the application.

This module provides type aliases for commonly used types to improve
type safety and consistency throughout the codebase.
"""
from typing import NewAlias

# Type alias for user_id - always an integer in the application
#
# JWT tokens store user ID as string in the "sub" claim, but our
# database models and services expect user_id to be an integer.
#
# Usage:
#     from app.core.types import UserId
#
#     def __init__(self, db: AsyncSession, user_id: UserId):
#         self.user_id = user_id  # Always an int
#
#     # In route handlers, use require_user_id dependency:
#     from app.core.security import require_user_id
#
#     @router.get("/example")
#     async def example(user_id: UserId = Depends(require_user_id)):
#         service = MyService(db, user_id)
UserId: NewAlias[int] = int

# Common generic types
from typing import Optional, List, Dict, Any, Tuple, Callable, Awaitable

__all__ = [
    "UserId",
    "Optional",
    "List",
    "Dict",
    "Any",
    "Tuple",
    "Callable",
    "Awaitable",
]
