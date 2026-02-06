"""Helpers for modularizing legacy admin routes without behavior changes."""

from collections.abc import Callable

from fastapi import APIRouter
from fastapi.routing import APIRoute


def build_filtered_router(
    source_router: APIRouter,
    path_predicate: Callable[[str], bool],
) -> APIRouter:
    """Clone selected APIRoutes from a source router."""
    router = APIRouter()
    for route in source_router.routes:
        if isinstance(route, APIRoute) and path_predicate(route.path):
            router.routes.append(route)
    return router

