"""Nautilus Admin UI — operator-facing dashboard and API routes."""

from fastapi import APIRouter

import nautilus.ui.sse as _sse  # noqa: F401  # pyright: ignore[reportUnusedImport]  # register SSE routes
from nautilus.ui.router import router as _source_router


def create_admin_router() -> APIRouter:
    """Return an APIRouter mounted at /admin for operator-facing views.

    Routes are defined in :mod:`nautilus.ui.router` and subsequent route
    modules.  The factory re-exports the shared router instance so
    ``fastapi_app.create_app`` can ``include_router()`` it directly.
    """
    return _source_router
