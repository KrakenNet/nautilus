"""Shared FastAPI dependencies for the Nautilus Admin UI (FR-10, AC-5.1, AC-5.4).

Provides reusable dependency functions that extract common objects from
``request.app.state`` so admin route handlers stay thin and testable.
"""

from __future__ import annotations

from starlette.requests import Request

# Runtime imports, not TYPE_CHECKING: with ``from __future__ import
# annotations`` FastAPI resolves these names when it registers the routes
# that depend on them. An unresolvable ``Request`` is treated as a body
# parameter (422 on every admin call); an unresolvable ``Broker`` 500s
# /openapi.json.
from nautilus.core.broker import Broker
from nautilus.transport.auth import (
    api_key_header,
    proxy_trust_dependency,
    verify_api_key,
)


async def get_broker(request: Request) -> Broker:
    """Return the :class:`Broker` instance attached during app lifespan."""
    return request.app.state.broker  # type: ignore[no-any-return]


async def get_auth_user(request: Request) -> str:
    """Authenticate the request and return the principal identity.

    Dispatches to :func:`proxy_trust_dependency` when the app is running in
    ``"proxy_trust"`` mode, or validates the ``X-API-Key`` header otherwise.

    For browser-based admin UI access, also accepts the API key from a
    ``nautilus_key`` cookie (set by the ``/admin/login`` page).
    """
    mode: str = getattr(request.app.state, "auth_mode", "api_key")
    if mode == "proxy_trust":
        return await proxy_trust_dependency(request)

    keys: list[str] = list(getattr(request.app.state, "api_keys", []) or [])

    # Try X-API-Key header first.
    try:
        header_value: str | None = await api_key_header(request)
    except Exception:
        header_value = None

    if header_value:
        verify_api_key(header_value, keys)
        return header_value

    # Fall back to cookie for browser-based admin UI access.
    cookie_value = request.cookies.get("nautilus_key")
    if cookie_value:
        verify_api_key(cookie_value, keys)
        return cookie_value

    from fastapi import HTTPException, status

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


async def get_audit_path(request: Request) -> str:
    """Return the audit JSONL file the broker actually writes to.

    ``config.audit.path`` is what the operator typed and is resolved against the
    config directory when the broker is built; reading it raw pointed the audit
    surface at the same relative name under the *process* cwd, so an incident
    response answered 200 with an empty trail.
    """
    broker: Broker = request.app.state.broker  # type: ignore[assignment]
    path = broker.audit_path
    return str(path) if path is not None else str(broker.config.audit.path)


__all__ = [
    "get_audit_path",
    "get_auth_user",
    "get_broker",
]
