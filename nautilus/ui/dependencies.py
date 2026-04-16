"""Shared FastAPI dependencies for the Nautilus Admin UI (FR-10, AC-5.1, AC-5.4).

Provides reusable dependency functions that extract common objects from
``request.app.state`` so admin route handlers stay thin and testable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from nautilus.transport.auth import (
    api_key_header,
    proxy_trust_dependency,
    verify_api_key,
)

if TYPE_CHECKING:
    from starlette.requests import Request

    from nautilus.core.broker import Broker


async def get_broker(request: Request) -> Broker:
    """Return the :class:`Broker` instance attached during app lifespan."""
    return request.app.state.broker  # type: ignore[no-any-return]


async def get_auth_user(request: Request) -> str:
    """Authenticate the request and return the principal identity.

    Dispatches to :func:`proxy_trust_dependency` when the app is running in
    ``"proxy_trust"`` mode, or validates the ``X-API-Key`` header otherwise.
    """
    mode: str = getattr(request.app.state, "auth_mode", "api_key")
    if mode == "proxy_trust":
        return await proxy_trust_dependency(request)
    # api_key mode — resolve header via the shared security scheme, then
    # verify against the configured allow-list.
    header_value: str | None = await api_key_header(request)
    if header_value is None:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    keys: list[str] = list(getattr(request.app.state, "api_keys", []) or [])
    verify_api_key(header_value, keys)
    return header_value


async def get_audit_path(request: Request) -> str:
    """Return the audit JSONL file path from the broker's configuration."""
    broker: Broker = request.app.state.broker  # type: ignore[assignment]
    return str(broker._config.audit.path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


__all__ = [
    "get_audit_path",
    "get_auth_user",
    "get_broker",
]
