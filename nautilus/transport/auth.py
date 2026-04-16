"""Shared auth primitives for Nautilus HTTP surfaces (design §3.12, D-11).

Two modes, selected by ``config.api.auth.mode``:

- ``"api_key"`` (default) — clients present ``X-API-Key: <token>``; the value
  is compared against every configured key via :func:`secrets.compare_digest`
  (constant-time, resistant to timing oracles).
- ``"proxy_trust"`` — upstream proxy has already authenticated the caller
  and forwards its identity in ``X-Forwarded-User``. Nautilus trusts the
  header verbatim; the value is exposed as the request principal but no
  cryptographic check is performed (FR-26, D-11).

Both FastAPI REST (``fastapi_app``) and the MCP HTTP transport wrap their
write endpoints with the dependency returned by :func:`require_api_key`
when the mode is ``"api_key"``, and with :func:`proxy_trust_dependency`
otherwise. Read-only probes (``/healthz``, ``/readyz``) stay un-gated.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

if TYPE_CHECKING:
    from starlette.requests import Request


# Module-level APIKeyHeader instance — FastAPI caches dependency providers
# by identity, so sharing one instance across routes keeps the OpenAPI
# security scheme declaration consistent.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)
"""FastAPI security scheme for the ``X-API-Key`` header (auto_error=True)."""


def verify_api_key(header_value: str, keys: list[str]) -> None:
    """Verify ``header_value`` against every key in ``keys`` in constant time.

    Uses :func:`secrets.compare_digest` per key — a plain ``in`` / ``==``
    comparison would leak per-byte timing and let an attacker derive the
    secret (D-11: "API key default, constant-time comparison").

    Args:
        header_value: Raw ``X-API-Key`` header value supplied by the caller.
        keys: Operator-configured allow-list (from ``config.api.keys``).

    Raises:
        HTTPException: 401 if ``header_value`` does not match any key, or
            if the operator has configured zero keys (fail-closed — a
            misconfigured allow-list MUST NOT silently accept anyone).
    """
    if not keys:
        # Fail-closed: an empty allow-list means "nobody is allowed",
        # not "everybody is allowed" (FR-26 — api_key is a hard gate).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )
    header_bytes = header_value.encode("utf-8") if header_value else b""
    for key in keys:
        if secrets.compare_digest(header_bytes, key.encode("utf-8")):
            return
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )


async def require_api_key(
    request: Request,
    header_value: str = Depends(api_key_header),
) -> str:
    """FastAPI dependency that pulls configured keys off ``app.state``.

    The :func:`create_app` factory populates ``app.state.api_keys`` during
    lifespan startup; this dependency reads that list and delegates to
    :func:`verify_api_key` for the constant-time check.

    Returns:
        The raw header value (useful for audit / principal logging).

    Raises:
        HTTPException: 401 — see :func:`verify_api_key`.
    """
    keys: list[str] = list(getattr(request.app.state, "api_keys", []) or [])
    verify_api_key(header_value, keys)
    return header_value


async def proxy_trust_dependency(request: Request) -> str:
    """Return the upstream-proxy-asserted user from ``X-Forwarded-User``.

    Used when ``config.api.auth.mode == "proxy_trust"`` — the upstream
    mesh/ingress has already authenticated the caller and forwarded the
    resolved identity. Nautilus trusts the header verbatim (D-11).

    Raises:
        HTTPException: 401 if ``X-Forwarded-User`` is missing or empty —
            the proxy SHOULD always set it when traffic reaches us;
            missing header implies a bypass attempt.
    """
    user = request.headers.get("X-Forwarded-User")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Forwarded-User",
        )
    return user


__all__ = [
    "api_key_header",
    "proxy_trust_dependency",
    "require_api_key",
    "verify_api_key",
]
