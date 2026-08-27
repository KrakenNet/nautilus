"""Shared auth primitives for Nautilus HTTP surfaces (design §3.12, D-11).

Two modes, selected by ``config.api.auth.mode``:

- ``"api_key"`` (default) — clients present ``X-API-Key: <token>``; the value
  is compared against every configured key via :func:`secrets.compare_digest`
  (constant-time, resistant to timing oracles).
- ``"proxy_trust"`` — upstream proxy has already authenticated the caller
  (mTLS, SPIFFE, OIDC) and forwards its identity in ``X-Forwarded-User``.
  Nautilus accepts the header only from a peer inside
  ``api.auth.trusted_proxies``, and resolves it to an agent through
  ``agents.<id>.subject`` (FR-26, D-11).

Either mode resolves a *caller*: who the transport authenticated, which agent
that credential may speak for, and what it may do. :func:`caller_identity` is
that resolution, and it is shared by REST, MCP and the admin UI so a client
cannot get a different answer by changing ports.

Both FastAPI REST (``fastapi_app``) and the MCP HTTP transport wrap their
write endpoints with the dependency returned by :func:`require_api_key`
when the mode is ``"api_key"``, and with :func:`proxy_trust_dependency`
otherwise. Read-only probes (``/healthz``, ``/readyz``) stay un-gated.
"""

from __future__ import annotations

import secrets
from ipaddress import ip_address, ip_network
from typing import TYPE_CHECKING, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

# Imported at runtime, not under TYPE_CHECKING: with ``from __future__ import
# annotations`` a TYPE_CHECKING-only name leaves FastAPI an unresolvable
# ForwardRef, so it read ``request`` as a query parameter and every call to a
# route depending on ``verify_session_token`` 422'd instead of being verified.
# The same trap is documented in ``ui/router.py`` and ``fastapi_app.py``.
from starlette.requests import Request

from nautilus.config.models import CAPABILITIES

if TYPE_CHECKING:
    from nautilus.attestation.session_token import SessionTokenClaims

# Optional session-token header for AC-18.f verification.
SESSION_TOKEN_HEADER = "X-Nautilus-Session-Token"
"""Header carrying the broker-issued session JWS. Mirrored (deliberately,
to keep the adapter layer off the transport layer) by
``nautilus.adapters.base.SESSION_TOKEN_HEADER``."""


# Module-level APIKeyHeader instance — FastAPI caches dependency providers
# by identity, so sharing one instance across routes keeps the OpenAPI
# security scheme declaration consistent.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)
"""FastAPI security scheme for the ``X-API-Key`` header (auto_error=True)."""


ALL_CAPABILITIES: frozenset[str] = frozenset(CAPABILITIES)
"""What an unbound credential holds — the bare-key and no-registry behaviour."""


def key_value(entry: object) -> str:
    """The secret in a configured key, whichever form the operator wrote."""
    return entry if isinstance(entry, str) else str(getattr(entry, "key", ""))


def _match_key(header_value: str, keys: list[Any]) -> Any | None:
    """The configured entry whose secret is ``header_value``, or ``None``.

    Compares every entry with :func:`secrets.compare_digest` — a plain ``in`` /
    ``==`` would leak per-byte timing and let an attacker derive the secret
    (D-11).
    """
    header_bytes = header_value.encode("utf-8") if header_value else b""
    for entry in keys:
        if secrets.compare_digest(header_bytes, key_value(entry).encode("utf-8")):
            return entry
    return None


def _capabilities_of(entry: object) -> frozenset[str]:
    """What a matched key entry may do; a bare string may do everything."""
    if isinstance(entry, str):
        return ALL_CAPABILITIES
    declared = getattr(entry, "capabilities", None)
    if declared is None:
        return ALL_CAPABILITIES
    return frozenset(str(c) for c in declared)


def caller_identity(
    request: Request,
    *,
    auth_mode: str = "api_key",
    keys: list[Any] | None = None,
    agent_subjects: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Who the transport authenticated this request as (§4.15, readiness §2).

    Four fields:

    - ``auth`` — the authenticated principal: the API key the request presented
      or, under ``proxy_trust``, the upstream's ``X-Forwarded-User``. This keys
      the cumulative-exposure ledger, so it must carry nothing the caller's own
      payload can set.
    - ``peer`` — the socket address, recorded for provenance and used as the
      ledger key's fallback only when the deployment authenticates nobody.
    - ``agent_id`` — the *only* agent this credential may speak for, or ``None``
      when nothing binds it (a bare-string key, or an unregistered subject).
      ``None`` is the historical behaviour: the caller names its own agent.
    - ``capabilities`` — what this credential may do. Everything, unless a
      structured key entry says otherwise.

    Shared rather than per-transport on purpose: it lived inside ``create_app``
    and only REST ever called it, so the same client presenting the same key to
    the MCP port accumulated into a different ledger and escaped escalation by
    switching transport.
    """
    agent_id: str | None = None
    capabilities = ALL_CAPABILITIES
    if auth_mode == "proxy_trust":
        auth = request.headers.get("X-Forwarded-User") or ""
        # The ingress authenticated the subject; ``agents.<id>.subject`` is what
        # says which agent it is. An unmapped subject stays unbound rather than
        # being refused here — ``proxy_trust_dependency`` owns the 401.
        if auth and agent_subjects:
            agent_id = agent_subjects.get(auth)
    else:
        auth = request.headers.get("X-API-Key") or ""
        entry = _match_key(auth, keys) if keys else None
        if entry is not None:
            agent_id = getattr(entry, "agent_id", None)
            capabilities = _capabilities_of(entry)
    peer = request.client.host if request.client else ""
    return {"auth": auth, "peer": peer, "agent_id": agent_id, "capabilities": capabilities}


def verify_api_key(header_value: str, keys: list[Any]) -> None:
    """Verify ``header_value`` against every key in ``keys`` in constant time.

    Uses :func:`secrets.compare_digest` per key — a plain ``in`` / ``==``
    comparison would leak per-byte timing and let an attacker derive the
    secret (D-11: "API key default, constant-time comparison").

    Args:
        header_value: Raw ``X-API-Key`` header value supplied by the caller.
        keys: Operator-configured allow-list (from ``config.api.keys``) —
            bare strings, structured :class:`~nautilus.config.models.ApiKeyEntry`
            records, or a mix.

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
    if _match_key(header_value, list(keys)) is not None:
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


def _peer_is_trusted(peer: str, trusted: list[str]) -> bool:
    """Is ``peer`` inside one of the configured ``trusted_proxies`` blocks?"""
    if not peer:
        return False
    try:
        address = ip_address(peer)
    except ValueError:
        return False
    for entry in trusted:
        try:
            if address in ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


async def proxy_trust_dependency(request: Request) -> str:
    """Return the upstream-proxy-asserted user from ``X-Forwarded-User``.

    Used when ``config.api.auth.mode == "proxy_trust"`` — the upstream
    mesh/ingress has already authenticated the caller (mTLS, SPIFFE, OIDC) and
    forwarded the resolved identity. Under this mode the header *is* the
    credential, so it is only an identity while nobody but the proxy can set
    it: the socket peer must fall inside ``api.auth.trusted_proxies``, which
    the config refuses to omit.

    Raises:
        HTTPException: 401 if the peer is not a configured proxy, or if
            ``X-Forwarded-User`` is missing or empty — the proxy SHOULD always
            set it when traffic reaches us; a missing header implies a bypass
            attempt.
    """
    app = request.scope.get("app")
    state = getattr(app, "state", None)
    trusted: list[str] = list(getattr(state, "trusted_proxies", []) or [])
    peer = request.client.host if request.client else ""
    if not _peer_is_trusted(peer, trusted):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Forwarded identity rejected: peer is not a trusted proxy",
        )
    user = request.headers.get("X-Forwarded-User")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Forwarded-User",
        )
    return user


async def verify_session_token(
    request: Request,
) -> SessionTokenClaims | None:
    """Optional FastAPI dependency — validate ``X-Nautilus-Session-Token`` if present.

    Returns the decoded :class:`~nautilus.attestation.session_token.SessionTokenClaims`
    when the header is present and valid. Returns ``None`` when the header is
    absent (the token is not required by all endpoints). Raises ``HTTPException``
    401 when the header is present but invalid (AC-18.d).

    The ``KeyRing`` is read from ``app.state.key_ring``; if the state attribute
    is absent the dependency is a no-op and returns ``None`` so existing tests
    that don't populate the state continue to pass.
    """
    token_value = request.headers.get(SESSION_TOKEN_HEADER)
    if not token_value:
        return None
    from nautilus.attestation.session_token import SessionTokenError, SessionTokenService

    # AC-18.f — prefer the broker's token service so verification failures
    # emit ``session_token_verification_failed`` audit entries. The
    # isinstance guard keeps mock-broker tests on the unaudited fallback.
    broker: Any = getattr(request.app.state, "broker", None)
    broker_service = getattr(broker, "session_tokens", None) if broker is not None else None
    if isinstance(broker_service, SessionTokenService):
        try:
            claims: SessionTokenClaims = broker.verify_session_token(token_value)
            return claims
        except SessionTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid session token: {exc.reason_code}",
            ) from exc

    key_ring = getattr(request.app.state, "key_ring", None)
    if key_ring is None:
        return None
    broker_instance_id = getattr(request.app.state, "broker_instance_id", "unknown")
    service = SessionTokenService(key_ring=key_ring, broker_instance_id=broker_instance_id)
    try:
        return service.verify(token_value)
    except SessionTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid session token: {exc.reason_code}",
        ) from exc


__all__ = [
    "ALL_CAPABILITIES",
    "SESSION_TOKEN_HEADER",
    "api_key_header",
    "caller_identity",
    "key_value",
    "proxy_trust_dependency",
    "require_api_key",
    "verify_api_key",
    "verify_session_token",
]
