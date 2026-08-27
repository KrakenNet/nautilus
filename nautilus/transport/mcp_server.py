"""MCP (Model Context Protocol) transport for Nautilus (design §3.13, FR-27).

Single public entrypoint — :func:`create_server` — returns a fully wired
:class:`FastMCP` instance. The server exposes one mandatory tool and one
optional tool:

- ``nautilus_request(agent_id, intent, context, ctx)`` — primary query
  entrypoint; thin wrapper over :meth:`Broker.arequest`. ``agent_id`` is
  taken VERBATIM from the tool argument (AC-13.3) — never derived from
  the MCP ``client_id`` or any other transport-provided identifier.
- ``nautilus_declare_handoff(...)`` — optional, gated on
  ``config.mcp.expose_declare_handoff == True`` (D-12). Surfaces the
  broker's reasoning-only handoff evaluation through MCP for clients
  that need to declare agent-to-agent data flows.

Session-id resolution (D-10 / UQ-4) — before calling ``broker.arequest``:

1. If ``context.get("session_id")`` is set → use it verbatim; audit
   ``session_id_source="context"``.
2. Else if ``ctx`` has a ``session_id`` attribute (HTTP streamable-
   transport mode) → use ``ctx.session_id``; audit
   ``session_id_source="transport"``.
3. Else (stdio or no context at all) → use ``ctx.request_id``; audit
   ``session_id_source="stdio_request_id"``.
4. If ``ctx`` is ``None`` and no context ``session_id`` was provided →
   generate a fresh UUID and audit ``session_id_source="generated"``
   (D-10 safe default — never leave ``session_id`` blank).

The resolved ``session_id`` and its source are injected back into the
broker ``context`` dict under the ``session_id`` and
``session_id_source`` keys so downstream audit wiring can stamp
:attr:`AuditEntry.session_id_source` once the broker honors the field.

HTTP transport auth: when callers host the Starlette sub-app via
:meth:`FastMCP.streamable_http_app`, they can wrap it with
:func:`wrap_http_with_api_key` to reuse the same ``X-API-Key`` scheme
that :mod:`nautilus.transport.fastapi_app` enforces on ``/v1/*``. The
stdio transport is un-gated by design — it is only reachable from a
parent process that already trusts the subprocess boundary (design
§3.13).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import Context, FastMCP

from nautilus.core.broker import Broker
from nautilus.core.models import BrokerResponse, HandoffDecision
from nautilus.transport.auth import verify_api_key

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.applications import Starlette
    from starlette.types import ASGIApp, Receive, Scope, Send


# Header name is shared verbatim with :mod:`nautilus.transport.fastapi_app`
# so operators can configure one allow-list for both surfaces (D-11).
_API_KEY_HEADER = "x-api-key"


def _resolve_session(
    context: dict[str, Any],
    ctx: Context[Any, Any, Any] | None,
) -> tuple[str, str]:
    """Resolve ``(session_id, session_id_source)`` per D-10 / UQ-4.

    Priority order:

    1. ``context["session_id"]`` (caller-asserted, e.g. carried across
       multi-turn reasoning) → source ``"context"``.
    2. ``ctx.session_id`` (HTTP streamable-transport supplies one per
       stream) → source ``"transport"``.
    3. ``ctx.request_id`` (stdio — per-tool-call id) → source
       ``"stdio_request_id"``.
    4. Freshly minted UUID → source ``"generated"`` (D-10 safe default;
       only reached when no ``ctx`` is present AND no context key set).
    """
    ctx_session = context.get("session_id")
    if isinstance(ctx_session, str) and ctx_session:
        return ctx_session, "context"
    if ctx is not None:
        transport_session = getattr(ctx, "session_id", None)
        if isinstance(transport_session, str) and transport_session:
            return transport_session, "transport"
        request_id = getattr(ctx, "request_id", None)
        if isinstance(request_id, str) and request_id:
            return request_id, "stdio_request_id"
    return str(uuid.uuid4()), "generated"


def _mcp_settings(broker: Broker | None) -> tuple[bool, str, list[str]]:
    """Extract ``(expose_declare_handoff, auth_mode, api_keys)`` defensively.

    Mirrors :func:`nautilus.transport.fastapi_app._resolve_auth_config` —
    tolerates partially-populated configs from tests that inject a mock
    broker without a full :class:`NautilusConfig`. Defaults are the
    safest possible: handoff tool off, auth mode ``"api_key"``, empty
    keys list (fail-closed — :func:`verify_api_key` raises 401).
    """
    if broker is None:
        return (False, "api_key", [])
    config = getattr(broker, "_config", None)
    mcp_cfg = getattr(config, "mcp", None) if config is not None else None
    expose_handoff = bool(getattr(mcp_cfg, "expose_declare_handoff", False))
    api_cfg = getattr(config, "api", None) if config is not None else None
    auth_obj = getattr(api_cfg, "auth", None)
    mode_raw = getattr(auth_obj, "mode", None) if auth_obj is not None else None
    mode = mode_raw if mode_raw in ("api_key", "proxy_trust") else "api_key"
    keys_raw: object = getattr(api_cfg, "keys", None)
    keys: list[str] = []
    if isinstance(keys_raw, list):
        for k in keys_raw:  # pyright: ignore[reportUnknownVariableType]
            keys.append(str(k))  # pyright: ignore[reportUnknownArgumentType]
    return (expose_handoff, mode, keys)


def wrap_http_with_api_key(app: Starlette, keys: list[str]) -> ASGIApp:
    """Wrap the FastMCP streamable-HTTP sub-app with the shared API-key gate.

    The official MCP Python SDK exposes :meth:`FastMCP.streamable_http_app`
    which returns a :class:`starlette.applications.Starlette` instance.
    This helper returns an ASGI callable that performs constant-time
    ``X-API-Key`` verification (via :func:`verify_api_key`) before
    delegating to ``app``. On auth failure the wrapper responds with a
    minimal ``401`` JSON body so the MCP client sees a clean HTTP error
    rather than a protocol-level decode failure.
    """

    async def middleware(scope: Scope, receive: Receive, send: Send) -> None:
        """Verify the ``X-API-Key`` header before delegating to the wrapped app.

        Lifespan and websocket scopes bypass the check so the MCP SDK's
        session-store initialization runs regardless of caller identity.
        Auth failures are translated into a minimal ``401`` JSON response.

        Args:
            scope: ASGI scope dict for the incoming connection.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope["type"] != "http":
            # Lifespan / websocket events bypass auth — the MCP SDK uses
            # lifespan for session-store init, which MUST run regardless
            # of caller identity.
            await app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        raw_value = headers.get(_API_KEY_HEADER.encode("latin-1"), b"")
        header_value = raw_value.decode("latin-1") if raw_value else ""
        try:
            verify_api_key(header_value, keys)
        except Exception:  # noqa: BLE001 — translate 401 to ASGI response
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": b'{"detail":"Invalid or missing API key"}',
                }
            )
            return
        await app(scope, receive, send)

    return middleware


def create_server(
    config_path: str | Path | None,
    *,
    existing_broker: Broker | None = None,
) -> FastMCP[Any]:
    """Construct the Nautilus FastMCP server (design §3.13, FR-27).

    Args:
        config_path: Path to ``nautilus.yaml``. Ignored when
            ``existing_broker`` is provided (tests inject a pre-built or
            mock broker to skip YAML loading).
        existing_broker: Pre-constructed broker. When supplied, the
            server reuses it and does NOT call :meth:`Broker.setup` or
            :meth:`Broker.aclose` — lifecycle ownership stays with the
            caller (mirrors the FastAPI factory contract for injected
            brokers, except here the caller must run setup themselves).

    Returns:
        Fully wired :class:`FastMCP` with ``nautilus_request`` tool
        registered and, when ``config.mcp.expose_declare_handoff`` is
        true, ``nautilus_declare_handoff`` registered alongside it.

    Raises:
        ValueError: if both ``config_path`` and ``existing_broker`` are
            ``None`` — the factory has no way to produce a broker.
    """
    if existing_broker is None and config_path is None:
        raise ValueError(
            "create_server requires either config_path or existing_broker",
        )
    if existing_broker is not None:
        broker: Broker = existing_broker
    else:
        assert config_path is not None  # noqa: S101 — guarded above
        broker = Broker.from_config(config_path)

    mcp: FastMCP[Any] = FastMCP(
        name="nautilus",
        stateless_http=True,
        json_response=True,
    )

    expose_handoff, _auth_mode, _api_keys = _mcp_settings(broker)

    # ------------------------------------------------------------------
    # Tool: nautilus_request — primary query entrypoint (AC-13.1, FR-27).
    # ``agent_id`` is taken VERBATIM from the tool argument; NEVER derived
    # from ``ctx.client_id`` or any other MCP-provided identifier
    # (AC-13.3).
    # ------------------------------------------------------------------

    @mcp.tool()
    async def nautilus_request(  # pyright: ignore[reportUnusedFunction]
        agent_id: str,
        intent: str,
        context: dict[str, Any] | None = None,
        ctx: Context[Any, Any, Any] | None = None,
    ) -> BrokerResponse:
        """Invoke :meth:`Broker.arequest` from an MCP client.

        The tool is intentionally thin — all policy, routing, and
        attestation logic live inside the broker. See :func:`_resolve_session`
        for the D-10 fallback chain.
        """
        ctx_dict: dict[str, Any] = dict(context) if context else {}
        session_id, source = _resolve_session(ctx_dict, ctx)
        ctx_dict["session_id"] = session_id
        ctx_dict["session_id_source"] = source
        return await broker.arequest(agent_id, intent, ctx_dict)

    # ------------------------------------------------------------------
    # Optional tool: nautilus_declare_handoff — gated on
    # ``config.mcp.expose_declare_handoff`` (D-12). Registered only when
    # the operator has opted in.
    # ------------------------------------------------------------------

    if expose_handoff:

        @mcp.tool()
        async def nautilus_declare_handoff(  # pyright: ignore[reportUnusedFunction]
            source_agent_id: str,
            receiving_agent_id: str,
            data_classifications: list[str],
            session_id: str | None = None,
            data_compartments: list[str] | None = None,
            ctx: Context[Any, Any, Any] | None = None,
        ) -> HandoffDecision:
            """Invoke :meth:`Broker.declare_handoff` from an MCP client.

            ``session_id`` follows the same D-10 fallback as
            ``nautilus_request``: caller-supplied → transport-supplied →
            stdio ``request_id`` → generated UUID.
            """
            resolved_session, _source = _resolve_session(
                {"session_id": session_id} if session_id else {},
                ctx,
            )
            return await broker.declare_handoff(
                source_agent_id=source_agent_id,
                receiving_agent_id=receiving_agent_id,
                session_id=resolved_session,
                data_classifications=data_classifications,
                data_compartments=data_compartments,
            )

    return mcp


def http_app(
    mcp: FastMCP[Any],
    *,
    api_keys: list[str] | None = None,
) -> ASGIApp:
    """Return the streamable-HTTP sub-app wrapped with the shared API-key gate.

    Convenience helper for operators who want to mount the MCP HTTP
    transport behind the same auth scheme as the FastAPI REST surface
    (D-11). When ``api_keys`` is ``None`` or empty the wrapper still
    runs :func:`verify_api_key`, which fails closed — so unconfigured
    deployments cannot accidentally expose an unauthenticated tool.
    """
    starlette_app = mcp.streamable_http_app()
    keys = list(api_keys) if api_keys else []
    return wrap_http_with_api_key(starlette_app, keys)


# Re-exports for static-import smoke tests and downstream callers.
__all__: list[str] = [
    "create_server",
    "http_app",
    "wrap_http_with_api_key",
]

# `Awaitable` / `Callable` are imported under TYPE_CHECKING solely to
# keep the module lightweight at runtime; reference them here so the
# import is not flagged as unused.
_typing_refs: tuple[object, ...] = ()
if TYPE_CHECKING:
    _typing_refs = (Awaitable, Callable)
