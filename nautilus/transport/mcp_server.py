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
2. Else if the request carries the transport's ``mcp-session-id``
   (HTTP streamable transport) → use ``mcp:<id>``; audit
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

import json
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, cast

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from nautilus.core.broker import Broker
from nautilus.core.models import BrokerResponse, HandoffDecision
from nautilus.transport.auth import caller_identity, capability_refusal, verify_api_key

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

# Header name is shared verbatim with :mod:`nautilus.transport.fastapi_app`
# so operators can configure one allow-list for both surfaces (D-11).
_API_KEY_HEADER = "x-api-key"


# Mirrors ``MCPConfig.max_response_bytes``; used only for the defensive
# path where a test injects a broker with no full NautilusConfig.
_DEFAULT_MAX_RESPONSE_BYTES = 262_144


def _resolve_session(
    context: dict[str, Any],
    ctx: Context[Any, Any, Any] | None,
) -> tuple[str, str]:
    """Resolve ``(session_id, session_id_source)`` per D-10 / UQ-4.

    Priority order:

    1. ``context["session_id"]`` (caller-asserted, e.g. carried across
       multi-turn reasoning) → source ``"context"``.
    2. the transport's ``mcp-session-id`` (HTTP streamable transport
       issues one per client at ``initialize``) → source ``"transport"``.
    3. ``ctx.request_id`` (stdio — per-tool-call id) → source
       ``"stdio_request_id"``.
    4. Freshly minted UUID → source ``"generated"`` (D-10 safe default;
       only reached when no ``ctx`` is present AND no context key set).
    """
    ctx_session = context.get("session_id")
    if isinstance(ctx_session, str) and ctx_session:
        return ctx_session, "context"
    if ctx is not None:
        transport_session = _transport_session(ctx)
        if transport_session:
            return transport_session, "transport"
        request_id = getattr(ctx, "request_id", None)
        if isinstance(request_id, str) and request_id:
            return request_id, "stdio_request_id"
    return str(uuid.uuid4()), "generated"


def _transport_session(ctx: Context[Any, Any, Any]) -> str | None:
    """The HTTP transport's own session id, or ``None`` (stdio, or no request).

    ``Context`` has no ``session_id`` attribute -- the value lives on the
    request as the ``mcp-session-id`` header the SDK issues at ``initialize``.
    Reading a non-existent attribute silently fell through to ``request_id``.
    """
    request = getattr(getattr(ctx, "request_context", None), "request", None)
    headers = getattr(request, "headers", None)
    if headers is None:
        return None
    session_id = headers.get("mcp-session-id")
    return f"mcp:{session_id}" if session_id else None


def _caller(
    ctx: Context[Any, Any, Any] | None,
    auth_mode: str,
    keys: list[Any] | None = None,
    agent_subjects: dict[str, str] | None = None,
    trusted_proxies: list[str] | None = None,
) -> dict[str, Any] | None:
    """The caller identity to key the exposure ledger with, or ``None``.

    Only the HTTP transport has one: it carries the same ``X-API-Key`` /
    ``X-Forwarded-User`` the REST surface authenticates, and the ledger has to
    be the same ledger -- otherwise a client that has tripped escalation over
    REST starts clean by sending its next request to the MCP port with the
    credentials it already has. stdio has no such header and no network peer;
    ``None`` there means the broker falls back to keying on ``agent_id``, which
    is right, because the parent process owns the pipe.
    """
    try:
        request = getattr(ctx.request_context, "request", None) if ctx is not None else None
    except (AttributeError, LookupError, ValueError):
        # ``Context.request_context`` raises "Context is not available outside
        # of a request" rather than returning None, and ``getattr`` with a
        # default only swallows AttributeError. A tool invoked outside a
        # request (a direct ``call_tool``, a stdio session) has no caller --
        # which is the same answer as stdio, not an error.
        return None
    if request is None or not hasattr(request, "headers"):
        return None
    return caller_identity(
        request,
        auth_mode=auth_mode,
        keys=keys,
        agent_subjects=agent_subjects,
        trusted_proxies=trusted_proxies,
    )


def _bound_response(response: BrokerResponse, max_bytes: int | None) -> BrokerResponse:
    """Trim ``response.data`` until the serialized result fits ``max_bytes``.

    An MCP tool result is read straight into a model's context window, and the
    SDK re-encodes it indented and puts it on the wire twice -- once as text
    content, once as ``structuredContent`` -- so the pipe carries about 2.1x
    what is measured here. Measured at 1.9 MB for one unbounded call over a
    single 2000-row source; adapters cap each source at 1000 rows, so several
    sources multiply from there. REST needs none of this: an HTTP client
    streams to a file.

    Rows are dropped whole and from the end, and every source that lost rows is
    named in ``truncated_sources`` -- the same field the adapter row cap
    already uses, because from the caller's side both mean "you were given a
    subset". The attestation still covers the full set the broker released;
    ``truncated_sources`` is what says the wire carried less than that.
    """
    if max_bytes is None or not response.data:
        return response
    if len(response.model_dump_json()) <= max_bytes:
        return response

    # Budget is what is left after everything that is not rows -- the
    # attestation JWT alone runs to a few kilobytes, and a bound that ignored
    # it would still overshoot.
    empty = response.model_copy(update={"data": {source: [] for source in response.data}})
    share = max((max_bytes - len(empty.model_dump_json())) // len(response.data), 0)

    kept: dict[str, list[dict[str, Any]]] = {}
    truncated = set(response.truncated_sources)
    for source_id, rows in response.data.items():
        used = 0
        keep: list[dict[str, Any]] = []
        for row in rows:
            used += len(json.dumps(row, default=str)) + 1
            if used > share:
                break
            keep.append(row)
        if len(keep) != len(rows):
            truncated.add(source_id)
        kept[source_id] = keep
    return response.model_copy(update={"data": kept, "truncated_sources": sorted(truncated)})


def _mcp_settings(broker: Broker | None) -> tuple[bool, str, list[Any], int | None]:
    """Extract ``(expose_declare_handoff, auth_mode, api_keys, max_response_bytes)``.

    Mirrors :func:`nautilus.transport.fastapi_app._resolve_auth_config` —
    tolerates partially-populated configs from tests that inject a mock
    broker without a full :class:`NautilusConfig`. Defaults are the
    safest possible: handoff tool off, auth mode ``"api_key"``, empty
    keys list (fail-closed — :func:`verify_api_key` raises 401).
    """
    if broker is None:
        return (False, "api_key", [], _DEFAULT_MAX_RESPONSE_BYTES)
    config = getattr(broker, "_config", None)
    mcp_cfg = getattr(config, "mcp", None) if config is not None else None
    expose_handoff = bool(getattr(mcp_cfg, "expose_declare_handoff", False))
    max_bytes_raw: object = getattr(mcp_cfg, "max_response_bytes", _DEFAULT_MAX_RESPONSE_BYTES)
    max_bytes = max_bytes_raw if isinstance(max_bytes_raw, int) or max_bytes_raw is None else None
    api_cfg = getattr(config, "api", None) if config is not None else None
    auth_obj = getattr(api_cfg, "auth", None)
    mode_raw = getattr(auth_obj, "mode", None) if auth_obj is not None else None
    mode = mode_raw if mode_raw in ("api_key", "proxy_trust") else "api_key"
    keys_raw: object = getattr(api_cfg, "keys", None)
    keys: list[Any] = []
    if isinstance(keys_raw, list):
        keys = list(cast("list[Any]", keys_raw))
    return (expose_handoff, mode, keys, max_bytes)


def _trusted_proxies(broker: Broker | None) -> list[str]:
    """``api.auth.trusted_proxies`` — who may assert ``X-Forwarded-User``.

    This port mounts no ``proxy_trust_dependency``; ``caller_identity`` does the
    vetting, and it can only do it with the list. Omitting it trusts nobody, so
    a deployment whose list never reached this door 401s rather than believing
    whatever the caller typed.
    """
    config = getattr(broker, "_config", None) if broker is not None else None
    api_cfg = getattr(config, "api", None)
    auth_obj = getattr(api_cfg, "auth", None)
    proxies: object = getattr(auth_obj, "trusted_proxies", None)
    if not isinstance(proxies, list):
        return []
    return [str(entry) for entry in cast("list[object]", proxies)]


def _api_key_from_scope(scope: Scope) -> str:
    """The ``X-API-Key`` value ``caller_identity`` will read, from a raw scope.

    ``dict(scope["headers"])`` keeps the **last** value of a repeated header;
    Starlette's ``Headers.get`` -- which is what ``caller_identity`` reads
    through -- keeps the **first**. Authenticating on one and authorising on the
    other let a caller who sent ``X-API-Key`` twice pass the gate on a valid key
    and then match no registry entry, falling through to the unauthenticated
    default: every capability, bound to no agent. One reader, one answer.
    """
    return Headers(scope=scope).get(_API_KEY_HEADER, "")


def _agent_subjects(broker: Broker | None) -> dict[str, str]:
    """``agents.<id>.subject`` → agent id, for ``proxy_trust`` (see REST twin)."""
    config = getattr(broker, "_config", None) if broker is not None else None
    agents: object = getattr(config, "agents", None)
    if not isinstance(agents, dict):
        return {}
    subjects: dict[str, str] = {}
    for agent_id, record in cast("dict[str, object]", agents).items():
        subject = getattr(record, "subject", None)
        if isinstance(subject, str) and subject:
            subjects[subject] = str(agent_id)
    return subjects


def wrap_http_with_api_key(app: Starlette, keys: list[Any] | Callable[[], list[Any]]) -> ASGIApp:
    """Wrap the FastMCP streamable-HTTP sub-app with the shared API-key gate.

    The official MCP Python SDK exposes :meth:`FastMCP.streamable_http_app`
    which returns a :class:`starlette.applications.Starlette` instance.
    This helper returns an ASGI callable that performs constant-time
    ``X-API-Key`` verification (via :func:`verify_api_key`) before
    delegating to ``app``. On auth failure the wrapper responds with a
    minimal ``401`` JSON body so the MCP client sees a clean HTTP error
    rather than a protocol-level decode failure.

    ``keys`` may be a callable, and ``serve`` passes one: a live credential
    rotation replaces the broker's config object, so a list captured here at
    construction would keep admitting the retired key on the MCP port after
    REST had stopped admitting it anywhere.
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
        header_value = _api_key_from_scope(scope)
        try:
            verify_api_key(header_value, list(keys()) if callable(keys) else keys)
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

    # Stateful streamable HTTP: the SDK issues one ``mcp-session-id`` per
    # client and ``_resolve_session`` keys session state on it. Under
    # ``stateless_http=True`` there is no transport session at all, so the
    # fallback was ``ctx.request_id`` -- the client's own JSON-RPC id, which is
    # usually a small integer, so two unrelated callers both sending ``id: 1``
    # landed in one session and read each other's cumulative exposure.
    mcp: FastMCP[Any] = FastMCP(
        name="nautilus",
        stateless_http=False,
        json_response=True,
    )

    expose_handoff, _, _, max_response_bytes = _mcp_settings(broker)
    agent_subjects = _agent_subjects(broker)

    def _resolve_caller(ctx: Context[Any, Any, Any] | None) -> dict[str, Any] | None:
        # Re-resolved per call rather than captured at construction: a rotation
        # adopted by ``SIGHUP`` has to reach this door too, or the retired key
        # keeps naming a caller here after it stopped opening the front one.
        _, auth_mode, api_keys, _ = _mcp_settings(broker)
        return _caller(ctx, auth_mode, api_keys, agent_subjects, _trusted_proxies(broker))

    def _refuse_without_capability(caller: dict[str, Any] | None, capability: str) -> None:
        """The credential must hold ``capability``, exactly as it must on REST.

        ``verify_api_key`` at the ASGI gate only asks whether the presented
        secret matches *some* configured entry; it never reads that entry's
        capabilities. So a key configured ``{capabilities: [audit_read]}`` --
        one whose whole configured purpose is reading the audit log -- was
        refused by ``/v1/request`` with a 403 and ran the same query here.

        ``caller is None`` is stdio, which carries no credential at all: the
        parent process owns the pipe, and there is nothing to scope.
        """
        if caller is None:
            return
        refusal = capability_refusal(caller, capability)
        if refusal is not None:
            raise ValueError(refusal)

    def _refuse_impersonation(caller: dict[str, Any] | None, agent_id: str) -> None:
        """The credential names one agent; the tool argument must match it.

        ``agent_id`` is taken verbatim from the tool argument (AC-13.3) and that
        does not change — what changes is that a *bound* credential may only
        pass its own. Without this the whole binding is bypassed by sending the
        same key to the MCP port instead of the REST one.
        """
        bound = (caller or {}).get("agent_id")
        if bound is not None and bound != agent_id:
            raise ValueError(
                f"This credential is bound to agent_id={bound!r}, so it cannot ask as {agent_id!r}"
            )

    # ------------------------------------------------------------------
    # Tool: nautilus_request — primary query entrypoint (AC-13.1, FR-27).
    # ``agent_id`` is taken VERBATIM from the tool argument; NEVER derived
    # from ``ctx.client_id`` or any other MCP-provided identifier
    # (AC-13.3).
    # ------------------------------------------------------------------

    @mcp.tool(
        description=(
            "Ask Nautilus for data. Nautilus decides which of its configured "
            "sources may answer, applies whatever restrictions its rules "
            "attach, runs the query, and returns the rows with a signed "
            "attestation of the decision.\n\n"
            "Arguments:\n"
            "  agent_id: which agent is asking. Its clearance and permitted "
            "purposes come from the broker's config, not from this call.\n"
            "  intent: what you want, in plain language "
            '("recent orders for user 42"). Restrictions you write here are '
            "not pushed into the query unless a rule says so — check "
            "'scope_restrictions' in the reply for what was actually "
            "applied.\n"
            "  context: why you want it. 'purpose' is the field policy is "
            "written against and should always be set; the purposes each "
            "source accepts are listed by nautilus_sources, so read them "
            "there rather than guessing. 'session_id' ties several requests "
            "into one session so cumulative exposure accrues to it.\n\n"
            "The response says what happened: 'outcome' is allowed / denied / "
            "errored / skipped, 'data' maps source id to rows, 'source_info' "
            "says what each of those sources is — read it before presenting "
            "rows as current or complete — and "
            "'denial_records' names the rule that refused a source and why. "
            "'truncated_sources' names any source whose rows were cut short — "
            "by the adapter's own row cap or to keep this reply inside its size "
            "bound — so treat those rows as a sample, not the whole set, and "
            "narrow the intent if you need all of it."
        )
    )
    async def nautilus_request(  # pyright: ignore[reportUnusedFunction]
        agent_id: str,
        intent: str,
        context: Annotated[
            dict[str, Any] | None,
            Field(
                description=(
                    "Request context. 'purpose' is what policy is written "
                    "against; 'session_id' groups requests into one session."
                )
            ),
        ] = None,
        ctx: Context[Any, Any, Any] | None = None,
    ) -> BrokerResponse:
        """Invoke :meth:`Broker.arequest` from an MCP client.

        The tool is intentionally thin — all policy, routing, and
        attestation logic live inside the broker. See :func:`_resolve_session`
        for the D-10 fallback chain. The client-facing description is the
        ``description=`` argument above: a model reads that, not this
        docstring, and a Sphinx cross-reference tells it nothing.
        """
        caller = _resolve_caller(ctx)
        _refuse_without_capability(caller, "query")
        _refuse_impersonation(caller, agent_id)
        ctx_dict: dict[str, Any] = dict(context) if context else {}
        session_id, source = _resolve_session(ctx_dict, ctx)
        ctx_dict["session_id"] = session_id
        ctx_dict["session_id_source"] = source
        return _bound_response(
            await broker.arequest(agent_id, intent, ctx_dict, caller=caller),
            max_response_bytes,
        )

    # ------------------------------------------------------------------
    # Optional tool: nautilus_declare_handoff — gated on
    # ``config.mcp.expose_declare_handoff`` (D-12). Registered only when
    # the operator has opted in.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Tool: nautilus_sources — what a client may ask for. The REST surface
    # has answered this at ``GET /v1/sources`` since AC-12.3; an MCP client
    # had to guess.
    # ------------------------------------------------------------------

    @mcp.tool(
        description=(
            "List the data sources this broker can route to: id, type, "
            "description, classification, the data types each one holds and "
            "the purposes it accepts. Metadata only — never connection "
            "strings or credentials. Use it to phrase an intent that some "
            "source can actually answer, and to pick a purpose from "
            "'allowed_purposes' rather than guessing one."
        )
    )
    async def nautilus_sources(  # pyright: ignore[reportUnusedFunction]
        ctx: Context[Any, Any, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Metadata-only source listing, the same shape as ``GET /v1/sources``.

        ``ctx`` is here only to resolve the caller: the REST twin is gated on
        the ``query`` capability and this must be too, or the gate is a door
        with a second entrance.
        """
        sources_caller = _resolve_caller(ctx)
        _refuse_without_capability(sources_caller, "query")
        # The capability decides *whether* you get a catalogue; the clearance
        # filter decides *which*. ``GET /v1/sources`` and both console surfaces
        # trim to ``sources_visible_to``; this door read ``broker.sources``
        # whole, so the second entrance the docstring warns about was open
        # after all -- just one guard further in.
        return [
            {
                "id": source.id,
                "type": source.type,
                "description": source.description,
                "classification": source.classification,
                "data_types": list(source.data_types),
                "allowed_purposes": list(source.allowed_purposes or []),
            }
            for source in broker.sources_visible_to((sources_caller or {}).get("agent_id"))
        ]

    if expose_handoff:

        @mcp.tool(
            description=(
                "Declare that one agent is handing data to another, and get "
                "the broker's decision before you do it. Reasoning only: no "
                "source is queried. Returns action 'allow' or 'deny', and on "
                "a denial the rule that refused it and why."
            )
        )
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
            handoff_caller = _resolve_caller(ctx)
            _refuse_without_capability(handoff_caller, "query")
            _refuse_impersonation(handoff_caller, source_agent_id)
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
    api_keys: list[Any] | Callable[[], list[Any]] | None = None,
) -> ASGIApp:
    """Return the streamable-HTTP sub-app wrapped with the shared API-key gate.

    Convenience helper for operators who want to mount the MCP HTTP
    transport behind the same auth scheme as the FastAPI REST surface
    (D-11). When ``api_keys`` is ``None`` or empty the wrapper still
    runs :func:`verify_api_key`, which fails closed — so unconfigured
    deployments cannot accidentally expose an unauthenticated tool.
    """
    starlette_app = mcp.streamable_http_app()
    if callable(api_keys):
        return wrap_http_with_api_key(starlette_app, api_keys)
    return wrap_http_with_api_key(starlette_app, list(api_keys) if api_keys else [])


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
