"""Smoke tests for :mod:`nautilus.transport.mcp_server` (VERIFY 2.19).

The MCP surface has three units worth smoke-covering:

* :func:`_resolve_session` — D-10 / UQ-4 fallback chain.
* :func:`create_server` — tool registration gating on
  ``expose_declare_handoff``, plus verbatim ``agent_id`` handling
  (AC-13.3).
* :func:`wrap_http_with_api_key` / :func:`http_app` — minimal ASGI auth
  wrapper exercised via a fake inner ASGI app.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.core.models import BrokerResponse
from nautilus.transport import mcp_server as mcp_server_mod
from nautilus.transport.mcp_server import (
    create_server,
    http_app,
    wrap_http_with_api_key,
)

_resolve_session = mcp_server_mod._resolve_session  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
_mcp_settings = mcp_server_mod._mcp_settings  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def _list_tools(server: Any) -> list[Any]:
    """Return all registered tools on a FastMCP instance.

    FastMCP exposes the tool manager under a leading underscore; the
    smoke suite is the boundary where we intentionally cross that line
    to verify wiring.
    """
    return list(server._tool_manager.list_tools())  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


pytestmark = pytest.mark.unit


def _fake_broker_response() -> BrokerResponse:
    return BrokerResponse(
        request_id="req-x",
        data={},
        sources_queried=[],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        scope_restrictions={},
        attestation_token=None,
        duration_ms=0,
    )


def _make_fake_broker(
    *,
    expose_handoff: bool = False,
    response: BrokerResponse | None = None,
) -> MagicMock:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    broker.arequest = AsyncMock(return_value=response or _fake_broker_response())
    broker.declare_handoff = AsyncMock()
    broker._config = SimpleNamespace(
        api=SimpleNamespace(auth=SimpleNamespace(mode="api_key"), keys=["k1"]),
        mcp=SimpleNamespace(expose_declare_handoff=expose_handoff),
    )
    return broker


# ---------------------------------------------------------------------------
# _resolve_session
# ---------------------------------------------------------------------------


def test_resolve_session_prefers_context_session_id() -> None:
    sid, src = _resolve_session({"session_id": "ctx-1"}, MagicMock(session_id="tx"))
    assert sid == "ctx-1"
    assert src == "context"


def test_resolve_session_falls_back_to_transport() -> None:
    ctx = SimpleNamespace(session_id="tx-2", request_id="ignored")
    sid, src = _resolve_session({}, ctx)  # type: ignore[arg-type]
    assert sid == "tx-2"
    assert src == "transport"


def test_resolve_session_falls_back_to_stdio_request_id() -> None:
    ctx = SimpleNamespace(session_id=None, request_id="req-3")
    sid, src = _resolve_session({}, ctx)  # type: ignore[arg-type]
    assert sid == "req-3"
    assert src == "stdio_request_id"


def test_resolve_session_generates_uuid_when_ctx_is_none() -> None:
    sid, src = _resolve_session({}, None)
    assert src == "generated"
    # UUIDs always contain hyphens in canonical form and are non-empty.
    assert len(sid) >= 32
    assert "-" in sid


def test_resolve_session_generates_uuid_when_ctx_has_no_fields() -> None:
    ctx = SimpleNamespace(session_id=None, request_id=None)
    sid, src = _resolve_session({}, ctx)  # type: ignore[arg-type]
    assert src == "generated"
    assert sid


# ---------------------------------------------------------------------------
# _mcp_settings
# ---------------------------------------------------------------------------


def test_mcp_settings_none_broker_defaults() -> None:
    expose, mode, keys = _mcp_settings(None)
    assert expose is False
    assert mode == "api_key"
    assert keys == []


def test_mcp_settings_reads_broker_config() -> None:
    broker = _make_fake_broker(expose_handoff=True)
    expose, mode, keys = _mcp_settings(broker)
    assert expose is True
    assert mode == "api_key"
    assert keys == ["k1"]


# ---------------------------------------------------------------------------
# create_server — registration + tool invocation
# ---------------------------------------------------------------------------


def test_create_server_requires_config_or_broker() -> None:
    with pytest.raises(ValueError, match="config_path or existing_broker"):
        create_server(None)


def test_create_server_registers_primary_tool() -> None:
    broker = _make_fake_broker(expose_handoff=False)
    server = create_server(None, existing_broker=broker)
    assert server.name == "nautilus"
    # FastMCP public API — list_tools returns registered tool objects.
    tool_names = {t.name for t in _list_tools(server)}
    assert "nautilus_request" in tool_names
    assert "nautilus_declare_handoff" not in tool_names


def test_create_server_registers_handoff_tool_when_enabled() -> None:
    broker = _make_fake_broker(expose_handoff=True)
    server = create_server(None, existing_broker=broker)
    tool_names = {t.name for t in _list_tools(server)}
    assert "nautilus_request" in tool_names
    assert "nautilus_declare_handoff" in tool_names


async def test_nautilus_request_passes_agent_id_verbatim() -> None:
    """AC-13.3 — the tool must never substitute ctx.client_id for agent_id."""
    broker = _make_fake_broker()
    server = create_server(None, existing_broker=broker)
    tool = next(t for t in _list_tools(server) if t.name == "nautilus_request")
    # Pull the registered coroutine function; fn is the pre-adapter callable.
    fn = tool.fn

    ctx = SimpleNamespace(session_id=None, request_id="req-99", client_id="transport-client")
    result = await fn(
        agent_id="agent-verbatim",
        intent="hello",
        context={"session_id": "sess-A"},
        ctx=ctx,
    )
    assert isinstance(result, BrokerResponse)
    broker.arequest.assert_awaited_once()
    args, _ = broker.arequest.call_args
    # Positional: (agent_id, intent, ctx_dict).
    assert args[0] == "agent-verbatim"
    assert args[1] == "hello"
    assert args[2]["session_id"] == "sess-A"
    assert args[2]["session_id_source"] == "context"


async def test_nautilus_request_injects_stdio_request_id_as_session() -> None:
    broker = _make_fake_broker()
    server = create_server(None, existing_broker=broker)
    tool = next(t for t in _list_tools(server) if t.name == "nautilus_request")
    ctx = SimpleNamespace(session_id=None, request_id="req-42")
    await tool.fn(agent_id="a", intent="i", context=None, ctx=ctx)
    args, _ = broker.arequest.call_args
    assert args[2]["session_id"] == "req-42"
    assert args[2]["session_id_source"] == "stdio_request_id"


async def test_nautilus_declare_handoff_routes_to_broker() -> None:
    broker = _make_fake_broker(expose_handoff=True)
    server = create_server(None, existing_broker=broker)
    tool = next(t for t in _list_tools(server) if t.name == "nautilus_declare_handoff")
    await tool.fn(
        source_agent_id="src",
        receiving_agent_id="dst",
        data_classifications=["unclassified"],
        session_id="sess-1",
        data_compartments=None,
        ctx=None,
    )
    broker.declare_handoff.assert_awaited_once()
    _, kwargs = broker.declare_handoff.call_args
    assert kwargs["source_agent_id"] == "src"
    assert kwargs["receiving_agent_id"] == "dst"
    assert kwargs["session_id"] == "sess-1"


# ---------------------------------------------------------------------------
# wrap_http_with_api_key — ASGI middleware
# ---------------------------------------------------------------------------


async def test_wrap_http_accepts_valid_key() -> None:
    inner_calls: list[Any] = []

    async def inner(scope: Any, _receive: Any, send: Any) -> None:
        inner_calls.append(scope["type"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    wrapped = wrap_http_with_api_key(inner, ["topsecret"])  # type: ignore[arg-type]
    sent: list[MutableMapping[str, Any]] = []

    async def send(msg: MutableMapping[str, Any]) -> None:
        sent.append(msg)

    async def receive() -> MutableMapping[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: MutableMapping[str, Any] = {
        "type": "http",
        "headers": [(b"x-api-key", b"topsecret")],
    }
    await wrapped(scope, receive, send)
    assert inner_calls == ["http"]
    assert sent[0]["status"] == 200


async def test_wrap_http_rejects_missing_key() -> None:
    async def inner(_scope: Any, _receive: Any, _send: Any) -> None:
        raise AssertionError("inner should not be called on 401")

    wrapped = wrap_http_with_api_key(inner, ["topsecret"])  # type: ignore[arg-type]
    sent: list[MutableMapping[str, Any]] = []

    async def send(msg: MutableMapping[str, Any]) -> None:
        sent.append(msg)

    async def receive() -> MutableMapping[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope: MutableMapping[str, Any] = {"type": "http", "headers": []}
    await wrapped(scope, receive, send)
    assert sent[0]["status"] == 401
    assert b"Invalid or missing API key" in sent[1]["body"]


async def test_wrap_http_bypasses_non_http_scopes() -> None:
    seen_scope_types: list[str] = []

    async def inner(scope: Any, _receive: Any, _send: Any) -> None:
        seen_scope_types.append(scope["type"])

    wrapped = wrap_http_with_api_key(inner, ["k"])  # type: ignore[arg-type]

    async def noop_send(_msg: MutableMapping[str, Any]) -> None:
        return None

    async def noop_receive() -> MutableMapping[str, Any]:
        return {"type": "lifespan.startup"}

    scope: MutableMapping[str, Any] = {"type": "lifespan"}
    await wrapped(scope, noop_receive, noop_send)
    assert seen_scope_types == ["lifespan"]


def test_http_app_returns_callable() -> None:
    """``http_app`` wraps FastMCP's streamable_http_app with the auth gate."""
    broker = _make_fake_broker()
    server = create_server(None, existing_broker=broker)
    wrapped = http_app(server, api_keys=["k"])
    assert callable(wrapped)
