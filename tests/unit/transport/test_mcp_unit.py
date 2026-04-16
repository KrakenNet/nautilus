"""Canonical MCP session-id resolution table (Task 3.13, AC-13.3, D-10).

Four cases exercising the D-10 / UQ-4 fallback chain in
:func:`nautilus.transport.mcp_server._resolve_session` AND the verbatim
``agent_id`` guarantee (AC-13.3) — the tool must never substitute the
MCP ``ctx.client_id`` for the caller-supplied ``agent_id``.

Cases:
    a. ``context["session_id"]`` present → used verbatim, source
       ``"context"``.
    b. HTTP streamable mode (no context session_id, ``ctx.session_id``
       set) → ``ctx.session_id``, source ``"transport"``.
    c. Stdio mode (no context session_id, ``ctx.session_id=None``,
       ``ctx.request_id`` set) → ``ctx.request_id``, source
       ``"stdio_request_id"``.
    d. ``agent_id`` is taken verbatim from the tool argument — never
       replaced by ``ctx.client_id`` (AC-13.3).

Each case invokes the registered ``nautilus_request`` tool directly via
its ``.fn`` attribute (same pattern as the smoke suite) and asserts the
``session_id`` / ``session_id_source`` keys that the tool injects into
the broker context dict before delegation.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.core.models import BrokerResponse
from nautilus.transport.mcp_server import create_server

pytestmark = pytest.mark.unit


def _fake_response() -> BrokerResponse:
    return BrokerResponse(
        request_id="req-mcp",
        data={},
        sources_queried=[],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        scope_restrictions={},
        attestation_token=None,
        duration_ms=0,
    )


def _make_broker() -> MagicMock:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    broker.arequest = AsyncMock(return_value=_fake_response())
    broker.declare_handoff = AsyncMock()
    broker._config = SimpleNamespace(
        api=SimpleNamespace(auth=SimpleNamespace(mode="api_key"), keys=["k1"]),
        mcp=SimpleNamespace(expose_declare_handoff=False),
    )
    return broker


def _tool_fn(broker: MagicMock) -> Any:
    server = create_server(None, existing_broker=broker)
    # FastMCP registers tools under the private ``_tool_manager`` — same
    # internal handle the smoke suite crosses. We document the boundary
    # rather than hide it.
    tools = list(server._tool_manager.list_tools())  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    for t in tools:
        if t.name == "nautilus_request":
            return t.fn
    raise AssertionError("nautilus_request tool not registered")


# ---------------------------------------------------------------------------
# (a) context.session_id present → "context"
# ---------------------------------------------------------------------------


async def test_a_context_session_id_used_as_context_source() -> None:
    broker = _make_broker()
    fn = _tool_fn(broker)
    # Even with ctx.session_id and ctx.request_id populated, the caller-
    # asserted context["session_id"] wins (D-10 priority 1).
    ctx = SimpleNamespace(
        session_id="tx-ignored",
        request_id="req-ignored",
        client_id="client-ignored",
    )
    await fn(
        agent_id="agent-A",
        intent="hi",
        context={"session_id": "caller-supplied"},
        ctx=ctx,
    )
    args, _ = broker.arequest.call_args
    ctx_dict = args[2]
    assert ctx_dict["session_id"] == "caller-supplied"
    assert ctx_dict["session_id_source"] == "context"


# ---------------------------------------------------------------------------
# (b) http transport mode → ctx.session_id, source "transport"
# ---------------------------------------------------------------------------


async def test_b_http_mode_falls_back_to_transport_session() -> None:
    broker = _make_broker()
    fn = _tool_fn(broker)
    # HTTP streamable-transport supplies ctx.session_id per stream.
    ctx = SimpleNamespace(
        session_id="http-session-42",
        request_id="req-should-lose",
    )
    await fn(agent_id="agent-B", intent="hi", context=None, ctx=ctx)
    args, _ = broker.arequest.call_args
    ctx_dict = args[2]
    assert ctx_dict["session_id"] == "http-session-42"
    assert ctx_dict["session_id_source"] == "transport"


# ---------------------------------------------------------------------------
# (c) stdio mode → ctx.request_id, source "stdio_request_id"
# ---------------------------------------------------------------------------


async def test_c_stdio_mode_uses_request_id_as_session() -> None:
    broker = _make_broker()
    fn = _tool_fn(broker)
    # Stdio never carries a transport-level session; FastMCP sets
    # ctx.session_id=None and stamps a per-call ctx.request_id.
    ctx = SimpleNamespace(session_id=None, request_id="stdio-req-7")
    await fn(agent_id="agent-C", intent="hi", context={}, ctx=ctx)
    args, _ = broker.arequest.call_args
    ctx_dict = args[2]
    assert ctx_dict["session_id"] == "stdio-req-7"
    assert ctx_dict["session_id_source"] == "stdio_request_id"


# ---------------------------------------------------------------------------
# (d) agent_id verbatim — never ctx.client_id (AC-13.3)
# ---------------------------------------------------------------------------


async def test_d_agent_id_is_verbatim_never_client_id() -> None:
    broker = _make_broker()
    fn = _tool_fn(broker)
    # ctx.client_id is a transport-assigned identifier; AC-13.3 demands
    # that it NEVER overrides the caller-supplied agent_id. If the tool
    # were to substitute ctx.client_id, this test would fail outright.
    ctx = SimpleNamespace(
        session_id=None,
        request_id="req-id",
        client_id="transport-assigned-client-id",
    )
    await fn(
        agent_id="caller-agent-verbatim",
        intent="do-thing",
        context=None,
        ctx=ctx,
    )
    args, _ = broker.arequest.call_args
    # Positional: (agent_id, intent, ctx_dict).
    assert args[0] == "caller-agent-verbatim"
    # Defensive — client_id must not appear anywhere in the broker call.
    assert "transport-assigned-client-id" not in str(args)
