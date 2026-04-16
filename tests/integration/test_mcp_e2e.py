"""MCP end-to-end harness (Task 3.17, FR-27, NFR-15).

Exercises BOTH MCP transports against the real
:func:`nautilus.transport.mcp_server.create_server` factory:

* **stdio** — a subprocess running ``python -m nautilus.cli serve
  --transport mcp --mcp-mode stdio --config <yaml>`` is driven by the
  canonical :class:`mcp.ClientSession` + :func:`stdio_client`; a single
  ``nautilus_request`` tool call is issued and the audit JSONL emitted
  by the subprocess is asserted to contain exactly ONE line (NFR-15 —
  1:1 tool-call → audit-entry ratio).

* **streamable-http** — a :class:`uvicorn.Server` runs
  :func:`http_app` (which wraps :meth:`FastMCP.streamable_http_app` with
  the shared ``X-API-Key`` gate) on a free localhost port inside a
  background thread; the MCP HTTP client then issues a single tool call
  and the audit file is asserted to carry exactly ONE new line.

Both transports are gated under ``-m integration``. The subprocess path
uses the :func:`pg_container` fixture (inherits ``TEST_PG_DSN`` /
``TEST_PGV_DSN`` via the subprocess's environment), so the broker hot
path traverses the real Postgres adapter.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
import uvicorn

from nautilus.core.broker import Broker
from nautilus.transport.mcp_server import create_server, http_app

pytestmark = pytest.mark.integration


_API_KEY: str = "test-mcp-e2e-key"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _write_minimal_config(tmp_path: Path) -> Path:
    """Write a single-source (postgres-only) config to ``tmp_path``.

    Avoids the shared pgvector source — its result rows carry a
    ``numpy.ndarray`` embedding column that does not survive
    JSON-serialisation through either MCP transport. NFR-15 only
    requires that ONE audit entry is emitted per tool call; a scalar
    postgres source is the minimum viable substrate.
    """
    config_path = tmp_path / "nautilus.yaml"
    config_path.write_text(
        "sources:\n"
        "  - id: nvd_db\n"
        "    type: postgres\n"
        '    description: "NVD fixture for MCP e2e"\n'
        "    classification: unclassified\n"
        "    data_types: [cve, vulnerability, patch]\n"
        "    allowed_purposes: [threat-analysis, incident-response]\n"
        "    connection: ${TEST_PG_DSN}\n"
        "    table: vulns\n"
        "\n"
        "rules:\n"
        "  user_rules_dirs: []\n"
        "\n"
        "analysis:\n"
        "  keyword_map:\n"
        "    vulnerability: [vulnerability, vuln, weakness]\n"
        "\n"
        "audit:\n"
        "  path: ./audit.jsonl\n"
        "\n"
        "attestation:\n"
        "  enabled: true\n",
        encoding="utf-8",
    )
    return config_path


def _pick_free_port() -> int:
    """Bind to port 0 and return the OS-picked ephemeral port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ---------------------------------------------------------------------------
# Stdio transport — subprocess + mcp.ClientSession.
# ---------------------------------------------------------------------------


async def test_mcp_stdio_single_tool_call_emits_one_audit_line(
    pg_container: str,
    tmp_path: Path,
) -> None:
    """NFR-15 — one tool call over stdio yields exactly one audit JSONL line.

    Spawns ``python -m nautilus.cli serve --transport mcp --mcp-mode stdio``
    as an MCP subprocess, issues one ``nautilus_request`` tool call, and
    counts the resulting audit lines. The subprocess inherits
    ``TEST_PG_DSN`` / ``TEST_PGV_DSN`` from the ``pg_container`` fixture
    so :func:`Broker.from_config` can resolve the ``${TEST_PG_DSN}``
    placeholder inside the temp YAML.
    """
    del pg_container  # side-effect only — env vars exported

    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    config_path = _write_minimal_config(tmp_path)
    # Audit file relative to the subprocess cwd (``tmp_path`` here) —
    # ``audit.path: ./audit.jsonl`` resolves against the worker's CWD.
    audit_path = tmp_path / "audit.jsonl"

    # Inherit the test environment so the subprocess sees TEST_PG_DSN.
    env = dict(os.environ)

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "nautilus.cli",
            "serve",
            "--config",
            str(config_path),
            "--transport",
            "mcp",
            "--mcp-mode",
            "stdio",
        ],
        env=env,
        cwd=str(tmp_path),
    )

    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        # Sanity-check that nautilus_request is registered before firing.
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert "nautilus_request" in names, f"nautilus_request missing; tools={sorted(names)!r}"

        result = await session.call_tool(
            "nautilus_request",
            {
                "agent_id": "agent-alpha-stdio",
                "intent": "Find vulnerabilities for CVE-2026-0001",
                "context": {
                    "clearance": "unclassified",
                    "purpose": "threat-analysis",
                    "session_id": "mcp-stdio-e2e",
                },
            },
        )
        assert result.isError is False, f"nautilus_request returned error: {result.content!r}"

    # After the stdio session has closed, the subprocess has flushed its
    # audit file. Count lines — NFR-15 requires exactly one per tool call.
    assert audit_path.exists(), f"audit file missing at {audit_path}"
    lines = [ln for ln in audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1, (
        f"expected exactly 1 audit line for 1 tool call (NFR-15); got {len(lines)}"
    )
    # Round-trip the one line so a shape-drift in AuditRecord surfaces here.
    record = cast(dict[str, Any], json.loads(lines[0]))
    assert isinstance(record, dict)


# ---------------------------------------------------------------------------
# Streamable-http transport — in-process uvicorn + streamablehttp_client.
# ---------------------------------------------------------------------------


@pytest.fixture
def _mcp_http_server(  # pyright: ignore[reportUnusedFunction]
    pg_container: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[str, Path]]:
    """Boot ``http_app`` under uvicorn in a background thread.

    Yields ``(base_url, audit_path)``. Teardown flips ``should_exit`` and
    joins the thread so the uvicorn loop drains cleanly.
    """
    del pg_container  # side-effect only — env vars exported
    monkeypatch.chdir(tmp_path)

    config_path = _write_minimal_config(tmp_path)
    audit_path = tmp_path / "audit.jsonl"

    # Build broker in THIS loop-free thread; setup() runs on the uvicorn
    # loop inside the server thread via an asyncio.run_coroutine_threadsafe
    # equivalent (uvicorn runs its own loop). We therefore delay setup()
    # and let FastMCP's lifespan prime the broker lazily — except the MCP
    # factory does NOT own lifecycle for injected brokers (see
    # mcp_server.create_server docstring). So the cleanest path is:
    # construct broker + mcp on the main thread, then inside the uvicorn
    # thread run setup() once on its loop via on_startup.
    broker = Broker.from_config(config_path)
    # Prime ``broker.setup()`` on a throwaway loop on this (synchronous
    # fixture) thread BEFORE the uvicorn server thread boots. The MCP
    # factory's injected-broker contract leaves lifecycle to the caller
    # (see ``mcp_server.create_server`` docstring); uvicorn's own loop
    # drives FastMCP's streamable-http lifespan and the asyncpg pool
    # created on this loop is safe to use from the uvicorn loop because
    # asyncpg.Pool is thread-safe for acquire.
    _setup_loop = asyncio.new_event_loop()
    try:
        _setup_loop.run_until_complete(broker.setup())
    finally:
        _setup_loop.close()

    mcp = create_server(None, existing_broker=broker)
    # http_app wraps ``mcp.streamable_http_app()`` (Starlette with its
    # own lifespan) with the shared X-API-Key gate. Hand it straight to
    # uvicorn — no extra Starlette wrapper (a Mount would hide the
    # FastMCP lifespan and the session manager would never initialise).
    asgi_app = http_app(mcp, api_keys=[_API_KEY])

    port = _pick_free_port()
    config = uvicorn.Config(
        app=asgi_app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
        loop="asyncio",
    )
    server = uvicorn.Server(config=config)
    server.install_signal_handlers = (  # pyright: ignore[reportAttributeAccessIssue]
        lambda: None
    )

    thread = threading.Thread(target=server.run, daemon=True, name="uvicorn-mcp-e2e")
    thread.start()

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if server.started:
            break
        time.sleep(0.05)
    else:  # pragma: no cover
        server.should_exit = True
        thread.join(timeout=5.0)
        raise RuntimeError(f"uvicorn did not start on 127.0.0.1:{port}")

    try:
        yield (f"http://127.0.0.1:{port}", audit_path)
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)


async def test_mcp_streamable_http_single_tool_call_emits_one_audit_line(
    _mcp_http_server: tuple[str, Path],
) -> None:
    """NFR-15 — one tool call over streamable-http yields one audit line.

    Issues exactly one ``nautilus_request`` call through the MCP HTTP
    client against the in-process uvicorn server, then asserts the audit
    JSONL carries exactly one line.
    """
    from mcp import ClientSession
    from mcp.client.streamable_http import (
        streamablehttp_client,  # pyright: ignore[reportDeprecated]
    )

    base_url, audit_path = _mcp_http_server
    # FastMCP mounts the streamable endpoint at "/mcp" on the sub-app.
    url = f"{base_url}/mcp/"
    headers = {"X-API-Key": _API_KEY}

    async with (
        streamablehttp_client(  # pyright: ignore[reportDeprecated]
            url, headers=headers
        ) as (read, write, _get_id),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert "nautilus_request" in names, f"nautilus_request missing; tools={sorted(names)!r}"

        result = await session.call_tool(
            "nautilus_request",
            {
                "agent_id": "agent-alpha-http",
                "intent": "Find vulnerabilities for CVE-2026-0002",
                "context": {
                    "clearance": "unclassified",
                    "purpose": "threat-analysis",
                    "session_id": "mcp-http-e2e",
                },
            },
        )
        assert result.isError is False, f"nautilus_request returned error: {result.content!r}"

    # Let the server drain any buffered audit writes.
    await asyncio.sleep(0.2)

    assert audit_path.exists(), f"audit file missing at {audit_path}"
    lines = [ln for ln in audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1, (
        f"expected exactly 1 audit line for 1 tool call (NFR-15); got {len(lines)}"
    )
