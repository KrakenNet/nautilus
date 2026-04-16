"""Integration e2e for :class:`RestAdapter` (Task 3.15).

Spins up a tiny FastAPI app on a free localhost port via
``uvicorn.Server`` inside a background thread, points :class:`RestAdapter`
at it (bypassing the adapter's private-IP SSRF guard by injecting a
pre-built :class:`httpx.AsyncClient`), and issues real round-trip HTTP
requests against the loopback server.

Two scenarios live here (AC-9.5 / FR-22, NFR-17):

1. ``test_rest_e2e_round_trip_against_uvicorn`` — a ``GET /v1/items``
   with an ``id IN (1, 2)`` scope returns the JSON envelope rows the
   adapter coerces into :class:`AdapterResult`.
2. ``test_rest_e2e_ssrf_cross_host_redirect_fails_closed`` — a 302
   response pointing at a different host triggers
   :class:`SSRFBlockedError` (the adapter is configured
   ``follow_redirects=False``).
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse, RedirectResponse

from nautilus.adapters.rest import RestAdapter, SSRFBlockedError
from nautilus.config.models import EndpointSpec, NoneAuth, SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# uvicorn harness
# ---------------------------------------------------------------------------


def _pick_free_port() -> int:
    """Bind to port 0 and return the OS-picked ephemeral port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _build_app() -> FastAPI:
    """FastAPI test upstream: ``/v1/items`` and ``/v1/redirect``."""
    app = FastAPI()

    # Fixture dataset. Endpoint filters by repeated ``id`` query params so
    # ``?id=1&id=2`` echoes back the matching rows.
    _rows: dict[int, dict[str, Any]] = {
        1: {"id": 1, "name": "alpha"},
        2: {"id": 2, "name": "beta"},
        3: {"id": 3, "name": "gamma"},
    }

    _id_query = Query(default=None)

    @app.get("/v1/items")
    def list_items(  # noqa: A002  # match REST param name  # pyright: ignore[reportUnusedFunction]
        id: list[int] | None = _id_query,
    ) -> JSONResponse:
        data = list(_rows.values()) if not id else [_rows[i] for i in id if i in _rows]
        return JSONResponse({"results": data})

    @app.get("/v1/redirect")
    def cross_host_redirect() -> RedirectResponse:  # pyright: ignore[reportUnusedFunction]
        # 302 to a different host — the RestAdapter must refuse to follow.
        return RedirectResponse(url="http://evil.example.com:1234/stolen", status_code=302)

    return app


@pytest.fixture(scope="module")
def uvicorn_server() -> Iterator[str]:
    """Boot a uvicorn server in a background thread; yield its base URL.

    The server runs on ``127.0.0.1:<ephemeral>``; we wait for the TCP
    port to become accept()able before yielding. Teardown flips
    ``Server.should_exit`` and joins the thread.
    """
    port = _pick_free_port()
    app = _build_app()
    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
        loop="asyncio",
    )
    server = uvicorn.Server(config=config)
    # ``Server.install_signal_handlers`` blocks non-main-thread startup;
    # disable it so the thread can run the event loop cleanly.
    server.install_signal_handlers = lambda: None  # pyright: ignore[reportAttributeAccessIssue]

    thread = threading.Thread(target=server.run, daemon=True, name="uvicorn-e2e")
    thread.start()

    # Wait up to ~5s for the socket to accept connections.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if server.started:
            break
        time.sleep(0.05)
    else:  # pragma: no cover  # only fires if uvicorn fails to start
        server.should_exit = True
        thread.join(timeout=5.0)
        raise RuntimeError(f"uvicorn did not start on 127.0.0.1:{port}")

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)


# ---------------------------------------------------------------------------
# Adapter helpers
# ---------------------------------------------------------------------------


def _rest_source(base_url: str) -> SourceConfig:
    return SourceConfig(
        id="rest_src",
        type="rest",
        description="rest upstream (uvicorn)",
        classification="unclassified",
        data_types=["item"],
        allowed_purposes=["research"],
        connection=base_url,
        endpoints=[EndpointSpec(path="/v1/items", method="GET")],
        auth=NoneAuth(),
    )


def _redirect_source(base_url: str) -> SourceConfig:
    return SourceConfig(
        id="rest_src",
        type="rest",
        description="rest upstream (uvicorn, redirect endpoint)",
        classification="unclassified",
        data_types=["item"],
        allowed_purposes=["research"],
        connection=base_url,
        endpoints=[EndpointSpec(path="/v1/redirect", method="GET")],
        auth=NoneAuth(),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="fetch items",
        data_types_needed=["item"],
        entities=[],
    )


async def _connect_against(base_url: str, config: SourceConfig) -> RestAdapter:
    """Build an adapter with an injected AsyncClient so the 127.0.0.1 SSRF
    guard does not reject the test upstream (the guard fires on private-IP
    base URLs unless we pre-supply the client).
    """
    client = httpx.AsyncClient(base_url=base_url, follow_redirects=False)
    adapter = RestAdapter(client=client)
    # Bypass the private-IP guard by inlining connect's post-guard steps.
    adapter._config = config  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    adapter._base_host = httpx.URL(config.connection).host  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert config.endpoints is not None
    adapter._endpoint = config.endpoints[0]  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    return adapter


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_rest_e2e_round_trip_against_uvicorn(uvicorn_server: str) -> None:
    """``RestAdapter`` issues a real HTTP request and parses the envelope."""
    adapter = await _connect_against(uvicorn_server, _rest_source(uvicorn_server))
    try:
        result = await adapter.execute(
            intent=_intent(),
            scope=[
                ScopeConstraint(
                    source_id="rest_src",
                    field="id",
                    operator="IN",
                    value=[1, 2],
                )
            ],
            context={},
        )
        assert result.source_id == "rest_src"
        # Upstream echoed the matching rows.
        returned_ids = sorted(row["id"] for row in result.rows)
        assert returned_ids == [1, 2], f"IN scope did not round-trip; got {result.rows!r}"
    finally:
        await adapter.close()


async def test_rest_e2e_ssrf_cross_host_redirect_fails_closed(uvicorn_server: str) -> None:
    """302 to a different host raises :class:`SSRFBlockedError` (NFR-17)."""
    adapter = await _connect_against(uvicorn_server, _redirect_source(uvicorn_server))
    try:
        with pytest.raises(SSRFBlockedError):
            await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()
