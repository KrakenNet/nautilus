"""Canonical FastAPI unit suite (Task 3.13, FR-25/26, AC-12.*, NFR-15).

Seven cases, all driven through ``httpx.AsyncClient`` +
:class:`httpx.ASGITransport` so the ASGI pipeline (middleware, routing,
dependencies) is exercised end-to-end without binding a real socket.
Lifespan is managed explicitly via ``app.router.lifespan_context(app)``
because httpx 0.28's ``ASGITransport`` does not drive lifespan itself.

Cases:
    a. Lifespan startup builds the broker singleton on ``app.state`` and
       populates the auth-mode / api-keys derived state.
    b. ``GET /healthz`` returns 200 with a static body.
    c. ``GET /readyz`` returns 503 before lifespan runs and 200 after.
    d. ``POST /v1/request`` returns 200 and the injected broker emits
       exactly one audit line (NFR-15 — audit-first invariant).
    e. ``POST /v1/query`` matches ``/v1/request`` body-for-body and
       produces one more audit line (D-9 alias, UQ-3).
    f. Missing or wrong ``X-API-Key`` → 401 (AC-12.2 — api_key is a hard
       gate; fail-closed).
    g. ``GET /v1/sources`` returns metadata only (id/type/description/
       classification/data_types) — never a DSN, key, secret, or password
       (AC-12.3).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from nautilus.core.models import BrokerResponse
from nautilus.transport.fastapi_app import create_app

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _fake_response() -> BrokerResponse:
    return BrokerResponse(
        request_id="req-unit",
        data={"src": [{"k": "v"}]},
        sources_queried=["src"],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        scope_restrictions={},
        attestation_token=None,
        duration_ms=0,
    )


def _fake_source(source_id: str = "nvd") -> Any:
    return SimpleNamespace(
        id=source_id,
        type="postgres",
        description="CVE data",
        classification="unclassified",
        data_types=["cve"],
    )


def _make_broker(
    *,
    audit_path: Path | None = None,
    mode: str = "api_key",
    keys: list[str] | None = None,
) -> MagicMock:
    """Build a MagicMock broker whose ``arequest`` appends one audit line.

    The append is synchronous (plain ``Path.write_text``) inside an
    ``AsyncMock.side_effect`` — satisfies NFR-15 "exactly one audit entry
    per request" without needing the real ``AuditLogger`` machinery.
    """
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()

    async def _arequest(agent_id: str, intent: str, context: dict[str, Any]) -> BrokerResponse:
        if audit_path is not None:
            line = json.dumps(
                {"agent_id": agent_id, "intent": intent, "context_keys": sorted(context)},
            )
            with audit_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return _fake_response()

    broker.arequest = AsyncMock(side_effect=_arequest)
    store = MagicMock()
    store.aget = AsyncMock(return_value=None)
    broker.session_store = store
    broker.sources = [_fake_source("nvd")]
    broker._config = SimpleNamespace(
        api=SimpleNamespace(
            auth=SimpleNamespace(mode=mode),
            keys=list(keys if keys is not None else ["topsecret"]),
        ),
    )
    return broker


# ---------------------------------------------------------------------------
# (a) lifespan startup builds the broker singleton
# ---------------------------------------------------------------------------


async def test_a_lifespan_startup_builds_broker_singleton() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    # Before lifespan fires, defaults are in place.
    assert app.state.broker is None
    assert app.state.ready is False

    async with app.router.lifespan_context(app):
        # Singleton attached to app.state after startup.
        assert app.state.broker is broker
        assert app.state.ready is True
        # Derived auth state populated from broker._config.
        assert app.state.auth_mode == "api_key"
        assert app.state.api_keys == ["topsecret"]
        broker.setup.assert_awaited_once()

    # Shutdown closed the broker exactly once.
    broker.aclose.assert_awaited_once()
    assert app.state.ready is False


# ---------------------------------------------------------------------------
# (b) /healthz → 200 static
# ---------------------------------------------------------------------------


async def test_b_healthz_returns_200_static_body() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# (c) /readyz → 503 before startup, 200 after
# ---------------------------------------------------------------------------


async def test_c_readyz_503_before_startup_and_200_after() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)

    # BEFORE startup: app.state.broker is None and ready is False → 503.
    transport_pre = ASGITransport(app=app)
    async with AsyncClient(transport=transport_pre, base_url="http://test") as client:
        pre = await client.get("/readyz")
    assert pre.status_code == 503
    assert pre.json()["status"] == "not_ready"
    assert pre.json()["reason"] == "startup_incomplete"

    # AFTER startup: lifespan active → 200.
    async with app.router.lifespan_context(app):
        transport_post = ASGITransport(app=app)
        async with AsyncClient(transport=transport_post, base_url="http://test") as client:
            post = await client.get("/readyz")
    assert post.status_code == 200
    assert post.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# (d) POST /v1/request → 200 + exactly one audit line (NFR-15)
# ---------------------------------------------------------------------------


async def test_d_post_request_returns_200_and_emits_one_audit_line(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    broker = _make_broker(audit_path=audit_path, keys=["k"])
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/request",
                headers={"X-API-Key": "k"},
                json={"agent_id": "a", "intent": "find stuff", "context": {}},
            )
    assert resp.status_code == 200
    assert resp.json()["request_id"] == "req-unit"
    assert resp.json()["sources_queried"] == ["src"]
    # NFR-15: one — and only one — audit entry was written.
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, f"expected 1 audit line, got {len(lines)}"
    payload = json.loads(lines[0])
    assert payload["agent_id"] == "a"
    assert payload["intent"] == "find stuff"


# ---------------------------------------------------------------------------
# (e) POST /v1/query behaves identically to /v1/request (D-9 / UQ-3 alias)
# ---------------------------------------------------------------------------


async def test_e_query_is_alias_of_request(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    broker = _make_broker(audit_path=audit_path, keys=["k"])
    app = create_app(None, existing_broker=broker)
    body: dict[str, Any] = {"agent_id": "a", "intent": "hello", "context": {}}
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post(
                "/v1/request",
                headers={"X-API-Key": "k"},
                json=body,
            )
            r2 = await client.post(
                "/v1/query",
                headers={"X-API-Key": "k"},
                json=body,
            )
    assert r1.status_code == r2.status_code == 200
    # Identical shape — the alias dispatches the same handler (D-9).
    assert r1.json() == r2.json()
    # Both wrote one audit line each → two in total.
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# (f) Missing / bad API key → 401 (AC-12.2)
# ---------------------------------------------------------------------------


async def test_f_missing_or_bad_api_key_is_rejected() -> None:
    broker = _make_broker(keys=["topsecret"])
    app = create_app(None, existing_broker=broker)
    body: dict[str, Any] = {"agent_id": "a", "intent": "hi", "context": {}}
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Missing header — APIKeyHeader(auto_error=True) → 403 by design,
            # wrong key → 401. AC-12.2 demands fail-closed, which both satisfy.
            missing = await client.post(
                "/v1/request",
                json=body,
            )
            wrong = await client.post(
                "/v1/request",
                headers={"X-API-Key": "nope"},
                json=body,
            )
    assert missing.status_code in (401, 403)
    assert wrong.status_code == 401
    # Broker is never invoked on auth failure.
    broker.arequest.assert_not_called()


# ---------------------------------------------------------------------------
# (g) GET /v1/sources returns metadata only — no secrets (AC-12.3)
# ---------------------------------------------------------------------------


_FORBIDDEN_SECRET_KEYS: set[str] = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "dsn",
    "connection",
    "connection_string",
    "credentials",
}


async def test_g_sources_endpoint_returns_metadata_no_secrets() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/sources")
    assert resp.status_code == 200
    body = resp.json()
    assert "sources" in body and body["sources"], "expected at least one source"
    source = body["sources"][0]
    # Present: exactly the metadata fields the factory emits.
    assert source["id"] == "nvd"
    assert source["type"] == "postgres"
    assert source["classification"] == "unclassified"
    assert source["data_types"] == ["cve"]
    # Absent: every forbidden field. Case-insensitive scan.
    for key in source:
        assert key.lower() not in _FORBIDDEN_SECRET_KEYS, (
            f"source metadata leaked a secret-ish key: {key}"
        )
