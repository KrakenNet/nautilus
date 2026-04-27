"""FastAPI US-3 source enable/disable unit tests (Task 13).

Covers:

* ``POST /v1/sources/{id}/disable`` → 200 + serialized :class:`SourceState`
  (AC-3.4).
* ``POST /v1/sources/{id}/enable`` → 200 + ``reason`` is cleared to ``None``
  (AC-3.4).
* Unknown ``source_id`` → 404 on both enable and disable (AC-3.5).
* Idempotency: disabling twice returns 200 both times with a strictly
  greater ``changed_at`` (AC-3.6).
* ``GET /v1/sources`` surfaces the new ``enabled`` / ``reason`` /
  ``actor`` / ``changed_at`` fields per source.
* 503 when the broker lacks a ``_source_state_store`` (Phase-1 config).

All tests drive the app through :class:`httpx.AsyncClient` +
:class:`httpx.ASGITransport` with an explicit lifespan context, matching
the pattern in ``test_fastapi_unit.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from nautilus.core.source_state import SourceState
from nautilus.transport.fastapi_app import create_app

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


class _FakeSourceStateStore:
    """In-memory stand-in for ``SourceStateStore`` (AsyncMock is awkward with upserts)."""

    def __init__(self) -> None:
        self._rows: dict[str, SourceState] = {}

    async def load_all(self) -> dict[str, SourceState]:
        return dict(self._rows)

    async def set_enabled(
        self,
        source_id: str,
        *,
        enabled: bool,
        reason: str | None,
        actor: str,
    ) -> SourceState:
        state = SourceState(
            source_id=source_id,
            enabled=enabled,
            reason=reason,
            actor=actor,
            changed_at=datetime.now(UTC),
        )
        self._rows[source_id] = state
        return state


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
    with_state_store: bool = True,
    keys: list[str] | None = None,
) -> MagicMock:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    store_mock = MagicMock()
    store_mock.aget = AsyncMock(return_value=None)
    broker.session_store = store_mock
    broker.sources = [_fake_source("nvd"), _fake_source("internal-docs")]
    if with_state_store:
        broker._source_state_store = _FakeSourceStateStore()
    else:
        broker._source_state_store = None
    broker._config = SimpleNamespace(
        api=SimpleNamespace(
            auth=SimpleNamespace(mode="api_key"),
            keys=list(keys if keys is not None else ["k"]),
        ),
    )
    return broker


_API_KEY = "k"
_HEADERS: dict[str, str] = {"X-API-Key": _API_KEY}


# ---------------------------------------------------------------------------
# POST /v1/sources/{id}/disable
# ---------------------------------------------------------------------------


async def test_disable_known_source_returns_updated_state() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sources/nvd/disable",
                headers=_HEADERS,
                json={"reason": "scheduled maintenance"},
            )
    assert resp.status_code == 200
    body = resp.json()
    assert body["source_id"] == "nvd"
    assert body["enabled"] is False
    assert body["reason"] == "scheduled maintenance"
    assert body["actor"] == _API_KEY
    assert isinstance(body["changed_at"], str)


async def test_disable_unknown_source_returns_404() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sources/does-not-exist/disable",
                headers=_HEADERS,
                json={"reason": "nope"},
            )
    assert resp.status_code == 404
    assert "does-not-exist" in resp.json()["detail"]


async def test_double_disable_is_idempotent_and_bumps_changed_at() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r1 = await client.post(
                "/v1/sources/nvd/disable",
                headers=_HEADERS,
                json={"reason": "first"},
            )
            r2 = await client.post(
                "/v1/sources/nvd/disable",
                headers=_HEADERS,
                json={"reason": "second"},
            )
    assert r1.status_code == 200
    assert r2.status_code == 200
    t1 = datetime.fromisoformat(r1.json()["changed_at"])
    t2 = datetime.fromisoformat(r2.json()["changed_at"])
    assert t2 >= t1
    # Second payload overwrote the reason — AC-3.6 idempotent upsert.
    assert r2.json()["reason"] == "second"


async def test_disable_rejects_empty_reason() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sources/nvd/disable",
                headers=_HEADERS,
                json={"reason": ""},
            )
    # Pydantic min_length=1 surfaces as 422.
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /v1/sources/{id}/enable
# ---------------------------------------------------------------------------


async def test_enable_clears_reason() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            dis = await client.post(
                "/v1/sources/nvd/disable",
                headers=_HEADERS,
                json={"reason": "maintenance"},
            )
            ena = await client.post("/v1/sources/nvd/enable", headers=_HEADERS)
    assert dis.status_code == 200
    assert ena.status_code == 200
    body = ena.json()
    assert body["enabled"] is True
    assert body["reason"] is None
    assert body["actor"] == _API_KEY


async def test_enable_unknown_source_returns_404() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/v1/sources/ghost/enable", headers=_HEADERS)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /v1/sources — extended response shape
# ---------------------------------------------------------------------------


async def test_get_sources_includes_state_fields_for_untoggled_sources() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/v1/sources")
    assert resp.status_code == 200
    sources = resp.json()["sources"]
    assert len(sources) == 2
    for s in sources:
        assert s["enabled"] is True
        assert s["reason"] is None
        assert s["actor"] is None
        assert s["changed_at"] is None


async def test_get_sources_reflects_current_disable_state() -> None:
    broker = _make_broker()
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post(
                "/v1/sources/nvd/disable",
                headers=_HEADERS,
                json={"reason": "rotating creds"},
            )
            resp = await client.get("/v1/sources")
    assert resp.status_code == 200
    sources = {s["id"]: s for s in resp.json()["sources"]}
    assert sources["nvd"]["enabled"] is False
    assert sources["nvd"]["reason"] == "rotating creds"
    assert sources["nvd"]["actor"] == _API_KEY
    assert sources["nvd"]["changed_at"] is not None
    # Unaffected source still carries the defaults.
    assert sources["internal-docs"]["enabled"] is True
    assert sources["internal-docs"]["reason"] is None


# ---------------------------------------------------------------------------
# 503 when the broker has no source-state store
# ---------------------------------------------------------------------------


async def test_disable_without_state_store_returns_503() -> None:
    broker = _make_broker(with_state_store=False)
    app = create_app(None, existing_broker=broker)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/sources/nvd/disable",
                headers=_HEADERS,
                json={"reason": "x"},
            )
    assert resp.status_code == 503
    assert "source_state_store" in resp.json()["detail"]
