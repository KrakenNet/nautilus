"""Smoke tests for :mod:`nautilus.transport.fastapi_app` (VERIFY 2.19).

Mock-driven: no live network, no real Broker. The factory accepts an
``existing_broker`` kwarg specifically for this — tests inject a
:class:`MagicMock` with async stubs matching the Broker public surface
exercised by the routes.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from nautilus.core.models import BrokerResponse
from nautilus.transport.fastapi_app import create_app

pytestmark = pytest.mark.unit


def _fake_broker_response() -> BrokerResponse:
    return BrokerResponse(
        request_id="req-1",
        data={"src": [{"id": 1}]},
        sources_queried=["src"],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        scope_restrictions={},
        attestation_token=None,
        duration_ms=1,
    )


def _make_fake_source(source_id: str = "nvd") -> Any:
    return SimpleNamespace(
        id=source_id,
        type="postgres",
        description="fake",
        classification="unclassified",
        data_types=["cve"],
    )


def _make_config(
    mode: str = "api_key",
    keys: list[str] | None = None,
) -> Any:
    return SimpleNamespace(
        api=SimpleNamespace(
            auth=SimpleNamespace(mode=mode),
            keys=list(keys or []),
        ),
    )


def _make_fake_broker(
    *,
    mode: str = "api_key",
    keys: list[str] | None = None,
    session_store_aget: AsyncMock | None = None,
    response: BrokerResponse | None = None,
) -> MagicMock:
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    broker.arequest = AsyncMock(return_value=response or _fake_broker_response())
    store = MagicMock()
    store.aget = session_store_aget or AsyncMock(return_value=None)
    broker.session_store = store
    broker.sources = [_make_fake_source("nvd")]
    broker._config = _make_config(mode=mode, keys=keys if keys is not None else ["k1"])
    return broker


def test_create_app_requires_config_or_broker() -> None:
    with pytest.raises(ValueError, match="config_path or existing_broker"):
        create_app(None)


def test_healthz_returns_200_without_auth() -> None:
    broker = _make_fake_broker()
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


def test_readyz_returns_200_when_session_store_responds() -> None:
    broker = _make_fake_broker()
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


def test_readyz_returns_503_when_session_store_raises() -> None:
    failing = AsyncMock(side_effect=RuntimeError("store down"))
    broker = _make_fake_broker(session_store_aget=failing)
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.get("/readyz")
        assert resp.status_code == 503
        assert resp.json()["status"] == "not_ready"
        assert resp.json()["reason"] == "RuntimeError"


def test_post_request_requires_api_key_header() -> None:
    broker = _make_fake_broker(keys=["topsecret"])
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/request",
            json={"agent_id": "a", "intent": "find stuff", "context": {}},
        )
        # APIKeyHeader(auto_error=True) → 403 on missing header.
        assert resp.status_code in (401, 403)


def test_post_request_rejects_wrong_api_key() -> None:
    broker = _make_fake_broker(keys=["topsecret"])
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/request",
            headers={"X-API-Key": "nope"},
            json={"agent_id": "a", "intent": "find stuff", "context": {}},
        )
        assert resp.status_code == 401


def test_post_request_accepts_correct_api_key() -> None:
    broker = _make_fake_broker(keys=["topsecret"])
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/request",
            headers={"X-API-Key": "topsecret"},
            json={"agent_id": "a", "intent": "find stuff", "context": {}},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["request_id"] == "req-1"
        assert body["sources_queried"] == ["src"]
    broker.arequest.assert_awaited_once()


def test_query_alias_matches_request_handler() -> None:
    broker = _make_fake_broker(keys=["topsecret"])
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/query",
            headers={"X-API-Key": "topsecret"},
            json={"agent_id": "a", "intent": "find stuff", "context": {}},
        )
        assert resp.status_code == 200
        assert resp.json()["request_id"] == "req-1"


def test_sources_endpoint_returns_metadata() -> None:
    broker = _make_fake_broker(keys=["topsecret"])
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.get("/v1/sources")
        assert resp.status_code == 200
        body = resp.json()
        assert "sources" in body
        assert body["sources"][0]["id"] == "nvd"
        assert body["sources"][0]["classification"] == "unclassified"
        # Never expose DSN / connection strings.
        assert "connection" not in body["sources"][0]


def test_proxy_trust_mode_bypasses_api_key() -> None:
    broker = _make_fake_broker(mode="proxy_trust", keys=[])
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/request",
            headers={"X-Forwarded-User": "alice"},
            json={"agent_id": "a", "intent": "hi", "context": {}},
        )
        assert resp.status_code == 200


def test_proxy_trust_mode_rejects_missing_forwarded_user() -> None:
    broker = _make_fake_broker(mode="proxy_trust", keys=[])
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/request",
            json={"agent_id": "a", "intent": "hi", "context": {}},
        )
        assert resp.status_code == 401


def test_lifespan_calls_setup_and_aclose() -> None:
    broker = _make_fake_broker()
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        client.get("/healthz")
    broker.setup.assert_awaited_once()
    broker.aclose.assert_awaited_once()


def test_resolve_auth_config_defaults_when_config_missing() -> None:
    """_resolve_auth_config handles brokers without a ``_config`` attribute."""
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    broker.session_store = MagicMock(aget=AsyncMock(return_value=None))
    broker.sources = []
    # No _config attribute at all — defensive path.
    broker._config = None
    app = create_app(None, existing_broker=broker)
    with TestClient(app) as client:
        # Defaults to api_key mode with empty keys → every write is 401.
        resp = client.post(
            "/v1/request",
            headers={"X-API-Key": "x"},
            json={"agent_id": "a", "intent": "hi", "context": {}},
        )
        assert resp.status_code == 401
