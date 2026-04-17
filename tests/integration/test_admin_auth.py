"""Integration tests for admin UI auth gate (Task 3.8).

Verifies that:
- Requests without authentication to /admin/sources return 401.
- Requests with a valid X-API-Key header return 200.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from nautilus.config.models import SourceConfig
from nautilus.ui.router import router


def _build_app() -> FastAPI:
    """Create a minimal FastAPI app with admin router, api_key auth, and mock broker."""
    app = FastAPI()
    app.include_router(router)

    broker = MagicMock()
    broker.sources = [
        SourceConfig(
            id="src-test",
            type="postgres",
            description="Test source",
            classification="internal",
            data_types=["structured"],
            connection="postgres://test/db",
        ),
    ]
    app.state.broker = broker
    app.state.auth_mode = "api_key"
    app.state.api_keys = ["test-key"]

    return app


@pytest.fixture()
def client() -> TestClient:
    """TestClient wired to the admin app with api_key auth."""
    return TestClient(_build_app())


class TestAdminAuthGate:
    """Admin endpoints reject unauthenticated requests and accept valid keys."""

    def test_no_auth_returns_401(self, client: TestClient) -> None:
        """Request without X-API-Key header returns 401."""
        resp = client.get("/admin/sources")
        assert resp.status_code == 401

    def test_invalid_key_returns_401(self, client: TestClient) -> None:
        """Request with wrong API key returns 401."""
        resp = client.get("/admin/sources", headers={"X-API-Key": "bad-key"})
        assert resp.status_code == 401

    def test_valid_key_returns_200(self, client: TestClient) -> None:
        """Request with correct X-API-Key returns 200."""
        resp = client.get("/admin/sources", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
