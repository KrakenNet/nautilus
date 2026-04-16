"""Unit tests for attestation verification routes (Task 3.4).

Covers:
- GET /admin/attestation with no signing key → "Attestation not configured"
- POST /admin/attestation/verify with valid token → stub "invalid" result
- POST /admin/attestation/verify with tampered token → stub "invalid" result
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.testclient import TestClient

from nautilus.ui.router import router

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

AUTH_HEADERS = {"X-Forwarded-User": "test-operator"}


def _build_app() -> FastAPI:
    """Create a minimal FastAPI app with the admin router (no broker needed)."""
    app = FastAPI()
    app.include_router(router)
    app.state.auth_mode = "proxy_trust"
    return app


# ---------------------------------------------------------------------------
# GET /admin/attestation — form page
# ---------------------------------------------------------------------------


class TestAttestationPage:
    """GET /admin/attestation — renders form page."""

    def test_no_signing_key_shows_not_configured(self) -> None:
        """When signing_key_configured is False (POC default), shows message."""
        client = TestClient(_build_app())
        resp = client.get("/admin/attestation", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "Attestation not configured" in resp.text


# ---------------------------------------------------------------------------
# POST /admin/attestation/verify — stub verification
# ---------------------------------------------------------------------------


class TestAttestationVerify:
    """POST /admin/attestation/verify — attestation token verification."""

    def test_valid_token_returns_invalid_stub(self) -> None:
        """POC stub: even a well-formed token returns 'invalid' result."""
        client = TestClient(_build_app())
        resp = client.post(
            "/admin/attestation/verify",
            data={"token": "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.signature"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.text
        # The stub always returns invalid (AttestationService not implemented)
        assert "Invalid" in body or "invalid" in body

    def test_tampered_token_returns_invalid_stub(self) -> None:
        """POC stub: tampered token also returns 'invalid' result."""
        client = TestClient(_build_app())
        resp = client.post(
            "/admin/attestation/verify",
            data={"token": "TAMPERED.TOKEN.DATA"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        body = resp.text
        assert "Invalid" in body or "invalid" in body
