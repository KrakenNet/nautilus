"""Integration tests for admin UI full flow (Task 3.9).

Verifies end-to-end rendering of admin pages with real router, mock
broker, and fixture audit JSONL data:
- GET /admin/sources -> 200 with source data rendered in HTML
- GET /admin/audit -> 200 with audit entries rendered
- GET /admin/attestation -> 200 with form
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from nautilus.config.models import SourceConfig
from nautilus.ui.router import router

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

AUTH_HEADERS = {"X-Forwarded-User": "test-operator"}


def _make_source(id: str, type: str = "postgres", **kwargs: Any) -> SourceConfig:  # noqa: A002
    """Build a minimal SourceConfig for testing."""
    return SourceConfig(
        id=id,
        type=type,  # pyright: ignore[reportArgumentType]
        description=f"Test source {id}",
        classification="internal",
        data_types=["structured"],
        connection="postgres://test/db",
        **kwargs,
    )


def _make_audit_entry_dict(
    *,
    request_id: str = "req-001",
    agent_id: str = "agent-1",
    source_id: str = "pg",
    ts: datetime | None = None,
) -> dict[str, object]:
    """Return a minimal AuditEntry-shaped dict."""
    if ts is None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
    return {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "request_id": request_id,
        "agent_id": agent_id,
        "session_id": None,
        "raw_intent": "test query",
        "intent_analysis": {
            "raw_intent": "test query",
            "data_types_needed": ["customer"],
            "entities": ["customer"],
        },
        "facts_asserted_summary": {"tpl": 1},
        "routing_decisions": [],
        "scope_constraints": [],
        "denial_records": [],
        "error_records": [],
        "rule_trace": ["rule:test"],
        "sources_queried": [source_id],
        "sources_denied": [],
        "sources_skipped": [],
        "sources_errored": [],
        "attestation_token": None,
        "duration_ms": 5,
        "event_type": "request",
    }


def _make_audit_record_line(entry_dict: dict[str, object]) -> str:
    """Wrap an AuditEntry dict inside a Fathom AuditRecord JSONL line."""
    entry_json = json.dumps(entry_dict, separators=(",", ":"))
    ts = entry_dict["timestamp"]
    session_id = entry_dict.get("session_id") or entry_dict["request_id"]
    rule_trace = entry_dict.get("rule_trace", [])
    duration_ms = entry_dict["duration_ms"]
    assert isinstance(duration_ms, int)
    return json.dumps(
        {
            "timestamp": ts,
            "session_id": session_id,
            "modules_traversed": [],
            "rules_fired": rule_trace,
            "decision": "allow",
            "reason": "queried=1 denied=0 skipped=0 errored=0",
            "duration_us": duration_ms * 1000,
            "metadata": {"nautilus_audit_entry": entry_json},
        }
    )


def _build_app(
    sources: list[SourceConfig] | None = None,
    audit_path: str | None = None,
) -> FastAPI:
    """Create a minimal FastAPI app with admin router and mock broker."""
    from unittest.mock import MagicMock

    app = FastAPI()
    app.include_router(router)

    broker = MagicMock()
    broker.sources = sources or []
    if audit_path:
        broker._config.audit.path = audit_path

    app.state.broker = broker
    app.state.auth_mode = "proxy_trust"
    return app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def three_sources() -> list[SourceConfig]:
    return [
        _make_source("pg-main", "postgres"),
        _make_source("pgv-embeddings", "pgvector"),
        _make_source("es-logs", "elasticsearch"),
    ]


@pytest.fixture()
def audit_jsonl(tmp_path: Path) -> Path:
    """Create a temp audit JSONL file with 3 entries."""
    audit_file = tmp_path / "audit.jsonl"
    entries = [
        _make_audit_entry_dict(request_id="req-100", agent_id="agent-alpha", source_id="pg"),
        _make_audit_entry_dict(request_id="req-101", agent_id="agent-beta", source_id="es"),
        _make_audit_entry_dict(request_id="req-102", agent_id="agent-gamma", source_id="neo4j"),
    ]
    lines = [_make_audit_record_line(e) for e in entries]
    audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return audit_file


# ---------------------------------------------------------------------------
# Tests: GET /admin/sources
# ---------------------------------------------------------------------------


class TestAdminSourcesFlow:
    """GET /admin/sources -> 200 with source data rendered in HTML."""

    def test_sources_returns_200_with_html(
        self,
        three_sources: list[SourceConfig],
    ) -> None:
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_all_sources_rendered_in_html(
        self,
        three_sources: list[SourceConfig],
    ) -> None:
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        body = resp.text
        for src in three_sources:
            assert src.id in body, f"Source {src.id} not found in rendered HTML"

    def test_source_types_rendered(
        self,
        three_sources: list[SourceConfig],
    ) -> None:
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        body = resp.text
        assert "postgres" in body
        assert "pgvector" in body
        assert "elasticsearch" in body

    def test_connection_string_not_exposed(
        self,
        three_sources: list[SourceConfig],
    ) -> None:
        """Source connection strings must never appear in rendered HTML."""
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        body = resp.text
        assert "postgres://test/db" not in body


# ---------------------------------------------------------------------------
# Tests: GET /admin/audit
# ---------------------------------------------------------------------------


class TestAdminAuditFlow:
    """GET /admin/audit -> 200 with audit entries rendered."""

    def test_audit_returns_200(self, audit_jsonl: Path) -> None:
        app = _build_app(audit_path=str(audit_jsonl))
        client = TestClient(app)
        resp = client.get("/admin/audit", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_audit_entries_rendered(self, audit_jsonl: Path) -> None:
        app = _build_app(audit_path=str(audit_jsonl))
        client = TestClient(app)
        resp = client.get("/admin/audit", headers=AUTH_HEADERS)
        body = resp.text
        # All 3 fixture entries should appear
        assert "req-100" in body
        assert "req-101" in body
        assert "req-102" in body

    def test_audit_agent_ids_rendered(self, audit_jsonl: Path) -> None:
        app = _build_app(audit_path=str(audit_jsonl))
        client = TestClient(app)
        resp = client.get("/admin/audit", headers=AUTH_HEADERS)
        body = resp.text
        assert "agent-alpha" in body
        assert "agent-beta" in body
        assert "agent-gamma" in body


# ---------------------------------------------------------------------------
# Tests: GET /admin/attestation
# ---------------------------------------------------------------------------


class TestAdminAttestationFlow:
    """GET /admin/attestation -> 200 with form."""

    def test_attestation_returns_200(self) -> None:
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/admin/attestation", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_attestation_shows_not_configured_when_no_key(self) -> None:
        """POC default: signing_key_configured=False shows empty-state message."""
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/admin/attestation", headers=AUTH_HEADERS)
        body = resp.text.lower()
        assert "attestation not configured" in body

    def test_attestation_page_has_nav(self) -> None:
        """Attestation page renders with full dashboard layout."""
        app = _build_app()
        client = TestClient(app)
        resp = client.get("/admin/attestation", headers=AUTH_HEADERS)
        body = resp.text
        assert "Attestation" in body or "attestation" in body
        # Dashboard layout includes navigation links
        assert "/admin/sources" in body
        assert "/admin/audit" in body
