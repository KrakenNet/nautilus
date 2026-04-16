"""Unit tests for admin UI source and decision routes (Task 3.2).

Covers:
- GET /admin/sources returns 200 with HTML content-type, 3 mocked sources rendered
- HTMX partial (HX-Request: true) returns fragment only, not full page
- GET /admin/decisions/{request_id} modal fragment contains rule_trace
- Filter params on /admin/decisions produce correct entries
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from nautilus.config.models import SourceConfig
from nautilus.core.models import (
    AuditEntry,
    DenialRecord,
    RoutingDecision,
    ScopeConstraint,
)
from nautilus.ui.audit_reader import AuditPage
from nautilus.ui.router import router

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_source(id: str, type: str = "postgres", **kwargs: Any) -> SourceConfig:
    """Build a minimal SourceConfig for testing."""
    return SourceConfig(
        id=id,
        type=type,
        description=f"Test source {id}",
        classification="internal",
        data_types=["structured"],
        connection="postgres://test/db",
        **kwargs,
    )


def _make_audit_entry(
    request_id: str = "req-001",
    agent_id: str = "agent-a",
    *,
    denied: bool = False,
    rule_trace: list[str] | None = None,
    raw_intent: str = "lookup user data",
) -> AuditEntry:
    """Build a minimal AuditEntry for testing."""
    denial_records = (
        [DenialRecord(source_id="src-x", rule_name="deny-rule", reason="blocked")]
        if denied
        else []
    )
    return AuditEntry(
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC),
        request_id=request_id,
        agent_id=agent_id,
        raw_intent=raw_intent,
        facts_asserted_summary={"agent": 1, "source": 2},
        routing_decisions=[RoutingDecision(source_id="src-a", reason="matched")],
        scope_constraints=[
            ScopeConstraint(source_id="src-a", field="dept", operator="=", value="eng"),
        ],
        denial_records=denial_records,
        error_records=[],
        rule_trace=rule_trace or ["rule-1 fired", "rule-2 fired"],
        sources_queried=["src-a"],
        sources_denied=["src-x"] if denied else [],
        sources_errored=[],
        duration_ms=42,
    )


def _build_app(sources: list[SourceConfig] | None = None, audit_path: str | None = None) -> FastAPI:
    """Create a minimal FastAPI app with the admin router and a mock broker."""
    app = FastAPI()
    app.include_router(router)

    broker = MagicMock()
    broker.sources = sources or []

    # Wire up a mock config for audit path
    if audit_path:
        broker._config.audit.path = audit_path

    app.state.broker = broker
    # Use proxy_trust auth mode so tests can just set X-Forwarded-User
    app.state.auth_mode = "proxy_trust"

    return app


@pytest.fixture()
def three_sources() -> list[SourceConfig]:
    return [
        _make_source("pg-main", "postgres"),
        _make_source("pgv-embeddings", "pgvector"),
        _make_source("es-logs", "elasticsearch"),
    ]


@pytest.fixture()
def audit_entries() -> list[AuditEntry]:
    return [
        _make_audit_entry("req-001", "agent-alpha", raw_intent="find user records"),
        _make_audit_entry("req-002", "agent-beta", denied=True, raw_intent="access secrets"),
        _make_audit_entry(
            "req-003",
            "agent-alpha",
            rule_trace=["compliance-rule fired", "routing-rule fired"],
            raw_intent="query inventory",
        ),
    ]


AUTH_HEADERS = {"X-Forwarded-User": "test-operator"}


# ---------------------------------------------------------------------------
# Source routes
# ---------------------------------------------------------------------------


class TestSourceStatus:
    """GET /admin/sources — source status page."""

    def test_returns_200_with_html(self, three_sources: list[SourceConfig]) -> None:
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_all_sources_rendered(self, three_sources: list[SourceConfig]) -> None:
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        body = resp.text
        for src in three_sources:
            assert src.id in body, f"Source {src.id} not rendered in page"

    def test_full_page_contains_layout(self, three_sources: list[SourceConfig]) -> None:
        """Non-HTMX request returns full page with layout chrome."""
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        body = resp.text
        # Full page includes the dashboard layout (sidebar nav)
        assert "Sources" in body
        assert "<table" in body

    def test_htmx_returns_partial_only(self, three_sources: list[SourceConfig]) -> None:
        """HX-Request: true returns table body fragment, not the full page."""
        app = _build_app(sources=three_sources)
        client = TestClient(app)
        headers = {**AUTH_HEADERS, "HX-Request": "true"}
        resp = client.get("/admin/sources", headers=headers)
        assert resp.status_code == 200
        body = resp.text
        # Partial should contain source IDs
        for src in three_sources:
            assert src.id in body
        # Partial should NOT contain the full-page layout elements
        assert "<!DOCTYPE" not in body and "<!doctype" not in body
        assert "<aside" not in body

    def test_broker_not_ready_returns_503(self) -> None:
        """When broker is None, returns 503."""
        app = FastAPI()
        app.include_router(router)
        app.state.auth_mode = "proxy_trust"
        # No broker on app.state
        client = TestClient(app)
        resp = client.get("/admin/sources", headers=AUTH_HEADERS)
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Decision detail route
# ---------------------------------------------------------------------------


class TestDecisionDetail:
    """GET /admin/decisions/{request_id} — modal fragment."""

    def _client_with_entries(self, entries: list[AuditEntry]) -> TestClient:
        page = AuditPage(entries=entries, total_estimate=len(entries))
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        app = _build_app(audit_path=audit_path)
        with patch("nautilus.ui.router.AuditReader") as mock_reader_cls:
            instance = mock_reader_cls.return_value
            instance.read_page.return_value = page
            return TestClient(app)

    def test_modal_contains_rule_trace(self, audit_entries: list[AuditEntry]) -> None:
        page = AuditPage(entries=audit_entries, total_estimate=len(audit_entries))
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        app = _build_app(audit_path=audit_path)
        with patch("nautilus.ui.router.AuditReader") as mock_reader_cls:
            instance = mock_reader_cls.return_value
            instance.read_page.return_value = page
            client = TestClient(app)
            resp = client.get("/admin/decisions/req-001", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        body = resp.text
        # The decision_detail template renders rule_trace via tojson
        assert "rule-1 fired" in body
        assert "rule-2 fired" in body

    def test_modal_contains_request_id(self, audit_entries: list[AuditEntry]) -> None:
        page = AuditPage(entries=audit_entries, total_estimate=len(audit_entries))
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        app = _build_app(audit_path=audit_path)
        with patch("nautilus.ui.router.AuditReader") as mock_reader_cls:
            instance = mock_reader_cls.return_value
            instance.read_page.return_value = page
            client = TestClient(app)
            resp = client.get("/admin/decisions/req-001", headers=AUTH_HEADERS)
        assert "req-001" in resp.text

    def test_not_found_returns_empty_state(self, audit_entries: list[AuditEntry]) -> None:
        page = AuditPage(entries=audit_entries, total_estimate=len(audit_entries))
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        app = _build_app(audit_path=audit_path)
        with patch("nautilus.ui.router.AuditReader") as mock_reader_cls:
            instance = mock_reader_cls.return_value
            instance.read_page.return_value = page
            client = TestClient(app)
            resp = client.get("/admin/decisions/nonexistent-id", headers=AUTH_HEADERS)
        assert resp.status_code == 200
        assert "not found" in resp.text.lower()


# ---------------------------------------------------------------------------
# Decisions list with filters
# ---------------------------------------------------------------------------


class TestDecisionsFilter:
    """GET /admin/decisions with filter query params."""

    def _get_decisions(
        self,
        entries: list[AuditEntry],
        params: dict[str, str] | None = None,
        htmx: bool = False,
    ) -> Any:
        page = AuditPage(entries=entries, total_estimate=len(entries))
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        app = _build_app(audit_path=audit_path)
        headers = {**AUTH_HEADERS}
        if htmx:
            headers["HX-Request"] = "true"
        with patch("nautilus.ui.router.AuditReader") as mock_reader_cls:
            instance = mock_reader_cls.return_value
            instance.read_page.return_value = page
            client = TestClient(app)
            return client.get("/admin/decisions", headers=headers, params=params or {})

    def test_outcome_denied_filter(self, audit_entries: list[AuditEntry]) -> None:
        """outcome=denied should only show entries with denial_records."""
        resp = self._get_decisions(audit_entries, {"outcome": "denied"})
        assert resp.status_code == 200
        body = resp.text
        # req-002 is the denied one
        assert "req-002" in body
        # req-001 and req-003 are allowed (no denials)
        assert "req-001" not in body
        assert "req-003" not in body

    def test_outcome_allowed_filter(self, audit_entries: list[AuditEntry]) -> None:
        """outcome=allowed should exclude entries with denial_records."""
        resp = self._get_decisions(audit_entries, {"outcome": "allowed"})
        assert resp.status_code == 200
        body = resp.text
        assert "req-001" in body
        assert "req-003" in body
        assert "req-002" not in body

    def test_search_filter(self, audit_entries: list[AuditEntry]) -> None:
        """search param filters by request_id, agent_id, raw_intent."""
        resp = self._get_decisions(audit_entries, {"search": "inventory"})
        assert resp.status_code == 200
        body = resp.text
        # Only req-003 has "inventory" in raw_intent
        assert "req-003" in body
        assert "req-001" not in body
        assert "req-002" not in body

    def test_search_by_agent_id(self, audit_entries: list[AuditEntry]) -> None:
        """search matches against agent_id."""
        resp = self._get_decisions(audit_entries, {"search": "agent-beta"})
        assert resp.status_code == 200
        body = resp.text
        assert "req-002" in body
        assert "req-001" not in body

    def test_htmx_decisions_returns_partial(self, audit_entries: list[AuditEntry]) -> None:
        """HTMX request to decisions list returns rows only, not full page."""
        resp = self._get_decisions(audit_entries, htmx=True)
        assert resp.status_code == 200
        body = resp.text
        # Should not contain full-page layout markers
        assert "<!DOCTYPE" not in body and "<!doctype" not in body
        assert "<aside" not in body

    def test_no_results_shows_empty_state(self) -> None:
        """When no entries match, empty state is shown."""
        resp = self._get_decisions([], htmx=True)
        assert resp.status_code == 200
        assert "No decisions found" in resp.text
