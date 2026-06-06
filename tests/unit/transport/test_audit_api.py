# starlette >= 1.2 TestClient annotations reference httpx private modules,
# which pyright strict surfaces as Unknown at every call site. Relax only
# the Unknown-type rules here; all other strict checks remain active.
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false
"""Unit tests for the public audit query API (#32).

Covers ``GET /v1/audit`` and ``GET /v1/audit/{request_id}`` against a real
:class:`AuditReader` backed by a tempfile JSONL log (records written in the
same shape :meth:`AuditLogger.emit` produces — outer Fathom ``AuditRecord``
wrapping the inner Nautilus ``AuditEntry``).

Cases:
- filtered page returns only matching entries
- cursor round-trip walks the whole log without dropping/duplicating
- single lookup returns the entry; 404 when absent
- auth required: 401 in proxy_trust (no X-Forwarded-User) and api_key
  (missing / wrong X-API-Key)
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal
from unittest.mock import AsyncMock, MagicMock

import pytest
from fathom.models import AuditRecord
from starlette.testclient import TestClient

from nautilus.audit.logger import NAUTILUS_METADATA_KEY
from nautilus.core.models import AuditEntry
from nautilus.transport.fastapi_app import create_app

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_entry(
    request_id: str,
    agent_id: str,
    minute: int,
    *,
    source_id: str = "src-a",
    event_type: Literal["request"] | None = None,
) -> AuditEntry:
    """Build a minimal AuditEntry stamped at 2025-06-15 12:<minute>:00Z."""
    return AuditEntry(
        timestamp=datetime(2025, 6, 15, 12, minute, 0, tzinfo=UTC),
        request_id=request_id,
        agent_id=agent_id,
        raw_intent="lookup",
        facts_asserted_summary={},
        routing_decisions=[],
        scope_constraints=[],
        denial_records=[],
        error_records=[],
        rule_trace=[],
        sources_queried=[source_id],
        sources_denied=[],
        sources_errored=[],
        duration_ms=minute,
        event_type=event_type,
    )


def _jsonl_line(entry: AuditEntry) -> str:
    """Render one JSONL line exactly as ``AuditLogger.emit`` would."""
    record = AuditRecord(
        timestamp=entry.timestamp.isoformat(),
        session_id=entry.request_id,
        modules_traversed=[],
        rules_fired=list(entry.rule_trace),
        decision="allow",
        reason="test",
        duration_us=entry.duration_ms * 1000,
        metadata={NAUTILUS_METADATA_KEY: entry.model_dump_json()},
    )
    return record.model_dump_json()


def _write_log(path: Path, entries: list[AuditEntry]) -> None:
    """Write ``entries`` (in order) as JSONL to ``path``."""
    with path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(_jsonl_line(entry) + "\n")


def _make_broker(audit_path: Path, *, mode: str = "proxy_trust") -> MagicMock:
    """Build a mock broker whose config points at ``audit_path``."""
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    store = MagicMock()
    store.aget = AsyncMock(return_value=None)
    broker.session_store = store
    broker.sources = []
    broker._config = SimpleNamespace(
        api=SimpleNamespace(
            auth=SimpleNamespace(mode=mode),
            keys=["topsecret"],
        ),
        audit=SimpleNamespace(path=str(audit_path)),
    )
    return broker


def _build_client(
    tmp_path: Path,
    entries: list[AuditEntry],
    *,
    mode: str = "proxy_trust",
) -> TestClient:
    """Create a TestClient over an app whose broker reads ``entries``."""
    audit_path = tmp_path / "audit.jsonl"
    _write_log(audit_path, entries)
    broker = _make_broker(audit_path, mode=mode)
    app = create_app(None, existing_broker=broker)
    client = TestClient(app)
    # TestClient drives lifespan on __enter__; do it manually so app.state
    # (broker, auth_mode, api_keys) is populated before requests.
    client.__enter__()
    return client


PROXY_AUTH = {"X-Forwarded-User": "operator"}


@pytest.fixture()
def sample_entries() -> list[AuditEntry]:
    """Six entries, alternating agents/sources, ascending timestamps."""
    return [
        _make_entry("req-0", "agent-a", 0, source_id="src-a"),
        _make_entry("req-1", "agent-b", 1, source_id="src-b"),
        _make_entry("req-2", "agent-a", 2, source_id="src-a", event_type="request"),
        _make_entry("req-3", "agent-b", 3, source_id="src-b"),
        _make_entry("req-4", "agent-a", 4, source_id="src-a"),
        _make_entry("req-5", "agent-b", 5, source_id="src-b"),
    ]


# ---------------------------------------------------------------------------
# GET /v1/audit — filtered page
# ---------------------------------------------------------------------------


def test_filtered_page_returns_only_matching_agent(
    tmp_path: Path, sample_entries: list[AuditEntry]
) -> None:
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit", params={"agent_id": "agent-a"}, headers=PROXY_AUTH)
    assert resp.status_code == 200
    body = resp.json()
    ids = {e["request_id"] for e in body["entries"]}
    assert ids == {"req-0", "req-2", "req-4"}
    assert all(e["agent_id"] == "agent-a" for e in body["entries"])


def test_filtered_page_by_source_id(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit", params={"source_id": "src-b"}, headers=PROXY_AUTH)
    assert resp.status_code == 200
    ids = {e["request_id"] for e in resp.json()["entries"]}
    assert ids == {"req-1", "req-3", "req-5"}


def test_filtered_page_by_event_type(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit", params={"event_type": "request"}, headers=PROXY_AUTH)
    assert resp.status_code == 200
    ids = [e["request_id"] for e in resp.json()["entries"]]
    assert ids == ["req-2"]


def test_limit_is_capped(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    """limit over the hard cap is rejected by query validation (422)."""
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit", params={"limit": "1000"}, headers=PROXY_AUTH)
    assert resp.status_code == 422


def test_bad_datetime_returns_400(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit", params={"start": "not-a-date"}, headers=PROXY_AUTH)
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /v1/audit — pagination cursor round-trip
# ---------------------------------------------------------------------------


def test_pagination_cursor_round_trip(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    """Walk every page (desc, default order) via next_cursor.

    The union covers all entries exactly once — this is the canonical
    pagination path SIEM / dashboard consumers drive (newest-first).
    """
    client = _build_client(tmp_path, sample_entries)
    seen: list[str] = []
    cursor: str | None = None
    params: dict[str, str] = {"limit": "2", "order": "desc"}
    for _ in range(10):  # generous bound to avoid infinite loop on regression
        if cursor is not None:
            params["cursor"] = cursor
        resp = client.get("/v1/audit", params=params, headers=PROXY_AUTH)
        assert resp.status_code == 200
        body = resp.json()
        seen.extend(e["request_id"] for e in body["entries"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    # Every entry surfaced exactly once across the paged walk.
    assert sorted(seen) == ["req-0", "req-1", "req-2", "req-3", "req-4", "req-5"]
    assert len(seen) == len(set(seen)), "an entry was returned on more than one page"


def test_default_order_is_desc(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    """Default order returns newest-first."""
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit", headers=PROXY_AUTH)
    assert resp.status_code == 200
    ids = [e["request_id"] for e in resp.json()["entries"]]
    assert ids == ["req-5", "req-4", "req-3", "req-2", "req-1", "req-0"]


# ---------------------------------------------------------------------------
# GET /v1/audit/{request_id} — single lookup
# ---------------------------------------------------------------------------


def test_single_lookup_returns_entry(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit/req-3", headers=PROXY_AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["request_id"] == "req-3"
    assert body["agent_id"] == "agent-b"


def test_single_lookup_404_when_absent(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit/does-not-exist", headers=PROXY_AUTH)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth — public API must require authentication
# ---------------------------------------------------------------------------


def test_list_requires_auth_proxy_trust(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    """No X-Forwarded-User in proxy_trust mode → 401."""
    client = _build_client(tmp_path, sample_entries, mode="proxy_trust")
    resp = client.get("/v1/audit")
    assert resp.status_code == 401


def test_single_requires_auth_proxy_trust(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries, mode="proxy_trust")
    resp = client.get("/v1/audit/req-0")
    assert resp.status_code == 401


def test_list_rejects_missing_api_key(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    """In api_key mode a missing X-API-Key is rejected (401/403)."""
    client = _build_client(tmp_path, sample_entries, mode="api_key")
    resp = client.get("/v1/audit")
    assert resp.status_code in (401, 403)


def test_list_rejects_wrong_api_key(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries, mode="api_key")
    resp = client.get("/v1/audit", headers={"X-API-Key": "wrong"})
    assert resp.status_code == 401


def test_list_accepts_valid_api_key(tmp_path: Path, sample_entries: list[AuditEntry]) -> None:
    client = _build_client(tmp_path, sample_entries, mode="api_key")
    resp = client.get("/v1/audit", headers={"X-API-Key": "topsecret"})
    assert resp.status_code == 200
    assert len(resp.json()["entries"]) == 6


def test_entries_are_full_audit_entry_dumps(
    tmp_path: Path, sample_entries: list[AuditEntry]
) -> None:
    """Each entry is a JSON-mode AuditEntry dump (round-trips back)."""
    client = _build_client(tmp_path, sample_entries)
    resp = client.get("/v1/audit", params={"agent_id": "agent-a", "limit": "1"}, headers=PROXY_AUTH)
    assert resp.status_code == 200
    entry: dict[str, Any] = resp.json()["entries"][0]
    # Re-validating the dump as an AuditEntry must succeed (loss-less shape).
    restored = AuditEntry.model_validate(entry)
    assert restored.request_id == entry["request_id"]
