"""Unit coverage for ingest-integrity wiring in :mod:`nautilus.adapters.rest` (Task 30, US-4).

Exercises the five :func:`_validate_ingest_integrity` orchestration paths
through a :class:`RestAdapter` connected over ``httpx.MockTransport``:

(a) No ``ingest_integrity`` config → zero-overhead path; orchestrator never
    runs (FR-20).
(b) ``on_schema_violation="quarantine"`` → invalid rows forwarded to the
    quarantine sink, valid rows returned in ``AdapterResult.rows``
    (AC-4.5, AC-4.7).
(c) ``on_schema_violation="reject"`` → first violation raises
    :class:`SchemaViolationError`.
(d) Schema-change mismatch + ``on_publisher_schema_change="pause"`` →
    :class:`IngestPausedError` (AC-4.10).
(e) Baseline anomaly → audit entry emitted, rows still returned (AC-4.9).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from nautilus.adapters.rest import RestAdapter
from nautilus.config.models import (
    EndpointSpec,
    NoneAuth,
    SourceConfig,
)
from nautilus.core.models import AdapterResult, AuditEntry, IntentAnalysis
from nautilus.ingest.config import IngestIntegrityConfig
from nautilus.ingest.errors import IngestPausedError, SchemaViolationError

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


_PERSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "age": {"type": "integer", "minimum": 0},
    },
    "required": ["name", "age"],
    "additionalProperties": False,
}


@pytest.fixture
def schema_file(tmp_path: Path) -> Path:
    """Write the person schema to a temp file the config can reference."""
    p = tmp_path / "person.json"
    p.write_text(json.dumps(_PERSON_SCHEMA))
    return p


class _RecordingAudit:
    """Minimal :class:`AuditLogger`-shaped stand-in that captures entries."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def emit(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class _FakeQuarantineSink:
    """Captures ``(source_id, row, reason, schema_hash)`` on each ``record``."""

    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any], str, str | None]] = []

    async def record(
        self,
        source_id: str,
        row: dict[str, Any],
        reason: str,
        schema_hash: str | None = None,
    ) -> None:
        self.records.append((source_id, row, reason, schema_hash))


def _make_source(
    *,
    ingest_integrity: IngestIntegrityConfig | None = None,
) -> SourceConfig:
    return SourceConfig(
        id="rest_src",
        type="rest",
        description="rest source",
        classification="secret",
        data_types=["person"],
        allowed_purposes=["research"],
        connection="http://api.example.com",
        endpoints=[EndpointSpec(path="/people", method="GET")],
        auth=NoneAuth(),
        ingest_integrity=ingest_integrity,
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="fetch people",
        data_types_needed=["person"],
        entities=[],
        temporal_scope=None,
        estimated_sensitivity=None,
    )


async def _build_adapter(
    *,
    handler: Any,
    source: SourceConfig,
    baseline_tracker: Any = None,
    schema_change_detector: Any = None,
    quarantine_sink: Any = None,
    audit_logger: Any = None,
) -> RestAdapter:
    """Build + connect a :class:`RestAdapter` with an injected mock transport."""
    client = httpx.AsyncClient(
        base_url="http://api.example.com",
        transport=httpx.MockTransport(handler),
    )
    adapter = RestAdapter(
        client=client,
        baseline_tracker=baseline_tracker,
        schema_change_detector=schema_change_detector,
        quarantine_sink=quarantine_sink,
        audit_logger=audit_logger,
    )
    await adapter.connect(source)
    return adapter


# ---------------------------------------------------------------------------
# (a) No ingest_integrity → zero-overhead path (FR-20).
# ---------------------------------------------------------------------------


async def test_no_ingest_integrity_config_skips_orchestrator() -> None:
    """Source with ``ingest_integrity=None`` never invokes the orchestrator."""
    source = _make_source(ingest_integrity=None)
    body: list[dict[str, Any]] = [{"name": "alice", "age": 30}, {"unrelated": True}]

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    adapter = await _build_adapter(handler=_handler, source=source)
    try:
        result = await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()

    assert isinstance(result, AdapterResult)
    # Every dict row flows through unchanged — no schema filtering happened.
    assert result.rows == body
    # The validator bundle is never materialised for unconfigured sources.
    assert adapter._ingest_cfg is None  # pyright: ignore[reportPrivateUsage]
    assert adapter._ingest_validators is None  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# (b) quarantine mode → invalid rows quarantined, valid rows returned.
# ---------------------------------------------------------------------------


async def test_quarantine_mode_forwards_invalid_rows_and_returns_valid(
    schema_file: Path,
) -> None:
    """``on_schema_violation="quarantine"`` routes invalid rows to the sink."""
    cfg = IngestIntegrityConfig.model_validate(
        {"schema": str(schema_file), "on_schema_violation": "quarantine"}
    )
    source = _make_source(ingest_integrity=cfg)
    body: list[dict[str, Any]] = [
        {"name": "alice", "age": 30},  # valid
        {"name": "bob", "age": -1},  # fails minimum: 0
        {"name": "carol", "age": 25},  # valid
    ]

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    sink = _FakeQuarantineSink()
    audit = _RecordingAudit()
    adapter = await _build_adapter(
        handler=_handler,
        source=source,
        quarantine_sink=sink,
        audit_logger=audit,
    )
    try:
        result = await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()

    # Only valid rows come out.
    assert result.rows == [
        {"name": "alice", "age": 30},
        {"name": "carol", "age": 25},
    ]
    # The single violating row was recorded.
    assert len(sink.records) == 1
    source_id, row, reason, schema_hash = sink.records[0]
    assert source_id == "rest_src"
    assert row == {"name": "bob", "age": -1}
    assert "minimum" in reason.lower()
    assert schema_hash is None  # no x-schema-hash header on this response
    # Audit entry emitted for the quarantined row.
    assert len(audit.entries) == 1
    assert audit.entries[0].event_type == "request"
    assert any("ingest_quarantine" in t for t in audit.entries[0].rule_trace)


# ---------------------------------------------------------------------------
# (c) reject mode → SchemaViolationError.
# ---------------------------------------------------------------------------


async def test_reject_mode_raises_on_first_violation(schema_file: Path) -> None:
    """``on_schema_violation="reject"`` hard-fails the batch."""
    cfg = IngestIntegrityConfig.model_validate(
        {"schema": str(schema_file), "on_schema_violation": "reject"}
    )
    source = _make_source(ingest_integrity=cfg)

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"name": "bob", "age": -1}])

    adapter = await _build_adapter(handler=_handler, source=source)
    try:
        with pytest.raises(SchemaViolationError) as excinfo:
            await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()

    assert "rest_src" in str(excinfo.value)


# ---------------------------------------------------------------------------
# (d) Schema-change mismatch + pause → IngestPausedError.
# ---------------------------------------------------------------------------


async def test_schema_change_mismatch_pauses_ingest(schema_file: Path) -> None:
    """``on_publisher_schema_change="pause"`` + hash drift raises ``IngestPausedError``."""
    cfg = IngestIntegrityConfig.model_validate(
        {
            "schema": str(schema_file),
            "on_schema_violation": "quarantine",
            "on_publisher_schema_change": "pause",
        }
    )
    source = _make_source(ingest_integrity=cfg)

    def _handler(_req: httpx.Request) -> httpx.Response:
        # Upstream echoes a schema hash header; detector compares it to the
        # operator-acknowledged hash and raises on mismatch.
        return httpx.Response(
            200,
            json=[{"name": "alice", "age": 30}],
            headers={"x-schema-hash": "deadbeef" * 8},  # 64-char hex digest
        )

    # Schema-change detector stub: whatever hash we pass in, it raises.
    detector = MagicMock()
    detector.check = AsyncMock(side_effect=IngestPausedError("schema drift"))

    adapter = await _build_adapter(
        handler=_handler,
        source=source,
        schema_change_detector=detector,
    )
    try:
        with pytest.raises(IngestPausedError):
            await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()

    # Detector was called with the schema-hash header value.
    detector.check.assert_awaited_once()
    _, kwargs = detector.check.call_args
    assert kwargs["current_schema_hash"] == "deadbeef" * 8
    assert kwargs["mode"] == "pause"


# ---------------------------------------------------------------------------
# (e) Baseline anomaly → audit emitted, rows still returned.
# ---------------------------------------------------------------------------


async def test_anomaly_emits_audit_but_does_not_block(schema_file: Path) -> None:
    """Anomaly detection is non-blocking: audit fires, rows still returned."""
    cfg = IngestIntegrityConfig.model_validate(
        {"schema": str(schema_file), "on_schema_violation": "quarantine"}
    )
    source = _make_source(ingest_integrity=cfg)
    body: list[dict[str, Any]] = [{"name": "alice", "age": 30}]

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    # Baseline tracker stub: returns one anomaly record.
    tracker = MagicMock()
    tracker.update_and_check = AsyncMock(
        return_value=[
            {
                "baseline_type": "row_count",
                "observed": 1.0,
                "mean": 50.0,
                "stddev": 5.0,
                "z_score": -9.8,
                "sample_size": 42,
            }
        ]
    )
    audit = _RecordingAudit()

    adapter = await _build_adapter(
        handler=_handler,
        source=source,
        baseline_tracker=tracker,
        audit_logger=audit,
    )
    try:
        result = await adapter.execute(intent=_intent(), scope=[], context={})
    finally:
        await adapter.close()

    # Rows still flow through — anomaly does not block.
    assert result.rows == body
    # Exactly one anomaly audit entry.
    assert len(audit.entries) == 1
    assert audit.entries[0].event_type == "request"
    assert any("ingest_anomaly" in t for t in audit.entries[0].rule_trace)
