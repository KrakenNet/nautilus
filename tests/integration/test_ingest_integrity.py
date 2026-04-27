"""US-4 ingest-integrity integration tests (Task 32, AC-4.13).

Pure-Python integration test using ``fallback_memory`` stores. A
docker-based testcontainers variant is deferred.

Three scenarios exercise the full :meth:`RestAdapter.execute` path with
``IngestIntegrityConfig`` wired end-to-end through the three
:class:`~nautilus.core.postgres_store.BasePostgresStore` subclasses
(``QuarantineLogStore``, ``IngestBaselineStore``, ``SchemaAckStore``):

1. **Malformed record -> quarantine + audit** (AC-4.6 / AC-4.7 / AC-4.8).
   Upstream returns 2 valid + 1 invalid row under the default
   ``on_schema_violation="quarantine"``. The invalid row lands in
   :class:`QuarantineLogStore` via :meth:`QuarantineSink.record` and the
   orchestrator emits a ``rule_trace=["ingest_quarantine ..."]`` audit
   entry; the adapter still returns the 2 valid rows.

2. **Baseline outlier -> audit** (AC-4.9). The baseline store is pre-seeded
   with a snapshot at ``(mean=100, stddev=10)`` for ``baseline_type="row_count"``.
   Upstream returns 500 rows -> ``z_score ~= 40`` -> anomaly -> audit
   ``rule_trace=["ingest_anomaly ..."]`` + all 500 rows pass through.

3. **Schema-hash change + pause -> halt, then schema-ack resumes** (AC-4.10).
   The ack store is seeded with ``acked_hash=<hash of "old-schema">`` for
   ``source_id="foo"``. Upstream's ``x-schema-hash`` header carries
   ``<hash of "new-schema">``; under ``on_publisher_schema_change="pause"``
   the first :meth:`~RestAdapter.execute` raises
   :class:`~nautilus.ingest.errors.IngestPausedError`. After
   :meth:`SchemaAckStore.set_ack` records the new hash, a second
   :meth:`~RestAdapter.execute` call returns rows as normal.

All three scenarios instantiate the stores in ``on_failure="fallback_memory"``
so ``setup()`` degrades to in-memory when asyncpg cannot reach the dummy
DSN. The broker is NOT exercised -- the adapter + ingest stack is tested
directly with :mod:`respx` mocking the upstream HTTP response.

:class:`AuditLogger` writes to a :class:`fathom.audit.FileSink` rooted
under ``tmp_path`` so each scenario can inspect the JSONL tail.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fathom.audit import FileSink

from nautilus.adapters.rest import RestAdapter
from nautilus.audit.logger import NAUTILUS_METADATA_KEY, AuditLogger
from nautilus.config.models import EndpointSpec, NoneAuth, SourceConfig
from nautilus.core.models import AuditEntry, IntentAnalysis
from nautilus.ingest.baseline import (
    BaselineSnapshot,
    BaselineTracker,
    IngestBaselineStore,
)
from nautilus.ingest.config import IngestIntegrityConfig
from nautilus.ingest.errors import IngestPausedError
from nautilus.ingest.quarantine import QuarantineLogStore, QuarantineSink
from nautilus.ingest.schema_change import SchemaAckStore, SchemaChangeDetector

# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------


_BASE_URL = "http://example.com"
"""Non-private hostname so the RestAdapter's private-IP SSRF guard does not
fire; :mod:`respx` intercepts the request at the httpx transport level."""

# Inline JSON Schema used by all three scenarios. ``id`` is required + integer,
# ``name`` is required + string. Row shape matches the adapter's ``_coerce_rows``
# envelope (bare list).
_INGEST_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["id", "name"],
    "properties": {
        "id": {"type": "integer"},
        "name": {"type": "string"},
    },
    "additionalProperties": True,
}


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="fetch items",
        data_types_needed=["item"],
        entities=[],
    )


def _source(source_id: str, cfg: IngestIntegrityConfig) -> SourceConfig:
    return SourceConfig(
        id=source_id,
        type="rest",
        description="ingest-integrity test upstream",
        classification="unclassified",
        data_types=["item"],
        allowed_purposes=["research"],
        connection=_BASE_URL,
        endpoints=[EndpointSpec(path="/v1/items", method="GET")],
        auth=NoneAuth(),
        ingest_integrity=cfg,
    )


def _read_audit_entries(audit_file: Path) -> list[AuditEntry]:
    """Decode the Nautilus payload from each JSONL row."""
    entries: list[AuditEntry] = []
    if not audit_file.exists():
        return entries
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record: dict[str, Any] = json.loads(line)
        entry_json = record["metadata"][NAUTILUS_METADATA_KEY]
        entries.append(AuditEntry.model_validate_json(entry_json))
    return entries


def _rule_trace_has(entries: Iterable[AuditEntry], marker: str) -> list[AuditEntry]:
    return [e for e in entries if any(marker in line for line in e.rule_trace)]


def _write_schema(tmp_path: Path) -> Path:
    """Persist the inline JSON schema so ``SchemaValidator.compile()`` loads it."""
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(_INGEST_SCHEMA), encoding="utf-8")
    return schema_path


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


async def _make_adapter(
    *,
    source: SourceConfig,
    audit_logger: AuditLogger | None = None,
    quarantine_sink: QuarantineSink | None = None,
    baseline_tracker: BaselineTracker | None = None,
    schema_change_detector: SchemaChangeDetector | None = None,
    client: httpx.AsyncClient,
) -> RestAdapter:
    """Build + connect a :class:`RestAdapter` for the test.

    The httpx client is injected explicitly so :mod:`respx` (mounted on the
    client) intercepts outbound requests. ``connect()`` still runs the full
    ingest-integrity wiring (schema compile, validator bundle) -- we just
    skip the SSRF private-IP guard because the upstream base-URL is a
    non-IP hostname.
    """
    adapter = RestAdapter(
        client=client,
        audit_logger=audit_logger,
        quarantine_sink=quarantine_sink,
        baseline_tracker=baseline_tracker,
        schema_change_detector=schema_change_detector,
    )
    await adapter.connect(source)
    return adapter


@pytest.fixture(autouse=True)
def _set_test_env(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Provide dummy DSNs + root audit writes under ``tmp_path``.

    Mirrors ``tests/integration/test_cost_caps.py`` so pyright's strict mode
    sees the same fixture shape across the integration suite.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")
    monkeypatch.chdir(tmp_path)


@pytest.fixture
async def audit_logger(tmp_path: Path) -> AsyncIterator[AuditLogger]:
    """An ``AuditLogger`` wired to a :class:`FileSink` under ``tmp_path``."""
    sink = FileSink(tmp_path / "audit.jsonl")
    yield AuditLogger(sink)


# ---------------------------------------------------------------------------
# Scenario 1: malformed record -> quarantine + audit (AC-4.6 / AC-4.7).
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_malformed_record_lands_in_quarantine_and_audit(
    tmp_path: Path,
    audit_logger: AuditLogger,
) -> None:
    """AC-4.6 / AC-4.7 -- invalid row quarantined, valid rows still returned.

    The upstream returns two schema-compliant rows plus one that drops the
    required ``name`` field. Under the default
    ``on_schema_violation="quarantine"``, the orchestrator routes the
    violation through :class:`QuarantineSink` and the adapter emits the
    two surviving rows in ``AdapterResult.rows``. A ``QuarantineLogStore``
    in ``fallback_memory`` mode captures the dropped row in its in-memory
    deque for :meth:`recent` to inspect.
    """
    schema_path = _write_schema(tmp_path)
    cfg = IngestIntegrityConfig(
        schema=str(schema_path),  # pyright: ignore[reportCallIssue]  # alias
        on_schema_violation="quarantine",
    )
    source = _source("foo", cfg)

    store = QuarantineLogStore("postgres://ignored/quarantine", on_failure="fallback_memory")
    await store.setup()  # degrades silently; mode flips to degraded_memory
    assert store.mode == "degraded_memory", (
        f"QuarantineLogStore must degrade under fallback_memory when PG is unreachable; "
        f"got mode={store.mode!r}"
    )
    sink = QuarantineSink(store)

    async with respx.mock(base_url=_BASE_URL) as mock:
        mock.get("/v1/items").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"id": 1, "name": "alpha"},
                    {"id": 2, "name": "beta"},
                    {"id": 3},  # missing "name" -> JSON-schema violation
                ],
            )
        )
        async with httpx.AsyncClient(base_url=_BASE_URL, follow_redirects=False) as client:
            adapter = await _make_adapter(
                source=source,
                audit_logger=audit_logger,
                quarantine_sink=sink,
                client=client,
            )
            try:
                result = await adapter.execute(intent=_intent(), scope=[], context={})
            finally:
                await adapter.close()

    # Valid rows still surfaced; the invalid one is dropped from response.data.
    returned_ids = sorted(row["id"] for row in result.rows)
    assert returned_ids == [1, 2], (
        f"valid rows must survive quarantine routing; got {result.rows!r}"
    )

    # Quarantine store captured the one violating row.
    recent = await store.recent("foo", limit=10)
    assert len(recent) == 1, f"QuarantineSink must record exactly one violation; got {recent!r}"
    quarantined_row = recent[0]
    assert quarantined_row["source_id"] == "foo"
    assert quarantined_row["original_payload"] == {"id": 3}
    assert quarantined_row["violation_reason"]  # non-empty reason string

    # Audit stream carries an ``ingest_quarantine`` sub-event.
    entries = _read_audit_entries(tmp_path / "audit.jsonl")
    quarantine_entries = _rule_trace_has(entries, "ingest_quarantine")
    assert len(quarantine_entries) == 1, (
        f"expected exactly one ingest_quarantine audit entry; got {len(quarantine_entries)} "
        f"from {entries!r}"
    )
    assert "source=foo" in quarantine_entries[0].rule_trace[0]


# ---------------------------------------------------------------------------
# Scenario 2: baseline outlier -> audit, rows still returned (AC-4.9).
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_baseline_outlier_emits_anomaly_audit(
    tmp_path: Path,
    audit_logger: AuditLogger,
) -> None:
    """AC-4.9 -- a 500-row batch against ``(mean=100, stddev=10)`` flags anomaly.

    Pre-seeds :class:`IngestBaselineStore` with a ``row_count`` snapshot
    anchored far enough in the past that the tracker's rolling window does
    NOT trim the hydrated samples before scoring. The observed z-score is
    ``(500 - 100) / 10 == 40``, well past the configured
    ``anomaly_sigma=3.0``, so :meth:`BaselineTracker.update_and_check`
    returns one anomaly record and the orchestrator emits an
    ``ingest_anomaly`` audit sub-event. All rows still round-trip via the
    adapter (anomalies are informational, never blocking).
    """
    schema_path = _write_schema(tmp_path)
    cfg = IngestIntegrityConfig(
        schema=str(schema_path),  # pyright: ignore[reportCallIssue]
        baseline_window="1d",
        anomaly_sigma=3.0,
    )
    source = _source("foo", cfg)

    store = IngestBaselineStore("postgres://ignored/baseline", on_failure="fallback_memory")
    await store.setup()
    assert store.mode == "degraded_memory"

    # Seed a baseline so _hydrate_if_cold() synthesizes two samples at
    # ``mean +/- stddev``. Anchor ``computed_at`` inside the 1d rolling
    # window so the tracker's trim does not discard them before scoring.
    now = datetime.now(UTC)
    anchor = now - timedelta(hours=6)
    seed_snapshot = BaselineSnapshot(
        source_id="foo",
        baseline_type="row_count",
        window_start=anchor - timedelta(days=1),
        window_end=anchor,
        mean=100.0,
        stddev=10.0,
        sample_size=5,
        computed_at=anchor,
    )
    await store.upsert(seed_snapshot)

    tracker = BaselineTracker(store, baseline_window="1d", anomaly_sigma=3.0)

    # Build 500 rows that all validate against the schema so the baseline
    # check sees the full batch size as the observation.
    upstream_rows = [{"id": i, "name": f"row-{i}"} for i in range(500)]

    async with respx.mock(base_url=_BASE_URL) as mock:
        mock.get("/v1/items").mock(return_value=httpx.Response(200, json=upstream_rows))
        async with httpx.AsyncClient(base_url=_BASE_URL, follow_redirects=False) as client:
            adapter = await _make_adapter(
                source=source,
                audit_logger=audit_logger,
                baseline_tracker=tracker,
                client=client,
            )
            try:
                result = await adapter.execute(intent=_intent(), scope=[], context={})
            finally:
                await adapter.close()

    # All 500 rows returned -- anomalies never filter the batch.
    assert len(result.rows) == 500, (
        f"baseline anomaly must not drop rows; got {len(result.rows)} rows"
    )

    # Audit stream carries the ``ingest_anomaly`` sub-event with the
    # expected shape (baseline_type + z_score > sigma).
    entries = _read_audit_entries(tmp_path / "audit.jsonl")
    anomaly_entries = _rule_trace_has(entries, "ingest_anomaly")
    assert len(anomaly_entries) == 1, (
        f"expected exactly one ingest_anomaly audit entry; got {len(anomaly_entries)} "
        f"from {entries!r}"
    )
    trace_line = anomaly_entries[0].rule_trace[0]
    assert "baseline_type=row_count" in trace_line, (
        f"anomaly rule_trace must name the baseline_type; got {trace_line!r}"
    )
    assert "observed=500" in trace_line, (
        f"anomaly rule_trace must carry observed value; got {trace_line!r}"
    )


# ---------------------------------------------------------------------------
# Scenario 3: schema-hash change pauses the source; ack resumes it (AC-4.10).
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_schema_change_pauses_until_ack(
    tmp_path: Path,
    audit_logger: AuditLogger,
) -> None:
    """AC-4.10 -- pause on mismatch, resume after :meth:`SchemaAckStore.set_ack`.

    The ack store starts with an ack for ``source_id="foo"`` at the
    sha256 of ``"old-schema"``. The upstream's ``x-schema-hash`` header
    advertises the sha256 of ``"new-schema"`` -- a mismatch that, under
    ``on_publisher_schema_change="pause"``, surfaces as
    :class:`IngestPausedError`. After the operator-simulated
    :meth:`set_ack` records the new hash, a second :meth:`execute` call
    no longer raises and returns the schema-compliant rows.
    """
    schema_path = _write_schema(tmp_path)
    cfg = IngestIntegrityConfig(
        schema=str(schema_path),  # pyright: ignore[reportCallIssue]
        on_publisher_schema_change="pause",
    )
    source = _source("foo", cfg)

    ack_store = SchemaAckStore("postgres://ignored/ack", on_failure="fallback_memory")
    await ack_store.setup()
    assert ack_store.mode == "degraded_memory"

    old_hash = _sha256_hex("old-schema")
    new_hash = _sha256_hex("new-schema")

    # Operator previously acked the OLD schema.
    await ack_store.set_ack("foo", acked_hash=old_hash, actor="tester")

    detector = SchemaChangeDetector(ack_store=ack_store, audit_logger=audit_logger)
    upstream_rows = [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}]

    async with respx.mock(base_url=_BASE_URL) as mock:
        mock.get("/v1/items").mock(
            return_value=httpx.Response(
                200,
                json=upstream_rows,
                headers={"x-schema-hash": new_hash},
            )
        )
        async with httpx.AsyncClient(base_url=_BASE_URL, follow_redirects=False) as client:
            adapter = await _make_adapter(
                source=source,
                audit_logger=audit_logger,
                schema_change_detector=detector,
                client=client,
            )
            try:
                # First request: schema mismatch -> pause -> IngestPausedError.
                with pytest.raises(IngestPausedError) as excinfo:
                    await adapter.execute(intent=_intent(), scope=[], context={})
                assert "foo" in str(excinfo.value), (
                    f"IngestPausedError must name the source; got {excinfo.value!r}"
                )

                # Operator acks the new schema hash (simulates
                # `nautilus sources schema-ack foo --new-hash ...`).
                await ack_store.set_ack("foo", acked_hash=new_hash, actor="tester")

                # Second request: hashes now agree -> rows round-trip.
                result = await adapter.execute(intent=_intent(), scope=[], context={})
            finally:
                await adapter.close()

    returned_ids = sorted(row["id"] for row in result.rows)
    assert returned_ids == [1, 2], (
        f"post-ack execute must return upstream rows; got {result.rows!r}"
    )

    # Audit stream carries the schema-drift event from the first (paused) call.
    entries = _read_audit_entries(tmp_path / "audit.jsonl")
    drift_entries = [e for e in entries if e.event_type == "schema_change_detected"]
    assert len(drift_entries) >= 1, (
        f"expected at least one schema_change_detected audit entry; got {entries!r}"
    )
    trace_line = drift_entries[0].rule_trace[0]
    assert f"current={new_hash}" in trace_line, (
        f"drift audit must carry the current schema hash; got {trace_line!r}"
    )
    assert "mode=pause" in trace_line, f"drift audit must record the pause mode; got {trace_line!r}"
