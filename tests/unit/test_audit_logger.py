"""Unit tests for :class:`nautilus.audit.logger.AuditLogger` (Task 2.10).

Covers AC-7.3 (deterministic JSONL output), AC-7.5 (ISO8601 UTC with ``Z``
suffix) and NFR-8 (flush-after-write durability). The scope is narrow: we
only probe the serialization hardening contract; the end-to-end broker
wiring of the logger is covered by the MVP integration test.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timezone
from pathlib import Path

import pytest
from fathom.audit import FileSink

from nautilus.audit.logger import (
    NAUTILUS_METADATA_KEY,
    AuditLogger,
    decode_nautilus_entry,
)
from nautilus.core.models import (
    AuditEntry,
    DenialRecord,
    ErrorRecord,
    IntentAnalysis,
    RoutingDecision,
    ScopeConstraint,
)


def _make_entry(ts: datetime) -> AuditEntry:
    return AuditEntry(
        timestamp=ts,
        request_id="req-7f3a",
        agent_id="agent-42",
        session_id=None,
        raw_intent="list customers",
        intent_analysis=IntentAnalysis(
            raw_intent="list customers",
            data_types_needed=["customer"],
            entities=["customer"],
        ),
        facts_asserted_summary={"source": 2},
        routing_decisions=[],
        scope_constraints=[],
        denial_records=[],
        error_records=[],
        rule_trace=["rule:routing/allow-basic"],
        sources_queried=["pg"],
        sources_denied=[],
        sources_skipped=[],
        sources_errored=[],
        attestation_token=None,
        duration_ms=12,
    )


@pytest.mark.unit
def test_audit_logger_writes_jsonl_line_with_trailing_newline(
    tmp_path: Path,
) -> None:
    """Written line must end with ``\\n`` (JSONL framing, AC-7.3)."""
    sink = FileSink(tmp_path / "audit.jsonl")
    logger = AuditLogger(sink)

    logger.emit(_make_entry(AuditLogger.utcnow()))

    raw = (tmp_path / "audit.jsonl").read_bytes()
    assert raw.endswith(b"\n"), f"audit file must end with newline, got {raw!r}"
    # Exactly one line produced for one emit.
    assert raw.count(b"\n") == 1


@pytest.mark.unit
def test_audit_logger_timestamp_ends_with_z(tmp_path: Path) -> None:
    """AC-7.5: the Nautilus timestamp field must serialise with a ``Z`` suffix."""
    sink = FileSink(tmp_path / "audit.jsonl")
    logger = AuditLogger(sink)

    ts = datetime(2026, 4, 14, 12, 34, 56, 789012, tzinfo=UTC)
    logger.emit(_make_entry(ts))

    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    outer = json.loads(line)
    # Outer AuditRecord timestamp is also Z-suffixed for consistency.
    assert outer["timestamp"].endswith("Z"), (
        f"outer timestamp must end with 'Z', got {outer['timestamp']!r}"
    )
    entry_json = outer["metadata"][NAUTILUS_METADATA_KEY]
    entry_dict = json.loads(entry_json)
    assert entry_dict["timestamp"].endswith("Z"), (
        f"inner timestamp must end with 'Z', got {entry_dict['timestamp']!r}"
    )
    # No leftover numeric offset.
    assert "+00:00" not in entry_dict["timestamp"]


@pytest.mark.unit
def test_audit_logger_roundtrips_through_model_validate_json(
    tmp_path: Path,
) -> None:
    """Done-when: written JSONL line re-parses via ``AuditEntry.model_validate_json``."""
    sink = FileSink(tmp_path / "audit.jsonl")
    logger = AuditLogger(sink)

    ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
    original = _make_entry(ts)
    logger.emit(original)

    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    outer = json.loads(line)
    entry_json: str = outer["metadata"][NAUTILUS_METADATA_KEY]

    # Must parse cleanly (Pydantic accepts ISO8601 with Z as UTC).
    parsed = AuditEntry.model_validate_json(entry_json)
    assert parsed.request_id == original.request_id
    assert parsed.agent_id == original.agent_id
    assert parsed.rule_trace == original.rule_trace
    assert parsed.sources_queried == original.sources_queried
    # Round-tripped timestamp equals the original (UTC-normalised).
    assert parsed.timestamp == ts

    # decode_nautilus_entry helper must also round-trip.
    from fathom.models import AuditRecord

    rec = AuditRecord.model_validate(outer)
    decoded = decode_nautilus_entry(rec)
    assert decoded.request_id == original.request_id


@pytest.mark.unit
def test_audit_logger_normalises_non_utc_timestamp_to_z(tmp_path: Path) -> None:
    """A non-UTC timestamp must still serialise with a ``Z`` suffix (AC-7.5)."""
    sink = FileSink(tmp_path / "audit.jsonl")
    logger = AuditLogger(sink)

    # 10:00 in +02:00 == 08:00 UTC
    from datetime import timedelta

    tz = timezone(timedelta(hours=2))
    ts = datetime(2026, 4, 14, 10, 0, 0, tzinfo=tz)
    logger.emit(_make_entry(ts))

    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    outer = json.loads(line)
    entry_dict = json.loads(outer["metadata"][NAUTILUS_METADATA_KEY])
    assert entry_dict["timestamp"].endswith("Z")
    assert entry_dict["timestamp"].startswith("2026-04-14T08:00:00")


@pytest.mark.unit
def test_audit_logger_flushes_sink_when_flush_available() -> None:
    """NFR-8: the logger must call ``flush()`` on sinks that expose it."""

    class RecordingSink:
        def __init__(self) -> None:
            self.records: list[object] = []
            self.flush_calls: int = 0

        def write(self, record: object) -> None:
            self.records.append(record)

        def flush(self) -> None:
            self.flush_calls += 1

    sink = RecordingSink()
    logger = AuditLogger(sink)  # type: ignore[arg-type]

    logger.emit(_make_entry(AuditLogger.utcnow()))
    logger.emit(_make_entry(AuditLogger.utcnow()))

    assert len(sink.records) == 2
    assert sink.flush_calls == 2, f"expected one flush per emit, got {sink.flush_calls}"


@pytest.mark.unit
def test_audit_logger_multiple_writes_append_lines(tmp_path: Path) -> None:
    """Each ``emit`` appends exactly one newline-terminated line."""
    sink = FileSink(tmp_path / "audit.jsonl")
    logger = AuditLogger(sink)

    logger.emit(_make_entry(AuditLogger.utcnow()))
    logger.emit(_make_entry(AuditLogger.utcnow()))
    logger.emit(_make_entry(AuditLogger.utcnow()))

    raw = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert len(lines) == 3
    for line in lines:
        outer = json.loads(line)
        AuditEntry.model_validate_json(outer["metadata"][NAUTILUS_METADATA_KEY])


# ---------------------------------------------------------------------------
# Task 3.10 — Done-when cases (a)–(e)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_audit_entry_schema_shape_matches_ac_7_2() -> None:
    """AC-7.2: ``AuditEntry`` must carry the documented field set (shape).

    The requirement pins a minimum field list. We assert each of those
    fields is declared on the Pydantic model so a future accidental
    rename / removal fails loudly here rather than in an integration run.
    """
    required_fields = {
        "timestamp",
        "request_id",
        "agent_id",
        "session_id",
        "raw_intent",
        "intent_analysis",
        "facts_asserted_summary",
        "routing_decisions",
        "scope_constraints",
        "denial_records",
        "rule_trace",
        "sources_queried",
        "sources_denied",
        "sources_skipped",
        "attestation_token",
        "duration_ms",
    }
    declared = set(AuditEntry.model_fields.keys())
    missing = required_fields - declared
    assert not missing, f"AuditEntry missing AC-7.2 fields: {sorted(missing)}"

    # A concrete instance must serialise with every required key present
    # and of the expected kind (so an accidental ``exclude`` default would
    # also be caught).
    entry = _make_entry(datetime(2026, 4, 14, tzinfo=UTC))
    dumped = json.loads(entry.model_dump_json())
    for field in required_fields:
        assert field in dumped, f"AC-7.2 field {field!r} absent from JSON dump"


@pytest.mark.unit
def test_audit_logger_append_only_first_line_byte_identical(tmp_path: Path) -> None:
    """AC-7.3: after a second ``emit``, the first line's bytes must not change.

    Reads the file after the first write, snapshots the first line, writes
    a second entry, then re-reads and confirms the first line is byte-for-byte
    identical (no in-place rewrite, no re-ordering, no truncation).
    """
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path)
    logger = AuditLogger(sink)

    ts1 = datetime(2026, 4, 14, 10, 0, 0, tzinfo=UTC)
    ts2 = datetime(2026, 4, 14, 10, 0, 1, tzinfo=UTC)

    logger.emit(_make_entry(ts1))
    raw_after_first = path.read_bytes()
    assert raw_after_first.count(b"\n") == 1, (
        f"expected 1 newline after first write, got {raw_after_first.count(b'\n')}"
    )
    first_line_snapshot = raw_after_first  # whole file == first line

    logger.emit(_make_entry(ts2))
    raw_after_second = path.read_bytes()
    assert raw_after_second.count(b"\n") == 2, (
        f"expected 2 newlines after second write, got {raw_after_second.count(b'\n')}"
    )
    # The first ``len(first_line_snapshot)`` bytes must be identical — the
    # new entry only appends, never mutates existing content (AC-7.3).
    assert raw_after_second.startswith(first_line_snapshot), (
        "first audit line changed after second write — append-only violated"
    )


@pytest.mark.unit
def test_audit_logger_round_trip_on_every_line(tmp_path: Path) -> None:
    """AC-7.5: every JSONL line must round-trip via ``AuditEntry.model_validate_json``."""
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path)
    logger = AuditLogger(sink)

    timestamps = [datetime(2026, 4, 14, 9, 0, i, tzinfo=UTC) for i in range(5)]
    originals = [_make_entry(ts) for ts in timestamps]
    for entry in originals:
        logger.emit(entry)

    raw = path.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert len(lines) == len(originals), f"expected {len(originals)} lines, got {len(lines)}"

    for idx, line in enumerate(lines):
        outer = json.loads(line)
        entry_json = outer["metadata"][NAUTILUS_METADATA_KEY]
        parsed = AuditEntry.model_validate_json(entry_json)
        # Timestamps must survive the JSON round-trip exactly (UTC-normalised).
        assert parsed.timestamp == timestamps[idx]
        assert parsed.request_id == originals[idx].request_id


@pytest.mark.unit
def test_audit_logger_written_on_full_denial(tmp_path: Path) -> None:
    """AC-7.4: a record must be emitted even when every source is denied.

    Builds an ``AuditEntry`` whose ``sources_queried`` is empty and
    ``sources_denied`` / ``denial_records`` carry the refusal rationale,
    then asserts the logger (a) writes exactly one JSONL line, (b) tags
    the Fathom ``AuditRecord.decision`` as ``"deny"``, and (c) the
    round-tripped Nautilus entry preserves the denial records.
    """
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path)
    logger = AuditLogger(sink)

    ts = datetime(2026, 4, 14, 11, 0, 0, tzinfo=UTC)
    entry = AuditEntry(
        timestamp=ts,
        request_id="req-denied",
        agent_id="agent-42",
        session_id=None,
        raw_intent="read confidential customer PII",
        intent_analysis=IntentAnalysis(
            raw_intent="read confidential customer PII",
            data_types_needed=["customer_pii"],
            entities=["customer"],
        ),
        facts_asserted_summary={"deny": 2},
        routing_decisions=[
            RoutingDecision(source_id="pg", reason="policy:deny"),
            RoutingDecision(source_id="vec", reason="policy:deny"),
        ],
        scope_constraints=[],
        denial_records=[
            DenialRecord(
                source_id="pg",
                reason="intent not allowlisted",
                rule_name="routing/no-pii",
            ),
            DenialRecord(
                source_id="vec",
                reason="intent not allowlisted",
                rule_name="routing/no-pii",
            ),
        ],
        error_records=[],
        rule_trace=["rule:routing/no-pii"],
        sources_queried=[],
        sources_denied=["pg", "vec"],
        sources_skipped=[],
        sources_errored=[],
        attestation_token=None,
        duration_ms=3,
    )

    logger.emit(entry)

    raw = path.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected 1 audit line on full denial, got {len(lines)}"

    outer = json.loads(lines[0])
    # AC-7.4: the sink received a record even though no source was queried.
    assert outer["decision"] == "deny", (
        f"decision summary must be 'deny' when only denials present, got {outer['decision']!r}"
    )
    parsed = AuditEntry.model_validate_json(outer["metadata"][NAUTILUS_METADATA_KEY])
    assert parsed.sources_queried == []
    assert parsed.sources_denied == ["pg", "vec"]
    assert [d.rule_name for d in parsed.denial_records] == [
        "routing/no-pii",
        "routing/no-pii",
    ]


@pytest.mark.unit
def test_audit_logger_written_on_adapter_exception(tmp_path: Path) -> None:
    """AC-7.4: a record must be emitted even when every queried adapter errors.

    Builds an ``AuditEntry`` where a source was queried but errored out
    (``error_records`` populated, ``sources_errored`` non-empty, no successful
    rows). Asserts the logger writes the line, that the Fathom decision
    summary is ``"error"``, and the error detail round-trips.
    """
    path = tmp_path / "audit.jsonl"
    sink = FileSink(path)
    logger = AuditLogger(sink)

    ts = datetime(2026, 4, 14, 11, 5, 0, tzinfo=UTC)
    err = ErrorRecord(
        source_id="pg",
        error_type="AdapterError",
        message="connection refused",
        trace_id="req-err",
    )
    entry = AuditEntry(
        timestamp=ts,
        request_id="req-err",
        agent_id="agent-42",
        session_id=None,
        raw_intent="list customers",
        intent_analysis=IntentAnalysis(
            raw_intent="list customers",
            data_types_needed=["customer"],
            entities=["customer"],
        ),
        facts_asserted_summary={"source": 1},
        routing_decisions=[RoutingDecision(source_id="pg", reason="allow")],
        scope_constraints=[
            ScopeConstraint(
                source_id="pg",
                field="tenant_id",
                operator="=",
                value="t-1",
            )
        ],
        denial_records=[],
        error_records=[err],
        rule_trace=["rule:routing/allow-basic"],
        sources_queried=[],  # adapter errored before returning rows
        sources_denied=[],
        sources_skipped=[],
        sources_errored=["pg"],
        attestation_token=None,
        duration_ms=7,
    )

    logger.emit(entry)

    raw = path.read_text(encoding="utf-8")
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected 1 audit line on adapter exception, got {len(lines)}"

    outer = json.loads(lines[0])
    assert outer["decision"] == "error", (
        f"decision must be 'error' when only errors present, got {outer['decision']!r}"
    )
    parsed = AuditEntry.model_validate_json(outer["metadata"][NAUTILUS_METADATA_KEY])
    assert parsed.sources_errored == ["pg"]
    assert len(parsed.error_records) == 1
    assert parsed.error_records[0].error_type == "AdapterError"
    assert parsed.error_records[0].message == "connection refused"
    # Scope constraints survive the round-trip even under error paths.
    assert [(sc.source_id, sc.field, sc.operator) for sc in parsed.scope_constraints] == [
        ("pg", "tenant_id", "=")
    ]
