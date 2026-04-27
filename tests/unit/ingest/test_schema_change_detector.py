"""Unit coverage for :mod:`nautilus.ingest.schema_change` (Task 28, US-4).

Exercises :class:`SchemaChangeDetector` + :class:`SchemaAckStore` against a
fully-mocked ``asyncpg.Pool`` so the suite stays offline-safe and hermetic.

Cases pin the pure-Python branching (AC-4.10, AC-4.12, FR-20):

(a) Hashes match → no-op, no audit emission, no exception.
(b) Hash mismatch + ``mode="pause"`` → ``IngestPausedError`` + audit event.
(c) Hash mismatch + ``mode="warn"`` → WARNING log + audit event, no raise.
(d) No prior ack + ``mode="pause"`` → ``IngestPausedError`` + audit event.
(e) ``set_ack`` is idempotent (round-trip: write twice, ``get_ack`` reflects
    latest acked_hash and ``acked_at`` is bumped).
(f) ``on_failure="fail_closed"`` + connect failure →
    :class:`SchemaAckStoreUnavailableError` with ``__cause__``.
(g) ``on_failure="fallback_memory"`` → WARNING log + degrades silently; writes
    land in the in-memory dict and round-trip via ``get_ack``.
"""

from __future__ import annotations

import hashlib
import logging
import sys
import types
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.core.models import AuditEntry
from nautilus.ingest.errors import IngestPausedError

if TYPE_CHECKING:
    from nautilus.audit.logger import AuditLogger
from nautilus.ingest.schema_change import (
    SchemaAck,
    SchemaAckStore,
    SchemaAckStoreUnavailableError,
    SchemaChangeDetector,
)


def _install_asyncpg_stub() -> None:
    """Guarantee ``asyncpg`` is importable so ``monkeypatch.setattr`` works."""
    if "asyncpg" not in sys.modules:
        stub = types.ModuleType("asyncpg")
        stub.create_pool = AsyncMock()  # type: ignore[attr-defined]
        sys.modules["asyncpg"] = stub


_install_asyncpg_stub()


class _AcquireCM:
    """Async context manager yielding a mocked asyncpg connection."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    async def __aenter__(self) -> Any:
        return self._conn

    async def __aexit__(self, *_exc: Any) -> None:
        return None


def _mock_pool() -> MagicMock:
    """Build a mock ``asyncpg.Pool`` with ``acquire``/``execute``/``fetch`` stubs."""
    conn = MagicMock()
    conn.execute = AsyncMock(return_value=None)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=_AcquireCM(conn))
    pool.close = AsyncMock(return_value=None)
    pool.fetch = AsyncMock(return_value=[])
    pool.fetchrow = AsyncMock(return_value=None)
    pool._conn = conn  # type: ignore[attr-defined]
    return pool


class _RecordingAuditLogger:
    """Minimal stand-in for :class:`~nautilus.audit.logger.AuditLogger`."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def emit(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# SchemaAckStore — persistence round-trip
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_set_ack_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    """``set_ack`` twice with same hash → ``get_ack`` returns latest + bumped ``acked_at``."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    current_hash = _sha256("schema-v1")

    first_ts = datetime.now(UTC)
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "acked_hash": current_hash,
        "actor": "op.sean",
        "acked_at": first_ts,
    }
    first = await store.set_ack("adapter.a", acked_hash=current_hash, actor="op.sean")
    assert isinstance(first, SchemaAck)
    assert first.acked_hash == current_hash

    # Second call — DB now()-semantics returns a later timestamp.
    second_ts = datetime.now(UTC)
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "acked_hash": current_hash,
        "actor": "op.sean",
        "acked_at": second_ts,
    }
    second = await store.set_ack("adapter.a", acked_hash=current_hash, actor="op.sean")
    assert second.acked_hash == current_hash
    assert second.acked_at >= first.acked_at
    assert pool.fetchrow.await_count == 2

    # get_ack reflects the row.
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "acked_hash": current_hash,
        "actor": "op.sean",
        "acked_at": second_ts,
    }
    got = await store.get_ack("adapter.a")
    assert got is not None
    assert got.acked_hash == current_hash
    assert got.acked_at == second_ts


@pytest.mark.unit
async def test_get_ack_returns_none_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """``get_ack`` on an unseeded source returns ``None``."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()
    pool.fetchrow.return_value = None

    assert await store.get_ack("adapter.missing") is None


# ---------------------------------------------------------------------------
# SchemaAckStore — failure modes
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fail_closed_raises_unavailable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connect failure under ``fail_closed`` surfaces the subclass sentinel."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = SchemaAckStore("postgres://user:pw@h/db", on_failure="fail_closed")
    with pytest.raises(SchemaAckStoreUnavailableError) as excinfo:
        await store.setup()

    assert excinfo.value.__cause__ is boom
    assert "user:pw" not in str(excinfo.value)
    assert "nautilus_schema_ack" in str(excinfo.value)
    assert store.mode == "primary"
    assert store.pool is None


@pytest.mark.unit
async def test_fallback_memory_degrades_silently(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``fallback_memory`` degrades + logs WARNING; writes round-trip via memory."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fallback_memory")
    with caplog.at_level(logging.WARNING):
        await store.setup()  # must NOT raise

    assert store.mode == "degraded_memory"
    assert isinstance(store.degraded_since, datetime)
    assert store._memory_backend == {}  # pyright: ignore[reportPrivateUsage]

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected WARNING log on degraded fallback"

    current_hash = _sha256("schema-v1")
    state = await store.set_ack("adapter.a", acked_hash=current_hash, actor="op.sean")
    assert state.source_id == "adapter.a"
    assert state.acked_hash == current_hash

    got = await store.get_ack("adapter.a")
    assert got is not None
    assert got.acked_hash == current_hash

    assert await store.get_ack("missing") is None


# ---------------------------------------------------------------------------
# SchemaChangeDetector — hot path + branching
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_check_noop_when_hashes_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seeded ack == current hash → no exception, no audit emission."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    current_hash = _sha256("schema-v1")
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "acked_hash": current_hash,
        "actor": "op.sean",
        "acked_at": datetime.now(UTC),
    }

    audit = _RecordingAuditLogger()
    detector = SchemaChangeDetector(ack_store=store, audit_logger=cast("AuditLogger", audit))
    # No raise, no audit.
    await detector.check("adapter.a", current_schema_hash=current_hash, mode="pause")
    assert audit.entries == []


@pytest.mark.unit
async def test_check_raises_paused_on_mismatch_pause_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mismatched hash + ``mode="pause"`` → ``IngestPausedError`` + audit event."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    acked_hash = _sha256("schema-v1")
    current_hash = _sha256("schema-v2")
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "acked_hash": acked_hash,
        "actor": "op.sean",
        "acked_at": datetime.now(UTC),
    }

    audit = _RecordingAuditLogger()
    detector = SchemaChangeDetector(ack_store=store, audit_logger=cast("AuditLogger", audit))
    with pytest.raises(IngestPausedError) as excinfo:
        await detector.check("adapter.a", current_schema_hash=current_hash, mode="pause")

    # Error message mentions both hashes (truncated OK).
    assert current_hash[:12] in str(excinfo.value)
    assert acked_hash[:12] in str(excinfo.value)

    # Audit entry emitted with schema_change_detected event_type.
    assert len(audit.entries) == 1
    assert audit.entries[0].event_type == "schema_change_detected"
    assert "adapter.a" in audit.entries[0].sources_queried


@pytest.mark.unit
async def test_check_warns_on_mismatch_warn_mode(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Mismatched hash + ``mode="warn"`` → WARNING log + audit event, no exception."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    acked_hash = _sha256("schema-v1")
    current_hash = _sha256("schema-v2")
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "acked_hash": acked_hash,
        "actor": "op.sean",
        "acked_at": datetime.now(UTC),
    }

    audit = _RecordingAuditLogger()
    detector = SchemaChangeDetector(ack_store=store, audit_logger=cast("AuditLogger", audit))

    with caplog.at_level(logging.WARNING):
        await detector.check("adapter.a", current_schema_hash=current_hash, mode="warn")

    # Warning fired.
    assert any(r.levelno == logging.WARNING for r in caplog.records)
    # Audit emitted.
    assert len(audit.entries) == 1
    assert audit.entries[0].event_type == "schema_change_detected"


@pytest.mark.unit
async def test_check_raises_on_no_prior_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    """No seeded ack + ``mode="pause"`` → ``IngestPausedError`` + audit event."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    current_hash = _sha256("schema-v1")
    pool.fetchrow.return_value = None  # no ack row

    audit = _RecordingAuditLogger()
    detector = SchemaChangeDetector(ack_store=store, audit_logger=cast("AuditLogger", audit))
    with pytest.raises(IngestPausedError) as excinfo:
        await detector.check("adapter.a", current_schema_hash=current_hash, mode="pause")

    # acked side reads as "none".
    assert "none" in str(excinfo.value)
    assert len(audit.entries) == 1
    assert audit.entries[0].event_type == "schema_change_detected"


@pytest.mark.unit
async def test_check_without_audit_logger_still_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Detector without an audit logger wired still applies the mode policy."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SchemaAckStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    current_hash = _sha256("schema-v2")
    pool.fetchrow.return_value = None

    detector = SchemaChangeDetector(ack_store=store)
    with pytest.raises(IngestPausedError):
        await detector.check("adapter.a", current_schema_hash=current_hash, mode="pause")
