"""Unit coverage for :mod:`nautilus.ingest.quarantine` (Task 29, US-4).

Exercises :class:`QuarantineLogStore` and :class:`QuarantineSink` against a
fully mocked ``asyncpg.Pool`` so the suite stays offline-safe and hermetic.
Integration coverage against a real Postgres is covered by Task 30 / Task 32.

Cases pin the pure-Python branching:

(a) Row round-trips through ``nautilus_quarantine_log`` in primary mode
    (mocked pool ``execute`` called with the INSERT SQL + params).
(b) Degraded-memory mode routes rows to a bounded ``collections.deque``.
(c) ``maxlen`` enforcement drops the oldest row on overflow.
(d) ``recent(source_id, limit)`` returns rows sorted by ``received_at`` DESC
    from both primary and degraded backends.
(e) Each ``record()`` call bumps ``nautilus.ingest.quarantine.total``.
(f) ``fail_closed`` + connect failure surfaces
    :class:`QuarantineLogStoreUnavailableError` with the original on
    ``__cause__``.
(g) ``fallback_memory`` degrades silently and returns the deque.
"""

from __future__ import annotations

import logging
import sys
import types
from collections import deque
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.ingest.quarantine import (
    QuarantineLogStore,
    QuarantineLogStoreUnavailableError,
    QuarantineSink,
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
    pool.execute = AsyncMock(return_value=None)
    pool.fetch = AsyncMock(return_value=[])
    pool.fetchrow = AsyncMock(return_value=None)
    pool._conn = conn  # type: ignore[attr-defined]
    return pool


# ---------------------------------------------------------------------------
# (a) primary-mode INSERT round-trip
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_record_writes_row_primary_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """``QuarantineSink.record`` issues an INSERT via the mocked pool (AC-4.6)."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()
    sink = QuarantineSink(store)

    await sink.record(
        source_id="adapter.nautobot",
        row={"hostname": "switch-1", "oob": "x" * 5},
        reason="schema_violation: required field 'mgmt_ip' missing",
        schema_hash="deadbeef",
    )

    assert pool.execute.await_count == 1
    sql, *params = pool.execute.await_args.args
    assert "INSERT INTO nautilus_quarantine_log" in sql
    # Six positional args: id, source_id, original_payload (jsonb text),
    # violation_reason, schema_hash, received_at (timestamp default now()
    # is handled by the server — we still pass for determinism).
    assert params[0] == "adapter.nautobot" or any(p == "adapter.nautobot" for p in params), (
        f"source_id must appear in params: {params}"
    )
    # JSON payload round-trips as a JSON string (jsonb cast in SQL).
    jsonish = [p for p in params if isinstance(p, str) and p.startswith("{")]
    assert jsonish, f"expected a JSON-string param among {params}"
    assert "switch-1" in jsonish[0]


# ---------------------------------------------------------------------------
# (b) degraded-memory append
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_record_writes_row_memory_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under ``fallback_memory`` the row lands in a bounded deque."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fallback_memory")
    await store.setup()
    assert store.mode == "degraded_memory"

    sink = QuarantineSink(store)
    await sink.record(
        source_id="adapter.nautobot",
        row={"hostname": "switch-1"},
        reason="schema_violation",
        schema_hash="abc123",
    )

    backend: deque[dict[str, Any]] = store._memory_backend  # pyright: ignore[reportPrivateUsage]
    assert isinstance(backend, deque)
    assert len(backend) == 1
    entry: dict[str, Any] = backend[0]
    assert entry["source_id"] == "adapter.nautobot"
    assert entry["original_payload"] == {"hostname": "switch-1"}
    assert entry["violation_reason"] == "schema_violation"
    assert entry["schema_hash"] == "abc123"
    received_at: datetime = entry["received_at"]
    assert isinstance(received_at, datetime)
    assert received_at.tzinfo is not None


# ---------------------------------------------------------------------------
# (c) bounded deque — oldest drops on overflow
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_bounded_deque_drops_oldest_when_at_maxlen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With ``maxlen=3`` the fourth write evicts the first (degraded protection)."""
    monkeypatch.setattr(
        "asyncpg.create_pool",
        AsyncMock(side_effect=ConnectionRefusedError("pg down")),
        raising=False,
    )

    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fallback_memory", memory_maxlen=3)
    await store.setup()
    sink = QuarantineSink(store)

    for i in range(4):
        await sink.record(
            source_id="src",
            row={"n": i},
            reason="r",
            schema_hash="h",
        )

    backend = store._memory_backend  # pyright: ignore[reportPrivateUsage]
    assert len(backend) == 3
    # Oldest (n=0) evicted; order preserved left→right.
    ns = [e["original_payload"]["n"] for e in backend]
    assert ns == [1, 2, 3]


# ---------------------------------------------------------------------------
# (d) recent() returns rows most-recent-first
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_recent_returns_rows_most_recent_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``recent`` returns newest-first both in memory and primary modes."""
    # Memory branch
    monkeypatch.setattr(
        "asyncpg.create_pool",
        AsyncMock(side_effect=ConnectionRefusedError("pg down")),
        raising=False,
    )
    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fallback_memory")
    await store.setup()
    sink = QuarantineSink(store)

    for i in range(3):
        await sink.record(
            source_id="src",
            row={"n": i},
            reason="r",
            schema_hash="h",
        )

    rows = await store.recent("src", limit=10)
    assert [r["original_payload"]["n"] for r in rows] == [2, 1, 0]


@pytest.mark.unit
async def test_recent_reads_primary_sorted_desc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Primary mode issues a SELECT ORDER BY received_at DESC LIMIT $2."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    now = datetime.now(UTC)
    pool.fetch.return_value = [
        {
            "id": "00000000-0000-0000-0000-000000000002",
            "source_id": "src",
            "received_at": now,
            "original_payload": '{"n": 2}',
            "violation_reason": "r",
            "schema_hash": "h",
        },
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "source_id": "src",
            "received_at": now,
            "original_payload": '{"n": 1}',
            "violation_reason": "r",
            "schema_hash": "h",
        },
    ]

    rows = await store.recent("src", limit=10)
    sql, *params = pool.fetch.await_args.args
    assert "nautilus_quarantine_log" in sql
    assert "ORDER BY received_at DESC" in sql
    assert "LIMIT" in sql
    assert params == ["src", 10]
    # original_payload strings get decoded back to dicts for callers.
    assert rows[0]["original_payload"] == {"n": 2}
    assert rows[1]["original_payload"] == {"n": 1}


# ---------------------------------------------------------------------------
# (e) counter emission
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_quarantine_counter_emitted(monkeypatch: pytest.MonkeyPatch) -> None:
    """``nautilus.ingest.quarantine.total`` increments once per record()."""
    monkeypatch.setattr(
        "asyncpg.create_pool",
        AsyncMock(side_effect=ConnectionRefusedError("pg down")),
        raising=False,
    )
    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fallback_memory")
    await store.setup()
    sink = QuarantineSink(store)

    adds: list[tuple[float, dict[str, Any] | None]] = []

    def _fake_add(amount: float = 1, attributes: dict[str, Any] | None = None) -> None:
        adds.append((amount, attributes))

    from nautilus.ingest import quarantine as quarantine_mod

    monkeypatch.setattr(
        quarantine_mod._metrics.ingest_quarantine_total,  # pyright: ignore[reportPrivateUsage]
        "add",
        _fake_add,
    )

    await sink.record(source_id="src", row={"a": 1}, reason="r", schema_hash="h")
    await sink.record(source_id="src2", row={"b": 2}, reason="r2", schema_hash="h2")

    assert len(adds) == 2
    # Each invocation tags source_id + reason per design line 1045.
    assert adds[0][1] == {"source_id": "src", "reason": "r"}
    assert adds[1][1] == {"source_id": "src2", "reason": "r2"}


# ---------------------------------------------------------------------------
# (f) fail_closed surfaces QuarantineLogStoreUnavailableError
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fail_closed_raises_unavailable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect failure under ``fail_closed`` raises the subclass sentinel."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = QuarantineLogStore("postgres://user:pw@h/db", on_failure="fail_closed")
    with pytest.raises(QuarantineLogStoreUnavailableError) as excinfo:
        await store.setup()

    assert excinfo.value.__cause__ is boom
    assert "user:pw" not in str(excinfo.value)  # credentials must not leak
    assert "nautilus_quarantine_log" in str(excinfo.value)
    assert store.mode == "primary"
    assert store.pool is None


# ---------------------------------------------------------------------------
# (g) fallback_memory degrades silently
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fallback_memory_degrades_silently(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``fallback_memory`` must not raise; WARNING log fires; backend is bounded deque."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fallback_memory")
    with caplog.at_level(logging.WARNING):
        await store.setup()  # must NOT raise

    assert store.mode == "degraded_memory"
    assert isinstance(store.degraded_since, datetime)
    assert store.degraded_since.tzinfo is not None
    assert store.degraded_since <= datetime.now(UTC)
    backend = store._memory_backend  # pyright: ignore[reportPrivateUsage]
    assert isinstance(backend, deque)
    assert backend.maxlen == 10_000  # default bound per Task 29 design intent

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected WARNING log on degraded fallback"


@pytest.mark.unit
async def test_warn_when_deque_at_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    """At-capacity deque logs a WARNING on each ``record`` (memory-pressure signal)."""
    monkeypatch.setattr(
        "asyncpg.create_pool",
        AsyncMock(side_effect=ConnectionRefusedError("pg down")),
        raising=False,
    )
    store = QuarantineLogStore("postgres://u:p@h/db", on_failure="fallback_memory", memory_maxlen=2)
    await store.setup()
    sink = QuarantineSink(store)

    import logging as _logging

    logger = _logging.getLogger("nautilus.ingest.quarantine")
    records: list[str] = []

    class _Handler(_logging.Handler):
        def emit(self, record: _logging.LogRecord) -> None:
            records.append(record.getMessage())

    handler = _Handler(level=_logging.WARNING)
    logger.addHandler(handler)
    try:
        await sink.record(source_id="s", row={"n": 0}, reason="r", schema_hash="h")
        # One below capacity — no capacity warning yet.
        cap_warnings_before = [r for r in records if "capacity" in r.lower()]
        await sink.record(source_id="s", row={"n": 1}, reason="r", schema_hash="h")
        # At capacity on this write.
        await sink.record(source_id="s", row={"n": 2}, reason="r", schema_hash="h")
        cap_warnings_after = [r for r in records if "capacity" in r.lower()]
    finally:
        logger.removeHandler(handler)

    assert len(cap_warnings_after) > len(cap_warnings_before)
