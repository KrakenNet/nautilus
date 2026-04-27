"""Unit coverage for :mod:`nautilus.ingest.baseline` (Task 27, US-4).

Pins the Phase-5 :class:`BaselineTracker` + :class:`IngestBaselineStore`
surface consumed by the ingest orchestrator (Task 30):

(a) First call for a source emits no anomalies (baseline seeding only).
(b) When a seeded baseline puts ``|z| > anomaly_sigma``, the observed sample
    is flagged with the full anomaly record (``baseline_type``, ``observed``,
    ``mean``, ``stddev``, ``z_score``, ``window_start``, ``window_end``).
(c) Rolling-window trim — samples older than ``baseline_window`` do NOT
    contribute to the mean/stddev of the current check.
(d) ``_z_score(observed, mean, stddev)`` math: returns ``(observed - mean)
    / stddev``; ``stddev == 0`` returns ``0.0`` (fail-safe — don't divide
    by zero, don't flag).
(e) ``_parse_window`` accepts ``"7d"`` / ``"24h"`` / ``"30m"`` and raises
    ``ValueError`` on garbage input.
(f) The ``nautilus.ingest.anomaly.total`` counter fires exactly once per
    anomaly (monkeypatched to avoid OTel global state).
(g) ``on_failure="fail_closed"`` + simulated ``create_pool`` failure raises
    :class:`IngestBaselineStoreUnavailableError` with ``__cause__`` preserved.
(h) ``on_failure="fallback_memory"`` degrades silently, logs WARNING, and
    routes subsequent writes/reads through the in-memory dict.
"""

from __future__ import annotations

import logging
import sys
import types
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.ingest.baseline import (
    BaselineSnapshot,
    BaselineTracker,
    IngestBaselineStore,
    IngestBaselineStoreUnavailableError,
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
    pool.execute = AsyncMock(return_value=None)
    pool._conn = conn  # type: ignore[attr-defined]
    return pool


def _memory_store() -> IngestBaselineStore:
    """Build a fallback-memory store so tests don't need a real pool."""
    # ``setup()`` is skipped — degrade manually by seeding the memory backend.
    store = IngestBaselineStore("postgres://u:p@h/db", on_failure="fallback_memory")
    store._memory_backend = {}  # pyright: ignore[reportPrivateUsage]
    store._mode = "degraded_memory"  # pyright: ignore[reportPrivateUsage]
    store._degraded_since = datetime.now(UTC)  # pyright: ignore[reportPrivateUsage]
    return store


# ---------------------------------------------------------------------------
# (a) first call — no anomaly, baseline seeded
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_update_and_check_returns_empty_on_first_call() -> None:
    """No prior baseline → ``update_and_check`` seeds stats but flags nothing."""
    store = _memory_store()
    tracker = BaselineTracker(store, baseline_window="7d", anomaly_sigma=3.0)

    anomalies = await tracker.update_and_check("adapter.a", [{"id": 1}, {"id": 2}, {"id": 3}])

    assert anomalies == []


# ---------------------------------------------------------------------------
# (b) seeded baseline → z > sigma → anomaly flagged
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_update_and_check_flags_anomaly_when_z_exceeds_sigma() -> None:
    """Seed ``(mean=100, stddev=10)``; observe ``row_count=200`` → ``|z|=10`` > 3.0."""
    store = _memory_store()
    tracker = BaselineTracker(store, baseline_window="7d", anomaly_sigma=3.0)

    # Seed a stable baseline by feeding many samples with ~constant row_count.
    # We inject the snapshot directly so the math is deterministic.
    now = datetime.now(UTC)
    snapshot = BaselineSnapshot(
        source_id="adapter.a",
        baseline_type="row_count",
        window_start=now - timedelta(days=7),
        window_end=now,
        mean=100.0,
        stddev=10.0,
        sample_size=100,
        computed_at=now,
    )
    await store.upsert(snapshot)

    # Observe a big spike: 200 rows → z = (200 - 100) / 10 = 10 >> 3.
    rows = [{"id": i} for i in range(200)]
    anomalies = await tracker.update_and_check("adapter.a", rows)

    assert len(anomalies) >= 1
    row_count_anom = next(a for a in anomalies if a["baseline_type"] == "row_count")
    assert row_count_anom["observed"] == 200
    assert row_count_anom["mean"] == 100.0
    assert row_count_anom["stddev"] == 10.0
    assert row_count_anom["z_score"] == pytest.approx(10.0)
    assert row_count_anom["window_start"] <= row_count_anom["window_end"]


# ---------------------------------------------------------------------------
# (c) rolling-window trim — old samples don't contribute
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_rolling_window_trims_out_of_window_samples() -> None:
    """Samples older than ``baseline_window`` are excluded from the stats."""
    store = _memory_store()
    tracker = BaselineTracker(store, baseline_window="1h", anomaly_sigma=3.0)

    now = datetime.now(UTC)
    # Simulate two samples — one inside the window, one outside.
    tracker._record_sample(  # pyright: ignore[reportPrivateUsage]
        "adapter.a", "row_count", 999.0, now - timedelta(hours=2)
    )
    tracker._record_sample(  # pyright: ignore[reportPrivateUsage]
        "adapter.a", "row_count", 10.0, now
    )

    mean, stddev, n = tracker._aggregate(  # pyright: ignore[reportPrivateUsage]
        "adapter.a", "row_count", now
    )

    # The 999.0 sample is outside the 1h window and must not skew the mean.
    assert n == 1
    assert mean == 10.0
    assert stddev == 0.0


# ---------------------------------------------------------------------------
# (d) z-score math — divide-by-zero safe
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_z_score_math() -> None:
    """Direct ``_z_score`` call: ``(observed - mean) / stddev``; stddev=0 → 0."""
    from nautilus.ingest.baseline import _z_score

    assert _z_score(200.0, 100.0, 10.0) == pytest.approx(10.0)
    assert _z_score(50.0, 100.0, 25.0) == pytest.approx(-2.0)
    # stddev == 0 → no anomaly possible; return 0.0 rather than raising.
    assert _z_score(42.0, 42.0, 0.0) == 0.0
    assert _z_score(999.0, 0.0, 0.0) == 0.0


# ---------------------------------------------------------------------------
# (e) _parse_window — 7d / 24h / 30m + ValueError on garbage
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_window_parse() -> None:
    """``_parse_window`` handles d/h/m suffixes; rejects garbage."""
    from nautilus.ingest.baseline import _parse_window

    assert _parse_window("7d") == timedelta(days=7)
    assert _parse_window("24h") == timedelta(hours=24)
    assert _parse_window("30m") == timedelta(minutes=30)
    assert _parse_window("1d") == timedelta(days=1)

    for bad in ("", "bad", "7", "d7", "7x", "1.5d", "-7d"):
        with pytest.raises(ValueError):
            _parse_window(bad)


# ---------------------------------------------------------------------------
# (f) counter emitted once per anomaly
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_anomaly_counter_emitted(monkeypatch: pytest.MonkeyPatch) -> None:
    """``nautilus.ingest.anomaly.total`` fires once per anomaly flagged."""
    store = _memory_store()
    tracker = BaselineTracker(store, baseline_window="7d", anomaly_sigma=3.0)

    # Seed a baseline that will flag the next observation.
    now = datetime.now(UTC)
    await store.upsert(
        BaselineSnapshot(
            source_id="adapter.a",
            baseline_type="row_count",
            window_start=now - timedelta(days=7),
            window_end=now,
            mean=10.0,
            stddev=1.0,
            sample_size=50,
            computed_at=now,
        )
    )

    calls: list[tuple[int, dict[str, Any] | None]] = []

    def _spy_add(amount: float = 1, attributes: dict[str, Any] | None = None) -> None:
        calls.append((int(amount), attributes))

    # Patch the module-level counter's ``.add`` hook.
    from nautilus.ingest import baseline as baseline_mod

    monkeypatch.setattr(baseline_mod._ANOMALY_COUNTER, "add", _spy_add)  # pyright: ignore[reportPrivateUsage]

    rows = [{"id": i} for i in range(100)]  # z=(100-10)/1=90 → anomaly
    anomalies = await tracker.update_and_check("adapter.a", rows)

    assert len(anomalies) == len(calls) >= 1
    # Attributes include source_id + baseline_type (per design line 1046).
    for _amount, attrs in calls:
        assert attrs is not None
        assert attrs.get("source_id") == "adapter.a"
        assert "baseline_type" in attrs


# ---------------------------------------------------------------------------
# (g) fail_closed — IngestBaselineStoreUnavailableError with __cause__
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fail_closed_raises_unavailable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect failure under ``fail_closed`` surfaces the subclass sentinel."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = IngestBaselineStore("postgres://user:pw@h/db", on_failure="fail_closed")
    with pytest.raises(IngestBaselineStoreUnavailableError) as excinfo:
        await store.setup()

    assert excinfo.value.__cause__ is boom
    assert "user:pw" not in str(excinfo.value)
    assert "nautilus_ingest_baseline" in str(excinfo.value)
    assert store.mode == "primary"
    assert store.pool is None


# ---------------------------------------------------------------------------
# (h) fallback_memory — degrades silently, memory round-trip
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fallback_memory_degrades_silently(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``fallback_memory`` degrades silently + logs WARNING; writes land in memory."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = IngestBaselineStore("postgres://u:p@h/db", on_failure="fallback_memory")
    with caplog.at_level(logging.WARNING):
        await store.setup()  # must NOT raise

    assert store.mode == "degraded_memory"
    assert isinstance(store.degraded_since, datetime)

    # Memory-round-trip: upsert + get returns the same snapshot.
    now = datetime.now(UTC)
    snap = BaselineSnapshot(
        source_id="adapter.a",
        baseline_type="row_count",
        window_start=now - timedelta(days=1),
        window_end=now,
        mean=42.0,
        stddev=5.0,
        sample_size=10,
        computed_at=now,
    )
    await store.upsert(snap)

    got = await store.get("adapter.a", "row_count")
    assert got is not None
    assert got.mean == 42.0
    assert got.stddev == 5.0
    assert got.sample_size == 10

    # WARNING fired with table-name context.
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings
    assert any("nautilus_ingest_baseline" in r.getMessage() for r in warnings)
