"""Unit coverage for :mod:`nautilus.core.source_state` (Task 11, US-3).

Exercises :class:`SourceStateStore` against a fully-mocked ``asyncpg.Pool``
so the suite stays offline-safe and hermetic. Integration coverage against a
real Postgres lives in Task 12.

Cases pin the pure-Python branching:

(a) ``load_all`` returns an empty dict on fresh setup; populated after
    ``set_enabled`` (round-trip via the mocked pool).
(b) Double ``set_enabled(enabled=False, ...)`` is idempotent — the second
    call returns a fresh ``SourceState`` with bumped ``changed_at`` and does
    NOT raise (AC-3.6).
(c) ``on_failure="fail_closed"`` + simulated connect failure raises
    :class:`SourceStateStoreUnavailableError` with the original exception
    preserved on ``__cause__``.
(d) ``on_failure="fallback_memory"`` degrades silently, logs WARNING, and
    routes subsequent writes/reads through the in-memory dict.
"""

from __future__ import annotations

import logging
import sys
import types
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.core.source_state import (
    SourceState,
    SourceStateStore,
    SourceStateStoreUnavailableError,
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
    # Store-level helpers (.fetch / .fetchrow) — tests wire their own
    # AsyncMock return values as needed.
    pool.fetch = AsyncMock(return_value=[])
    pool.fetchrow = AsyncMock(return_value=None)
    pool._conn = conn  # type: ignore[attr-defined]
    return pool


# ---------------------------------------------------------------------------
# (a) load_all round-trip: empty then populated after set_enabled
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_load_all_empty_then_populated_after_set_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh store returns ``{}``; after ``set_enabled`` the next load has the row."""
    pool = _mock_pool()
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr("asyncpg.create_pool", create_pool, raising=False)

    store = SourceStateStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    # load_all on empty DB → empty dict.
    pool.fetch.return_value = []
    assert await store.load_all() == {}

    # set_enabled → mock the RETURNING row.
    changed_at = datetime.now(UTC)
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "enabled": False,
        "reason": "maintenance",
        "actor": "op.sean",
        "changed_at": changed_at,
    }
    state = await store.set_enabled(
        "adapter.a", enabled=False, reason="maintenance", actor="op.sean"
    )
    assert isinstance(state, SourceState)
    assert state.enabled is False
    assert state.reason == "maintenance"
    assert state.actor == "op.sean"
    assert state.changed_at == changed_at

    # Subsequent load_all now returns the row keyed by source_id.
    pool.fetch.return_value = [
        {
            "source_id": "adapter.a",
            "enabled": False,
            "reason": "maintenance",
            "actor": "op.sean",
            "changed_at": changed_at,
        }
    ]
    loaded = await store.load_all()
    assert set(loaded.keys()) == {"adapter.a"}
    assert loaded["adapter.a"].enabled is False
    assert loaded["adapter.a"].actor == "op.sean"


# ---------------------------------------------------------------------------
# (b) idempotent double-disable
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_set_enabled_idempotent_double_disable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling ``set_enabled(enabled=False, ...)`` twice is a no-op + fresh ts (AC-3.6)."""
    pool = _mock_pool()
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = SourceStateStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    first_ts = datetime.now(UTC)
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "enabled": False,
        "reason": "maintenance",
        "actor": "op.sean",
        "changed_at": first_ts,
    }
    first = await store.set_enabled(
        "adapter.a", enabled=False, reason="maintenance", actor="op.sean"
    )

    # Second call — returned ``changed_at`` is bumped by the DB's
    # now()-semantics (we simulate by returning a later timestamp).
    second_ts = datetime.now(UTC)
    pool.fetchrow.return_value = {
        "source_id": "adapter.a",
        "enabled": False,
        "reason": "maintenance",
        "actor": "op.sean",
        "changed_at": second_ts,
    }
    second = await store.set_enabled(
        "adapter.a", enabled=False, reason="maintenance", actor="op.sean"
    )

    assert first.enabled is False
    assert second.enabled is False
    assert second.changed_at >= first.changed_at
    # The ON CONFLICT upsert should have been issued twice.
    assert pool.fetchrow.await_count == 2


# ---------------------------------------------------------------------------
# (c) fail_closed — SourceStateStoreUnavailableError with __cause__
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fail_closed_raises_unavailable_with_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect failure under ``fail_closed`` surfaces the subclass sentinel."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = SourceStateStore("postgres://user:pw@h/db", on_failure="fail_closed")
    with pytest.raises(SourceStateStoreUnavailableError) as excinfo:
        await store.setup()

    assert excinfo.value.__cause__ is boom
    # DSN credentials must not leak.
    assert "user:pw" not in str(excinfo.value)
    # Table name present for triage.
    assert "nautilus_source_state" in str(excinfo.value)
    assert store.mode == "primary"
    assert store.pool is None


# ---------------------------------------------------------------------------
# (d) fallback_memory — degrades silently, logs WARNING, memory round-trip
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fallback_memory_degrades_and_warns(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``fallback_memory`` degrades silently + logs WARNING; writes land in memory."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = SourceStateStore("postgres://u:p@h/db", on_failure="fallback_memory")
    with caplog.at_level(logging.WARNING):
        await store.setup()  # must NOT raise

    assert store.mode == "degraded_memory"
    assert isinstance(store.degraded_since, datetime)
    assert store.degraded_since.tzinfo is not None
    assert store.degraded_since <= datetime.now(UTC)
    # Memory backend initialized to empty dict.
    assert store._memory_backend == {}  # pyright: ignore[reportPrivateUsage]

    # WARNING fired — at least one carrying the degrade gauge tag.
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected WARNING log on degraded fallback"
    assert any("nautilus.source_state.store.degraded=1" in r.getMessage() for r in warnings) or any(
        "nautilus_source_state" in r.getMessage() for r in warnings
    )

    # Writes in memory mode land in the dict and are readable via get/load_all.
    state = await store.set_enabled(
        "adapter.a", enabled=False, reason="maintenance", actor="op.sean"
    )
    assert state.source_id == "adapter.a"
    assert state.enabled is False
    assert state.reason == "maintenance"
    assert state.actor == "op.sean"
    assert state.changed_at.tzinfo is not None

    got = await store.get("adapter.a")
    assert got is not None
    assert got.enabled is False

    assert await store.get("missing") is None

    loaded = await store.load_all()
    assert set(loaded.keys()) == {"adapter.a"}
    # load_all returns a copy — mutating it must not poison the store.
    loaded.clear()
    assert "adapter.a" in await store.load_all()
