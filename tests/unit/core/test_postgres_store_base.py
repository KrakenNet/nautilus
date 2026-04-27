"""Unit coverage for :mod:`nautilus.core.postgres_store` (Task 2, TD-11).

Exercises :class:`BasePostgresStore` via a minimal ``_FakeStore`` subclass
against a fully-mocked ``asyncpg.Pool`` so the suite stays offline-safe.

Cases pin the hoisted pure-Python branching:

(a) ``setup()`` idempotent DDL — subclass's ``_DDL`` runs once per setup and
    the second ``setup()`` is a no-op (does not re-create the pool).
(b) ``fail_closed``: simulated ``create_pool`` failure raises the subclass's
    ``_unavailable_error()`` with the original exception as ``__cause__``.
(c) ``fallback_memory``: same failure degrades silently — ``mode ==
    "degraded_memory"``, ``degraded_since`` is a tz-aware UTC timestamp, and a
    WARNING-level log is emitted.
(d) Concurrent ``setup()``: ``asyncio.gather(store.setup(), store.setup())``
    runs ``create_pool`` exactly once.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import types
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.core.postgres_store import BasePostgresStore


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
    """Build a mock ``asyncpg.Pool`` with ``acquire`` + ``execute`` stubs."""
    conn = MagicMock()
    conn.execute = AsyncMock(return_value=None)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=_AcquireCM(conn))
    pool.close = AsyncMock(return_value=None)
    pool._conn = conn  # type: ignore[attr-defined]  # exposed for assertions
    return pool


class _FakeUnavailableError(RuntimeError):
    """Subclass-specific unavailable sentinel raised under ``fail_closed``."""


class _FakeStore(BasePostgresStore):
    """Minimal concrete subclass used to drive the base's branching."""

    _DDL = "CREATE TABLE IF NOT EXISTS nautilus_fake (id TEXT PRIMARY KEY)"
    _TABLE = "nautilus_fake"

    def _init_memory_backend(self) -> dict[str, Any]:
        return {}

    def _unavailable_error(self) -> type[Exception]:
        return _FakeUnavailableError


# ---------------------------------------------------------------------------
# (a) setup() — DDL runs, second call is a no-op
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_setup_runs_ddl_and_second_call_is_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two ``setup()`` calls: first runs DDL on the pool, second is a no-op."""
    pool = _mock_pool()
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr("asyncpg.create_pool", create_pool, raising=False)

    store = _FakeStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()
    await store.setup()

    # Second setup() must NOT create a new pool or re-run DDL.
    assert create_pool.await_count == 1
    ddl_calls = [c.args[0] for c in pool._conn.execute.await_args_list]
    assert ddl_calls == [_FakeStore._DDL]  # pyright: ignore[reportPrivateUsage]
    assert store.mode == "primary"
    assert store.pool is pool


# ---------------------------------------------------------------------------
# (b) fail_closed — raises subclass's _unavailable_error with __cause__
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fail_closed_raises_unavailable_error_with_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Connect failure under ``fail_closed`` surfaces the subclass sentinel."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = _FakeStore("postgres://user:pw@h/db", on_failure="fail_closed")
    with pytest.raises(_FakeUnavailableError) as excinfo:
        await store.setup()

    # Original exception is preserved for operator diagnosis (NFR-DEGRAD).
    assert excinfo.value.__cause__ is boom
    # DSN credentials must not leak into the error message.
    assert "user:pw" not in str(excinfo.value)
    # Table name appears in the error message for triage.
    assert _FakeStore._TABLE in str(excinfo.value)  # pyright: ignore[reportPrivateUsage]
    # Mode remains "primary" — fail_closed never degrades.
    assert store.mode == "primary"
    assert store.pool is None


# ---------------------------------------------------------------------------
# (c) fallback_memory — degrades silently, logs WARNING
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fallback_memory_degrades_and_warns(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Connect failure under ``fallback_memory`` degrades + logs WARNING."""
    boom = ConnectionRefusedError("pg down")
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(side_effect=boom), raising=False)

    store = _FakeStore("postgres://u:p@h/db", on_failure="fallback_memory")
    with caplog.at_level(logging.WARNING, logger="nautilus.core.postgres_store"):
        await store.setup()  # must NOT raise

    assert store.mode == "degraded_memory"
    assert isinstance(store.degraded_since, datetime)
    assert store.degraded_since.tzinfo is not None
    assert store.degraded_since <= datetime.now(UTC)
    # Memory backend initialized via the subclass hook.
    assert store._memory_backend == {}  # pyright: ignore[reportPrivateUsage]
    # WARNING log fired with identifying context.
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "expected a WARNING log on degraded fallback"
    assert any(_FakeStore._TABLE in r.getMessage() for r in warnings)  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# (d) concurrent setup() — create_pool runs exactly once
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_concurrent_setup_creates_pool_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``asyncio.gather(setup(), setup(), setup())`` initializes exactly once.

    The setup lock in :class:`BasePostgresStore` serializes concurrent entry;
    the first task creates the pool + runs DDL, later tasks observe the
    populated pool under the lock and return immediately (FR-34).
    """
    pool = _mock_pool()
    call_count = {"n": 0}

    async def _slow_create_pool(*_args: Any, **_kwargs: Any) -> MagicMock:
        call_count["n"] += 1
        # Yield the event loop so any concurrent setup() task is actively
        # waiting on the lock when we finish — proving the lock (not timing
        # luck) is what prevents a second create_pool call.
        await asyncio.sleep(0)
        return pool

    monkeypatch.setattr("asyncpg.create_pool", _slow_create_pool, raising=False)

    store = _FakeStore("postgres://u:p@h/db", on_failure="fail_closed")
    await asyncio.gather(store.setup(), store.setup(), store.setup())

    assert call_count["n"] == 1
    # DDL runs exactly once.
    assert pool._conn.execute.await_count == 1
    assert store.mode == "primary"
    assert store.pool is pool
