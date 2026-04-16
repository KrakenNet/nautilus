"""Unit coverage for :mod:`nautilus.core.session_pg` (Task 3.3).

Exercises :class:`PostgresSessionStore` against a fully-mocked
``asyncpg.Pool`` so the suite stays offline-safe and hermetic. Phase-2
testcontainer coverage lives in the integration tree; these cases pin
the pure-Python branching:

(a) ``setup()`` idempotent DDL — can be run twice without error.
(b) ``aget`` / ``aupdate`` happy-path round-trip.
(c) ``CannotConnectNowError`` + ``on_failure="fail_closed"`` raises
    :class:`SessionStoreUnavailableError` (NFR-7 safe default, D-1).
(d) Same failure + ``on_failure="fallback_memory"`` flips ``mode`` to
    ``"degraded_memory"`` without raising.
(e) Broker audit field propagation — when the wired store reports
    ``mode == "degraded_memory"`` the synthesized :class:`AuditEntry`
    carries ``session_store_mode="degraded_memory"`` (NFR-7, §3.2).
"""

from __future__ import annotations

import sys
import types
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.core.broker import (
    _build_audit_entry,  # pyright: ignore[reportPrivateUsage]
    _RequestState,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.core.models import IntentAnalysis
from nautilus.core.session_pg import (
    PostgresSessionStore,
    SessionStoreUnavailableError,
)


# Ensure ``asyncpg`` + ``asyncpg.exceptions`` can be patched regardless of
# whether the running environment has asyncpg installed. We do NOT want to
# actually connect — every test below patches ``asyncpg.create_pool`` with a
# ``MagicMock``/``AsyncMock`` so the real driver is never imported at runtime.
def _install_asyncpg_stubs() -> None:
    """Guarantee ``asyncpg`` + ``asyncpg.exceptions`` are importable."""
    if "asyncpg" not in sys.modules:
        stub = types.ModuleType("asyncpg")
        stub.create_pool = AsyncMock()  # type: ignore[attr-defined]
        sys.modules["asyncpg"] = stub
    if "asyncpg.exceptions" not in sys.modules:
        exc_mod = types.ModuleType("asyncpg.exceptions")

        class CannotConnectNowError(Exception):
            """Stub mirror of asyncpg's CannotConnectNowError."""

        class ConnectionDoesNotExistError(Exception):
            """Stub mirror of asyncpg's ConnectionDoesNotExistError."""

        class UndefinedTableError(Exception):
            """Stub mirror of asyncpg's UndefinedTableError."""

        exc_mod.CannotConnectNowError = CannotConnectNowError  # type: ignore[attr-defined]
        exc_mod.ConnectionDoesNotExistError = ConnectionDoesNotExistError  # type: ignore[attr-defined]
        exc_mod.UndefinedTableError = UndefinedTableError  # type: ignore[attr-defined]
        sys.modules["asyncpg.exceptions"] = exc_mod


_install_asyncpg_stubs()


class _AcquireCM:
    """Async context manager that yields a mocked asyncpg connection."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    async def __aenter__(self) -> Any:
        return self._conn

    async def __aexit__(self, *_exc: Any) -> None:
        return None


class _TxnCM:
    """No-op async transaction context manager for mocked connections."""

    async def __aenter__(self) -> _TxnCM:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None


def _mock_pool(*, rows: dict[str, dict[str, Any]] | None = None) -> MagicMock:
    """Build a mock ``asyncpg.Pool`` with ``acquire`` / ``fetchrow`` stubs.

    ``rows`` seeds the ``fetchrow`` response mapping (session_id -> row dict).
    """
    store: dict[str, dict[str, Any]] = dict(rows or {})
    conn = MagicMock()
    conn.execute = AsyncMock(return_value=None)

    async def _fetchrow(sql: str, session_id: str) -> dict[str, Any] | None:
        del sql  # unused — we only key on session_id
        if session_id in store:
            return {"state": store[session_id]}
        return None

    conn.fetchrow = AsyncMock(side_effect=_fetchrow)
    conn.transaction = MagicMock(return_value=_TxnCM())

    async def _pool_fetchrow(sql: str, session_id: str) -> dict[str, Any] | None:
        return await _fetchrow(sql, session_id)

    pool = MagicMock()
    pool.acquire = MagicMock(return_value=_AcquireCM(conn))
    pool.execute = AsyncMock(return_value=None)
    pool.fetchrow = AsyncMock(side_effect=_pool_fetchrow)
    pool.close = AsyncMock(return_value=None)
    # Expose the seeded state + conn so tests can mutate and inspect.
    pool._store = store  # type: ignore[attr-defined]
    pool._conn = conn  # type: ignore[attr-defined]
    return pool


# ---------------------------------------------------------------------------
# (a) setup() idempotent DDL
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_setup_issues_idempotent_ddl_twice_without_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calling ``setup()`` twice executes the same DDL twice, no errors."""
    pool = _mock_pool()
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr("asyncpg.create_pool", create_pool, raising=False)

    store = PostgresSessionStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()
    await store.setup()  # second invocation must not blow up

    # Both setup calls should have created a pool and run the CREATE TABLE DDL.
    assert create_pool.await_count == 2
    # The pool's conn.execute is where DDL is run (via ``acquire`` context).
    ddl_calls = [c.args[0] for c in pool._conn.execute.await_args_list]
    assert len(ddl_calls) == 2
    for sql in ddl_calls:
        assert "CREATE TABLE IF NOT EXISTS nautilus_session_state" in sql


# ---------------------------------------------------------------------------
# (b) aget / aupdate happy-path
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_aget_and_aupdate_happy_path_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """aget returns stored state; aupdate merges new keys via upsert."""
    pool = _mock_pool(rows={"s1": {"foo": "bar"}})
    monkeypatch.setattr("asyncpg.create_pool", AsyncMock(return_value=pool), raising=False)

    store = PostgresSessionStore("postgres://u:p@h/db", on_failure="fail_closed")
    await store.setup()

    # aget hits the pool-level fetchrow path and returns the decoded state.
    state = await store.aget("s1")
    assert state == {"foo": "bar"}
    # Missing rows return an empty dict (not None).
    assert await store.aget("missing") == {}

    # aupdate merges into the existing row (current + entry) and upserts it.
    await store.aupdate("s1", {"baz": 1})
    # Confirm the INSERT ... ON CONFLICT was executed on the acquired conn.
    upsert_calls = [c for c in pool._conn.execute.await_args_list if "INSERT INTO" in c.args[0]]
    assert len(upsert_calls) == 1
    assert "ON CONFLICT (session_id) DO UPDATE" in upsert_calls[0].args[0]


# ---------------------------------------------------------------------------
# (c) CannotConnectNowError + fail_closed -> SessionStoreUnavailableError
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_cannot_connect_now_fail_closed_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``CannotConnectNowError`` under ``fail_closed`` surfaces the sentinel."""
    from asyncpg.exceptions import CannotConnectNowError  # type: ignore[import-not-found]

    create_pool = AsyncMock(side_effect=CannotConnectNowError("db starting"))
    monkeypatch.setattr("asyncpg.create_pool", create_pool, raising=False)

    store = PostgresSessionStore("postgres://u:p@h/db", on_failure="fail_closed")
    with pytest.raises(SessionStoreUnavailableError) as excinfo:
        await store.setup()
    # Underlying cause is preserved for operator diagnosis (NFR-7).
    assert isinstance(excinfo.value.__cause__, CannotConnectNowError)
    # DSN credentials must not leak into the error message.
    assert "u:p" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# (d) CannotConnectNowError + fallback_memory -> degraded
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_cannot_connect_now_fallback_memory_degrades(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``fallback_memory`` swallows the connect error and flips mode."""
    from asyncpg.exceptions import CannotConnectNowError  # type: ignore[import-not-found]

    create_pool = AsyncMock(side_effect=CannotConnectNowError("db starting"))
    monkeypatch.setattr("asyncpg.create_pool", create_pool, raising=False)

    store = PostgresSessionStore("postgres://u:p@h/db", on_failure="fallback_memory")
    await store.setup()  # must NOT raise

    assert store.mode == "degraded_memory"
    assert store.degraded_since is not None
    # Degraded reads/writes are serviced by the internal InMemorySessionStore.
    await store.aupdate("s1", {"k": "v"})
    assert await store.aget("s1") == {"k": "v"}


# ---------------------------------------------------------------------------
# (e) Broker audit field — degraded mode propagates to AuditEntry
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_degraded_mode_propagates_to_audit_entry() -> None:
    """``AuditEntry.session_store_mode == "degraded_memory"`` when store is degraded.

    Exercises :func:`nautilus.core.broker._build_audit_entry` directly (the
    same helper the hot path funnels through) to confirm the degraded-mode
    flag reaches the on-disk audit line without spinning the full broker.
    """
    state = _RequestState(
        request_id="r-1",
        session_id="s-1",
        started=0.0,
        intent="probe",
        intent_analysis=IntentAnalysis(raw_intent="probe", data_types_needed=[], entities=[]),
    )
    state.rule_trace = []
    state.facts_summary = {}
    # Mimic the broker contract: ``_session_store_mode()`` reads
    # ``self._session_store.mode`` and passes the string through. Here we
    # pass the same value directly into the builder.
    entry = _build_audit_entry(
        agent_id="agent-alpha",
        state=state,
        attestation_token=None,
        session_store_mode="degraded_memory",
    )
    assert entry.session_store_mode == "degraded_memory"
    # ``timestamp`` should still be UTC-aware (sanity pin).
    assert entry.timestamp.tzinfo is not None
    assert entry.timestamp <= datetime.now(UTC)
