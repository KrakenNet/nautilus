"""Unit coverage for :mod:`nautilus.core.session_sqlite` (#26).

Mirrors the :mod:`test_session_pg_unit` structure. Cases:

(a) ``setup()`` idempotent — safe to call twice; parent dirs are created.
(b) ``aget`` / ``aupdate`` round-trip with Phase-1 "later wins" merge
    semantics; absent session returns ``{}``.
(c) Durability — a NEW store opened on the same path reads state written
    by a closed one (the "restart broker, sessions still readable"
    acceptance, store level).
(d) ``aget`` before ``setup()`` raises :class:`SessionStoreUnavailableError`.
(e) Postgres connect failure + ``on_failure="fallback_sqlite"`` flips
    ``mode`` to ``"degraded_sqlite"`` and services reads/writes from the
    SQLite file — which a second (post-"restart") store can still read.
(f) SQLite fallback that itself cannot open escalates to
    :class:`SessionStoreUnavailableError` (no silent memory downgrade).
(g) ``AuditEntry`` accepts ``session_store_mode="degraded_sqlite"`` via
    the broker's audit builder.
(h) ``Broker._build_session_store`` maps ``backend: sqlite`` to
    :class:`SqliteSessionStore` and plumbs ``sqlite_path`` to the
    Postgres store for ``fallback_sqlite``.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from nautilus.config.models import NautilusConfig
from nautilus.core.broker import (
    Broker,
    _build_audit_entry,  # pyright: ignore[reportPrivateUsage]
    _RequestState,  # pyright: ignore[reportPrivateUsage]
)
from nautilus.core.models import IntentAnalysis
from nautilus.core.session_pg import (
    PostgresSessionStore,
    SessionStoreUnavailableError,
)
from nautilus.core.session_sqlite import SqliteSessionStore


def _install_asyncpg_stubs() -> None:
    """Guarantee ``asyncpg`` + ``asyncpg.exceptions`` are importable (offline-safe)."""
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


# ---------------------------------------------------------------------------
# (a) setup() idempotent + creates parent dirs
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_setup_idempotent_and_creates_parent_dirs(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "dir" / "sessions.db"
    store = SqliteSessionStore(db_path)
    try:
        await store.setup()
        await store.setup()  # second call is a no-op
        assert db_path.exists()
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# (b) round-trip + merge semantics
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_round_trip_and_later_wins_merge(tmp_path: Path) -> None:
    store = SqliteSessionStore(tmp_path / "sessions.db")
    try:
        await store.setup()
        assert await store.aget("absent") == {}
        await store.aupdate("s1", {"a": 1, "b": 2})
        await store.aupdate("s1", {"b": 3, "c": 4})
        assert await store.aget("s1") == {"a": 1, "b": 3, "c": 4}
        # Distinct sessions do not bleed into each other.
        await store.aupdate("s2", {"x": "y"})
        assert await store.aget("s2") == {"x": "y"}
        assert await store.aget("s1") == {"a": 1, "b": 3, "c": 4}
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# (c) durability across close/reopen ("restart")
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_state_survives_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "sessions.db"
    first = SqliteSessionStore(db_path)
    await first.setup()
    await first.aupdate("s1", {"sources_visited": ["vuln-db"]})
    await first.aclose()

    second = SqliteSessionStore(db_path)
    try:
        await second.setup()
        assert await second.aget("s1") == {"sources_visited": ["vuln-db"]}
    finally:
        await second.aclose()


# ---------------------------------------------------------------------------
# (d) use before setup
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_aget_before_setup_raises(tmp_path: Path) -> None:
    store = SqliteSessionStore(tmp_path / "sessions.db")
    with pytest.raises(SessionStoreUnavailableError):
        await store.aget("s1")


# ---------------------------------------------------------------------------
# (e) PG failure + fallback_sqlite -> degraded_sqlite, durable
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_pg_failure_falls_back_to_sqlite_and_persists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from asyncpg.exceptions import CannotConnectNowError  # type: ignore[import-not-found]

    create_pool = AsyncMock(side_effect=CannotConnectNowError("db down"))
    monkeypatch.setattr("asyncpg.create_pool", create_pool, raising=False)

    db_path = tmp_path / "fallback.db"
    store = PostgresSessionStore(
        "postgres://u:p@h/db", on_failure="fallback_sqlite", sqlite_path=db_path
    )
    await store.setup()  # must NOT raise

    assert store.mode == "degraded_sqlite"
    assert store.degraded_since is not None
    await store.aupdate("s1", {"k": "v"})
    assert await store.aget("s1") == {"k": "v"}
    await store.aclose()

    # "Restart": a fresh store degrading onto the same file still reads s1
    # — the durability property fallback_memory cannot provide.
    store2 = PostgresSessionStore(
        "postgres://u:p@h/db", on_failure="fallback_sqlite", sqlite_path=db_path
    )
    try:
        await store2.setup()
        assert store2.mode == "degraded_sqlite"
        assert await store2.aget("s1") == {"k": "v"}
    finally:
        await store2.aclose()


# ---------------------------------------------------------------------------
# (f) sqlite fallback failure escalates (no silent memory downgrade)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_sqlite_fallback_failure_escalates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from asyncpg.exceptions import CannotConnectNowError  # type: ignore[import-not-found]

    create_pool = AsyncMock(side_effect=CannotConnectNowError("db down"))
    monkeypatch.setattr("asyncpg.create_pool", create_pool, raising=False)

    # A directory path is not a valid sqlite database file target.
    bogus = tmp_path  # exists and IS a directory -> sqlite3.connect fails
    store = PostgresSessionStore(
        "postgres://u:p@h/db", on_failure="fallback_sqlite", sqlite_path=bogus
    )
    with pytest.raises(SessionStoreUnavailableError) as excinfo:
        await store.setup()
    assert "sqlite fallback" in str(excinfo.value)
    # DSN credentials must not leak into the error message.
    assert "u:p" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# (g) AuditEntry accepts degraded_sqlite
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_degraded_sqlite_propagates_to_audit_entry() -> None:
    state = _RequestState(
        request_id="r-1",
        session_id="s-1",
        started=0.0,
        intent="probe",
        intent_analysis=IntentAnalysis(raw_intent="probe", data_types_needed=[], entities=[]),
    )
    state.rule_trace = []
    state.facts_summary = {}
    entry = _build_audit_entry(
        agent_id="agent-alpha",
        state=state,
        attestation_token=None,
        session_store_mode="degraded_sqlite",
    )
    assert entry.session_store_mode == "degraded_sqlite"


# ---------------------------------------------------------------------------
# (h) config -> store construction
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_build_session_store_sqlite_backend(tmp_path: Path) -> None:
    cfg = NautilusConfig.model_validate(
        {"session_store": {"backend": "sqlite", "sqlite_path": str(tmp_path / "s.db")}}
    )
    store = Broker._build_session_store(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        cfg, base_dir=tmp_path
    )
    assert isinstance(store, SqliteSessionStore)
    assert store.path == tmp_path / "s.db"


@pytest.mark.unit
def test_build_session_store_resolves_relative_path_against_config_dir(
    tmp_path: Path,
) -> None:
    """A relative sqlite_path must not depend on the process CWD."""
    cfg = NautilusConfig.model_validate(
        {"session_store": {"backend": "sqlite", "sqlite_path": "./.nautilus/sessions.db"}}
    )
    store = Broker._build_session_store(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        cfg, base_dir=tmp_path
    )
    assert isinstance(store, SqliteSessionStore)
    assert store.path == tmp_path / ".nautilus" / "sessions.db"


@pytest.mark.unit
def test_build_session_store_pg_plumbs_sqlite_path(tmp_path: Path) -> None:
    cfg = NautilusConfig.model_validate(
        {
            "session_store": {
                "backend": "postgres",
                "dsn": "postgres://u:p@h/db",
                "on_failure": "fallback_sqlite",
                "sqlite_path": str(tmp_path / "fb.db"),
            }
        }
    )
    store: Any = Broker._build_session_store(  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
        cfg, base_dir=tmp_path
    )
    assert isinstance(store, PostgresSessionStore)
    assert store._sqlite_path == tmp_path / "fb.db"  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
