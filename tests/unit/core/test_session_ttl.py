"""``session_store.ttl_seconds`` reaches every backend (AUDIT.md:506).

The config field was modelled and documented, but ``_build_session_store``
never passed it to a store: a session written at t=0 came back in full
however long it sat idle, and the row was never deleted. These tests pin
expiry on all three stores plus the wiring that hands them the value.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from nautilus.config.models import NautilusConfig
from nautilus.core.broker import Broker
from nautilus.core.session import AsyncSessionStore, InMemorySessionStore, SessionStore
from nautilus.core.session_pg import PostgresSessionStore
from nautilus.core.session_sqlite import SqliteSessionStore


def _age_sqlite_row(path: Path, session_id: str, seconds: int) -> None:
    """Backdate a row's ``updated_at`` so a TTL test needs no real sleep."""
    conn = sqlite3.connect(path)
    with conn:
        conn.execute(
            "UPDATE nautilus_session_state "
            f"SET updated_at = datetime('now', '-{seconds} seconds') "
            "WHERE session_id = ?",
            (session_id,),
        )
    conn.close()


class TestInMemoryTtl:
    def test_a_fresh_session_is_returned(self) -> None:
        store = InMemorySessionStore(ttl_seconds=3600)
        store.update("s1", {"sources_visited": ["a"]})
        assert store.get("s1") == {"sources_visited": ["a"]}

    def test_an_idle_session_reads_as_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemorySessionStore(ttl_seconds=10)
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1000.0)
        store.update("s1", {"sources_visited": ["a"]})
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1011.0)
        assert store.get("s1") == {}

    def test_expiry_drops_the_entry_rather_than_hiding_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = InMemorySessionStore(ttl_seconds=10)
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1000.0)
        store.update("s1", {"sources_visited": ["a"]})
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1011.0)
        store.get("s1")
        assert "s1" not in store._store  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def test_a_write_after_expiry_starts_from_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemorySessionStore(ttl_seconds=10)
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1000.0)
        store.update("s1", {"sources_visited": ["a"]})
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1011.0)
        store.update("s1", {"data_types_seen": ["pii"]})
        assert store.get("s1") == {"data_types_seen": ["pii"]}

    def test_activity_refreshes_the_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemorySessionStore(ttl_seconds=10)
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1000.0)
        store.update("s1", {"a": 1})
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1005.0)
        store.update("s1", {"b": 2})
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1012.0)
        assert store.get("s1") == {"a": 1, "b": 2}

    def test_ttl_zero_never_expires(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemorySessionStore(ttl_seconds=0)
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 1000.0)
        store.update("s1", {"a": 1})
        monkeypatch.setattr("nautilus.core.session.time.time", lambda: 10_000_000.0)
        assert store.get("s1") == {"a": 1}

    def test_the_default_store_keeps_phase_1_behaviour(self) -> None:
        store = InMemorySessionStore()
        store.update("s1", {"a": 1})
        assert store.get("s1") == {"a": 1}


class TestSqliteTtl:
    @pytest.mark.asyncio
    async def test_a_fresh_session_is_returned(self, tmp_path: Path) -> None:
        store = SqliteSessionStore(tmp_path / "s.db", 3600)
        await store.setup()
        await store.aupdate("s1", {"sources_visited": ["a"]})
        assert await store.aget("s1") == {"sources_visited": ["a"]}
        await store.aclose()

    @pytest.mark.asyncio
    async def test_an_idle_session_reads_as_absent(self, tmp_path: Path) -> None:
        path = tmp_path / "s.db"
        store = SqliteSessionStore(path, 10)
        await store.setup()
        await store.aupdate("s1", {"sources_visited": ["a"]})
        _age_sqlite_row(path, "s1", 60)
        assert await store.aget("s1") == {}
        await store.aclose()

    @pytest.mark.asyncio
    async def test_a_write_purges_expired_rows(self, tmp_path: Path) -> None:
        path = tmp_path / "s.db"
        store = SqliteSessionStore(path, 10)
        await store.setup()
        await store.aupdate("stale", {"a": 1})
        _age_sqlite_row(path, "stale", 60)
        # A write for an unrelated session must still reclaim the stale row —
        # otherwise a store whose sessions are never revisited grows forever.
        await store.aupdate("fresh", {"b": 2})
        conn = sqlite3.connect(path)
        remaining = {r[0] for r in conn.execute("SELECT session_id FROM nautilus_session_state")}
        conn.close()
        assert remaining == {"fresh"}
        await store.aclose()

    @pytest.mark.asyncio
    async def test_a_write_after_expiry_starts_from_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "s.db"
        store = SqliteSessionStore(path, 10)
        await store.setup()
        await store.aupdate("s1", {"sources_visited": ["a"]})
        _age_sqlite_row(path, "s1", 60)
        await store.aupdate("s1", {"data_types_seen": ["pii"]})
        assert await store.aget("s1") == {"data_types_seen": ["pii"]}
        await store.aclose()

    @pytest.mark.asyncio
    async def test_ttl_zero_never_expires(self, tmp_path: Path) -> None:
        path = tmp_path / "s.db"
        store = SqliteSessionStore(path, 0)
        await store.setup()
        await store.aupdate("s1", {"a": 1})
        _age_sqlite_row(path, "s1", 10_000_000)
        assert await store.aget("s1") == {"a": 1}
        await store.aclose()


def _build(config: NautilusConfig, base_dir: Path) -> SessionStore | AsyncSessionStore:
    """Run the broker's own store factory — the only place the TTL is read."""
    return Broker._build_session_store(  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        config, base_dir=base_dir
    )


def _ttl(store: object) -> int:
    """The TTL a constructed store actually holds."""
    assert isinstance(store, InMemorySessionStore | SqliteSessionStore | PostgresSessionStore)
    return store._ttl_seconds  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


class TestBrokerWiring:
    """The config value has to actually reach the store it configures."""

    def _config(self, **session_store: object) -> NautilusConfig:
        return NautilusConfig.model_validate(
            {"version": "1.0", "sources": [], "session_store": session_store}
        )

    def test_the_memory_store_gets_the_configured_ttl(self, tmp_path: Path) -> None:
        store = _build(self._config(backend="memory", ttl_seconds=42), tmp_path)
        assert isinstance(store, InMemorySessionStore)
        assert _ttl(store) == 42

    def test_the_sqlite_store_gets_the_configured_ttl(self, tmp_path: Path) -> None:
        store = _build(self._config(backend="sqlite", ttl_seconds=42, sqlite_path="s.db"), tmp_path)
        assert isinstance(store, SqliteSessionStore)
        assert _ttl(store) == 42

    def test_the_postgres_store_gets_the_configured_ttl(self, tmp_path: Path) -> None:
        store = _build(
            self._config(backend="postgres", dsn="postgres://h/db", ttl_seconds=42), tmp_path
        )
        assert _ttl(store) == 42

    async def test_the_postgres_fallback_inherits_the_ttl(self, tmp_path: Path) -> None:
        # A degradation must not silently turn expiry off. Port 1 refuses, so
        # ``setup()`` takes the real ``fallback_memory`` branch.
        store = _build(
            self._config(
                backend="postgres",
                dsn="postgres://127.0.0.1:1/db",
                ttl_seconds=42,
                on_failure="fallback_memory",
            ),
            tmp_path,
        )
        assert isinstance(store, PostgresSessionStore)
        await store.setup()
        degraded = store._degraded_memory  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert degraded is not None
        assert _ttl(degraded) == 42

    def test_the_documented_default_is_one_hour(self, tmp_path: Path) -> None:
        store = _build(self._config(), tmp_path)
        assert isinstance(store, InMemorySessionStore)
        assert _ttl(store) == 3600
