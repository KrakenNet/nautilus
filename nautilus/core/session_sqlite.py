"""``SqliteSessionStore`` — durable single-node session store (#26).

Implements the same :class:`~nautilus.core.session.AsyncSessionStore`
Protocol as :class:`~nautilus.core.session_pg.PostgresSessionStore`, backed
by stdlib ``sqlite3``. Two roles (roadmap §05:422 "Postgres with SQLite
fallback"):

- Primary backend via ``session_store.backend: sqlite`` — durable
  single-node deployments with no Postgres.
- Degradation target via ``session_store.on_failure: fallback_sqlite`` —
  unlike ``fallback_memory``, session state survives a broker restart.

Schema mirrors ``nautilus_session_state`` from :mod:`session_pg` with the
JSONB column flattened to JSON ``TEXT``. sqlite3 calls are synchronous, so
each operation hops through ``asyncio.to_thread`` and is serialized by an
``asyncio.Lock`` (the connection is shared across worker threads via
``check_same_thread=False``).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

_DDL: str = (
    "CREATE TABLE IF NOT EXISTS nautilus_session_state ("
    "session_id TEXT PRIMARY KEY, "
    "state TEXT NOT NULL, "
    "updated_at TEXT NOT NULL DEFAULT (datetime('now'))"
    ")"
)


def _decode_state(raw: str) -> dict[str, Any]:
    """Normalize a stored JSON ``TEXT`` value into a plain dict (parity with session_pg)."""
    loaded: Any = json.loads(raw)
    if isinstance(loaded, dict):
        return cast("dict[str, Any]", loaded)
    return {}


class SqliteSessionStore:
    """sqlite3-backed session store satisfying :class:`AsyncSessionStore`.

    Args:
        path: SQLite database file location. Parent directories are
            created on :meth:`setup`.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()
        self._closed: bool = False

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def mode(self) -> Literal["primary"]:
        """Always ``"primary"`` — when used as a *fallback*, the wrapping
        :class:`PostgresSessionStore` reports ``"degraded_sqlite"`` itself."""
        return "primary"

    @property
    def degraded_since(self) -> datetime | None:
        """Protocol parity with :class:`PostgresSessionStore`; never degraded."""
        return None

    @property
    def path(self) -> Path:
        """Backing database file (operators may want it in error messages)."""
        return self._path

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Open the database and ensure the schema exists. Idempotent."""
        if self._conn is not None:
            return
        async with self._lock:
            if self._conn is not None:
                return
            self._conn = await asyncio.to_thread(self._connect_sync)

    def _connect_sync(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False — asyncio.to_thread may run each call on a
        # different worker thread; the asyncio.Lock serializes access.
        conn = sqlite3.connect(self._path, check_same_thread=False)
        # WAL keeps readers unblocked during the read-merge-write transactions.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(_DDL)
        conn.commit()
        return conn

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            from nautilus.core.session_pg import SessionStoreUnavailableError

            raise SessionStoreUnavailableError(
                f"SqliteSessionStore({self._path}) used before setup() succeeded"
            )
        return self._conn

    # ------------------------------------------------------------------
    # AsyncSessionStore surface
    # ------------------------------------------------------------------

    async def aget(self, session_id: str) -> dict[str, Any]:
        """Fetch the state row for ``session_id`` (empty dict if absent)."""
        async with self._lock:
            return await asyncio.to_thread(self._get_sync, session_id)

    def _get_sync(self, session_id: str) -> dict[str, Any]:
        conn = self._require_conn()
        row = conn.execute(
            "SELECT state FROM nautilus_session_state WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return {}
        return _decode_state(row[0])

    async def aupdate(self, session_id: str, entry: dict[str, Any]) -> None:
        """Merge ``entry`` into the session row (read-merge-write upsert)."""
        async with self._lock:
            await asyncio.to_thread(self._update_sync, session_id, entry)

    def _update_sync(self, session_id: str, entry: dict[str, Any]) -> None:
        conn = self._require_conn()
        # ``with conn`` wraps the read-merge-write in one transaction so the
        # "later wins" Phase-1 merge semantics match InMemorySessionStore and
        # PostgresSessionStore.aupdate.
        with conn:
            row = conn.execute(
                "SELECT state FROM nautilus_session_state WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            current: dict[str, Any] = {} if row is None else _decode_state(row[0])
            current.update(entry)
            conn.execute(
                "INSERT INTO nautilus_session_state (session_id, state) "
                "VALUES (?, ?) "
                "ON CONFLICT(session_id) DO UPDATE "
                "SET state = excluded.state, updated_at = datetime('now')",
                (session_id, json.dumps(current)),
            )

    async def aclose(self) -> None:
        """Idempotent close — release the sqlite connection (FR-17)."""
        if self._closed:
            return
        self._closed = True
        conn = self._conn
        self._conn = None
        if conn is not None:
            await asyncio.to_thread(conn.close)


__all__ = ["SqliteSessionStore"]
