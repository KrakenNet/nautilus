"""``PostgresSessionStore`` — persistent Phase-2 session store (design §3.2).

Implements the :class:`~nautilus.core.session.AsyncSessionStore` Protocol over
an ``asyncpg.Pool``. Schema is a single ``nautilus_session_state`` table with
``(session_id TEXT PRIMARY KEY, state JSONB, updated_at TIMESTAMPTZ)`` — minted
idempotently by :meth:`PostgresSessionStore.setup` so ``Broker.setup()`` can
stand the schema up on first use (design §3.2, UQ-1 / D-2).

Failure policy (NFR-7, D-1):
- ``on_failure="fail_closed"``: any asyncpg connect / table failure raises
  :class:`SessionStoreUnavailableError`. The broker surfaces this to callers
  and refuses to proceed (safe default for air-gap deployments).
- ``on_failure="fallback_memory"``: connect / table failures degrade to an
  internal :class:`~nautilus.core.session.InMemorySessionStore`; ``mode``
  flips to ``"degraded_memory"`` and ``degraded_since`` records the UTC
  timestamp. Recovery-probe cadence lives in the broker (design §8).
- ``on_failure="fallback_sqlite"`` (#26, roadmap §05:422): degrade to a
  :class:`~nautilus.core.session_sqlite.SqliteSessionStore` at
  ``sqlite_path`` instead — ``mode`` flips to ``"degraded_sqlite"`` and
  session state survives a broker restart, unlike the in-memory fallback.
  If the SQLite store itself cannot be opened, the failure escalates to
  :class:`SessionStoreUnavailableError` (no silent downgrade to memory).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from nautilus.core.session import InMemorySessionStore
from nautilus.core.session_sqlite import SqliteSessionStore

# Fallback database location when ``fallback_sqlite`` is selected without an
# explicit ``sqlite_path`` (mirrors the ``.nautilus/`` convention used by keys).
_DEFAULT_SQLITE_PATH: Path = Path(".nautilus/sessions.db")

# ``asyncpg`` is a Phase-2 runtime dep (pyproject) but imports are deferred
# into ``setup`` / ``aget`` / ``aupdate`` to keep ``from nautilus.core.session_pg
# import ...`` cheap (the Task 1.8 Verify smoke imports the module without
# touching asyncpg) and to tolerate environments where asyncpg is unavailable.


# Idempotent DDL — design §3.2, mirrors ``PostgresFactStore._ensure_schema``
# from Phase 1. ``session_id`` is the primary key so ``ON CONFLICT`` can
# upsert without a separate row existence check.
_DDL: str = (
    "CREATE TABLE IF NOT EXISTS nautilus_session_state ("
    "session_id TEXT PRIMARY KEY, "
    "state JSONB NOT NULL, "
    "updated_at TIMESTAMPTZ NOT NULL DEFAULT now()"
    ")"
)


# One advisory-lock key for the schema DDL. ``CREATE TABLE IF NOT EXISTS`` is
# not concurrency-safe: two replicas starting together collide on the composite
# type Postgres creates alongside the table.
_DDL_LOCK_KEY: int = 0x6E617574  # "naut"


def _decode_state(raw: Any) -> dict[str, Any]:
    """Normalize ``row["state"]`` (JSONB) into a plain ``dict[str, Any]``.

    asyncpg returns JSONB either as a pre-decoded Python object (when a codec
    is registered) or as a string. Accept both, and coerce to a fresh dict so
    callers can safely mutate without touching the row buffer.
    """
    if isinstance(raw, str):
        loaded: Any = json.loads(raw)
        if isinstance(loaded, dict):
            return cast("dict[str, Any]", loaded)
        return {}
    if isinstance(raw, dict):
        return cast("dict[str, Any]", dict(raw))  # pyright: ignore[reportUnknownArgumentType]
    return {}


class SessionStoreUnavailableError(Exception):
    """Raised when a ``fail_closed`` PostgresSessionStore cannot reach PG.

    Wraps the underlying ``asyncpg`` exception in ``__cause__`` so operators
    can diagnose the root cause (NFR-7, D-1).
    """


FailureMode = Literal["fail_closed", "fallback_memory", "fallback_sqlite"]
Mode = Literal["primary", "degraded_memory", "degraded_sqlite"]


class PostgresSessionStore:
    """asyncpg-backed session store (design §3.2).

    Satisfies :class:`~nautilus.core.session.AsyncSessionStore` — the broker
    detects via ``hasattr(store, 'aget')`` and prefers the async path.

    Args:
        dsn: Postgres DSN (``postgres://user:pw@host:port/db``).
        on_failure: Failure policy — ``"fail_closed"`` (default, NFR-7 safe
            default) raises :class:`SessionStoreUnavailableError` on connect
            failure; ``"fallback_memory"`` degrades to an in-memory store;
            ``"fallback_sqlite"`` degrades to a durable SQLite store at
            ``sqlite_path`` (#26).
        sqlite_path: Database file for the ``"fallback_sqlite"`` policy.
            Ignored under other policies.
        ttl_seconds: Idle lifetime of a session row. A row untouched for
            longer reads as absent and is deleted on the next write. ``0``
            (or negative) disables expiry. Inherited by whichever store a
            degradation falls back to, so expiry survives a fallback.
    """

    def __init__(
        self,
        dsn: str,
        *,
        on_failure: FailureMode = "fail_closed",
        sqlite_path: str | Path | None = None,
        ttl_seconds: int = 0,
        pool_min_size: int = 1,
        pool_max_size: int = 10,
        lock_pool_max_size: int = 32,
        acquire_timeout_s: float = 10.0,
    ) -> None:
        self._dsn: str = dsn
        self._on_failure: FailureMode = on_failure
        self._ttl_seconds: int = ttl_seconds
        self._pool_min_size: int = pool_min_size
        self._pool_max_size: int = pool_max_size
        self._lock_pool_max_size: int = lock_pool_max_size
        self._acquire_timeout_s: float = acquire_timeout_s
        self._sqlite_path: Path = Path(sqlite_path) if sqlite_path else _DEFAULT_SQLITE_PATH
        self._pool: Any = None
        self._lock_pool: Any = None
        self._closed: bool = False
        self._degraded_memory: InMemorySessionStore | None = None
        self._degraded_sqlite: SqliteSessionStore | None = None
        self._degraded_since: datetime | None = None
        self._mode: Mode = "primary"

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def mode(self) -> Mode:
        """``"primary"`` while asyncpg is healthy; ``"degraded_memory"`` /
        ``"degraded_sqlite"`` after fallback (per ``on_failure``)."""
        return self._mode

    @property
    def degraded_since(self) -> datetime | None:
        """UTC timestamp of first degradation, or ``None`` while healthy."""
        return self._degraded_since

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Create the pool and ensure the schema exists — design §3.2.

        Honors ``on_failure``: connect/DDL failures either raise
        :class:`SessionStoreUnavailableError` (fail_closed) or flip the store
        into degraded in-memory mode (fallback_memory).
        """
        # Deferred import: keeps ``from nautilus.core.session_pg import ...``
        # cheap and lets environments without asyncpg still import the module
        # (the Protocol smoke test in Task 1.8's Verify does exactly that).
        import asyncpg  # pyright: ignore[reportMissingTypeStubs]
        from asyncpg.exceptions import (  # pyright: ignore[reportMissingTypeStubs]
            CannotConnectNowError,
            ConnectionDoesNotExistError,
            UndefinedTableError,
        )

        try:
            # Two pools, deliberately. Ledger locks are held for the whole
            # length of a request; the reads and writes they protect are taken
            # and returned *inside* that hold. Drawn from one pool, the request
            # holding the last connection can never acquire the one it needs to
            # finish, and nothing in flight can release — measured at 32
            # concurrent callers against a single pool of 10.
            self._pool = await asyncpg.create_pool(  # pyright: ignore[reportUnknownMemberType]
                dsn=self._dsn,
                min_size=self._pool_min_size,
                max_size=self._pool_max_size,
            )
            # One connection per in-flight request, so this is the store's real
            # concurrency ceiling — sized above the query pool for that reason.
            self._lock_pool = await asyncpg.create_pool(  # pyright: ignore[reportUnknownMemberType]
                dsn=self._dsn,
                min_size=self._pool_min_size,
                max_size=self._lock_pool_max_size,
            )
            async with self._acquire() as conn, conn.transaction():
                # The lock is transaction-scoped, so it releases with the DDL
                # even if this process dies mid-statement.
                await conn.execute("SELECT pg_advisory_xact_lock($1)", _DDL_LOCK_KEY)
                await conn.execute(_DDL)
        except (
            CannotConnectNowError,
            ConnectionDoesNotExistError,
            UndefinedTableError,
            OSError,
        ) as exc:
            await self._handle_failure(exc)
        except Exception as exc:  # noqa: BLE001 — any asyncpg / network error
            # Other asyncpg exceptions (InvalidCatalogName, InvalidPasswordError,
            # etc.) also constitute unavailability. Treat identically to the
            # enumerated trio so callers get a single failure mode.
            await self._handle_failure(exc)

    async def _handle_failure(self, exc: BaseException) -> None:
        """Apply ``on_failure`` policy to a connect/DDL failure."""
        if self._on_failure == "fail_closed":
            raise SessionStoreUnavailableError(
                f"PostgresSessionStore unavailable (dsn={self._sanitized_dsn()}): {exc}"
            ) from exc
        if self._on_failure == "fallback_sqlite":
            # #26 — durable degradation: session state survives restarts.
            # If SQLite itself cannot be opened, escalate rather than
            # silently downgrading to memory (the operator chose durability).
            sqlite_store = SqliteSessionStore(self._sqlite_path, self._ttl_seconds)
            try:
                await sqlite_store.setup()
            except Exception as sqlite_exc:  # noqa: BLE001 — any sqlite3/OS error
                raise SessionStoreUnavailableError(
                    f"PostgresSessionStore unavailable (dsn={self._sanitized_dsn()}: {exc}) "
                    f"and sqlite fallback at {self._sqlite_path} failed: {sqlite_exc}"
                ) from sqlite_exc
            self._degraded_sqlite = sqlite_store
            self._mode = "degraded_sqlite"
        else:
            # fallback_memory: degrade, do not raise.
            self._degraded_memory = InMemorySessionStore(self._ttl_seconds)
            self._mode = "degraded_memory"
        self._degraded_since = datetime.now(UTC)
        # Release any partial pools so we do not leak sockets.
        for attr in ("_pool", "_lock_pool"):
            pool = getattr(self, attr)
            setattr(self, attr, None)
            if pool is not None:
                with contextlib.suppress(Exception):
                    await pool.close()

    def _sanitized_dsn(self) -> str:
        """Strip credentials from the DSN for error messages."""
        # Crude but dependency-free: ``postgres://user:pw@host/db`` →
        # ``postgres://host/db``. Good enough for log/error lines.
        if "@" in self._dsn:
            scheme, _, rest = self._dsn.partition("://")
            _, _, host_and_path = rest.partition("@")
            return f"{scheme}://{host_and_path}"
        return self._dsn

    # ------------------------------------------------------------------
    # AsyncSessionStore surface
    # ------------------------------------------------------------------

    async def aget(self, session_id: str) -> dict[str, Any]:
        """Fetch the state row for ``session_id`` (empty dict if absent)."""
        if self._degraded_sqlite is not None:
            return await self._degraded_sqlite.aget(session_id)
        if self._degraded_memory is not None:
            return self._degraded_memory.get(session_id)
        if self._pool is None:
            raise SessionStoreUnavailableError(
                "PostgresSessionStore.aget() called before setup() succeeded"
            )
        # Bounded: ``pool.fetchrow`` acquires with no deadline, and /readyz
        # calls this. A probe that hangs instead of answering 503 leaves a pod
        # that cannot serve sitting in the load balancer.
        async with self._acquire() as conn:
            row = await conn.fetchrow(
                "SELECT state FROM nautilus_session_state WHERE session_id = $1"
                + self._ttl_clause(),
                session_id,
            )
        if row is None:
            return {}
        return _decode_state(row["state"])

    def _ttl_clause(self) -> str:
        """SQL fragment restricting a read to rows inside the TTL window."""
        if self._ttl_seconds <= 0:
            return ""
        return f" AND updated_at > now() - interval '{int(self._ttl_seconds)} seconds'"

    async def aupdate(self, session_id: str, entry: dict[str, Any]) -> None:
        """Merge ``entry`` into the session row (upsert with JSONB concat)."""
        if self._degraded_sqlite is not None:
            await self._degraded_sqlite.aupdate(session_id, entry)
            return
        if self._degraded_memory is not None:
            self._degraded_memory.update(session_id, entry)
            return
        if self._pool is None:
            raise SessionStoreUnavailableError(
                "PostgresSessionStore.aupdate() called before setup() succeeded"
            )
        # Read-merge-write under a transaction so concurrent writers for the
        # same session_id don't clobber each other's keys. JSONB concat (``||``)
        # would merge at the DB layer but loses the "later wins" Phase-1
        # semantics for nested dicts — keep parity with InMemorySessionStore.
        async with self._acquire() as conn, conn.transaction():
            if self._ttl_seconds > 0:
                # Drop every expired row, not just this session's: without it
                # a store whose sessions are never revisited grows forever.
                await conn.execute(
                    "DELETE FROM nautilus_session_state WHERE updated_at <= "
                    f"now() - interval '{int(self._ttl_seconds)} seconds'"
                )
            row = await conn.fetchrow(
                "SELECT state FROM nautilus_session_state WHERE session_id = $1 FOR UPDATE",
                session_id,
            )
            current: dict[str, Any] = {} if row is None else _decode_state(row["state"])
            current.update(entry)
            await conn.execute(
                "INSERT INTO nautilus_session_state (session_id, state) "
                "VALUES ($1, $2::jsonb) "
                "ON CONFLICT (session_id) DO UPDATE "
                "SET state = EXCLUDED.state, updated_at = now()",
                session_id,
                json.dumps(current),
            )

    @contextlib.asynccontextmanager
    async def _acquire(self) -> AsyncIterator[Any]:
        """Take a pooled connection, or say so when the pool is exhausted.

        ``pool.acquire()`` with no timeout waits forever: a deployment past its
        pool size stopped answering, with no error, no audit entry and nothing
        in the logs. A deadline turns that into something an operator can see
        and act on — the message names the setting that fixes it.
        """
        assert self._pool is not None  # noqa: S101 — callers check
        try:
            conn = await self._pool.acquire(timeout=self._acquire_timeout_s)
        except TimeoutError as exc:
            raise SessionStoreUnavailableError(
                f"session-store pool exhausted: no connection became free within "
                f"{self._acquire_timeout_s}s (pool max_size={self._pool_max_size}). "
                f"Raise session_store.pool_max_size to at least your peak concurrency."
            ) from exc
        try:
            yield conn
        finally:
            await self._pool.release(conn)

    @contextlib.asynccontextmanager
    async def alock(self, key: str) -> AsyncIterator[None]:
        """Hold a cross-process lock on ``key`` for the block's duration.

        The broker's exposure ledger is a read-merge-write spanning two calls
        into this store, so serialising it needs a lock the *store* owns: an
        in-process ``asyncio.Lock`` serialises one replica against itself and
        nothing against the replica next to it. Postgres advisory locks are
        that lock — held on their own connection, released on exit, and dropped
        by the server if the holder's connection dies.

        A degraded store (in-memory / SQLite fallback) is per-process by
        definition; there is nothing to serialise against, so this is a no-op.
        """
        async with self.alock_all([key]):
            yield

    @contextlib.asynccontextmanager
    async def alock_all(self, keys: list[str]) -> AsyncIterator[None]:
        """Hold a cross-process lock on every key in ``keys`` — one connection.

        A request accumulates under more than one key (its declared session and
        its caller's principal), and every one of them is read-modify-written.
        Postgres advisory locks are session-scoped, not statement-scoped, so one
        connection can hold all of them: taking a connection per key made the
        store's concurrency ceiling ``pool_max_size / keys-per-request``, which
        measured as five concurrent requests on the shipped pool of ten.

        Keys are locked in sorted order so two requests sharing one key and
        differing on another cannot deadlock against each other. Connections
        come from the dedicated lock pool, never the query pool, so a request
        holding a lock can always acquire the connection it needs to finish.

        A degraded store (in-memory / SQLite fallback) is per-process by
        definition; there is nothing to serialise against, so this is a no-op.
        """
        if self._lock_pool is None:
            yield
            return
        ordered = sorted({k for k in keys if k})
        if not ordered:
            yield
            return
        async with self._acquire_lock_connection() as conn:
            for key in ordered:
                await conn.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", key)
            try:
                yield
            finally:
                # Shielded: a cancelled request must still release what it took.
                # asyncpg's pool reset would catch this on release anyway, but
                # relying on that puts correctness in a library's cleanup path.
                for key in reversed(ordered):
                    await asyncio.shield(
                        conn.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", key)
                    )

    @contextlib.asynccontextmanager
    async def _acquire_lock_connection(self) -> AsyncIterator[Any]:
        """Take a connection from the lock pool, or say the ceiling was hit."""
        assert self._lock_pool is not None  # noqa: S101 — callers check
        try:
            conn = await self._lock_pool.acquire(timeout=self._acquire_timeout_s)
        except TimeoutError as exc:
            raise SessionStoreUnavailableError(
                f"session-store lock pool exhausted: no connection became free within "
                f"{self._acquire_timeout_s}s (lock pool max_size={self._lock_pool_max_size}). "
                f"One is held per in-flight request, so raise "
                f"session_store.lock_pool_max_size to at least your peak concurrency."
            ) from exc
        try:
            yield conn
        finally:
            await self._lock_pool.release(conn)

    async def aclose(self) -> None:
        """Idempotent close — release the pool (FR-17)."""
        if self._closed:
            return
        self._closed = True
        for attr in ("_pool", "_lock_pool"):
            pool = getattr(self, attr)
            setattr(self, attr, None)
            if pool is not None:
                await pool.close()
        self._degraded_memory = None
        sqlite_store = self._degraded_sqlite
        self._degraded_sqlite = None
        if sqlite_store is not None:
            await sqlite_store.aclose()


__all__ = [
    "FailureMode",
    "Mode",
    "PostgresSessionStore",
    "SessionStoreUnavailableError",
]
