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
"""

from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime
from typing import Any, Literal, cast

from nautilus.core.session import InMemorySessionStore

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


FailureMode = Literal["fail_closed", "fallback_memory"]
Mode = Literal["primary", "degraded_memory"]


class PostgresSessionStore:
    """asyncpg-backed session store (design §3.2).

    Satisfies :class:`~nautilus.core.session.AsyncSessionStore` — the broker
    detects via ``hasattr(store, 'aget')`` and prefers the async path.

    Args:
        dsn: Postgres DSN (``postgres://user:pw@host:port/db``).
        on_failure: Failure policy — ``"fail_closed"`` (default, NFR-7 safe
            default) raises :class:`SessionStoreUnavailableError` on connect
            failure; ``"fallback_memory"`` degrades to an in-memory store.
    """

    def __init__(
        self,
        dsn: str,
        *,
        on_failure: FailureMode = "fail_closed",
    ) -> None:
        self._dsn: str = dsn
        self._on_failure: FailureMode = on_failure
        self._pool: Any = None
        self._closed: bool = False
        self._degraded_memory: InMemorySessionStore | None = None
        self._degraded_since: datetime | None = None
        self._mode: Mode = "primary"

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def mode(self) -> Mode:
        """``"primary"`` while asyncpg is healthy; ``"degraded_memory"`` after fallback."""
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
            self._pool = await asyncpg.create_pool(dsn=self._dsn)  # pyright: ignore[reportUnknownMemberType]
            async with self._pool.acquire() as conn:
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
        # fallback_memory: degrade, do not raise.
        self._degraded_memory = InMemorySessionStore()
        self._degraded_since = datetime.now(UTC)
        self._mode = "degraded_memory"
        # Release any partial pool so we do not leak sockets.
        pool = self._pool
        self._pool = None
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
        if self._degraded_memory is not None:
            return self._degraded_memory.get(session_id)
        if self._pool is None:
            raise SessionStoreUnavailableError(
                "PostgresSessionStore.aget() called before setup() succeeded"
            )
        row = await self._pool.fetchrow(
            "SELECT state FROM nautilus_session_state WHERE session_id = $1",
            session_id,
        )
        if row is None:
            return {}
        return _decode_state(row["state"])

    async def aupdate(self, session_id: str, entry: dict[str, Any]) -> None:
        """Merge ``entry`` into the session row (upsert with JSONB concat)."""
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
        async with self._pool.acquire() as conn, conn.transaction():
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

    async def aclose(self) -> None:
        """Idempotent close — release the pool (FR-17)."""
        if self._closed:
            return
        self._closed = True
        pool = self._pool
        self._pool = None
        if pool is not None:
            await pool.close()
        self._degraded_memory = None


__all__ = [
    "FailureMode",
    "Mode",
    "PostgresSessionStore",
    "SessionStoreUnavailableError",
]
