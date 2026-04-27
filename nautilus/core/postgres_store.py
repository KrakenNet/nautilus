"""``BasePostgresStore`` — shared asyncpg lifecycle + failure-mode base (TD-11).

Hoists the common pattern from :class:`nautilus.core.session_pg.PostgresSessionStore`
(setup, pool lifecycle, ``on_failure`` semantics, degraded-memory fallback) into a
reusable abstract base. Concrete subclasses override the class-level DDL / table
name and the two abstract methods (``_init_memory_backend``, ``_unavailable_error``)
that specialise the store.

Failure policy mirrors ``session_pg`` (design §3.2, NFR-7, NFR-DEGRAD):

- ``on_failure="fail_closed"``: connect / DDL failures raise the subclass-specific
  unavailable error (via :meth:`_unavailable_error`) with the underlying exception
  preserved on ``__cause__`` for operator diagnosis.
- ``on_failure="fallback_memory"``: connect / DDL failures degrade silently to an
  in-memory backend produced by :meth:`_init_memory_backend`; ``mode`` flips to
  ``"degraded_memory"``, ``degraded_since`` records the UTC timestamp, and a
  WARNING is logged.

This module intentionally does NOT refactor ``session_pg.py`` — TD-11 leaves that
migration for a later task and keeps the Phase-2 PostgresSessionStore untouched.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Literal

from nautilus.core.types import FailureMode

__all__ = ["BasePostgresStore", "Mode"]

Mode = Literal["primary", "degraded_memory"]
"""Store operational mode — healthy ``primary`` or fallen-back ``degraded_memory``."""


_LOG = logging.getLogger(__name__)


class BasePostgresStore(ABC):
    """Abstract base for asyncpg-backed persistence stores (TD-11).

    Subclasses supply:

    * ``_DDL`` — ``CREATE TABLE IF NOT EXISTS ...`` statement executed by
      :meth:`setup`.
    * ``_TABLE`` — table name used in error messages and log lines.
    * :meth:`_init_memory_backend` — factory for the in-memory fallback structure.
    * :meth:`_unavailable_error` — exception class raised under ``fail_closed``.

    Args:
        dsn: Postgres DSN (``postgres://user:pw@host:port/db``).
        on_failure: Failure policy (``"fail_closed"`` default; safe under NFR-7).
    """

    # Subclass overrides --------------------------------------------------
    _DDL: str = ""
    """Idempotent ``CREATE TABLE IF NOT EXISTS`` DDL — subclasses override."""

    _TABLE: str = ""
    """Table name, used in error messages / logs — subclasses override."""

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
        self._memory_backend: Any = None
        self._degraded_since: datetime | None = None
        self._mode: Mode = "primary"
        # Serializes concurrent ``setup()`` so the pool + DDL are created once.
        self._setup_lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Abstract hooks
    # ------------------------------------------------------------------

    @abstractmethod
    def _init_memory_backend(self) -> Any:
        """Return a fresh in-memory fallback structure (e.g. ``{}``)."""

    @abstractmethod
    def _unavailable_error(self) -> type[Exception]:
        """Return the subclass-specific "unavailable" exception class."""

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

    @property
    def pool(self) -> Any:
        """The asyncpg pool, or ``None`` before ``setup()`` / after fallback."""
        return self._pool

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Create the pool and apply ``_DDL`` idempotently (design §3.2).

        Honors ``on_failure``: connect / DDL errors either raise the subclass's
        unavailable error (``fail_closed``) or degrade to an in-memory backend
        (``fallback_memory``). Safe under concurrent entry — the setup lock
        serializes initialization so ``create_pool`` runs exactly once
        (FR-34).
        """
        # Fast path (no lock) — the common case after initial setup.
        if self._pool is not None or self._mode == "degraded_memory":
            return

        async with self._setup_lock:
            # Re-check under the lock: a concurrent caller may have finished
            # initialization while we were waiting. Pyright can't see across
            # the await, so narrow-reset checks look "unreachable" statically.
            if self._pool is not None or self._mode == "degraded_memory":  # pyright: ignore[reportUnnecessaryComparison]
                return

            # Deferred import keeps ``from nautilus.core.postgres_store import ...``
            # cheap and lets environments without asyncpg still import the module.
            import asyncpg  # pyright: ignore[reportMissingTypeStubs]

            try:
                self._pool = await asyncpg.create_pool(dsn=self._dsn)  # pyright: ignore[reportUnknownMemberType]
                async with self._pool.acquire() as conn:
                    await conn.execute(self._DDL)
            except Exception as exc:  # noqa: BLE001 — any asyncpg / network error
                await self._handle_failure(exc, at="setup")

    async def aclose(self) -> None:
        """Idempotent close — release the pool (FR-17)."""
        if self._closed:
            return
        self._closed = True
        pool = self._pool
        self._pool = None
        if pool is not None:
            with contextlib.suppress(Exception):
                await pool.close()
        self._memory_backend = None

    # ------------------------------------------------------------------
    # Failure handling
    # ------------------------------------------------------------------

    async def _handle_failure(self, exc: BaseException, at: str) -> None:
        """Apply ``on_failure`` policy to a connect / DDL failure.

        Args:
            exc: Originating asyncpg / network exception.
            at: Short label identifying the failure site (e.g. ``"setup"``).
        """
        if self._on_failure == "fail_closed":
            # Release any partial pool before raising, so sockets don't leak.
            await self._release_partial_pool()
            err_cls = self._unavailable_error()
            raise err_cls(
                f"{type(self).__name__} unavailable at {at} "
                f"(dsn={self._sanitized_dsn()}, table={self._TABLE}): {exc}"
            ) from exc

        # fallback_memory: degrade silently (WARNING-level log, no raise).
        self._memory_backend = self._init_memory_backend()
        self._degraded_since = datetime.now(UTC)
        self._mode = "degraded_memory"
        await self._release_partial_pool()
        _LOG.warning(
            "%s degraded to in-memory fallback at %s (table=%s): %s",
            type(self).__name__,
            at,
            self._TABLE,
            exc,
        )

    async def _release_partial_pool(self) -> None:
        """Close and drop any partially-created pool without raising."""
        pool = self._pool
        self._pool = None
        if pool is not None:
            with contextlib.suppress(Exception):
                await pool.close()

    def _sanitized_dsn(self) -> str:
        """Strip credentials from the DSN for safe inclusion in error messages."""
        if "@" in self._dsn:
            scheme, _, rest = self._dsn.partition("://")
            _, _, host_and_path = rest.partition("@")
            return f"{scheme}://{host_and_path}"
        return self._dsn
