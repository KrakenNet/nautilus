"""``SessionStore`` Protocol + ``InMemorySessionStore`` (design §3.9, §3.2).

Phase 1 shipped a sync-only Protocol (``get`` / ``update``) over an in-memory
dict. Phase 2 adds a persistent ``PostgresSessionStore`` (see
:mod:`nautilus.core.session_pg`) whose surface is inherently async. To preserve
the NFR-5 invariant that Phase-1 code still satisfies
``isinstance(store, SessionStore)``, we use approach (a) from the design:
split into two Protocols — ``SessionStore`` keeps the Phase-1 sync surface
(backwards-compatible, runtime-checkable), and ``AsyncSessionStore`` layers the
async surface on top. The broker prefers async when the implementer provides
it (``hasattr(store, 'aget')`` / ``isinstance(store, AsyncSessionStore)``).
"""

from __future__ import annotations

import time
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SessionStore(Protocol):
    """Phase-1 sync surface — design §3.9.

    Kept sync-only so ``InMemorySessionStore`` (which predates Phase 2)
    remains a valid implementer under ``isinstance(store, SessionStore)``.
    Phase-2 async implementers should ALSO satisfy :class:`AsyncSessionStore`.
    """

    def get(self, session_id: str) -> dict[str, Any]:
        """Return the stored state mapping for ``session_id``.

        Args:
            session_id: Opaque session identifier provided by the caller.

        Returns:
            The session's current state dict, or an empty dict if no
            state exists yet.
        """
        ...

    def update(self, session_id: str, entry: dict[str, Any]) -> None:
        """Merge ``entry`` into the stored state for ``session_id``.

        Args:
            session_id: Opaque session identifier.
            entry: Key/value pairs to merge into the session's state.
        """
        ...


@runtime_checkable
class AsyncSessionStore(Protocol):
    """Phase-2 async surface — design §3.2.

    Independent of :class:`SessionStore` so implementers can provide either
    surface. :class:`PostgresSessionStore` satisfies ``AsyncSessionStore``
    only; :class:`InMemorySessionStore` satisfies ``SessionStore`` only.
    The broker uses ``hasattr(store, 'aget')`` at request time to prefer
    the async path when available (design §3.2 — "broker prefers async").
    """

    async def aget(self, session_id: str) -> dict[str, Any]:
        """Async counterpart to :meth:`SessionStore.get`."""
        ...

    async def aupdate(self, session_id: str, entry: dict[str, Any]) -> None:
        """Async counterpart to :meth:`SessionStore.update`."""
        ...

    async def aclose(self) -> None:
        """Release any backing resources (pool, connections). Idempotent."""
        ...


class InMemorySessionStore:
    """Dict-backed :class:`SessionStore` (Phase 1 swap-target for Phase 2).

    All state lives in a single process; restart wipes the store. Phase 2
    introduces persistent backends (see :class:`PostgresSessionStore`); the
    Protocol contract is stable so broker call sites do not change.
    """

    def __init__(self, ttl_seconds: int = 0) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._updated_at: dict[str, float] = {}
        self._ttl_seconds: int = ttl_seconds

    def _expired(self, session_id: str) -> bool:
        """True when ``session_id`` has been idle longer than the TTL."""
        if self._ttl_seconds <= 0:
            return False
        written = self._updated_at.get(session_id)
        return written is not None and (time.time() - written) > self._ttl_seconds

    def get(self, session_id: str) -> dict[str, Any]:
        """Return the stored dict for ``session_id`` (empty dict if absent).

        An expired session reads as absent and is dropped, so cumulative
        exposure does not accumulate against a session id forever.
        """
        if self._expired(session_id):
            self._store.pop(session_id, None)
            self._updated_at.pop(session_id, None)
            return {}
        # Return a shallow copy so callers mutating the returned dict do not
        # accidentally persist changes without going through ``update``.
        return dict(self._store.get(session_id, {}))

    def update(self, session_id: str, entry: dict[str, Any]) -> None:
        """Merge ``entry`` into the stored state for ``session_id``.

        Phase 1 semantics: later keys overwrite earlier keys (dict.update).
        Phase 2 may introduce richer merge strategies per design §3.9.
        """
        if self._expired(session_id):
            self._store.pop(session_id, None)
        current = self._store.setdefault(session_id, {})
        current.update(entry)
        self._updated_at[session_id] = time.time()


__all__ = ["AsyncSessionStore", "InMemorySessionStore", "SessionStore"]
