"""Smoke-level unit coverage for :mod:`nautilus.core.session_pg` (Task 1.11).

Phase-1 unit coverage was sitting one statement short of the 80% gate because
``PostgresSessionStore`` is otherwise only exercised by the Phase-2 Postgres
testcontainer suite (Task 3.3). These tiny, offline-safe tests nudge the
setup() failure paths over the line without pulling in a container.

They intentionally do *not* stand up a real Postgres — they rely on an
unrouted loopback port (``127.0.0.1:1``) so ``asyncpg.create_pool`` fails
immediately with an OSError-derived exception, letting us assert the two
``on_failure`` branches of :meth:`PostgresSessionStore.setup`.

When Task 3.3 lands the real testcontainer suite, these smokes stay as
fast regression pins for the failure-policy branch; they should not be
expanded to cover happy paths.
"""

from __future__ import annotations

import pytest

from nautilus.core.session_pg import (
    PostgresSessionStore,
    SessionStoreUnavailableError,
)

# Unrouted loopback: port 1 on 127.0.0.1 is reserved/unused, so asyncpg's
# connect will bounce with ECONNREFUSED instantly. No DNS resolution, no
# network round-trip that could stall CI.
_BAD_DSN = "postgres://nautilus:none@127.0.0.1:1/nowhere"


@pytest.mark.unit
async def test_postgres_session_store_fail_closed_raises_on_bad_dsn() -> None:
    """``fail_closed`` (default, NFR-7) must surface connect failure as
    :class:`SessionStoreUnavailableError` with the original asyncpg error
    chained via ``__cause__``.
    """
    store = PostgresSessionStore(_BAD_DSN, on_failure="fail_closed")
    with pytest.raises(SessionStoreUnavailableError) as excinfo:
        await store.setup()
    # DSN sanitizer strips credentials before the error message is built.
    assert "nautilus:none" not in str(excinfo.value)
    assert excinfo.value.__cause__ is not None


@pytest.mark.unit
async def test_postgres_session_store_fallback_memory_degrades_silently() -> None:
    """``fallback_memory`` must swallow connect failure and flip ``mode``
    to ``"degraded_memory"`` with a ``degraded_since`` timestamp set.
    """
    store = PostgresSessionStore(_BAD_DSN, on_failure="fallback_memory")
    await store.setup()  # must NOT raise
    assert store.mode == "degraded_memory"
    assert store.degraded_since is not None


@pytest.mark.unit
def test_session_store_unavailable_error_is_exception() -> None:
    """Sanity pin: the sentinel error stays an ``Exception`` subclass so
    callers can ``except Exception`` without missing it.
    """
    assert issubclass(SessionStoreUnavailableError, Exception)
