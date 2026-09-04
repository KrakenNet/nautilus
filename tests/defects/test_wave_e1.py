"""WAVE E1 — the exposure-ledger lock caps the store at half its pool.

Reproduced first-hand against a real Postgres before writing a line of fix:

* 64 concurrent requests from 64 distinct principals against the shipped
  defaults (``pool_max_size: 10``) fail with ``SessionStoreUnavailableError:
  session-store pool exhausted`` after the 10 s acquire deadline. Every
  in-flight request holds **two** pooled connections for its whole pipeline —
  one advisory lock for the declared session, one for the caller's principal —
  so ten connections carry five concurrent requests.
* Locks and ledger reads/writes come from the same pool, so the requests
  holding the last connections cannot acquire the one they need to finish.
* ``aget`` reads through ``self._pool.fetchrow``, which acquires with no
  deadline. ``/readyz`` calls ``aget`` and turns any exception into 503, which
  is how a wedged pod leaves the load balancer — an unbounded acquire turns
  that into a probe that never answers at all.

Two claims from the same audit did **not** reproduce and are deliberately not
pinned here: advisory locks did not survive cancellation (asyncpg's pool reset
issues ``pg_advisory_unlock_all`` when a connection is released), and the store
recovered on its own after every burst rather than wedging permanently.

Note for whoever reads this next: same-principal requests are serialised by the
per-process ``asyncio.Lock`` in ``Broker._hold_ledger_locks``, so a single agent
never reaches the ceiling — it is one request at a time by design. The ceiling
is reached by concurrent requests from *different* principals, which is what a
multi-agent deployment is.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import pytest

from nautilus.core.session_pg import PostgresSessionStore, SessionStoreUnavailableError

pytestmark = [pytest.mark.integration]

# The shipped defaults, not numbers chosen to make a pin pass: a test that
# invents a small pool proves nothing about what operators actually run.
_SHIPPED_POOL_MAX = 10
_SHIPPED_ACQUIRE_TIMEOUT = 10.0


async def _one_request(store: PostgresSessionStore, session: str, principal: str) -> None:
    """One request's worth of ledger work, exactly as the broker does it.

    ``Broker._hold_ledger_locks`` sorts the keys and holds every one of them for
    the whole pipeline, reading and writing the ledger inside that hold.
    """
    async with store.alock_all(sorted({session, principal})):
        await store.aget(session)
        await store.aupdate(session, {"sources_visited": [session]})


@pytest.fixture
async def store(pg_container: str) -> Any:
    """A store on the shipped defaults — nothing widened to make a pin pass."""
    s = PostgresSessionStore(
        pg_container,
        pool_max_size=_SHIPPED_POOL_MAX,
        acquire_timeout_s=_SHIPPED_ACQUIRE_TIMEOUT,
    )
    await s.setup()
    try:
        yield s
    finally:
        await s.aclose()


@pytest.mark.asyncio
async def test_e1_concurrent_distinct_principals_all_succeed(
    store: PostgresSessionStore,
) -> None:
    """32 concurrent requests from distinct principals must all be served.

    At the shipped ``pool_max_size: 10`` this failed for most callers: two
    connections per request means ten connections carry five concurrent
    requests, and everyone else waited out the acquire deadline and got an
    error. Distinct principals are the ordinary case for a multi-agent
    deployment, which is the only kind Nautilus has.
    """
    await asyncio.wait_for(
        asyncio.gather(*(_one_request(store, f"session-{i}", f"principal-{i}") for i in range(32))),
        timeout=90.0,
    )


@pytest.mark.asyncio
async def test_e1_holding_both_ledger_keys_takes_one_connection(
    store: PostgresSessionStore,
) -> None:
    """Two keys, one connection. Two per request halves the store's capacity."""
    lock_pool: Any = store._lock_pool  # pyright: ignore[reportPrivateUsage]
    idle_before = lock_pool.get_idle_size()
    async with store.alock_all(["session-a", "principal-b"]):
        idle_during = lock_pool.get_idle_size()
    assert idle_before - idle_during == 1, (
        f"holding two ledger keys checked out {idle_before - idle_during} connections; "
        f"one hold must cost one connection however many keys it covers"
    )


@pytest.mark.asyncio
async def test_e1_held_locks_do_not_starve_ledger_reads(
    store: PostgresSessionStore,
) -> None:
    """A pool saturated with lock holders must still serve reads and writes.

    Locks are held for the length of a request; reads and writes are taken and
    returned inside that hold. Drawn from one pool, the request holding the last
    connection can never acquire the one it needs to finish. They have to be
    separate pools.
    """
    async with contextlib.AsyncExitStack() as stack:
        for i in range(_SHIPPED_POOL_MAX):
            await stack.enter_async_context(store.alock_all([f"saturating-{i}"]))

        await asyncio.wait_for(store.aget("still-readable"), timeout=15.0)
        await asyncio.wait_for(store.aupdate("still-writable", {"ok": True}), timeout=15.0)


@pytest.mark.asyncio
async def test_e1_aget_fails_fast_when_the_query_pool_is_exhausted(
    store: PostgresSessionStore,
) -> None:
    """``aget`` must answer within the acquire deadline, or ``/readyz`` hangs.

    ``/readyz`` calls ``aget`` and downgrades any exception to 503, which is how
    a pod that cannot serve leaves the rotation. Reading through the pool's own
    ``fetchrow`` acquires with no deadline, so the probe never answers: the
    Deployment still reads READY while the Service drops to zero endpoints.
    """
    async with contextlib.AsyncExitStack() as stack:
        for _ in range(_SHIPPED_POOL_MAX):
            await stack.enter_async_context(store._acquire())  # pyright: ignore[reportPrivateUsage]

        with pytest.raises(SessionStoreUnavailableError):
            await asyncio.wait_for(store.aget("probe"), timeout=_SHIPPED_ACQUIRE_TIMEOUT + 5.0)
