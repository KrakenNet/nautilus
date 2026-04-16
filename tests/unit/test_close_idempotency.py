"""Broker.close() idempotency across a mix of adapter types (Task 4.5).

Pins FR-17 / AC-8.6 end-to-end: regardless of how many Postgres vs.
pgvector adapters the broker owns, calling ``close()`` any number of times
must release each adapter's pool exactly once and flip the broker's
``_closed`` flag.

Strategy:
- Build a :class:`Broker` via :func:`Broker.from_config` so the collaborator
  graph (router, audit, session, attestation) is wired by production code.
- Replace the adapter dict with 2 :class:`PostgresAdapter` + 2
  :class:`PgVectorAdapter` instances, each pre-populated with an
  :class:`unittest.mock.AsyncMock` pool (no real ``asyncpg.create_pool`` call
  ever happens — connection is bypassed, matching the mocked-pool guidance
  in the task brief).
- Call ``broker.close()`` three times and assert each adapter's
  ``pool.close`` was awaited exactly once and ``broker._closed is True``.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from nautilus import Broker
from nautilus.adapters.base import Adapter
from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.adapters.postgres import PostgresAdapter

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "nautilus.yaml"


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide dummy DSNs so ``Broker.from_config`` env-interpolation succeeds.

    No adapter is ever ``connect()``-ed in this test, so DSN values just
    need to be non-empty strings.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


def _build_mixed_adapters() -> dict[str, tuple[Adapter, AsyncMock]]:
    """Return 2 PG + 2 pgvector adapters, each carrying its own mock pool.

    Returns a mapping ``{source_id: (adapter, mock_pool)}`` so the test can
    assert per-adapter ``pool.close.await_count`` afterwards.
    """
    adapters: dict[str, tuple[Adapter, AsyncMock]] = {}
    for source_id in ("pg_a", "pg_b"):
        pool = AsyncMock(name=f"{source_id}_pool")
        adapters[source_id] = (PostgresAdapter(pool=pool), pool)
    for source_id in ("pgv_a", "pgv_b"):
        pool = AsyncMock(name=f"{source_id}_pool")
        adapters[source_id] = (PgVectorAdapter(pool=pool), pool)
    return adapters


@pytest.mark.unit
def test_close_is_idempotent_across_adapter_mix() -> None:
    """AC-8.6 / FR-17: three ``close()`` calls → exactly one ``pool.close`` per adapter."""
    broker = Broker.from_config(FIXTURE_PATH)
    mixed = _build_mixed_adapters()

    # Swap the real adapter dict for our mocked mix. Accessing ``_adapters``
    # is intentional — ``Broker`` has no public DI surface for adapters in
    # Phase 1; all wiring flows through ``from_config``. Same pattern as
    # ``_install_fakes`` in ``tests/unit/test_broker.py``.
    broker._adapters = {sid: adapter for sid, (adapter, _pool) in mixed.items()}  # type: ignore[attr-defined]  # noqa: SLF001

    # Sanity: broker starts unclosed.
    assert broker._closed is False  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    broker.close()
    broker.close()
    broker.close()

    # Each adapter's pool.close was awaited exactly once — the second and
    # third broker.close() invocations must be no-ops at both the broker
    # level (``self._closed`` short-circuit) AND the adapter level
    # (``adapter._closed`` short-circuit).
    for source_id, (_adapter, pool) in mixed.items():
        assert pool.close.await_count == 1, (
            f"pool.close for '{source_id}' awaited {pool.close.await_count}x — expected exactly 1"
        )

    # Broker flag flipped.
    assert broker._closed is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
