"""Unit coverage for the :class:`Broker` ↔ :class:`SourceStateStore` wiring (Task 12, US-3).

Exercises the two surgical edits in ``nautilus/core/broker.py``:

1. ``arequest`` calls ``SourceStateStore.load_all()`` once per request and
   caches the result on ``_RequestState.source_states`` (AC-3.7).
2. ``_route`` filters sources whose ``state.enabled is False`` out of
   ``routing_decisions`` BEFORE any adapter connect/execute, and appends
   ``f"source_disabled:{source_id}"`` to ``sources_skipped`` (FR-29).

The test wires a real :class:`Broker` from the shared fixture YAML, swaps
its adapters for fakes (same pattern as ``tests/unit/test_broker.py``),
injects a degraded-memory :class:`SourceStateStore`, seeds one disabled
row, and asserts the disabled source never reached the fake adapter while
still surfacing in the ``sources_skipped`` aggregation.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from nautilus import Broker
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint
from nautilus.core.source_state import SourceStateStore

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"


def _install_asyncpg_stub() -> None:
    """Mirror the shim in ``test_source_state.py`` so ``SourceStateStore`` imports cleanly."""
    if "asyncpg" not in sys.modules:
        stub = types.ModuleType("asyncpg")
        stub.create_pool = AsyncMock()  # type: ignore[attr-defined]
        sys.modules["asyncpg"] = stub


_install_asyncpg_stub()


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide dummy DSNs so the fixture YAML's env interpolation succeeds."""
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


class _FakeAdapter:
    """Minimal Adapter double that records every ``connect`` / ``execute`` call."""

    source_type: str = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id
        self.connect_calls: int = 0
        self.execute_calls: int = 0

    async def connect(self, config: SourceConfig) -> None:
        del config
        self.connect_calls += 1

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        self.execute_calls += 1
        return AdapterResult(source_id=self._source_id, rows=[{"id": 1}], duration_ms=0)

    async def close(self) -> None:
        return None


def _ctx() -> dict[str, Any]:
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "s1",
        "embedding": [0.1, 0.2, 0.3],
    }


async def _make_memory_store() -> SourceStateStore:
    """Build a fully-degraded :class:`SourceStateStore` (no Postgres required)."""
    store = SourceStateStore("postgres://ignored/src_state", on_failure="fallback_memory")
    # Force the degraded-memory branch directly so ``setup()`` is a no-op and
    # ``load_all``/``set_enabled`` operate on the in-memory dict. Mirrors the
    # internal transition made by ``BasePostgresStore._handle_failure`` on a
    # real connect failure (see postgres_store.py:_handle_failure).
    store._mode = "degraded_memory"  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    store._memory_backend = store._init_memory_backend()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    return store


@pytest.mark.unit
async def test_broker_source_state_disabled_source_is_skipped() -> None:
    """AC-3.7: disabled source surfaces under ``source_disabled:*`` and no adapter runs."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        fakes = {
            "nvd_db": _FakeAdapter("nvd_db"),
            "internal_vulns": _FakeAdapter("internal_vulns"),
        }
        # Swap real adapters for the doubles — same pattern as
        # ``tests/unit/test_broker.py::_install_fakes``.
        broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
        broker._connected_adapters = set(fakes.keys())  # type: ignore[attr-defined]  # noqa: SLF001

        # Inject an in-memory SourceStateStore and disable ``nvd_db``.
        store = await _make_memory_store()
        await store.set_enabled("nvd_db", enabled=False, reason="task-12 test", actor="test-actor")
        broker._source_state_store = store  # type: ignore[attr-defined]  # noqa: SLF001

        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())

        # The disabled source never reached the adapter layer.
        assert fakes["nvd_db"].execute_calls == 0, "disabled source must not be executed"
        # The surviving source was queried.
        assert resp.sources_queried == ["internal_vulns"]
        # ``source_disabled:nvd_db`` appears in the skipped list (FR-29).
        assert "source_disabled:nvd_db" in resp.sources_skipped, (
            f"expected source_disabled:nvd_db in sources_skipped; got {resp.sources_skipped!r}"
        )
    finally:
        await broker.aclose()


@pytest.mark.unit
async def test_broker_source_state_enabled_source_runs_normally() -> None:
    """Non-disabled sources are unaffected by the filter (NFR-5 back-compat)."""
    broker = Broker.from_config(FIXTURE_PATH)
    try:
        fakes = {
            "nvd_db": _FakeAdapter("nvd_db"),
            "internal_vulns": _FakeAdapter("internal_vulns"),
        }
        broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
        broker._connected_adapters = set(fakes.keys())  # type: ignore[attr-defined]  # noqa: SLF001

        store = await _make_memory_store()
        # Explicit enable — should be a no-op vs. the "no row" default.
        await store.set_enabled("nvd_db", enabled=True, reason=None, actor="test-actor")
        broker._source_state_store = store  # type: ignore[attr-defined]  # noqa: SLF001

        resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())

        # Both adapters ran exactly once.
        assert fakes["nvd_db"].execute_calls == 1
        assert fakes["internal_vulns"].execute_calls == 1
        # No ``source_disabled:*`` markers leaked into the skipped list.
        assert not any(s.startswith("source_disabled:") for s in resp.sources_skipped), (
            f"no source_disabled markers expected; got {resp.sources_skipped!r}"
        )
    finally:
        await broker.aclose()
