"""Unit coverage for :meth:`SourceStateStore.set_enabled` audit emission (Task 15, US-3).

Pins the three behaviours required by FR-59:

(a) ``set_enabled`` emits exactly one :class:`AuditEntry` per write with
    ``event_type="source_state_changed"``, ``sources_queried == [source_id]``,
    and ``agent_id == actor``.
(b) Idempotent double-disable emits TWO entries (not one) — every call
    bumps ``changed_at`` and is a genuine state-change event per FR-59.
(c) ``audit_logger=None`` skips the emit without raising — unit tests that
    don't care about audit aren't forced to wire a logger.
"""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus.core.models import AuditEntry
from nautilus.core.source_state import SourceStateStore


def _install_asyncpg_stub() -> None:
    """Mirror the shim in ``test_source_state.py`` so the store imports cleanly."""
    if "asyncpg" not in sys.modules:
        stub = types.ModuleType("asyncpg")
        stub.create_pool = AsyncMock()  # type: ignore[attr-defined]
        sys.modules["asyncpg"] = stub


_install_asyncpg_stub()


async def _degraded_store(audit_logger: Any = None) -> SourceStateStore:
    """Build a degraded-memory :class:`SourceStateStore` wired to ``audit_logger``.

    Forces the ``degraded_memory`` branch directly so ``setup()`` is a no-op
    and ``set_enabled`` operates on the in-memory dict. Mirrors the internal
    transition made by ``BasePostgresStore._handle_failure`` on real connect
    failure — same pattern as ``test_broker_source_state.py``.
    """
    store = SourceStateStore(
        "postgres://ignored/src_state",
        on_failure="fallback_memory",
        audit_logger=audit_logger,
    )
    store._mode = "degraded_memory"  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    store._memory_backend = store._init_memory_backend()  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    return store


# ---------------------------------------------------------------------------
# (a) single set_enabled → one AuditEntry with the expected shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_set_enabled_emits_source_state_changed_audit() -> None:
    """``set_enabled`` calls ``audit_logger.emit`` once with the expected entry (FR-59)."""
    audit_logger = MagicMock()
    audit_logger.emit = MagicMock(return_value=None)

    store = await _degraded_store(audit_logger=audit_logger)
    await store.set_enabled("adapter.a", enabled=False, reason="maintenance", actor="op.sean")

    assert audit_logger.emit.call_count == 1
    (entry,) = audit_logger.emit.call_args.args
    assert isinstance(entry, AuditEntry)
    assert entry.event_type == "source_state_changed"
    assert entry.sources_queried == ["adapter.a"]
    assert entry.agent_id == "op.sean"
    # Placeholder fields collapse to empty per FR-59.
    assert entry.raw_intent == ""
    assert entry.facts_asserted_summary == {}
    assert entry.denial_records == []
    assert entry.error_records == []
    assert entry.rule_trace == []
    assert entry.sources_denied == []
    assert entry.sources_errored == []
    assert entry.duration_ms == 0
    assert entry.attestation_token is None
    # Synthetic request_id uses the documented prefix so audit consumers can
    # partition source-state events from request events.
    assert entry.request_id.startswith("src-state-")


# ---------------------------------------------------------------------------
# (b) idempotent double-disable emits TWO audit entries
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_double_disable_emits_two_audit_entries() -> None:
    """Each ``set_enabled`` is a genuine state-change event — no dedup (FR-59)."""
    audit_logger = MagicMock()
    audit_logger.emit = MagicMock(return_value=None)

    store = await _degraded_store(audit_logger=audit_logger)

    await store.set_enabled("adapter.a", enabled=False, reason="maintenance", actor="op.sean")
    await store.set_enabled("adapter.a", enabled=False, reason="maintenance", actor="op.sean")

    assert audit_logger.emit.call_count == 2
    first_entry: AuditEntry = audit_logger.emit.call_args_list[0].args[0]
    second_entry: AuditEntry = audit_logger.emit.call_args_list[1].args[0]
    # Both carry the same event_type / target; only the synthetic request_id
    # and changed_at timestamp differ.
    assert first_entry.event_type == "source_state_changed"
    assert second_entry.event_type == "source_state_changed"
    assert first_entry.sources_queried == ["adapter.a"]
    assert second_entry.sources_queried == ["adapter.a"]
    assert first_entry.request_id != second_entry.request_id


# ---------------------------------------------------------------------------
# (c) audit_logger=None is a clean no-op (no crash)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_set_enabled_no_audit_logger_is_noop() -> None:
    """``audit_logger=None`` skips the emit without raising (unit-test ergonomics)."""
    store = await _degraded_store(audit_logger=None)

    # Must not raise and must still persist the in-memory row.
    state = await store.set_enabled("adapter.a", enabled=True, reason=None, actor="op.sean")
    assert state.source_id == "adapter.a"
    assert state.enabled is True
