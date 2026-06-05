"""Integration: rule retraction + lineage cascade (#35.10)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nautilus.rkm.lineage import LineageRecord, LineageStore

pytestmark = pytest.mark.integration


def _make(name: str, *, version: int = 1, derived_from: tuple[str, ...] = ()) -> LineageRecord:
    return LineageRecord(
        rule_name=name,
        version=version,
        proposer="meta-rule:pattern-tracker",
        observation_ids={"start": 0, "end": 10},
        sandbox_results={},
        approver="alice@example.com",
        derived_from=derived_from,
        promoted_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def test_ac_35_10_d_cascade_retracts_all_descendants() -> None:
    store = LineageStore()
    store.insert(_make("a"))
    store.insert(_make("b", derived_from=("a",)))
    store.insert(_make("c", derived_from=("b",)))
    affected = store.mark_retired(
        "a",
        version=1,
        reason="superseded",
        reviewer="alice@example.com",
        cascade="cascade",
    )
    assert set(affected) >= {"b", "c"}


def test_ac_35_10_d_orphan_children_retracts_only_named() -> None:
    store = LineageStore()
    store.insert(_make("a"))
    store.insert(_make("b", derived_from=("a",)))
    affected = store.mark_retired(
        "a",
        version=1,
        reason="superseded",
        reviewer="alice@example.com",
        cascade="orphan-children",
    )
    assert "b" in affected
    # b is flagged but not retracted — still queryable.
    record = store.get("b", version=1)
    assert record is not None
    assert record.retired_at is None
