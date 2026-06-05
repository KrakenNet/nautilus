"""Unit tests for :mod:`nautilus.rkm.lineage` (#35.10)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nautilus.rkm.lineage import LineageCycleError, LineageRecord, LineageStore

pytestmark = pytest.mark.unit


def _make_record(
    name: str, *, version: int = 1, derived_from: tuple[str, ...] = ()
) -> LineageRecord:
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


def test_ac_35_10_b_insert_and_get_round_trip(tmp_path: Path) -> None:
    store = LineageStore()
    record = _make_record("rule_a")
    store.insert(record)
    fetched = store.get("rule_a", version=1)
    assert fetched is not None
    assert fetched.rule_name == "rule_a"


def test_ac_35_10_b_history_returns_all_versions_oldest_first() -> None:
    store = LineageStore()
    store.insert(_make_record("rule_a", version=1))
    store.insert(_make_record("rule_a", version=2))
    history = store.history("rule_a")
    assert [r.version for r in history] == [1, 2]


def test_ac_35_10_c_descendants_returns_child_rules() -> None:
    store = LineageStore()
    store.insert(_make_record("parent"))
    store.insert(_make_record("child", derived_from=("parent",)))
    descendants = store.descendants("parent")
    assert "child" in descendants


def test_ac_35_10_b_cycle_detection_raises() -> None:
    store = LineageStore()
    store.insert(_make_record("a"))
    store.insert(_make_record("b", derived_from=("a",)))
    # a's new version listing b as parent would close an a → b → a cycle.
    cyclic = _make_record("a", version=2, derived_from=("b",))
    with pytest.raises(LineageCycleError):
        store.insert(cyclic)


def test_ac_35_10_d_mark_retired_returns_affected_descendants() -> None:
    store = LineageStore()
    store.insert(_make_record("parent"))
    store.insert(_make_record("child", derived_from=("parent",)))
    affected = store.mark_retired(
        "parent",
        version=1,
        reason="superseded",
        reviewer="alice@example.com",
        cascade="orphan-children",
    )
    assert "child" in affected
