"""Smoke coverage for :mod:`nautilus.core.temporal` (Task 2.5 bridge).

Interim Phase-2 coverage for :class:`TemporalFilter` so the `[VERIFY] 2.5`
checkpoint clears the 80% branch-coverage floor. The complete suite lands
in Phase 3 (Task 3.6). These smokes exercise the four documented branches:

- Empty / no-constraint input → no drops, no denials.
- Past ``expires_at`` → constraint dropped + single ``scope-expired`` denial.
- Future ``valid_from`` → constraint dropped + single ``scope-expired`` denial.
- Malformed ISO-8601 in either slot → fail-closed drop + denial.
- Multiple constraints across multiple sources → independent evaluation.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nautilus.core.models import ScopeConstraint
from nautilus.core.temporal import TemporalFilter

_NOW = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)


def _c(
    source_id: str = "src-1",
    *,
    field: str = "role",
    value: str = "viewer",
    expires_at: str | None = None,
    valid_from: str | None = None,
) -> ScopeConstraint:
    """Minimal-ceremony :class:`ScopeConstraint` factory for tests."""
    return ScopeConstraint(
        source_id=source_id,
        field=field,
        operator="=",
        value=value,
        expires_at=expires_at,
        valid_from=valid_from,
    )


@pytest.mark.unit
def test_apply_empty_constraints_returns_empty_denials() -> None:
    """No constraints → kept dict preserved (empty), denials list empty."""
    kept, denials = TemporalFilter.apply({}, _NOW)
    assert kept == {}
    assert denials == []


@pytest.mark.unit
def test_apply_preserves_constraints_without_temporal_slots() -> None:
    """Constraint with neither ``expires_at`` nor ``valid_from`` is kept."""
    scope = {"src-1": [_c()]}
    kept, denials = TemporalFilter.apply(scope, _NOW)
    assert len(kept["src-1"]) == 1
    assert denials == []


@pytest.mark.unit
def test_apply_drops_expired_constraint_and_emits_denial() -> None:
    """Past ``expires_at`` → dropped + ``scope-expired`` denial."""
    scope = {"src-1": [_c(expires_at="2020-01-01T00:00:00Z")]}
    kept, denials = TemporalFilter.apply(scope, _NOW)
    assert kept["src-1"] == []
    assert len(denials) == 1
    assert denials[0].source_id == "src-1"
    assert denials[0].rule_name == "scope-expired"
    assert "expires_at" in denials[0].reason
    assert "past" in denials[0].reason


@pytest.mark.unit
def test_apply_drops_not_yet_valid_constraint_and_emits_denial() -> None:
    """Future ``valid_from`` → dropped + ``scope-expired`` denial."""
    scope = {"src-1": [_c(valid_from="2099-01-01T00:00:00Z")]}
    kept, denials = TemporalFilter.apply(scope, _NOW)
    assert kept["src-1"] == []
    assert len(denials) == 1
    assert denials[0].rule_name == "scope-expired"
    assert "valid_from" in denials[0].reason
    assert "future" in denials[0].reason


@pytest.mark.unit
def test_apply_drops_malformed_expires_at_and_emits_denial() -> None:
    """Unparseable ``expires_at`` → fail-closed drop + denial."""
    scope = {"src-1": [_c(expires_at="not-a-real-timestamp")]}
    kept, denials = TemporalFilter.apply(scope, _NOW)
    assert kept["src-1"] == []
    assert len(denials) == 1
    assert "malformed" in denials[0].reason
    assert "expires_at" in denials[0].reason


@pytest.mark.unit
def test_apply_drops_malformed_valid_from_and_emits_denial() -> None:
    """Unparseable ``valid_from`` → fail-closed drop + denial."""
    scope = {"src-1": [_c(valid_from="garbage")]}
    kept, denials = TemporalFilter.apply(scope, _NOW)
    assert kept["src-1"] == []
    assert len(denials) == 1
    assert "malformed" in denials[0].reason
    assert "valid_from" in denials[0].reason


@pytest.mark.unit
def test_apply_keeps_constraint_inside_window() -> None:
    """Past ``valid_from`` + future ``expires_at`` → kept, no denial."""
    scope = {
        "src-1": [
            _c(
                valid_from="2020-01-01T00:00:00Z",
                expires_at="2099-01-01T00:00:00Z",
            )
        ]
    }
    kept, denials = TemporalFilter.apply(scope, _NOW)
    assert len(kept["src-1"]) == 1
    assert denials == []


@pytest.mark.unit
def test_apply_handles_multiple_constraints_across_sources() -> None:
    """Each source evaluated independently; drops localised to their bucket."""
    scope = {
        "src-a": [
            _c(source_id="src-a", field="role", expires_at="2020-01-01T00:00:00Z"),
            _c(source_id="src-a", field="team"),  # keep
        ],
        "src-b": [
            _c(source_id="src-b", field="region", valid_from="2099-01-01T00:00:00Z"),
        ],
    }
    kept, denials = TemporalFilter.apply(scope, _NOW)
    assert [c.field for c in kept["src-a"]] == ["team"]
    assert kept["src-b"] == []
    assert len(denials) == 2
    sources_with_denials = {d.source_id for d in denials}
    assert sources_with_denials == {"src-a", "src-b"}


@pytest.mark.unit
def test_apply_accepts_naive_now_by_treating_it_as_utc() -> None:
    """Naive ``now`` is promoted to UTC so comparisons don't raise."""
    naive_now = datetime(2026, 4, 15, 12, 0, 0)  # no tzinfo
    scope = {"src-1": [_c(expires_at="2020-01-01T00:00:00Z")]}
    kept, denials = TemporalFilter.apply(scope, naive_now)
    assert kept["src-1"] == []
    assert len(denials) == 1
