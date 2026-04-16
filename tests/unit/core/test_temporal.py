"""Unit coverage for :mod:`nautilus.core.temporal` (Task 3.3).

Four canonical cases for :class:`TemporalFilter.apply`:

(a) ``expires_at`` in the past → constraint dropped, one ``scope-expired``
    :class:`DenialRecord` emitted.
(b) ``valid_from`` in the future → constraint dropped, one ``scope-expired``
    denial emitted.
(c) Both slots empty → constraint kept, no denial.
(d) Malformed ISO-8601 timestamp → constraint dropped (fail-closed) with the
    denial reason flagged ``malformed`` so operators see a WARN-worthy line.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from nautilus.core.models import ScopeConstraint
from nautilus.core.temporal import TemporalFilter

# Fixed anchor point used by every case so the tests stay time-independent.
_NOW = datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC)


def _constraint(
    *,
    source_id: str = "src-1",
    field: str = "role",
    value: str = "viewer",
    expires_at: str | None = None,
    valid_from: str | None = None,
) -> ScopeConstraint:
    """Factory for a minimal-ceremony :class:`ScopeConstraint`."""
    return ScopeConstraint(
        source_id=source_id,
        field=field,
        operator="=",
        value=value,
        expires_at=expires_at,
        valid_from=valid_from,
    )


@pytest.mark.unit
def test_expires_at_in_past_drops_with_scope_expired_denial() -> None:
    """(a) Past ``expires_at`` → dropped + single ``scope-expired`` denial."""
    scope = {"src-1": [_constraint(expires_at="2020-01-01T00:00:00Z")]}
    kept, denials = TemporalFilter.apply(scope, _NOW)

    assert kept == {"src-1": []}
    assert len(denials) == 1
    denial = denials[0]
    assert denial.rule_name == "scope-expired"
    assert denial.source_id == "src-1"
    assert "expires_at" in denial.reason
    assert "past" in denial.reason


@pytest.mark.unit
def test_valid_from_in_future_drops_with_scope_expired_denial() -> None:
    """(b) Future ``valid_from`` → dropped + single ``scope-expired`` denial."""
    scope = {"src-1": [_constraint(valid_from="2099-01-01T00:00:00Z")]}
    kept, denials = TemporalFilter.apply(scope, _NOW)

    assert kept == {"src-1": []}
    assert len(denials) == 1
    denial = denials[0]
    assert denial.rule_name == "scope-expired"
    assert "valid_from" in denial.reason
    assert "future" in denial.reason


@pytest.mark.unit
def test_both_temporal_slots_empty_keeps_constraint() -> None:
    """(c) Neither ``expires_at`` nor ``valid_from`` set → constraint kept."""
    kept_constraint = _constraint()
    scope = {"src-1": [kept_constraint]}
    kept, denials = TemporalFilter.apply(scope, _NOW)

    assert kept["src-1"] == [kept_constraint]
    assert denials == []


@pytest.mark.unit
def test_malformed_iso8601_drops_with_warn_flagged_denial() -> None:
    """(d) Malformed timestamp → dropped + denial whose reason flags ``malformed``.

    The WARN signal is encoded in the denial reason (string starts with
    ``"malformed "``) so log plumbing can pattern-match without coupling to
    a secondary log channel.
    """
    scope = {
        "src-1": [_constraint(expires_at="not-a-real-timestamp")],
        "src-2": [_constraint(valid_from="also-not-a-date")],
    }
    kept, denials = TemporalFilter.apply(scope, _NOW)

    assert kept["src-1"] == []
    assert kept["src-2"] == []
    assert len(denials) == 2
    reasons = sorted(d.reason for d in denials)
    assert all("malformed" in r for r in reasons)
    # Rule name stays ``scope-expired`` (fail-closed precedence, design §3.9).
    assert {d.rule_name for d in denials} == {"scope-expired"}
