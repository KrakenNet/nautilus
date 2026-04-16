"""Additional canonicalization smokes for :mod:`nautilus.core.attestation_payload`.

Bridges the Phase-2 coverage gap on the v1/v2 selection logic ahead of
`[VERIFY] 2.5`. Full determinism harness + v2 cross-version round-trip
tests live in Phase 3 (Task 3.14 — NFR-6 backwards compat).

Covered here:

- Empty constraint list → ``"v1"`` with a stable digest.
- Constraint carrying only ``valid_from`` (no ``expires_at``) → ``"v2"``.
- Constraint carrying only ``expires_at`` → ``"v2"``.
- Multiple constraints canonicalised into sorted order (same digest
  regardless of input order).
- Broker-internal ``dict[source_id, list[ScopeConstraint]]`` shape flattens
  to the Phase-1 4-key list when no temporal slot is present (NFR-6).
"""

from __future__ import annotations

import pytest

from nautilus.core.attestation_payload import build_payload
from nautilus.core.models import ScopeConstraint


@pytest.mark.unit
def test_empty_scope_list_yields_v1() -> None:
    """Empty ``scope_constraints`` stays on the v1 path."""
    payload, version = build_payload("r", "a", ["s"], [], [])
    assert version == "v1"
    assert payload["scope_hash"].startswith("sha256:")


@pytest.mark.unit
def test_valid_from_only_triggers_v2() -> None:
    """``valid_from`` populated → v2 even without ``expires_at``."""
    scope = [
        {
            "source_id": "s",
            "field": "role",
            "operator": "=",
            "value": "viewer",
            "valid_from": "2026-01-01T00:00:00Z",
        }
    ]
    _, version = build_payload("r", "a", ["s"], scope, [])
    assert version == "v2"


@pytest.mark.unit
def test_expires_at_only_triggers_v2() -> None:
    """``expires_at`` populated → v2 even without ``valid_from``."""
    scope = [
        {
            "source_id": "s",
            "field": "role",
            "operator": "=",
            "value": "viewer",
            "expires_at": "2099-01-01T00:00:00Z",
        }
    ]
    _, version = build_payload("r", "a", ["s"], scope, [])
    assert version == "v2"


@pytest.mark.unit
def test_v2_canonicalization_is_order_independent() -> None:
    """v2 sorts by ``(source_id, field, operator)`` → input order can't
    shift the digest (design §3.10, FR-19)."""
    forward = [
        {
            "source_id": "s-a",
            "field": "role",
            "operator": "=",
            "value": "viewer",
            "expires_at": "2099-01-01T00:00:00Z",
        },
        {
            "source_id": "s-a",
            "field": "team",
            "operator": "IN",
            "value": ["x", "y"],
            "expires_at": "2099-01-01T00:00:00Z",
        },
    ]
    reversed_ = list(reversed(forward))
    a, va = build_payload("r", "a", ["s-a"], forward, [])
    b, vb = build_payload("r", "a", ["s-a"], reversed_, [])
    assert va == vb == "v2"
    assert a["scope_hash"] == b["scope_hash"]


@pytest.mark.unit
def test_empty_string_temporal_slots_do_not_trigger_v2() -> None:
    """An explicit empty string for ``expires_at`` / ``valid_from`` is
    treated as unset (falsy) so the v1 path is preserved (NFR-6)."""
    scope = [
        {
            "source_id": "s",
            "field": "role",
            "operator": "=",
            "value": "viewer",
            "expires_at": "",
            "valid_from": "",
        }
    ]
    _, version = build_payload("r", "a", ["s"], scope, [])
    assert version == "v1"


@pytest.mark.unit
def test_internal_dict_shape_flattens_to_v1_when_no_temporal_slots() -> None:
    """``dict[source_id, list[ScopeConstraint]]`` without temporal slots
    must produce the same v1 digest as the pre-flattened list form so
    Phase-1 tokens remain verifiable."""
    flat = [
        {"source_id": "s", "field": "role", "operator": "=", "value": "viewer"},
    ]
    internal = {
        "s": [
            ScopeConstraint(
                source_id="s",
                field="role",
                operator="=",
                value="viewer",
            )
        ]
    }
    flat_payload, flat_v = build_payload("r", "a", ["s"], flat, [])
    internal_payload, internal_v = build_payload("r", "a", ["s"], internal, [])
    assert flat_v == internal_v == "v1"
    assert flat_payload["scope_hash"] == internal_payload["scope_hash"]


@pytest.mark.unit
def test_internal_dict_shape_triggers_v2_when_temporal_slot_populated() -> None:
    """Broker's internal dict shape carrying an ``expires_at`` on any
    bucketed :class:`ScopeConstraint` lights up the v2 path."""
    internal = {
        "s": [
            ScopeConstraint(
                source_id="s",
                field="role",
                operator="=",
                value="viewer",
                expires_at="2099-01-01T00:00:00Z",
            )
        ]
    }
    _, version = build_payload("r", "a", ["s"], internal, [])
    assert version == "v2"
