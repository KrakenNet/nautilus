"""Unit tests for :mod:`nautilus.attestation.key_ring` (#18, AC-18.e)."""

from __future__ import annotations

import pytest

from nautilus.attestation.key_ring import KeyEntry, KeyRing

pytestmark = pytest.mark.unit


def test_ac_18_e_key_ring_has_primary_at_init() -> None:
    """``KeyRing`` autogenerates a primary on first use (Failure modes table)."""
    ring = KeyRing()
    primary = ring.primary()
    assert isinstance(primary, KeyEntry)
    assert primary.status == "primary"


def test_ac_18_e_rotate_marks_previous_primary_rotating_out() -> None:
    ring = KeyRing()
    old_primary = ring.primary()
    new_primary = ring.rotate()
    assert new_primary.kid != old_primary.kid
    assert new_primary.status == "primary"
    previous = ring.verifier_for(old_primary.kid)
    assert previous is not None
    assert previous.status == "rotating-out"


def test_ac_18_e_active_returns_primary_and_rotating_out() -> None:
    ring = KeyRing()
    ring.rotate()
    active = ring.active()
    statuses = {entry.status for entry in active}
    assert statuses == {"primary", "rotating-out"}


def test_ac_18_e_revoke_marks_status_revoked() -> None:
    ring = KeyRing()
    old = ring.primary()
    ring.rotate()
    ring.revoke(old.kid, reason="compromised", reviewer="alice@example.com")
    entry = ring.verifier_for(old.kid)
    assert entry is not None
    assert entry.status == "revoked"
