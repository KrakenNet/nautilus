"""Unit tests for :mod:`nautilus.attestation.jwks` (#18, AC-18.c)."""

from __future__ import annotations

import pytest

from nautilus.attestation.jwks import export_jwks
from nautilus.attestation.key_ring import KeyRing

pytestmark = pytest.mark.unit


def test_ac_18_c_jwks_contains_one_entry_per_active_key() -> None:
    ring = KeyRing()
    ring.rotate()
    jwks = export_jwks(ring)
    assert "keys" in jwks
    assert isinstance(jwks["keys"], list)
    kids_in_jwks = {entry["kid"] for entry in jwks["keys"]}
    kids_active = {entry.kid for entry in ring.active()}
    assert kids_in_jwks == kids_active


def test_ac_18_c_jwks_entries_carry_ed25519_metadata() -> None:
    ring = KeyRing()
    jwks = export_jwks(ring)
    for entry in jwks["keys"]:
        assert entry.get("kty") == "OKP"
        assert entry.get("crv") == "Ed25519"
