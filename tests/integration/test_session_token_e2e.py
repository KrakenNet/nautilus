"""Integration: session-token issuance + verification + rotation (#18 e2e)."""

from __future__ import annotations

import pytest

from nautilus.attestation.key_ring import KeyRing
from nautilus.attestation.session_token import (
    SessionTokenError,
    SessionTokenService,
)

pytestmark = pytest.mark.integration


def test_ac_18_a_b_issue_then_verify_round_trip() -> None:
    service = SessionTokenService(
        key_ring=KeyRing(), broker_instance_id="broker-int"
    )
    token = service.issue(
        session_id="s", agent_id="a", purpose="p", clearance="c"
    )
    claims = service.verify(token)
    assert claims.session_id == "s"


def test_ac_18_d_broker_instance_mismatch_is_rejected() -> None:
    ring = KeyRing()
    issuer = SessionTokenService(key_ring=ring, broker_instance_id="broker-a")
    verifier = SessionTokenService(key_ring=ring, broker_instance_id="broker-b")
    token = issuer.issue(
        session_id="s", agent_id="a", purpose="p", clearance="c"
    )
    with pytest.raises(SessionTokenError) as excinfo:
        verifier.verify(token)
    assert excinfo.value.reason_code == "broker_instance_mismatch"


def test_ac_18_e_rotation_overlap_window_holds_two_active_keys() -> None:
    ring = KeyRing()
    ring.rotate()
    active = ring.active()
    assert len(active) >= 2
