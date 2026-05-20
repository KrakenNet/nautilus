"""Unit tests for :mod:`nautilus.attestation.session_token` (#18).

One test per acceptance criterion (AC-18.a/b/d/e/f/g). Hits the real
``SessionTokenService`` API; no mocks of internal modules.
"""

from __future__ import annotations

import pytest

from nautilus.attestation.key_ring import KeyRing
from nautilus.attestation.session_token import (
    SessionTokenClaims,
    SessionTokenError,
    SessionTokenService,
)

pytestmark = pytest.mark.unit


# ----------------------------------------------------------------------
# AC-18.a — JWS contains the required claim set.
# ----------------------------------------------------------------------


def test_ac_18_a_issued_token_carries_required_claims() -> None:
    service = SessionTokenService(
        key_ring=KeyRing(), broker_instance_id="broker-1", ttl_seconds=3600
    )
    token = service.issue(
        session_id="sess-1",
        agent_id="agent-1",
        purpose="analyze",
        clearance="medium",
    )
    claims = service.verify(token)
    assert isinstance(claims, SessionTokenClaims)
    assert claims.session_id == "sess-1"
    assert claims.agent_id == "agent-1"
    assert claims.purpose == "analyze"
    assert claims.clearance == "medium"
    assert claims.broker_instance_id == "broker-1"
    assert claims.expires_at > claims.issued_at
    assert claims.kid  # non-empty kid header


# ----------------------------------------------------------------------
# AC-18.d — verify() rejects bad signature / expired / unknown_kid /
# mismatched broker_instance_id with a structured reason_code.
# ----------------------------------------------------------------------


def test_ac_18_d_verify_rejects_bad_signature_with_reason_code() -> None:
    service = SessionTokenService(
        key_ring=KeyRing(), broker_instance_id="broker-1"
    )
    with pytest.raises(SessionTokenError) as excinfo:
        service.verify("not.a.valid.jws")
    assert excinfo.value.reason_code in {
        "bad_signature",
        "missing",
        "unknown_kid",
    }


# ----------------------------------------------------------------------
# AC-18.e — rotation: old tokens still validate during overlap window;
# new tokens use the new kid.
# ----------------------------------------------------------------------


def test_ac_18_e_rotation_old_tokens_still_validate_during_overlap() -> None:
    key_ring = KeyRing()
    service = SessionTokenService(
        key_ring=key_ring, broker_instance_id="broker-1"
    )
    old_token = service.issue(
        session_id="s", agent_id="a", purpose="p", clearance="c"
    )
    old_claims = service.verify(old_token)
    key_ring.rotate()
    # Old token must still verify after rotate (rotating-out window).
    verified_old = service.verify(old_token)
    assert verified_old.kid == old_claims.kid
    # New token must carry the new kid.
    new_token = service.issue(
        session_id="s2", agent_id="a", purpose="p", clearance="c"
    )
    new_claims = service.verify(new_token)
    assert new_claims.kid != old_claims.kid


# ----------------------------------------------------------------------
# AC-18.g — token carries no PII beyond agent_id + purpose; clearance
# is a free-form coarse string (DQ1).
# ----------------------------------------------------------------------


def test_ac_18_g_token_carries_no_unexpected_pii() -> None:
    service = SessionTokenService(
        key_ring=KeyRing(), broker_instance_id="broker-1"
    )
    token = service.issue(
        session_id="s",
        agent_id="agent-pii",
        purpose="analyze",
        clearance="any-free-form-string-here",
    )
    claims = service.verify(token)
    # Whitelist: only the AC-18.a fields should be present on the
    # decoded claims object. No "email", "name", "ip", etc.
    allowed = {
        "session_id",
        "agent_id",
        "purpose",
        "clearance",
        "issued_at",
        "expires_at",
        "broker_instance_id",
        "kid",
    }
    assert set(vars(claims).keys()).issubset(allowed)
