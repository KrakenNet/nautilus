"""Unit tests for the three new ``_has_*`` attestation helpers (spec Task 9).

Exercises :func:`nautilus.core.attestation_payload._has_cost_cap_context`,
:func:`nautilus.core.attestation_payload._has_fact_set_hash`, and
:func:`nautilus.core.attestation_payload._has_session_signatures`, plus
the corresponding conditional-on-presence extension of
:func:`nautilus.core.attestation_payload.build_payload`.

True / False boundary is enforced per helper; the payload-level tests
prove each new key appears only when its helper returns True
(NFR-ATT-V2-FROZEN's conditional strictness).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from nautilus.core.attestation_payload import (
    _has_cost_cap_context,  # pyright: ignore[reportPrivateUsage]
    _has_fact_set_hash,  # pyright: ignore[reportPrivateUsage]
    _has_session_signatures,  # pyright: ignore[reportPrivateUsage]
    build_payload,
)

# ---------------------------------------------------------------------------
# Helper unit tests — True/False boundary per helper.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_has_cost_cap_context_true_when_response_cap_breached() -> None:
    """``response.cap_breached`` truthy → helper fires."""
    response = SimpleNamespace(cap_breached=True, source_session_signatures=None)
    assert _has_cost_cap_context(None, response) is True


@pytest.mark.unit
def test_has_cost_cap_context_false_when_none() -> None:
    """Missing response → helper returns False (legacy callers safe)."""
    assert _has_cost_cap_context(None, None) is False


@pytest.mark.unit
def test_has_cost_cap_context_false_when_cap_not_breached() -> None:
    """``cap_breached=False`` → helper returns False (Task 20 branch still latent)."""
    response = SimpleNamespace(cap_breached=False, source_session_signatures=None)
    assert _has_cost_cap_context(None, response) is False


@pytest.mark.unit
def test_has_fact_set_hash_true_when_populated() -> None:
    """Non-empty ``request.fact_set_hash`` → helper fires."""
    request = SimpleNamespace(fact_set_hash="abc123")
    assert _has_fact_set_hash(request) is True


@pytest.mark.unit
def test_has_fact_set_hash_false_when_none() -> None:
    """None request or empty ``fact_set_hash`` → helper returns False."""
    assert _has_fact_set_hash(None) is False
    assert _has_fact_set_hash(SimpleNamespace(fact_set_hash=None)) is False
    assert _has_fact_set_hash(SimpleNamespace(fact_set_hash="")) is False


@pytest.mark.unit
def test_has_session_signatures_true_when_populated() -> None:
    """Non-empty ``response.source_session_signatures`` → helper fires."""
    response = SimpleNamespace(source_session_signatures={"llm_a": {"dsse": "env"}})
    assert _has_session_signatures(response) is True


@pytest.mark.unit
def test_has_session_signatures_false_when_none_or_empty() -> None:
    """None response or empty dict → helper returns False."""
    assert _has_session_signatures(None) is False
    assert _has_session_signatures(SimpleNamespace(source_session_signatures=None)) is False
    assert _has_session_signatures(SimpleNamespace(source_session_signatures={})) is False


# ---------------------------------------------------------------------------
# build_payload conditional-on-presence tests.
# ---------------------------------------------------------------------------


def _v2_scope() -> list[dict[str, object]]:
    """A scope-constraint list that forces v2 routing (populated temporal slot)."""
    return [
        {
            "source_id": "src-a",
            "field": "role",
            "operator": "=",
            "value": "viewer",
            "expires_at": "2099-01-01T00:00:00Z",
            "valid_from": "",
        }
    ]


@pytest.mark.unit
def test_v2_payload_omits_all_new_keys_when_request_response_none() -> None:
    """Legacy 5-positional-arg caller → none of the three new keys appear."""
    payload, version = build_payload("r", "a", ["s"], _v2_scope(), [])
    assert version == "v2"
    for forbidden in ("cost_cap_context", "fact_set_hash", "session_signatures"):
        assert forbidden not in payload


@pytest.mark.unit
def test_v2_payload_includes_fact_set_hash_only_when_helper_true() -> None:
    """``fact_set_hash`` key appears iff ``_has_fact_set_hash`` fires."""
    empty_req = SimpleNamespace(fact_set_hash=None)
    payload_absent, _ = build_payload("r", "a", ["s"], _v2_scope(), [], request=empty_req)
    assert "fact_set_hash" not in payload_absent

    populated_req = SimpleNamespace(fact_set_hash="hash-xyz")
    payload_present, _ = build_payload("r", "a", ["s"], _v2_scope(), [], request=populated_req)
    assert payload_present["fact_set_hash"] == "hash-xyz"


@pytest.mark.unit
def test_v2_payload_includes_session_signatures_only_when_helper_true() -> None:
    """``session_signatures`` key appears iff ``_has_session_signatures`` fires."""
    empty_resp = SimpleNamespace(cap_breached=None, source_session_signatures=None)
    payload_absent, _ = build_payload("r", "a", ["s"], _v2_scope(), [], response=empty_resp)
    assert "session_signatures" not in payload_absent

    sigs = {"llm_a": {"dsse": "env-1"}}
    populated_resp = SimpleNamespace(cap_breached=None, source_session_signatures=sigs)
    payload_present, _ = build_payload("r", "a", ["s"], _v2_scope(), [], response=populated_resp)
    assert payload_present["session_signatures"] == sigs


@pytest.mark.unit
def test_v2_payload_includes_cost_cap_context_only_when_helper_true() -> None:
    """``cost_cap_context`` key appears iff ``_has_cost_cap_context`` fires."""
    unbreached = SimpleNamespace(cap_breached=False, source_session_signatures=None)
    payload_absent, _ = build_payload("r", "a", ["s"], _v2_scope(), [], response=unbreached)
    assert "cost_cap_context" not in payload_absent

    breached = SimpleNamespace(cap_breached=True, source_session_signatures=None)
    payload_present, _ = build_payload("r", "a", ["s"], _v2_scope(), [], response=breached)
    assert payload_present["cost_cap_context"] == {"cap_breached": True}
