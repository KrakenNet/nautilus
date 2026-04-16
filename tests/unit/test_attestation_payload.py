"""Unit tests for :mod:`nautilus.core.attestation_payload` (Task 2.6).

Verifies design §9.3 payload shape and NFR-14 determinism — identical
inputs (including dict-key-reordered / nested-dict variants) must
produce bitwise-identical ``scope_hash`` / ``rule_trace_hash`` digests.

``build_payload`` returns ``(payload, version)`` from Task 1.12 onward
(design §3.10, D-7, FR-19); tests unpack both. Phase-1-shape inputs
(no ``expires_at`` / ``valid_from``) must return ``"v1"`` with the
frozen canonicalization so Phase-1 tokens remain verifiable (NFR-6).
"""

from __future__ import annotations

import pytest

from nautilus.core.attestation_payload import build_payload


@pytest.mark.unit
def test_payload_has_design_9_3_shape() -> None:
    """Payload exposes exactly the keys listed in design §9.3."""
    payload, version = build_payload("req-1", "agent-a", ["src-1"], [], [])
    assert set(payload) == {
        "iss",
        "request_id",
        "agent_id",
        "sources_queried",
        "scope_hash",
        "rule_trace_hash",
    }
    assert payload["iss"] == "nautilus"
    assert payload["scope_hash"].startswith("sha256:")
    assert payload["rule_trace_hash"].startswith("sha256:")
    assert version == "v1"


@pytest.mark.unit
def test_identical_inputs_yield_identical_hashes() -> None:
    """NFR-14 — same inputs, same digest, same payload (repeat calls)."""
    a, va = build_payload("r", "a", ["s"], [], {})
    b, vb = build_payload("r", "a", ["s"], [], {})
    assert a == b
    assert a["scope_hash"] == b["scope_hash"]
    assert a["rule_trace_hash"] == b["rule_trace_hash"]
    assert va == vb == "v1"


@pytest.mark.unit
def test_scope_hash_is_canonical_across_key_order() -> None:
    """Dict-key order inside scope constraints must not affect the hash."""
    scope_a = [
        {"source_id": "s", "field": "role", "operator": "=", "value": "viewer"},
        {"source_id": "s", "field": "team", "operator": "IN", "value": ["x", "y"]},
    ]
    # Same constraints, keys re-ordered within each dict.
    scope_b = [
        {"operator": "=", "value": "viewer", "field": "role", "source_id": "s"},
        {"value": ["x", "y"], "field": "team", "source_id": "s", "operator": "IN"},
    ]
    a, _ = build_payload("r", "a", ["s"], scope_a, [])
    b, _ = build_payload("r", "a", ["s"], scope_b, [])
    assert a["scope_hash"] == b["scope_hash"]


@pytest.mark.unit
def test_nested_dict_key_order_does_not_affect_hash() -> None:
    """Nested structures are canonicalized recursively via ``sort_keys``."""
    a, _ = build_payload("r", "a", ["s"], [{"outer": {"x": 1, "y": {"p": 2, "q": 3}}}], [])
    b, _ = build_payload("r", "a", ["s"], [{"outer": {"y": {"q": 3, "p": 2}, "x": 1}}], [])
    assert a["scope_hash"] == b["scope_hash"]


@pytest.mark.unit
def test_different_inputs_yield_different_hashes() -> None:
    """Sanity — distinct scope payloads must not collide."""
    a, _ = build_payload("r", "a", ["s"], [{"field": "role"}], [])
    b, _ = build_payload("r", "a", ["s"], [{"field": "team"}], [])
    assert a["scope_hash"] != b["scope_hash"]


@pytest.mark.unit
def test_rule_trace_hash_reflects_order() -> None:
    """Rule trace ordering is semantically meaningful → hash must change."""
    a, _ = build_payload("r", "a", ["s"], [], ["rule-1", "rule-2"])
    b, _ = build_payload("r", "a", ["s"], [], ["rule-2", "rule-1"])
    assert a["rule_trace_hash"] != b["rule_trace_hash"]


@pytest.mark.unit
def test_sources_queried_is_copied_not_referenced() -> None:
    """Mutating the caller's list must not corrupt the payload."""
    sources = ["s1"]
    payload, _ = build_payload("r", "a", sources, [], [])
    sources.append("s2")
    assert payload["sources_queried"] == ["s1"]
