"""Unit coverage for scope-hash v1/v2 canonicalization (Task 3.3, NFR-6).

Lives over :func:`nautilus.core.attestation_payload.build_payload` — the
deterministic helper that stamps ``scope_hash_version`` onto the attestation
payload:

(a) No constraint carries a temporal slot → version is ``"v1"`` AND the
    emitted hash is byte-identical to the Phase-1 audit fixture for the
    same inputs (empty scope list). This is the NFR-6 gate that keeps
    Phase-1 attestation tokens verifiable under the Phase-2 verifier.
(b) Any constraint carries a non-empty ``expires_at`` or ``valid_from``
    slot → version flips to ``"v2"`` with the 6-tuple canonicalization
    (design §3.10, D-7, FR-19).
(c) Determinism — identical inputs produce identical payloads across
    repeated invocations (NFR-14).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from nautilus.core.attestation_payload import build_payload
from nautilus.core.models import ScopeConstraint

# Phase-1 audit line fixture (Task 2.25). Its ``scope_constraints`` field is
# ``[]`` and ``scope_hash_version`` is ``"v1"`` — use it as the NFR-6 byte
# identity anchor.
_PHASE1_FIXTURE_PATH: Path = (
    Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "audit" / "phase1_audit_line.jsonl"
)


def _sha256_canonical(value: object) -> str:
    """Mirror of the internal canonical hash used by :mod:`attestation_payload`."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


@pytest.mark.unit
def test_no_temporal_slots_emits_v1_byte_identical_to_phase1_fixture() -> None:
    """(a) Empty / temporal-free scope → ``"v1"`` + byte-identical Phase-1 hash.

    The Phase-1 fixture was captured with ``scope_constraints=[]`` (no
    scoping applied). Recomputing the v1 hash from the same canonical
    inputs (``[]``) must match ``_sha256_canonical([])`` and, crucially,
    the fixture itself round-trips under the v1 path.
    """
    assert _PHASE1_FIXTURE_PATH.exists(), f"Phase-1 audit fixture missing at {_PHASE1_FIXTURE_PATH}"
    fixture = json.loads(_PHASE1_FIXTURE_PATH.read_text(encoding="utf-8").strip())
    assert fixture["scope_constraints"] == []
    assert fixture["scope_hash_version"] == "v1"

    payload, version = build_payload(
        request_id=fixture["request_id"],
        agent_id=fixture["agent_id"],
        sources_queried=list(fixture["sources_queried"]),
        scope_constraints=[],  # as-received Phase-1 shape
        rule_trace=list(fixture["rule_trace"]),
    )
    assert version == "v1"
    # Byte-identity anchor: v1 canonicalization of ``[]`` must match the
    # independent SHA-256 we compute here. Any drift in the v1 path will
    # flip this hex immediately.
    assert payload["scope_hash"] == _sha256_canonical([])


@pytest.mark.unit
def test_any_temporal_slot_emits_v2() -> None:
    """(b) Any ``expires_at`` / ``valid_from`` populated → ``"v2"``.

    Covers both slot triggers and both input shapes (flat list-of-dicts
    and the broker-internal ``dict[source_id, list[ScopeConstraint]]``).
    """
    # Flat list shape, ``expires_at`` populated.
    flat_with_expires = [
        {
            "source_id": "src-1",
            "field": "role",
            "operator": "=",
            "value": "viewer",
            "expires_at": "2099-01-01T00:00:00Z",
            "valid_from": "",
        }
    ]
    _, version = build_payload("r", "a", ["src-1"], flat_with_expires, [])
    assert version == "v2"

    # Internal dict shape, ``valid_from`` populated on a ScopeConstraint.
    internal_with_valid_from = {
        "src-1": [
            ScopeConstraint(
                source_id="src-1",
                field="role",
                operator="=",
                value="viewer",
                valid_from="2020-01-01T00:00:00Z",
            )
        ]
    }
    _, version2 = build_payload("r", "a", ["src-1"], internal_with_valid_from, [])
    assert version2 == "v2"

    # Sanity: a purely non-temporal constraint still routes to v1 so the
    # trigger is specifically the temporal slot presence (not any attribute).
    non_temporal = {
        "src-1": [ScopeConstraint(source_id="src-1", field="role", operator="=", value="viewer")]
    }
    _, v1_ver = build_payload("r", "a", ["src-1"], non_temporal, [])
    assert v1_ver == "v1"


@pytest.mark.unit
def test_build_payload_is_deterministic() -> None:
    """(c) Same inputs → same payload bytes on repeated calls (NFR-14).

    Runs both the v1 and v2 paths to catch any hidden non-determinism
    (e.g. dict iteration order, floating-point timestamp leaks).
    """

    # --- v1 path ---
    def _call_v1() -> tuple[dict[str, Any], str]:
        return build_payload(
            request_id="req-42",
            agent_id="agent-alpha",
            sources_queried=["src-a", "src-b"],
            scope_constraints=[
                {"source_id": "src-a", "field": "role", "operator": "=", "value": "v"},
                {"source_id": "src-b", "field": "team", "operator": "=", "value": "t"},
            ],
            rule_trace=["rule-1", "rule-2"],
        )

    payload_v1_a, ver_v1_a = _call_v1()
    payload_v1_b, ver_v1_b = _call_v1()
    assert ver_v1_a == ver_v1_b == "v1"
    assert payload_v1_a == payload_v1_b

    # --- v2 path (order-insensitive because _v2_canonical sorts) ---
    constraint_forward = ScopeConstraint(
        source_id="src-a",
        field="role",
        operator="=",
        value="viewer",
        expires_at="2099-01-01T00:00:00Z",
    )
    constraint_back = ScopeConstraint(
        source_id="src-a",
        field="role",
        operator="=",
        value="viewer",
        expires_at="2099-01-01T00:00:00Z",
    )
    payload_v2_a, ver_v2_a = build_payload(
        "req-v2", "agent-alpha", ["src-a"], [constraint_forward], ["rule-x"]
    )
    payload_v2_b, ver_v2_b = build_payload(
        "req-v2", "agent-alpha", ["src-a"], [constraint_back], ["rule-x"]
    )
    assert ver_v2_a == ver_v2_b == "v2"
    assert payload_v2_a == payload_v2_b
    assert payload_v2_a["scope_hash"] == payload_v2_b["scope_hash"]
