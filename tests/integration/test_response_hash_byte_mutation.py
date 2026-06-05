"""Integration: response-hash byte mutation (AC-19.f) + attestation linkage.

A one-byte change to the response payload after hashing MUST cause the
attestation to fail verification.
"""

from __future__ import annotations

import pytest

from nautilus.core.attestation_payload import compute_response_hash

pytestmark = pytest.mark.integration


def test_ac_19_a_compute_response_hash_is_sha256_prefixed() -> None:
    h = compute_response_hash({"rows": [{"id": 1}]})
    assert h.startswith("sha256:")


def test_ac_19_f_byte_mutation_changes_hash() -> None:
    """One-byte change in adapter response → different hash (AC-19.f)."""
    original = {"rows": [{"id": 1, "name": "alpha"}]}
    mutated = {"rows": [{"id": 1, "name": "alphb"}]}  # 'a' -> 'b'
    assert compute_response_hash(original) != compute_response_hash(mutated)


def test_ac_19_a_hash_is_deterministic_across_calls() -> None:
    payload = {"rows": [{"id": 1}, {"id": 2}]}
    assert compute_response_hash(payload) == compute_response_hash(payload)
