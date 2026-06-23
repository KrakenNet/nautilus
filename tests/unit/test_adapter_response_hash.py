"""Unit tests for per-source adapter response hashing (issue #19, AC-19).

These reproduce the gap identified in issue #19: PR #41 shipped a coarse,
broker-level hash over the whole synthesized response, but the design
(§5.7 Weakness 7) requires a per-source hash computed at the *adapter*
boundary over the adapter's own response, carried on
:class:`AdapterResult`.

Test A — the broker owns hashing: :class:`AdapterResult` exposes NO
``response_hash`` field (issue #56 review — an adapter-supplied digest would be
an unverifiable trust channel into the signed attestation), and the shared
:func:`compute_raw_response_hash` helper produces a ``sha256:``-prefixed,
deterministic, byte-sensitive digest.
"""

from __future__ import annotations

import pytest

from nautilus.core.attestation_payload import compute_raw_response_hash
from nautilus.core.models import AdapterResult

pytestmark = pytest.mark.unit


def test_adapter_result_has_no_response_hash_field() -> None:
    """Security (issue #56 review): AdapterResult must NOT expose a
    ``response_hash`` field. The per-source digest is computed centrally by the
    broker over ``rows`` (``Broker._gather_adapter_results``); an adapter-supplied
    digest would let a malicious/buggy adapter forge the signed attestation.
    """
    assert "response_hash" not in AdapterResult.model_fields


def test_compute_raw_response_hash_is_sha256_prefixed() -> None:
    h = compute_raw_response_hash([{"id": 1}])
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64  # hex sha256 digest


def test_compute_raw_response_hash_is_deterministic() -> None:
    rows = [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}]
    assert compute_raw_response_hash(rows) == compute_raw_response_hash(rows)


def test_compute_raw_response_hash_ignores_dict_key_order() -> None:
    a = [{"id": 1, "name": "alpha"}]
    b = [{"name": "alpha", "id": 1}]
    assert compute_raw_response_hash(a) == compute_raw_response_hash(b)


def test_compute_raw_response_hash_detects_byte_mutation() -> None:
    """A one-byte change in any row yields a different hash (AC-19.f)."""
    original = [{"id": 1, "name": "alpha"}]
    mutated = [{"id": 1, "name": "alphb"}]
    assert compute_raw_response_hash(original) != compute_raw_response_hash(mutated)
