"""Unit tests for per-source adapter response hashing (issue #19, AC-19).

These reproduce the gap identified in issue #19: PR #41 shipped a coarse,
broker-level hash over the whole synthesized response, but the design
(§5.7 Weakness 7) requires a per-source hash computed at the *adapter*
boundary over the adapter's own response, carried on
:class:`AdapterResult`.

Test A — :class:`AdapterResult` must carry a ``response_hash`` field and the
shared :func:`compute_raw_response_hash` helper must produce a
``sha256:``-prefixed, deterministic, byte-sensitive digest.
"""

from __future__ import annotations

import pytest

from nautilus.core.attestation_payload import compute_raw_response_hash
from nautilus.core.models import AdapterResult

pytestmark = pytest.mark.unit


def test_adapter_result_has_response_hash_field() -> None:
    """AC-19: a successful AdapterResult can carry a per-source response_hash."""
    rows = [{"id": 1, "cve": "CVE-2026-0001"}]
    result = AdapterResult(
        source_id="pg",
        rows=rows,
        duration_ms=1,
        response_hash=compute_raw_response_hash(rows),
    )
    assert result.response_hash is not None
    assert result.response_hash.startswith("sha256:")


def test_response_hash_defaults_to_none() -> None:
    """NFR-5: the field is optional so legacy/non-deterministic results round-trip."""
    result = AdapterResult(source_id="llm", rows=[], duration_ms=0)
    assert result.response_hash is None


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
