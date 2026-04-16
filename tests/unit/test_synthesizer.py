"""Unit tests for :class:`nautilus.synthesis.basic.BasicSynthesizer` (Task 3.9).

Covers:
- AC-6.1 — ``merge()`` returns a ``{source_id: rows}`` dict for N inputs
  preserving each adapter's per-source shape.
- AC-6.2 — Partial failure: one adapter surfacing an ``ErrorRecord`` (pre-filter
  contract from design §3.6) or being omitted entirely does not cause
  ``merge()`` to raise; the other sources round-trip intact.
- AC-6.4 — ``sources_queried`` ordering is stable and derived from
  routing-decision order, not adapter completion order. Tested at the
  synthesizer layer by asserting that ``merge()`` preserves the caller's
  input order in the returned dict (Python dicts preserve insertion
  order — the broker feeds results in routing-decision order).
"""

from __future__ import annotations

import pytest

from nautilus.core.models import AdapterResult, ErrorRecord
from nautilus.synthesis.basic import BasicSynthesizer


@pytest.mark.unit
def test_merge_shape_for_n_inputs() -> None:
    """AC-6.1 — ``{source_id: rows}`` for N adapters, rows preserved verbatim."""
    results = [
        AdapterResult(
            source_id="nvd_db",
            rows=[{"cve": "CVE-2024-0001"}, {"cve": "CVE-2024-0002"}],
            duration_ms=12,
        ),
        AdapterResult(
            source_id="internal_vulns",
            rows=[{"id": 42, "severity": "high"}],
            duration_ms=7,
        ),
        AdapterResult(
            source_id="threat_intel",
            rows=[],
            duration_ms=3,
        ),
    ]

    merged = BasicSynthesizer().merge(results)

    assert merged == {
        "nvd_db": [{"cve": "CVE-2024-0001"}, {"cve": "CVE-2024-0002"}],
        "internal_vulns": [{"id": 42, "severity": "high"}],
        "threat_intel": [],
    }
    # Each source's row list is a fresh copy, not the adapter's own list
    # (merge() defensively copies so downstream mutation cannot leak back).
    assert merged["nvd_db"] is not results[0].rows


@pytest.mark.unit
def test_merge_partial_failure_returns_other_sources_and_never_raises() -> None:
    """AC-6.2 — one errored adapter must not prevent successful sources from landing.

    Two scenarios exercised here — both must succeed without raising:

    1. An ``AdapterResult`` carrying an ``error`` slips through (defensive
       branch in ``merge()``): synthesizer skips it, keeps the rest.
    2. The broker pre-filter omitted the failed adapter entirely (the
       documented Phase-1 contract from design §3.6): synthesizer returns
       the surviving inputs untouched.
    """
    synth = BasicSynthesizer()

    # Scenario 1: defensive skip of an error-carrying result.
    errored = AdapterResult(
        source_id="flaky_source",
        rows=[],
        duration_ms=99,
        error=ErrorRecord(
            source_id="flaky_source",
            error_type="AdapterError",
            message="boom",
            trace_id="req-1",
        ),
    )
    ok_a = AdapterResult(source_id="nvd_db", rows=[{"cve": "X"}], duration_ms=5)
    ok_b = AdapterResult(source_id="internal_vulns", rows=[{"id": 1}], duration_ms=4)

    merged = synth.merge([ok_a, errored, ok_b])

    assert "flaky_source" not in merged
    assert merged == {"nvd_db": [{"cve": "X"}], "internal_vulns": [{"id": 1}]}

    # Scenario 2: broker already pre-filtered the failure — synthesizer sees
    # only survivors and returns them exactly.
    merged_prefiltered = synth.merge([ok_a, ok_b])
    assert merged_prefiltered == {"nvd_db": [{"cve": "X"}], "internal_vulns": [{"id": 1}]}


@pytest.mark.unit
def test_merge_preserves_routing_decision_order_not_completion_order() -> None:
    """AC-6.4 — dict key order mirrors input order (broker feeds routing order).

    The broker builds its ``AdapterResult`` list via
    ``zip(task_source_ids, await asyncio.gather(...))`` — gather preserves
    *input* order, which itself comes from ``routing_decisions``. So the
    synthesizer is contractually handed results in routing order and its
    returned dict must preserve that ordering (not re-sort alphabetically
    and not reflect which task happened to finish first).
    """
    # Routing order deliberately not alphabetical and not completion-driven.
    routing_order = ["zeta_source", "alpha_source", "mike_source"]
    results = [
        # ``duration_ms`` is *not* what the synthesizer should key off —
        # included here to make the "not completion-based" intent obvious:
        # the fastest adapter (``mike_source``, 1ms) comes LAST in input
        # order and must therefore come LAST in the returned dict.
        AdapterResult(source_id="zeta_source", rows=[{"n": 1}], duration_ms=50),
        AdapterResult(source_id="alpha_source", rows=[{"n": 2}], duration_ms=25),
        AdapterResult(source_id="mike_source", rows=[{"n": 3}], duration_ms=1),
    ]

    merged = BasicSynthesizer().merge(results)

    # Python dicts preserve insertion order — verify the synthesizer did
    # not sort, shuffle, or re-order by duration.
    assert list(merged.keys()) == routing_order
    # Negative control: an alphabetical sort WOULD change this list, and a
    # completion-order sort WOULD put "mike_source" first. Neither happened.
    assert list(merged.keys()) != sorted(routing_order)
