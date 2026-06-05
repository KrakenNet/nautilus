"""Spike POC: replay ≥10k synthetic events into a CLIPS env (AC-35.1.b).

This is a decision-artifact spike, NOT shipped code (AC-35.1.d). The
test asserts hash-equality of the reconstructed fact set against a
known-good snapshot, and records performance (AC-35.1.c).
"""

from __future__ import annotations

import time

import pytest

pytestmark = pytest.mark.integration

# Known-good sha256 of the canonical fact dump after replaying exactly 10 000
# synthetic events with the deterministic generator in replay.py.
# Computed on 2026-05-20 — update if the event schema or template set changes.
_SNAPSHOT_HASH_10K = "sha256:c457a1e8cbf60e605ffb53026962b4c2a20db3b345e6cccaf5d3250229b59fb2"


def test_ac_35_1_b_replay_10k_events_yields_stable_fact_set_hash() -> None:
    """Replay 10 000 synthetic events; assert reconstructed fact-set hash matches snapshot."""
    from spikes.event_sourcing import replay  # type: ignore[import-not-found]

    actual_hash = replay.replay_synthetic_events(n=10_000)
    assert actual_hash == _SNAPSHOT_HASH_10K


def test_ac_35_1_c_replay_10k_events_under_5s_and_deterministic() -> None:
    """10k replay completes in <5 s and produces identical hashes on two runs (AC-35.1.c)."""
    from spikes.event_sourcing import replay  # type: ignore[import-not-found]

    t0 = time.perf_counter()
    hash_a = replay.replay_synthetic_events(n=10_000)
    elapsed_a = time.perf_counter() - t0

    t0 = time.perf_counter()
    hash_b = replay.replay_synthetic_events(n=10_000)
    elapsed_b = time.perf_counter() - t0

    assert hash_a == hash_b, "replay is not deterministic"
    assert elapsed_a < 5.0, f"first replay took {elapsed_a:.2f}s (limit 5s)"
    assert elapsed_b < 5.0, f"second replay took {elapsed_b:.2f}s (limit 5s)"
