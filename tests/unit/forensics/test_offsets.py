"""Canonical unit tests for :mod:`nautilus.forensics.offsets` (Task 3.6).

Complements the Phase-2 smoke tests (``test_offsets_smoke.py``) by pinning the
four contract behaviours the spec calls out explicitly:

(a) round-trip save/load
(b) atomic rename via :func:`os.replace`
(c) corruption detection raises :class:`OffsetsCorruptError`
    (truncated JSON *and* non-monotonic regression)
(d) bounded-set behaviour at the ``SEEN_HASH_CAP`` cap (10**6)

The smoke suite exercises coverage; this suite pins semantics.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nautilus.forensics import offsets as offsets_mod
from nautilus.forensics.offsets import (
    SEEN_HASH_CAP,
    OffsetsCorruptError,
    ProcessedOffsets,
)

# ---------------------------------------------------------------------------
# (a) Round-trip save/load
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_save_load_roundtrip_preserves_state(tmp_path: Path) -> None:
    """A :class:`ProcessedOffsets` round-trips through save/load verbatim.

    The on-disk payload is a sorted list of hashes + the byte offset; the
    invariants we pin here are the fields the worker *actually* depends on
    — ``last_byte_offset`` (byte-exact resume) and ``seen_line_sha256``
    (content-addressed dedup set).
    """
    target = tmp_path / "offsets.json"
    original = ProcessedOffsets(
        last_byte_offset=4242,
        seen_line_sha256={"deadbeef", "cafebabe", "feedface"},
    )
    original.save(target)

    loaded = ProcessedOffsets.load(target)
    assert loaded.last_byte_offset == 4242
    assert loaded.seen_line_sha256 == {"deadbeef", "cafebabe", "feedface"}


# ---------------------------------------------------------------------------
# (b) Atomic rename via os.replace
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_save_uses_os_replace_for_atomic_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``save`` MUST call :func:`os.replace` exactly once per persist.

    The atomic-rename discipline is load-bearing: a crash between tmp-write
    and rename leaves the old file intact; a crash after rename leaves the
    new file. Anything else (write-in-place, copy-then-delete) would risk
    a torn on-disk state.
    """
    target = tmp_path / "atomic.json"
    calls: list[tuple[str, str]] = []

    real_replace = offsets_mod.os.replace

    def _recording_replace(src: str | Path, dst: str | Path) -> None:
        calls.append((str(src), str(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(offsets_mod.os, "replace", _recording_replace)

    offsets = ProcessedOffsets(last_byte_offset=77, seen_line_sha256={"abc"})
    offsets.save(target)

    assert len(calls) == 1
    src_path, dst_path = calls[0]
    # The source is the .tmp sidecar; the destination is the target path.
    assert src_path.endswith(".tmp")
    assert dst_path == str(target)
    # The .tmp sidecar is consumed by the rename and must not linger.
    assert not target.with_suffix(target.suffix + ".tmp").exists()
    assert target.exists()


# ---------------------------------------------------------------------------
# (c) Corruption detection
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_corruption_detection_raises_offsets_corrupt_error(tmp_path: Path) -> None:
    """Both corruption modes raise :class:`OffsetsCorruptError`:

    - Truncated JSON on disk => load refuses to return a partial object.
    - Non-monotonic offset regression on save => refuses to clobber a
      higher persisted offset (guards against stale in-memory state).

    Both branches are critical for forensic resume safety; grouping them
    here pins "corruption = OffsetsCorruptError, never None / silent".
    """
    # --- truncated JSON -----------------------------------------------------
    truncated = tmp_path / "truncated.json"
    truncated.write_text('{"last_byte_offset": 123, "seen_line_sha256": ["a', encoding="utf-8")
    with pytest.raises(OffsetsCorruptError):
        ProcessedOffsets.load(truncated)

    # --- non-monotonic regression ------------------------------------------
    monotonic = tmp_path / "monotonic.json"
    ProcessedOffsets(last_byte_offset=500).save(monotonic)
    with pytest.raises(OffsetsCorruptError):
        ProcessedOffsets(last_byte_offset=499).save(monotonic)
    # Persisted state is unchanged after the refused regression.
    assert ProcessedOffsets.load(monotonic).last_byte_offset == 500


# ---------------------------------------------------------------------------
# (d) Bounded-set behaviour (SEEN_HASH_CAP == 10**6)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_mark_seen_respects_bounded_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """``mark_seen`` bounds the seen-hash set at ``SEEN_HASH_CAP``.

    The production cap is 10**6; rather than allocate a million strings
    per test run, we monkeypatch the deque/cap to a small value for this
    assertion. Both the ``_order`` deque and the ``seen_line_sha256`` set
    must honour the bound — the deque because its ``maxlen`` drives
    eviction, the set because ``mark_seen`` mirrors the eviction.
    """
    # Assert the production cap hasn't silently drifted from the spec.
    assert SEEN_HASH_CAP == 10**6

    # Shrink the cap for a fast, deterministic eviction check.
    from collections import deque

    cap = 100
    monkeypatch.setattr(offsets_mod, "SEEN_HASH_CAP", cap)

    offsets = ProcessedOffsets()
    # Re-bind the private deque to honour the patched cap (model_post_init
    # already captured the original cap at construction time).
    object.__setattr__(offsets, "_order", deque(maxlen=cap))

    # Push well past the cap; confirm the set never exceeds it.
    total = cap + 50
    for i in range(total):
        offsets.mark_seen(f"sha-{i:06d}")

    assert len(offsets._order) == cap  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert len(offsets.seen_line_sha256) == cap
    # The oldest entries were evicted; the newest survived.
    assert f"sha-{total - 1:06d}" in offsets.seen_line_sha256
    assert "sha-000000" not in offsets.seen_line_sha256
