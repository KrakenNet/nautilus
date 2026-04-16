"""Canonical unit tests for :mod:`nautilus.forensics.sinks` (Task 3.6).

Two cases, pinning the spec contract:

(a) :class:`JSONLForensicSink`: :meth:`emit` writes + flushes + fsyncs each
    record as exactly one JSONL line. We pin both the on-disk line and the
    ``flush`` + ``os.fsync`` syscall trio — the durability contract mirrors
    :class:`nautilus.core.attestation_sink.FileAttestationSink`.

(b) :class:`HttpForensicSink`: successive :meth:`emit` calls re-POST on
    failure. The production sink does NOT implement an in-process retry
    ladder (design §3.7: offline forensic inference is re-runnable from
    the audit JSONL, so a dropped POST is replayed from source). We prove
    the worker-level retry story: a first POST returning 500 is logged
    at ``WARNING`` and swallowed (never raises), and a subsequent
    :meth:`emit` on the same sink succeeds — the mocked transport replays
    the receiver's 500 → 200 transition to assert that behaviour.

Uses :class:`httpx.MockTransport` rather than ``respx`` to match the style
already established by the sibling smoke suite. ``respx`` is a dep of the
repo (see ``pyproject.toml``) so either tool would be acceptable; the
``MockTransport`` route keeps the fixture setup tight and in-process.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from nautilus.core.models import InferredHandoff
from nautilus.forensics import sinks as sinks_mod
from nautilus.forensics.sinks import HttpForensicSink, JSONLForensicSink


def _record(session_id: str = "sess-1") -> InferredHandoff:
    """Minimal valid :class:`InferredHandoff` fixture."""
    return InferredHandoff(
        session_id=session_id,
        source_agent="alice",
        receiving_agent="bob",
        confidence=0.75,
        signals=["shared-session", "overlap-sources"],
        inferred_at=datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC),
    )


# ---------------------------------------------------------------------------
# (a) JSONL sink writes + flushes
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_jsonl_sink_writes_and_flushes_each_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each :meth:`emit` produces one JSONL line + flush + ``os.fsync``.

    Three records go in; three parseable JSONL lines come out in insertion
    order. We also pin the syscall contract: every ``emit`` must call
    :func:`os.fsync` exactly once (the per-record durability promise that
    mirrors FileAttestationSink).
    """
    target = tmp_path / "sink.jsonl"

    fsync_calls: list[int] = []
    real_fsync = sinks_mod.os.fsync

    def _recording_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(sinks_mod.os, "fsync", _recording_fsync)

    sink = JSONLForensicSink(target)
    try:
        await sink.emit(_record("sess-a"))
        await sink.emit(_record("sess-b"))
        await sink.emit(_record("sess-c"))
    finally:
        await sink.close()

    # One fsync per emit — three emits, three syscalls.
    assert len(fsync_calls) == 3

    # On-disk line count + order + shape.
    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    ids = [json.loads(raw)["session_id"] for raw in lines]
    assert ids == ["sess-a", "sess-b", "sess-c"]
    # Round-trip each line back through the model.
    for raw in lines:
        rec = InferredHandoff.model_validate_json(raw)
        assert rec.source_agent == "alice"
        assert rec.receiving_agent == "bob"

    # Sanity: the fd we fsynced is still a valid kernel fd number. (We can't
    # re-check it after close; just confirm it was an int during emit.)
    assert all(isinstance(fd, int) for fd in fsync_calls)
    _ = os  # retained so the import is non-decorative on stricter linters


# ---------------------------------------------------------------------------
# (b) HTTP sink POSTs with retry (receiver-side 500 → 200)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_http_sink_posts_with_retry_via_mock_transport(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Successive emits drive a 500-then-200 POST ladder cleanly.

    The production sink does NOT retry in-process (design §3.7 — the offline
    worker is re-runnable from the audit JSONL so a dropped POST is replayed
    from source). We prove the observable worker-level contract instead:

    1. First :meth:`emit` hits a 500 — logs ``WARNING``, never raises.
    2. Second :meth:`emit` hits a 200 — posts the body, no warning added.

    The mock transport flips its response the first time it's called, so two
    ``emit`` invocations walk the full failure-then-success ladder the
    re-runnable design relies on.
    """
    posted_bodies: list[dict[str, object]] = []
    attempts: list[int] = []  # [0, 1, 2, ...] — used to drive the flip.

    def _handler(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        attempts.append(len(attempts))
        # First call: 500. Subsequent calls: 200.
        if attempts[-1] == 0:
            return httpx.Response(500, json={"error": "upstream"})
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(_handler)
    sink = HttpForensicSink(url="http://receiver/emit")
    # Swap the real AsyncClient for one wired to our mock transport.
    sink._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    try:
        with caplog.at_level("WARNING"):
            # Attempt 1 — receiver returns 500; emit logs WARN + swallows.
            await sink.emit(_record("sess-1"))
            # Attempt 2 — receiver returns 200; clean success.
            await sink.emit(_record("sess-2"))
    finally:
        await sink.close()

    # Two POSTs total — the retry story is expressed at the worker level.
    assert len(posted_bodies) == 2
    assert posted_bodies[0]["session_id"] == "sess-1"
    assert posted_bodies[1]["session_id"] == "sess-2"

    # Exactly one WARN — from the 500 attempt. The 200 attempt adds nothing.
    warn_records = [r for r in caplog.records if "forensic_sink.http" in r.message]
    assert len(warn_records) == 1
    assert "500" in warn_records[0].message
