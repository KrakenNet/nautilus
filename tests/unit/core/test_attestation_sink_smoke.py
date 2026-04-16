"""Smoke coverage for :mod:`nautilus.core.attestation_sink` (Task 2.5 bridge).

Interim Phase-2 coverage for :class:`NullAttestationSink` +
:class:`FileAttestationSink` so the `[VERIFY] 2.5` checkpoint clears the
80% branch-coverage floor. Full sink tests (including rotation, HTTP sink)
land in Phase 3 (Task 3.7). These smokes verify:

- Null sink ``emit``/``close`` are no-ops and safe to call multiple times.
- File sink appends a JSONL line per ``emit`` with durable write semantics
  (the ``flush`` + ``fsync`` calls are exercised by the happy-path write).
- File sink ``close`` is idempotent — AC-14.5 / design §3.14 lifecycle rule.
- ``emit`` after ``close`` is fine (no-op closed handle → swallowed).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nautilus.core.attestation_sink import (
    AttestationPayload,
    FileAttestationSink,
    NullAttestationSink,
)


def _payload(token: str = "jwt.header.signature") -> AttestationPayload:
    """Minimal valid :class:`AttestationPayload` fixture."""
    return AttestationPayload(
        token=token,
        nautilus_payload={"iss": "nautilus", "request_id": "r-1"},
        emitted_at=datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC),
    )


@pytest.mark.unit
async def test_null_sink_emit_is_noop() -> None:
    """``NullAttestationSink.emit`` returns ``None`` without side effects."""
    sink = NullAttestationSink()
    result = await sink.emit(_payload())
    assert result is None


@pytest.mark.unit
async def test_null_sink_close_is_idempotent() -> None:
    """Multiple ``close`` calls are safe (Protocol contract)."""
    sink = NullAttestationSink()
    assert await sink.close() is None
    assert await sink.close() is None
    # Emit-after-close still no-ops on the null sink (it owns no state).
    assert await sink.emit(_payload()) is None


@pytest.mark.unit
async def test_file_sink_writes_one_jsonl_line_per_emit(tmp_path: Path) -> None:
    """AC-14.2 — each ``emit`` is one JSONL line; round-trip parses back."""
    target = tmp_path / "attestation.jsonl"
    sink = FileAttestationSink(target)
    try:
        await sink.emit(_payload("tok-1"))
        await sink.emit(_payload("tok-2"))
    finally:
        await sink.close()

    raw = target.read_text(encoding="utf-8").splitlines()
    assert len(raw) == 2
    decoded = [json.loads(line) for line in raw]
    assert decoded[0]["token"] == "tok-1"
    assert decoded[1]["token"] == "tok-2"
    assert decoded[0]["nautilus_payload"] == {"iss": "nautilus", "request_id": "r-1"}


@pytest.mark.unit
async def test_file_sink_creates_missing_parent_directory(tmp_path: Path) -> None:
    """Constructor ``mkdir(parents=True, exist_ok=True)`` branch."""
    nested = tmp_path / "a" / "b" / "attest.jsonl"
    sink = FileAttestationSink(nested)
    try:
        await sink.emit(_payload())
    finally:
        await sink.close()
    assert nested.exists()
    assert nested.read_text(encoding="utf-8").strip() != ""


@pytest.mark.unit
async def test_file_sink_close_is_idempotent(tmp_path: Path) -> None:
    """Double-close short-circuits via ``self._closed`` flag (AC-14.5)."""
    sink = FileAttestationSink(tmp_path / "a.jsonl")
    await sink.close()
    # Second close must not raise even though the handle is already closed.
    await sink.close()
    assert sink._closed is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_file_sink_accepts_str_path(tmp_path: Path) -> None:
    """``Path | str`` signature — string path also works."""
    target = tmp_path / "str_path.jsonl"
    sink = FileAttestationSink(str(target))
    try:
        await sink.emit(_payload())
    finally:
        await sink.close()
    assert target.exists()
