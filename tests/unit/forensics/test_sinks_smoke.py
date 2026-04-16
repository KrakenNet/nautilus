"""Smoke coverage for :mod:`nautilus.forensics.sinks` (VERIFY 2.24 bridge).

Exercises :class:`JSONLForensicSink` and :class:`HttpForensicSink` so the
`[VERIFY] 2.24` gate clears the 80% branch-coverage floor. No real network
is touched — :class:`httpx.MockTransport` stands in for the receiver.

Locked behavior (design §3.7, FR-11):

- Both concrete sinks satisfy the ``@runtime_checkable`` :class:`ForensicSink`
  Protocol.
- ``JSONLForensicSink.emit`` writes exactly one JSONL line per record;
  multiple emits append; ``close`` is idempotent.
- ``HttpForensicSink.emit`` swallows :class:`httpx.TransportError` + non-2xx
  responses and logs at ``WARNING``. Never raises.
- ``HttpForensicSink.close`` is idempotent and awaits
  :meth:`httpx.AsyncClient.aclose`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from nautilus.core.models import InferredHandoff
from nautilus.forensics.sinks import (
    ForensicSink,
    HttpForensicSink,
    JSONLForensicSink,
)


def _record(session_id: str = "sess-1") -> InferredHandoff:
    """Minimal valid :class:`InferredHandoff` fixture."""
    return InferredHandoff(
        session_id=session_id,
        source_agent="alice",
        receiving_agent="bob",
        confidence=0.8,
        signals=["shared-session"],
        inferred_at=datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC),
    )


def _install_transport(sink: HttpForensicSink, transport: httpx.MockTransport) -> None:
    """Swap the sink's real client for a :class:`httpx.MockTransport`-backed one."""
    sink._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_jsonl_sink_satisfies_forensic_sink_protocol(tmp_path: Path) -> None:
    """``@runtime_checkable`` Protocol accepts :class:`JSONLForensicSink`."""
    sink = JSONLForensicSink(tmp_path / "out.jsonl")
    try:
        assert isinstance(sink, ForensicSink)
    finally:
        await sink.close()


@pytest.mark.unit
async def test_http_sink_satisfies_forensic_sink_protocol() -> None:
    """``@runtime_checkable`` Protocol accepts :class:`HttpForensicSink`."""
    sink = HttpForensicSink(url="http://receiver/emit")
    try:
        assert isinstance(sink, ForensicSink)
    finally:
        await sink.close()


# ---------------------------------------------------------------------------
# JSONLForensicSink.emit / close
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_jsonl_sink_emit_writes_one_line(tmp_path: Path) -> None:
    """One ``emit`` == one JSONL line; round-trip parses back to the model."""
    target = tmp_path / "out.jsonl"
    sink = JSONLForensicSink(target)
    try:
        await sink.emit(_record())
    finally:
        await sink.close()

    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    decoded = json.loads(lines[0])
    assert decoded["session_id"] == "sess-1"
    assert decoded["source_agent"] == "alice"
    assert decoded["receiving_agent"] == "bob"


@pytest.mark.unit
async def test_jsonl_sink_multiple_emits_append(tmp_path: Path) -> None:
    """Successive emits append; order is preserved."""
    target = tmp_path / "multi.jsonl"
    sink = JSONLForensicSink(target)
    try:
        await sink.emit(_record("sess-a"))
        await sink.emit(_record("sess-b"))
        await sink.emit(_record("sess-c"))
    finally:
        await sink.close()

    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    ids = [json.loads(raw)["session_id"] for raw in lines]
    assert ids == ["sess-a", "sess-b", "sess-c"]


@pytest.mark.unit
async def test_jsonl_sink_creates_missing_parent_directory(tmp_path: Path) -> None:
    """Constructor ``mkdir(parents=True, exist_ok=True)`` branch."""
    nested = tmp_path / "deep" / "nest" / "out.jsonl"
    sink = JSONLForensicSink(nested)
    try:
        await sink.emit(_record())
    finally:
        await sink.close()
    assert nested.exists()


@pytest.mark.unit
async def test_jsonl_sink_accepts_str_path(tmp_path: Path) -> None:
    """``Path | str`` signature — string path also works."""
    target = tmp_path / "str_path.jsonl"
    sink = JSONLForensicSink(str(target))
    try:
        await sink.emit(_record())
    finally:
        await sink.close()
    assert target.exists()


@pytest.mark.unit
async def test_jsonl_sink_close_is_idempotent(tmp_path: Path) -> None:
    """Double-close short-circuits via ``self._closed`` flag."""
    sink = JSONLForensicSink(tmp_path / "idem.jsonl")
    await sink.close()
    # Second close must not raise even though handle is already closed.
    await sink.close()
    assert sink._closed is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# HttpForensicSink.emit — happy path + failure modes (never raises)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_http_sink_emit_200_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    """A 200 response logs nothing; the body is the model's JSON dump."""
    calls: list[dict[str, object]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(_handler)
    sink = HttpForensicSink(url="http://receiver/emit")
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_record("sess-happy"))
    finally:
        await sink.close()

    assert len(calls) == 1
    assert calls[0]["session_id"] == "sess-happy"
    assert not any("forensic_sink.http" in r.message for r in caplog.records)


@pytest.mark.unit
async def test_http_sink_emit_500_logs_warn_does_not_raise(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """5xx => WARN logged, ``emit`` still returns cleanly (no raise)."""

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "upstream"})

    transport = httpx.MockTransport(_handler)
    sink = HttpForensicSink(url="http://receiver/emit")
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            # Must not raise — offline worker is re-runnable.
            await sink.emit(_record())
    finally:
        await sink.close()

    warn_records = [r for r in caplog.records if "forensic_sink.http" in r.message]
    assert len(warn_records) == 1
    assert "500" in warn_records[0].message


@pytest.mark.unit
async def test_http_sink_emit_4xx_logs_warn_does_not_raise(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """4xx is also swallowed (no retry ladder on forensic sink)."""

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(418, json={"error": "teapot"})

    transport = httpx.MockTransport(_handler)
    sink = HttpForensicSink(url="http://receiver/emit")
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_record())
    finally:
        await sink.close()

    warn_records = [r for r in caplog.records if "forensic_sink.http" in r.message]
    assert len(warn_records) == 1


@pytest.mark.unit
async def test_http_sink_emit_transport_error_logs_warn_does_not_raise(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """:class:`httpx.TransportError` => WARN logged, no exception."""

    def _handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(_handler)
    sink = HttpForensicSink(url="http://receiver/emit")
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_record())
    finally:
        await sink.close()

    warn_records = [r for r in caplog.records if "forensic_sink.http" in r.message]
    assert len(warn_records) == 1
    assert "ConnectError" in warn_records[0].message


@pytest.mark.unit
async def test_http_sink_emit_timeout_logs_warn_does_not_raise(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """:class:`httpx.TimeoutException` => same WARN-and-swallow path."""

    def _handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out")

    transport = httpx.MockTransport(_handler)
    sink = HttpForensicSink(url="http://receiver/emit")
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_record())
    finally:
        await sink.close()

    warn_records = [r for r in caplog.records if "forensic_sink.http" in r.message]
    assert len(warn_records) == 1


# ---------------------------------------------------------------------------
# HttpForensicSink.close
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_http_sink_close_awaits_async_client_aclose() -> None:
    """``close`` awaits :meth:`httpx.AsyncClient.aclose` on the wrapped client."""
    sink = HttpForensicSink(url="http://receiver/emit")
    mock_aclose = AsyncMock()
    sink._client.aclose = mock_aclose  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    await sink.close()
    mock_aclose.assert_awaited_once()


@pytest.mark.unit
async def test_http_sink_close_is_idempotent() -> None:
    """Second ``close`` is a no-op; does not re-aclose the client."""
    sink = HttpForensicSink(url="http://receiver/emit")
    mock_aclose = AsyncMock()
    sink._client.aclose = mock_aclose  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    await sink.close()
    await sink.close()
    # Only the first call triggers aclose.
    mock_aclose.assert_awaited_once()
    assert sink._closed is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
