"""Smoke coverage for :class:`HttpAttestationSink` (Task 2.14 bridge).

Exercises the retry / dead-letter surface of
:class:`nautilus.core.attestation_sink.HttpAttestationSink` so the
[VERIFY] 2.14 gate clears the 80% branch floor. No live network is touched
— :class:`httpx.MockTransport` stands in for the verifier upstream.

Locked behavior (design §3.14, AC-14.3, NFR-16):

- Constructor with defaults + ``RetryPolicy(max_retries=0)`` smoke-passes.
- 2xx response → no dead-letter, no WARN log.
- ``max_retries=0`` + :class:`httpx.TransportError` → exactly one POST
  attempt, one dead-letter JSONL line written, one WARN logged.
- ``max_retries=2`` + repeated 5xx → three POSTs (initial + 2 retries)
  then dead-letter spill, one WARN.
- 4xx response short-circuits (no retry) straight to dead-letter.
- ``dead_letter_path=None`` + failure → WARN only, no exception leaked.
- ``close()`` idempotent: second call is a no-op; first call awaits both
  :meth:`httpx.AsyncClient.aclose` and the wrapped dead-letter sink close.
- :class:`RetryPolicy` defaults match the design (``max_retries=3``,
  ``initial_backoff_s=0.1``, ``max_backoff_s=5.0``).
- :class:`HttpSinkSpec` parses via Pydantic V2.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from nautilus.config.models import HttpSinkSpec, RetryPolicySpec
from nautilus.core.attestation_sink import (
    AttestationPayload,
    HttpAttestationSink,
    RetryPolicy,
)


def _payload(token: str = "jwt.header.signature") -> AttestationPayload:
    return AttestationPayload(
        token=token,
        nautilus_payload={"iss": "nautilus", "request_id": "r-1"},
        emitted_at=datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC),
    )


def _fast_policy(max_retries: int = 0) -> RetryPolicy:
    """A :class:`RetryPolicy` with negligible backoff so tests stay under 100 ms."""
    return RetryPolicy(
        max_retries=max_retries,
        initial_backoff_s=0.001,
        max_backoff_s=0.01,
    )


def _install_transport(sink: HttpAttestationSink, transport: httpx.MockTransport) -> None:
    """Swap the sink's real :class:`httpx.AsyncClient` for a mock-transport client.

    The sink builds its own client in ``__init__`` (so construction stays
    network-free in practice); we replace it with a ``MockTransport``-backed
    one before any ``emit`` call so tests exercise the retry loop without
    hitting the network.
    """
    sink._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# Construction smoke
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_construct_with_zero_retries_smoke_passes() -> None:
    """Done-when for Task 2.13: zero-retry construction is cheap and network-free."""
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=RetryPolicy(max_retries=0),
    )
    try:
        assert sink._retry_policy.max_retries == 0  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert sink._dead_letter is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        await sink.close()


@pytest.mark.unit
async def test_construct_with_defaults_uses_default_retry_policy() -> None:
    """``RetryPolicy`` defaults land on the sink when the arg is omitted."""
    sink = HttpAttestationSink(url="http://verifier/emit")
    try:
        policy = sink._retry_policy  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert policy.max_retries == 3
        assert policy.initial_backoff_s == 0.1
        assert policy.max_backoff_s == 5.0
    finally:
        await sink.close()


# ---------------------------------------------------------------------------
# emit() — happy path
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_emit_happy_path_200_no_dead_letter(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A 200 response writes nothing to the dead-letter file and logs nothing."""
    dead_letter = tmp_path / "dead.jsonl"
    calls: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(_handler)
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=_fast_policy(max_retries=2),
        dead_letter_path=dead_letter,
    )
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_payload())
    finally:
        await sink.close()

    assert len(calls) == 1
    assert not any("attestation_sink.http" in r.message for r in caplog.records)
    # Dead-letter file may exist (FileAttestationSink opens at init) but must be empty.
    if dead_letter.exists():
        assert dead_letter.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------
# emit() — TransportError paths
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_emit_zero_retries_transport_error_writes_dead_letter(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``max_retries=0`` + ``TransportError`` → 1 attempt, 1 dead-letter line, 1 WARN."""
    dead_letter = tmp_path / "dead.jsonl"
    attempts: list[int] = []

    def _handler(_req: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(_handler)
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=_fast_policy(max_retries=0),
        dead_letter_path=dead_letter,
    )
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_payload("zero-retry"))
    finally:
        await sink.close()

    assert len(attempts) == 1
    # One WARN from the sink's own logger.
    warn_records = [r for r in caplog.records if "attestation_sink.http" in r.message]
    assert len(warn_records) == 1
    # One dead-letter JSONL line.
    lines = dead_letter.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    decoded = json.loads(lines[0])
    assert decoded["token"] == "zero-retry"


@pytest.mark.unit
async def test_emit_with_retries_retries_5xx_then_dead_letters(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """``max_retries=2`` + repeated 5xx → 3 POSTs, then spill."""
    dead_letter = tmp_path / "dead.jsonl"
    attempts: list[int] = []

    def _handler(_req: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503, json={"error": "upstream busy"})

    transport = httpx.MockTransport(_handler)
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=_fast_policy(max_retries=2),
        dead_letter_path=dead_letter,
    )
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_payload("with-retries"))
    finally:
        await sink.close()

    # Initial + 2 retries == 3 attempts.
    assert len(attempts) == 3
    warn_records = [r for r in caplog.records if "attestation_sink.http" in r.message]
    assert len(warn_records) == 1
    lines = dead_letter.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


@pytest.mark.unit
async def test_emit_4xx_short_circuits_to_dead_letter(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A 4xx client error is permanent — no retry, immediate dead-letter spill."""
    dead_letter = tmp_path / "dead.jsonl"
    attempts: list[int] = []

    def _handler(_req: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(400, json={"error": "bad request"})

    transport = httpx.MockTransport(_handler)
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=_fast_policy(max_retries=5),  # would normally retry 5 times
        dead_letter_path=dead_letter,
    )
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_payload("four-xx"))
    finally:
        await sink.close()

    # 4xx must short-circuit — exactly ONE attempt even with max_retries=5.
    assert len(attempts) == 1
    warn_records = [r for r in caplog.records if "attestation_sink.http" in r.message]
    assert len(warn_records) == 1
    lines = dead_letter.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


@pytest.mark.unit
async def test_emit_without_dead_letter_logs_warn_no_exception(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``dead_letter_path=None`` + failure → WARN only; ``emit`` must not raise."""
    attempts: list[int] = []

    def _handler(_req: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ReadTimeout("read timed out")

    transport = httpx.MockTransport(_handler)
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=_fast_policy(max_retries=0),
        dead_letter_path=None,
    )
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            # No exception should escape — audit-first invariant.
            await sink.emit(_payload())
    finally:
        await sink.close()

    assert len(attempts) == 1
    assert sink._dead_letter is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    warn_records = [r for r in caplog.records if "attestation_sink.http" in r.message]
    assert len(warn_records) == 1


@pytest.mark.unit
async def test_emit_succeeds_on_retry_after_transient_5xx(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Transient 503 then 200 → no dead-letter, no WARN."""
    dead_letter = tmp_path / "dead.jsonl"
    attempts: list[int] = []

    def _handler(_req: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(_handler)
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=_fast_policy(max_retries=3),
        dead_letter_path=dead_letter,
    )
    _install_transport(sink, transport)
    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_payload())
    finally:
        await sink.close()

    assert len(attempts) == 2  # first 503, second 200
    assert not any("attestation_sink.http" in r.message for r in caplog.records)
    if dead_letter.exists():
        assert dead_letter.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_close_is_idempotent_without_dead_letter() -> None:
    """Double-close short-circuits via ``self._closed`` flag."""
    sink = HttpAttestationSink(url="http://verifier/emit")
    await sink.close()
    # Second close must not re-aclose the underlying client.
    await sink.close()
    assert sink._closed is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
async def test_close_awaits_dead_letter_sink_close(tmp_path: Path) -> None:
    """``close`` must also close the wrapped :class:`FileAttestationSink`."""
    dead_letter = tmp_path / "dead.jsonl"
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        dead_letter_path=dead_letter,
    )
    wrapped = sink._dead_letter  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert wrapped is not None
    await sink.close()
    assert wrapped._closed is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    # Second close is a no-op.
    await sink.close()
    assert sink._closed is True  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------------------
# RetryPolicy + HttpSinkSpec config discriminator
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_retry_policy_defaults() -> None:
    """Design §3.14 / AC-14.3 default schedule."""
    p = RetryPolicy()
    assert p.max_retries == 3
    assert p.initial_backoff_s == 0.1
    assert p.max_backoff_s == 5.0


@pytest.mark.unit
def test_http_sink_spec_parses_via_pydantic_v2() -> None:
    """``HttpSinkSpec`` is Pydantic-V2-selectable via ``type='http'``."""
    spec = HttpSinkSpec.model_validate({"type": "http", "url": "http://verifier/emit"})
    assert spec.type == "http"
    assert spec.url == "http://verifier/emit"
    # Default retry policy survives validation.
    assert isinstance(spec.retry_policy, RetryPolicySpec)
    assert spec.retry_policy.max_retries == 3
    assert spec.dead_letter_path is None


@pytest.mark.unit
def test_http_sink_spec_accepts_custom_retry_and_dead_letter() -> None:
    spec = HttpSinkSpec.model_validate(
        {
            "type": "http",
            "url": "http://verifier/emit",
            "retry_policy": {"max_retries": 7, "initial_backoff_s": 0.5, "max_backoff_s": 30.0},
            "dead_letter_path": "/var/lib/nautilus/dead.jsonl",
        }
    )
    assert spec.retry_policy.max_retries == 7
    assert spec.retry_policy.initial_backoff_s == 0.5
    assert spec.dead_letter_path == "/var/lib/nautilus/dead.jsonl"


# ---------------------------------------------------------------------------
# Backoff helper
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_backoff_caps_at_max_backoff_s() -> None:
    """``_backoff_for`` is capped by ``max_backoff_s`` for large attempts."""
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=RetryPolicy(max_retries=10, initial_backoff_s=1.0, max_backoff_s=4.0),
    )
    try:
        assert sink._backoff_for(0) == 1.0  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert sink._backoff_for(1) == 2.0  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert sink._backoff_for(2) == 4.0  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        # Cap engages at attempt 3 (2**3 == 8 > 4.0).
        assert sink._backoff_for(3) == 4.0  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        assert sink._backoff_for(10) == 4.0  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    finally:
        await sink.close()
