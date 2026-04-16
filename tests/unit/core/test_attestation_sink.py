"""Task 3.5 unit coverage for attestation sinks + broker aclose ordering.

Five locked cases (design §3.14, FR-28/FR-29, AC-14.5/AC-14.6):

(a) :class:`NullAttestationSink`.emit` is a strict no-op.
(b) :class:`FileAttestationSink` writes exactly one JSONL line per emit
    and calls ``flush`` + ``os.fsync`` on each (AC-14.2 durable-before-ack).
(c) :class:`HttpAttestationSink` retries retriable failures then spills the
    payload to the wrapped dead-letter :class:`FileAttestationSink`.
(d) An ``AttestationSink`` whose ``emit`` raises does NOT fail
    :meth:`Broker.arequest` — the audit entry is still written and the
    :class:`BrokerResponse` is still returned (AC-14.5, NFR-16).
(e) :meth:`Broker.aclose` closes in the order
    ``session_store.aclose`` → ``attestation_sink.close`` → adapter
    ``close`` (D-8, design §3.14, AC-14.6).

Sibling smoke coverage (``test_attestation_sink_smoke.py`` +
``test_http_attestation_sink_smoke.py``) exercises branch depth on the
sinks themselves; this file focuses on the behaviour contracts the task
brief pins and on broker-level integration (d + e).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from nautilus import Broker
from nautilus.adapters.base import Adapter
from nautilus.config.models import SourceConfig
from nautilus.core.attestation_sink import (
    AttestationPayload,
    FileAttestationSink,
    HttpAttestationSink,
    NullAttestationSink,
    RetryPolicy,
)
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

FIXTURE_PATH = Path(__file__).resolve().parents[2] / "fixtures" / "nautilus.yaml"


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _payload(token: str = "jwt.header.signature") -> AttestationPayload:
    """Minimal :class:`AttestationPayload` instance."""
    return AttestationPayload(
        token=token,
        nautilus_payload={"iss": "nautilus", "request_id": "r-1"},
        emitted_at=datetime(2026, 4, 15, 12, 0, 0, tzinfo=UTC),
    )


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dummy DSNs so ``Broker.from_config`` env interpolation succeeds.

    Adapters in this file are never ``connect()``-ed — the DSN values just
    need to be non-empty so config loading does not raise.
    """
    monkeypatch.setenv("TEST_PG_DSN", "postgres://ignored/0")
    monkeypatch.setenv("TEST_PGV_DSN", "postgres://ignored/1")


class _FakeAdapter:
    """Minimal :class:`Adapter` Protocol impl returning a fixed row list."""

    source_type: str = "fake"

    def __init__(self, source_id: str) -> None:
        self._source_id = source_id
        self.closed: bool = False

    async def connect(self, config: SourceConfig) -> None:
        del config

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        del intent, scope, context
        return AdapterResult(source_id=self._source_id, rows=[{"id": 1}], duration_ms=0)

    async def close(self) -> None:
        self.closed = True


def _install_fakes(broker: Broker, fakes: dict[str, _FakeAdapter]) -> None:
    """Swap broker adapters for fakes and mark them connected (test-broker parity)."""
    broker._adapters = dict(fakes)  # type: ignore[attr-defined]  # noqa: SLF001
    broker._connected_adapters = set(fakes.keys())  # type: ignore[attr-defined]  # noqa: SLF001


def _ctx() -> dict[str, Any]:
    """Baseline request context routable against the two-source fixture."""
    return {
        "clearance": "unclassified",
        "purpose": "threat-analysis",
        "session_id": "s1",
        "embedding": [0.1, 0.2, 0.3],
    }


# ---------------------------------------------------------------------------
# (a) NullAttestationSink.emit is a strict no-op
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_null_attestation_sink_emit_is_noop() -> None:
    """``emit`` returns ``None`` and performs no side effects (AC-14.4)."""
    sink = NullAttestationSink()
    result = await sink.emit(_payload())
    assert result is None
    # Double-emit remains a no-op with no internal state to mutate.
    assert await sink.emit(_payload("t2")) is None
    assert await sink.close() is None


# ---------------------------------------------------------------------------
# (b) FileAttestationSink: one line per emit + flush + fsync
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_file_sink_writes_one_line_per_emit_and_fsyncs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each ``emit`` is one JSONL line with matching ``flush`` + ``os.fsync`` (AC-14.2).

    The sink's contract is ``write → flush → os.fsync`` per emit. We spy on
    ``os.fsync`` — exactly one invocation per emit proves the fsync call —
    and separately pin the per-emit ``flush`` by spying on the file handle's
    ``flush`` method and asserting it was called at least once per emit
    *before* ``close`` (close's own trailing flush is filtered out).
    """
    target = tmp_path / "attestation.jsonl"
    sink = FileAttestationSink(target)

    # Spy on os.fsync — count invocations across both emits only (not close).
    fsync_calls: list[int] = []
    import os as _os

    real_fsync = _os.fsync

    def _counting_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr("nautilus.core.attestation_sink.os.fsync", _counting_fsync)

    # Spy on the file handle's flush; record count pre-close so the
    # close-path flush (implicit in ``_fh.close()``) never contaminates the
    # per-emit assertion.
    flush_calls: list[int] = []
    real_flush = sink._fh.flush  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def _counting_flush() -> None:
        flush_calls.append(1)
        real_flush()

    sink._fh.flush = _counting_flush  # type: ignore[method-assign]  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    try:
        await sink.emit(_payload("tok-A"))
        await sink.emit(_payload("tok-B"))
        # Snapshot BEFORE close so we exclude any close-time flush.
        flush_before_close = len(flush_calls)
        fsync_before_close = len(fsync_calls)
    finally:
        await sink.close()

    lines = target.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2, "one JSONL line per emit"
    decoded = [json.loads(line) for line in lines]
    assert decoded[0]["token"] == "tok-A"
    assert decoded[1]["token"] == "tok-B"
    # Two emits → two flushes, two fsyncs (AC-14.2).
    assert flush_before_close == 2, f"expected 2 flush calls pre-close, got {flush_before_close}"
    assert fsync_before_close == 2, f"expected 2 fsync calls pre-close, got {fsync_before_close}"


# ---------------------------------------------------------------------------
# (c) HttpAttestationSink: retries, then dead-letter spill
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_http_sink_retries_then_spills_to_dead_letter(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Transport errors exhaust retries, then payload lands on the dead-letter file.

    ``max_retries=2`` + every POST raising :class:`httpx.ConnectError` → 3 total
    attempts (initial + 2 retries), one dead-letter JSONL line, one WARN log
    (AC-14.3).
    """
    dead_letter = tmp_path / "dead.jsonl"
    attempts: list[str] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        attempts.append(str(request.url))
        raise httpx.ConnectError("verifier unreachable")

    transport = httpx.MockTransport(_handler)
    sink = HttpAttestationSink(
        url="http://verifier/emit",
        retry_policy=RetryPolicy(max_retries=2, initial_backoff_s=0.001, max_backoff_s=0.01),
        dead_letter_path=dead_letter,
    )
    # Replace the real client with one wired to the mock transport so the
    # retry loop never hits the network (mirrors the smoke-test pattern).
    sink._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    try:
        with caplog.at_level("WARNING"):
            await sink.emit(_payload("spill-me"))
    finally:
        await sink.close()

    # Initial + 2 retries → 3 POST attempts.
    assert len(attempts) == 3, f"expected 3 attempts, got {len(attempts)}"
    # Exactly one WARN from the sink's own logger after exhaustion.
    warn_records = [r for r in caplog.records if "attestation_sink.http" in r.message]
    assert len(warn_records) == 1
    # Exactly one dead-letter JSONL line carrying the original token.
    lines = dead_letter.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["token"] == "spill-me"


# ---------------------------------------------------------------------------
# (d) Sink raising does NOT fail broker.arequest (AC-14.5, NFR-16)
# ---------------------------------------------------------------------------


class _RaisingSink:
    """``AttestationSink`` whose ``emit`` always raises."""

    emitted: int

    def __init__(self) -> None:
        self.emitted = 0
        self.closed: bool = False

    async def emit(self, payload: AttestationPayload) -> None:
        del payload
        self.emitted += 1
        raise RuntimeError("sink outage — must not fail arequest")

    async def close(self) -> None:
        self.closed = True


@pytest.mark.unit
async def test_broker_arequest_survives_sink_emit_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """AC-14.5 — an ``AttestationSink`` that raises is swallowed + WARN-logged.

    The request completes successfully, the response contains the signed
    attestation token (AC-14.4), and the sink's ``emit`` was invoked exactly
    once.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    raising_sink = _RaisingSink()
    # Replace the wired NullAttestationSink with the raising stand-in.
    broker._attestation_sink = raising_sink  # type: ignore[attr-defined]  # noqa: SLF001
    try:
        _install_fakes(
            broker,
            {
                "nvd_db": _FakeAdapter("nvd_db"),
                "internal_vulns": _FakeAdapter("internal_vulns"),
            },
        )
        with caplog.at_level("WARNING"):
            resp = await broker.arequest("agent-alpha", "vulnerability scan", _ctx())
    finally:
        await broker.aclose()

    # Happy path semantics intact.
    assert resp.attestation_token is not None, "AC-14.4: token still returned"
    assert resp.sources_queried, "request pipeline still produced results"
    # Sink was called exactly once and raised; broker logged a WARN.
    assert raising_sink.emitted == 1
    warn_records = [r for r in caplog.records if "attestation_sink.emit failed" in r.message]
    assert len(warn_records) == 1


# ---------------------------------------------------------------------------
# (e) Broker.aclose order: session_store → sink → adapters (D-8, AC-14.6)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_broker_aclose_order_session_then_sink_then_adapters() -> None:
    """AC-14.6 / D-8: aclose fires ``session_store`` → sink → adapter close.

    Three :class:`AsyncMock` stand-ins share a single ``order`` list; each
    wraps its ``aclose``/``close`` such that invocation appends a tag. After
    ``broker.aclose()`` the list must be ``["session", "sink", "adapter"]``.
    """
    broker = Broker.from_config(FIXTURE_PATH)
    order: list[str] = []

    # Session store mock — the broker calls ``aclose`` iff it exists.
    session_mock = AsyncMock(name="session_store_mock")

    async def _session_aclose() -> None:
        order.append("session")

    session_mock.aclose.side_effect = _session_aclose
    broker._session_store = session_mock  # type: ignore[attr-defined]  # noqa: SLF001

    # Attestation sink mock — async ``close`` contract.
    sink_mock = AsyncMock(name="attestation_sink_mock")

    async def _sink_close() -> None:
        order.append("sink")

    sink_mock.close.side_effect = _sink_close
    broker._attestation_sink = sink_mock  # type: ignore[attr-defined]  # noqa: SLF001

    # Adapter mock — async ``close`` contract.
    adapter_mock = AsyncMock(name="adapter_mock", spec=Adapter)

    async def _adapter_close() -> None:
        order.append("adapter")

    adapter_mock.close.side_effect = _adapter_close
    broker._adapters = {"a1": adapter_mock}  # type: ignore[attr-defined]  # noqa: SLF001

    await broker.aclose()

    assert order == ["session", "sink", "adapter"], (
        f"expected session→sink→adapter close order; got {order!r}"
    )
    # Second aclose is a no-op (idempotency contract); order list unchanged.
    await broker.aclose()
    assert order == ["session", "sink", "adapter"]
