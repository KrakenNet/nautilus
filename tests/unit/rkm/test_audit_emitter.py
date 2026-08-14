"""Unit tests for :mod:`nautilus.rkm.audit_emitter` (OQ1 resolution)."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from nautilus.rkm.audit_emitter import AuditEventEmitter

pytestmark = pytest.mark.unit


class _RecordingLogger:
    """Capture emitted entries for assertion. Mocks the *boundary* audit
    sink (a public Protocol surface) — not internal RKM modules."""

    def __init__(self) -> None:
        self.entries: list[Any] = []

    def emit_event(self, entry: Any) -> None:
        self.entries.append(entry)


def test_oq1_queue_and_flush_emits_per_event() -> None:
    logger = _RecordingLogger()
    emitter = AuditEventEmitter(audit_logger=logger)  # type: ignore[arg-type]
    emitter.queue("meta_rule_fired", fields={"rule_name": "x"})
    emitter.queue("relationship_observed", fields={"pattern_hash": "abc"})
    count = emitter.flush(trace_id="trace-1", session_id="sess-1")
    assert count == 2
    assert len(logger.entries) == 2


class _ExplodingMapping(Mapping[str, Any]):
    """A Mapping whose iteration raises — what ``dict(fields)`` chokes on.

    ``{"bad": object()}`` does not raise: an arbitrary object is a legal
    dict *value*, so the old version of this test never reached the guard
    it was named for.
    """

    def __getitem__(self, key: str) -> Any:
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("cannot iterate")

    def __len__(self) -> int:
        return 1


def test_oq1_queue_failure_is_swallowed(capsys: pytest.CaptureFixture[str]) -> None:
    """``queue()`` exceptions must NOT break the request path."""
    logger = _RecordingLogger()
    emitter = AuditEventEmitter(audit_logger=logger)  # type: ignore[arg-type]
    emitter.queue("meta_rule_fired", fields=_ExplodingMapping())

    assert "queue swallowed" in capsys.readouterr().err
    # The request path continues: the bad event is dropped, not buffered,
    # and a later good event still flushes.
    emitter.queue("meta_rule_fired", fields={"rule_name": "x"})
    assert emitter.flush(trace_id="t", session_id=None) == 1


def test_oq1_flush_failure_is_swallowed(capsys: pytest.CaptureFixture[str]) -> None:
    """A sink that raises must not break the request path either."""

    class _BrokenLogger:
        def emit_event(self, entry: Any) -> None:
            raise OSError("audit sink is down")

    emitter = AuditEventEmitter(audit_logger=_BrokenLogger())  # type: ignore[arg-type]
    emitter.queue("meta_rule_fired", fields={"rule_name": "x"})

    assert emitter.flush(trace_id="t", session_id=None) == 0
    assert "flush swallowed" in capsys.readouterr().err


def test_oq1_flush_returns_zero_on_empty_buffer() -> None:
    logger = _RecordingLogger()
    emitter = AuditEventEmitter(audit_logger=logger)  # type: ignore[arg-type]
    assert emitter.flush(trace_id="trace-empty", session_id=None) == 0
