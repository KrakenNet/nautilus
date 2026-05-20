"""Unit tests for :mod:`nautilus.rkm.audit_emitter` (OQ1 resolution)."""

from __future__ import annotations

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


def test_oq1_queue_failure_is_swallowed() -> None:
    """``queue()`` exceptions must NOT break the request path."""
    logger = _RecordingLogger()
    emitter = AuditEventEmitter(audit_logger=logger)  # type: ignore[arg-type]
    # Passing an unrepresentable object should be swallowed (best-effort).
    emitter.queue("meta_rule_fired", fields={"bad": object()})


def test_oq1_flush_returns_zero_on_empty_buffer() -> None:
    logger = _RecordingLogger()
    emitter = AuditEventEmitter(audit_logger=logger)  # type: ignore[arg-type]
    assert emitter.flush(trace_id="trace-empty", session_id=None) == 0
