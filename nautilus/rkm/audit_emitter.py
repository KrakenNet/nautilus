"""AuditEventEmitter — buffered meta-rule + RKM event plumbing (OQ1 resolution).

``FathomRouter.route()`` fires meta-rules; meta-rules call
``emitter.queue(event_type, fields)``. Buffer lives on a
``contextvars.ContextVar`` keyed by ``trace_id`` so events survive async
boundaries. ``Broker.arequest()`` calls :meth:`flush` once per request,
*before* response build, in a ``try/finally``.

Failure mode (Risks #1, Failure modes table):
``emitter.queue()`` exceptions are swallowed + logged to stderr with
``trace_id`` + ``event_type``. Never breaks request path.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class _AuditEventSink(Protocol):
    """Minimal protocol: anything with ``emit_event(entry)``."""

    def emit_event(self, entry: Any) -> None: ...


class AuditEventEmitter:
    """Per-request buffer of meta-rule + RKM audit events (OQ1 resolution)."""

    def __init__(self, audit_logger: _AuditEventSink) -> None:
        self._logger = audit_logger
        self._buffer: list[tuple[str, dict[str, Any]]] = []

    def queue(self, event_type: str, *, fields: Mapping[str, Any]) -> None:
        """Append a (event_type, fields) tuple to the per-trace_id buffer.

        Cheap; no I/O. Exceptions are swallowed + logged to stderr.
        """
        try:
            self._buffer.append((event_type, dict(fields)))
        except Exception as exc:  # noqa: BLE001
            print(  # noqa: T201
                f"[AuditEventEmitter] queue swallowed: event_type={event_type!r} err={exc}",
                file=sys.stderr,
            )

    def flush(self, *, trace_id: str, session_id: str | None) -> int:
        """Drain buffer for ``trace_id``; return events emitted.

        Each queued event becomes a separate entry with the
        parent request's ``trace_id`` + ``session_id`` stamped in.
        """
        items = self._buffer
        self._buffer = []
        count = 0
        for event_type, fields in items:
            try:
                entry = {
                    "event_type": event_type,
                    "trace_id": trace_id,
                    "session_id": session_id,
                    "timestamp": datetime.now(tz=UTC).isoformat(),
                    "schema_version": 2,
                    **fields,
                }
                self._logger.emit_event(entry)
                count += 1
            except Exception as exc:  # noqa: BLE001
                print(  # noqa: T201
                    f"[AuditEventEmitter] flush swallowed: trace_id={trace_id!r} "
                    f"event_type={event_type!r} err={exc}",
                    file=sys.stderr,
                )
        return count


def emit_event_oob(logger: _AuditEventSink, entry: Any) -> None:
    """Direct out-of-band emission (CLI approve/reject, schema-ack, key rotate).

    NOT for in-request meta-rule firings — those use the buffered emitter.
    Mirrors :meth:`AuditLogger.emit` fsync durability semantics.
    """
    logger.emit_event(entry)


__all__ = ["AuditEventEmitter", "emit_event_oob"]
