"""Structured JSON logging for application logs (#28, roadmap §05:435).

The broker's *decision* trail already lives in ``audit.jsonl``; this module
covers the surrounding application logs (startup, errors, lifecycle) so
SIEM/compliance pipelines can ingest them. One stdlib :class:`logging.Formatter`
subclass — no ``structlog`` dependency.

Schema per line::

    {"ts": "...", "level": "INFO", "logger": "nautilus.core.broker",
     "module": "broker", "msg": "...", ...extras, "trace_id"?, "span_id"?}

- Any ``extra={...}`` keys passed to a logging call are emitted as
  top-level fields (e.g. ``log.info("...", extra={"request_id": rid})``).
- ``trace_id`` / ``span_id`` are attached when an OpenTelemetry span is
  active (the OTel SDK is optional — enrichment degrades to a no-op).

Applied process-wide only at entry points (``nautilus serve --log-format
json``, the forensic worker ``__main__``); library code keeps plain
``logging.getLogger(__name__)``.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, Literal

LogFormat = Literal["text", "json"]

# Attributes present on every stdlib LogRecord — anything else on the record's
# __dict__ arrived via ``extra={...}`` and is passed through to the payload.
_STANDARD_ATTRS: frozenset[str] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


def _trace_context() -> dict[str, str]:
    """Return ``trace_id`` / ``span_id`` for the active OTel span, if any.

    The OTel SDK is an optional dependency (see
    :func:`nautilus.observability.setup_otel`) — missing packages or an
    invalid/absent span context degrade to an empty dict.
    """
    try:
        from opentelemetry import trace
    except ImportError:
        return {}
    ctx = trace.get_current_span().get_span_context()
    if not ctx.is_valid:
        return {}
    return {
        "trace_id": format(ctx.trace_id, "032x"),
        "span_id": format(ctx.span_id, "016x"),
    }


class JsonFormatter(logging.Formatter):
    """Render each record as one JSON object per line (SIEM-ingestable)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "msg": record.getMessage(),
        }
        # ``extra={...}`` passthrough — e.g. request_id correlation.
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = value
        payload.update(_trace_context())
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)
        return json.dumps(payload, default=str)


def configure_logging(log_format: LogFormat = "text", level: int = logging.INFO) -> None:
    """Configure root logging for a process entry point.

    ``"json"`` installs a stdout :class:`JsonFormatter` handler; ``"text"``
    is plain :func:`logging.basicConfig` (local-dev default). ``force=True``
    so re-invocation (e.g. tests) deterministically replaces prior handlers.
    """
    if log_format == "json":
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logging.basicConfig(level=level, handlers=[handler], force=True)
    else:
        logging.basicConfig(level=level, force=True)


__all__ = ["JsonFormatter", "LogFormat", "configure_logging"]
