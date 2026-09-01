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
  The passthrough is unfiltered by design — callers MUST NOT put
  credentials, DSNs, or tokens into ``extra`` (they would land verbatim
  in SIEM-ingested logs).
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


# C0 controls and DEL, rendered as their escape sequences. ``\n`` is the one
# that matters (it ends a text log record); ``\r`` can overwrite the line a
# terminal already drew, and ``\x1b`` starts an ANSI sequence, so an operator
# reading the file with ``cat`` is covered too. ``\t`` is escaped for the same
# reason a TSV would want it: nothing here needs a literal control character.
_CONTROL_ESCAPES: dict[int, str] = {c: f"\\x{c:02x}" for c in range(0x20)}
_CONTROL_ESCAPES.update({0x09: "\\t", 0x0A: "\\n", 0x0D: "\\r", 0x7F: "\\x7f"})


class TextFormatter(logging.Formatter):
    """:data:`logging.BASIC_FORMAT`, with control characters escaped.

    The text log's record separator is the newline, so any newline that
    reaches the rendered message *is* a record boundary. A source id or a
    config path containing one splits a single warning into two lines, and the
    second is indistinguishable from a line the broker wrote itself::

        $ F=$'evil\\nWARNING:nautilus.core.broker:audit chain verified OK.yaml'
        $ nautilus serve --config "$F"
        WARNING:nautilus.core.broker:No 'agents:' are declared in evil
        WARNING:nautilus.core.broker:audit chain verified OK.yaml, so every ...

    The second line is a forged "chain verified" claim, in the log an operator
    reads to decide whether the chain is intact, emitted by the product's own
    startup path. :class:`JsonFormatter` never had the problem --
    :func:`json.dumps` escapes the newline and the record stays one line -- so
    this is the text formatter catching up, and it is the default format.

    Escaping is applied to the interpolated message only. ``exc_info`` and
    ``stack_info`` are appended by :meth:`logging.Formatter.format` after this
    runs, so a traceback is still a readable multi-line traceback: it is
    generated from the interpreter's own frames, not from a caller's value.
    """

    def __init__(self) -> None:
        super().__init__(logging.BASIC_FORMAT)

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802 — stdlib hook
        record.message = record.message.translate(_CONTROL_ESCAPES)
        return super().formatMessage(record)


def configure_logging(log_format: LogFormat = "text", level: int = logging.INFO) -> None:
    """Configure root logging for a process entry point.

    ``"json"`` installs a stdout :class:`JsonFormatter` handler; ``"text"``
    installs a stderr :class:`TextFormatter` one -- same stream and same layout
    :func:`logging.basicConfig` would have given, with control characters
    escaped. ``force=True`` so re-invocation (e.g. tests) deterministically
    replaces prior handlers.
    """
    handler: logging.Handler
    if log_format == "json":
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
    else:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(TextFormatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)


__all__ = ["JsonFormatter", "LogFormat", "TextFormatter", "configure_logging"]
