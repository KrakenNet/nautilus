"""Unit coverage for :mod:`nautilus.observability.logging` (#28).

Covers:

(a) :class:`JsonFormatter` renders one parseable JSON object with the
    documented schema fields (``ts``/``level``/``logger``/``module``/``msg``).
(b) ``extra={...}`` keys (e.g. ``request_id``) pass through as top-level
    fields; non-JSON-native values stringify instead of raising.
(c) ``exc_info`` is serialized into the payload.
(d) No active OTel span → no ``trace_id``/``span_id`` keys.
(e) ``configure_logging`` installs the JSON handler on the root logger and
    a known event emits a parseable JSON line on stdout (the issue's
    integration acceptance); ``"text"`` keeps a plain formatter.
(f) ``nautilus serve --log-format`` parses, defaults to ``text``.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest

from nautilus.cli import _build_parser  # pyright: ignore[reportPrivateUsage]
from nautilus.observability.logging import JsonFormatter, configure_logging

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def restore_root_logging() -> Iterator[None]:
    """Snapshot + restore root logger handlers/level around configure_logging tests."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)


def _record(
    msg: str = "hello %s",
    args: tuple[Any, ...] = ("world",),
    exc_info: Any = None,
) -> logging.LogRecord:
    return logging.LogRecord(
        name="nautilus.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=42,
        msg=msg,
        args=args,
        exc_info=exc_info,
    )


# ---------------------------------------------------------------------------
# (a) schema fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_formatter_emits_documented_schema() -> None:
    payload: dict[str, Any] = json.loads(JsonFormatter().format(_record()))
    assert payload["level"] == "INFO"
    assert payload["logger"] == "nautilus.test"
    assert payload["module"] == "test_json_logging"
    assert payload["msg"] == "hello world"
    # ``ts`` is ISO-8601 UTC and parses back to an aware datetime.
    ts = datetime.fromisoformat(payload["ts"])
    assert ts.tzinfo is not None


# ---------------------------------------------------------------------------
# (b) extra passthrough
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_extra_fields_pass_through() -> None:
    logger = logging.getLogger("nautilus.test")
    record = logger.makeRecord(
        "nautilus.test",
        logging.WARNING,
        __file__,
        1,
        "scoped",
        (),
        None,
        extra={"request_id": "r-123", "when": datetime(2026, 1, 1, tzinfo=UTC)},
    )
    payload: dict[str, Any] = json.loads(JsonFormatter().format(record))
    assert payload["request_id"] == "r-123"
    # Non-JSON-native extras stringify (default=str) instead of raising.
    assert payload["when"].startswith("2026-01-01")


# ---------------------------------------------------------------------------
# (c) exc_info serialization
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_exc_info_serialized() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        record = _record(msg="failed", args=(), exc_info=sys.exc_info())
    payload: dict[str, Any] = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exc_info"]


# ---------------------------------------------------------------------------
# (d) no active span -> no trace keys
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_no_trace_keys_without_active_span() -> None:
    payload: dict[str, Any] = json.loads(JsonFormatter().format(_record()))
    assert "trace_id" not in payload
    assert "span_id" not in payload


# ---------------------------------------------------------------------------
# (e) configure_logging integration
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_configure_logging_json_emits_parseable_line(
    restore_root_logging: None, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging("json")
    logging.getLogger("nautilus.startup").info("broker ready", extra={"request_id": "r-9"})
    line = capsys.readouterr().out.strip().splitlines()[-1]
    payload: dict[str, Any] = json.loads(line)
    assert payload["msg"] == "broker ready"
    assert payload["logger"] == "nautilus.startup"
    assert payload["request_id"] == "r-9"


@pytest.mark.unit
def test_configure_logging_text_is_not_json(restore_root_logging: None) -> None:
    configure_logging("text")
    root = logging.getLogger()
    assert root.handlers, "basicConfig must install a handler"
    assert not any(isinstance(h.formatter, JsonFormatter) for h in root.handlers)


# ---------------------------------------------------------------------------
# (f) serve --log-format flag
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_serve_log_format_flag_parses_and_defaults_to_text() -> None:
    parser = _build_parser()
    default_args = parser.parse_args(["serve", "--config", "x.yaml"])
    assert default_args.log_format == "text"
    json_args = parser.parse_args(["serve", "--config", "x.yaml", "--log-format", "json"])
    assert json_args.log_format == "json"
    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--config", "x.yaml", "--log-format", "xml"])
