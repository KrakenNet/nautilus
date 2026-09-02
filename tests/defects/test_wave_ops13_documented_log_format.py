"""WAVE ops13 — the docs published a unit in one log format and a procedure in the other.

``docs/how-to/hardening.md`` publishes the systemd unit an operator is told to
install, and its ``ExecStart`` carries ``--log-format json``.
``docs/how-to/operator-guide.md`` then tells the same operator that a successful
``systemctl reload nautilus`` looks like

.. code-block:: text

    INFO:nautilus.cli.serve:SIGHUP: reloaded /etc/nautilus/nautilus.yaml (adopted sources)

and shows the refusal in the same shape. That is :class:`TextFormatter` output.
Under the unit the documentation itself publishes the record goes through
:class:`JsonFormatter`, so ``journalctl`` returns

.. code-block:: text

    {"ts": "...", "level": "INFO", "logger": "nautilus.cli.serve", "module":
     "serve", "msg": "SIGHUP: reloaded /etc/nautilus/nautilus.yaml (adopted sources)"}

and the quoted line never appears. An operator who follows the hardening guide
and then the operator guide is told to look for something their own deployment
cannot print. Neither side was wrong on its own; nothing compared them.

**The check is general, not an assertion about those two lines.** It reads the
unit's ``--log-format`` out of the documentation rather than assuming it, finds
every section whose procedure drives the service through ``systemctl``, and
requires every Nautilus log record that section quotes to be quoted in the
format that unit runs. Change the unit to ``text`` and the JSON blocks become
the failures; add a third procedure and it is covered the day it is written.

Verification is by rendering: the JSON block is rebuilt into a
:class:`logging.LogRecord` and pushed back through the real
:class:`JsonFormatter`, so a hand-written block that is *almost* the formatter's
output — a missing ``module``, an invented field — fails too.

The uvicorn tests cover the other half. The guide's non-systemd fallback reads
the PID out of ``INFO:     Started server process [N]``, which is uvicorn's
string and not this project's, and it is only the one PID because ``serve``
never asks for workers. Both are now pinned against what is installed, so a
uvicorn that renames the line, or a change here that adds workers, fails in this
suite instead of on a host at 3am.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from nautilus.observability.logging import JsonFormatter, TextFormatter

REPO_ROOT = Path(__file__).resolve().parents[2]

_FENCE = re.compile(r"^```(\w*)\n(.*?)^```", re.MULTILINE | re.DOTALL)
_HEADING = re.compile(r"^#{1,6} .*$", re.MULTILINE)

# `systemctl reload nautilus`, `sudo systemctl restart nautilus`, and the rest:
# a command that drives *this* service through the unit the docs publish.
_SYSTEMCTL = re.compile(r"\bsystemctl\s+(?:-\S+\s+)*[a-z-]+\s+nautilus\b")
# One rendered TextFormatter record: logging.BASIC_FORMAT is `%(levelname)s:%(name)s:%(message)s`.
_TEXT_RECORD = re.compile(r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL):(nautilus[\w.]*):(.*)$")
_LOG_FORMAT_FLAG = re.compile(r"--log-format[= ]+(\w+)")

_LEVELS = logging.getLevelNamesMapping()


def _pages() -> list[Path]:
    """Every operator-facing markdown page."""
    return [REPO_ROOT / "deploy" / "README.md", *sorted((REPO_ROOT / "docs").rglob("*.md"))]


def _blocks(section: str) -> Iterator[tuple[str, str]]:
    """Yield ``(language, body)`` for every fenced block in ``section``."""
    for match in _FENCE.finditer(section):
        yield match.group(1), match.group(2)


def _sections(text: str) -> Iterator[str]:
    """Yield each heading and the body under it, as one string.

    A section is the unit of scope: the command that drives the service and the
    output the reader is told to expect from it are written together, under one
    heading, and a reader who has scrolled past the heading has left the
    procedure.
    """
    bounds = [match.start() for match in _HEADING.finditer(text)]
    if not bounds:
        return
    for start, end in zip(bounds, [*bounds[1:], len(text)], strict=True):
        yield text[start:end]


def _published_unit_log_format() -> str:
    """The ``--log-format`` of the systemd unit the documentation publishes.

    Read out of the docs, not assumed: the check follows the unit rather than
    pinning a format, so editing ``ExecStart`` moves what the procedures must
    show instead of silently disagreeing with them.
    """
    formats: list[str] = []
    for page in _pages():
        for language, body in _blocks(page.read_text(encoding="utf-8")):
            if language != "ini" or "ExecStart=" not in body or "nautilus serve" not in body:
                continue
            exec_start = body.replace("\\\n", " ").partition("ExecStart=")[2].partition("\n")[0]
            found = _LOG_FORMAT_FLAG.search(exec_start)
            formats.append(found.group(1) if found else "text")
    assert formats, (
        "found no systemd unit in the documentation — the `ini` block holding "
        "`ExecStart=... nautilus serve` moved or was relabelled, so this check "
        "is vacuous"
    )
    assert len(set(formats)) == 1, (
        f"the documentation publishes units disagreeing on --log-format: {formats}. "
        "An operator's procedures cannot be right for both."
    )
    return formats[0]


def _text_records(section: str) -> list[tuple[str, str, str]]:
    """``(level, logger, message)`` for every text-rendered Nautilus record quoted."""
    out: list[tuple[str, str, str]] = []
    for _, body in _blocks(section):
        for line in body.splitlines():
            hit = _TEXT_RECORD.match(line)
            if hit:
                out.append((hit.group(1), hit.group(2), hit.group(3)))
    return out


def _json_records(section: str) -> list[dict[str, Any]]:
    """Every JSON-rendered Nautilus record quoted, as its parsed payload."""
    out: list[dict[str, Any]] = []
    for _, body in _blocks(section):
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped.startswith("{"):
                continue
            try:
                parsed: Any = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue
            payload = cast("dict[str, Any]", parsed)
            if str(payload.get("logger", "")).startswith("nautilus"):
                out.append(payload)
    return out


_SCHEMA_FIELDS = frozenset({"ts", "level", "logger", "module", "msg"})


def _record_from(payload: dict[str, Any]) -> logging.LogRecord:
    """Rebuild the :class:`logging.LogRecord` a quoted JSON payload came from."""
    record = logging.LogRecord(
        name=payload["logger"],
        level=_LEVELS[payload["level"]],
        # LogRecord derives `module` from the basename of `pathname`.
        pathname=f"{payload['module']}.py",
        lineno=1,
        msg=payload["msg"],
        args=None,
        exc_info=None,
    )
    # Anything outside the schema reached the payload through `extra={...}`,
    # which the formatter passes through unfiltered — put it back the same way.
    for key, value in payload.items():
        if key not in _SCHEMA_FIELDS:
            setattr(record, key, value)
    return record


def _systemd_scoped_sections() -> list[tuple[str, str]]:
    """``(page, section)`` for every section whose procedure runs ``systemctl``."""
    out: list[tuple[str, str]] = []
    for page in _pages():
        for section in _sections(page.read_text(encoding="utf-8")):
            if any(
                language in {"bash", "console", "shell", "sh"} and _SYSTEMCTL.search(body)
                for language, body in _blocks(section)
            ):
                out.append((page.relative_to(REPO_ROOT).as_posix(), section))
    return out


def test_every_log_line_a_systemd_procedure_quotes_is_one_that_unit_can_emit() -> None:
    """A procedure driven through the published unit must quote that unit's format.

    This is the check that was missing. The hardening guide's unit has run
    ``--log-format json`` for as long as it has existed and the reload procedure
    has been written in text for as long as *it* has existed, and nothing
    compared them, because each page is right on its own.
    """
    unit_format = _published_unit_log_format()
    sections = _systemd_scoped_sections()
    assert sections, (
        "found no section running `systemctl ... nautilus` in deploy/README.md "
        "or docs/**.md — the parser stopped matching, so this check is vacuous"
    )

    quoted = 0
    missing: list[str] = []
    for page, section in sections:
        heading = section.splitlines()[0]
        texts = _text_records(section)
        payloads = _json_records(section)
        quoted += len(texts) + len(payloads)
        as_text = {record for record in texts}
        as_json = {(p["level"], p["logger"], p["msg"]) for p in payloads}
        shown = as_text | as_json
        available = as_json if unit_format == "json" else as_text
        missing += [
            f"{page} {heading!r}: {level}:{logger}:{message}"
            for level, logger, message in sorted(shown - available)
        ]
    assert quoted, (
        "found no Nautilus log record quoted in any systemd procedure — the "
        "record parsers stopped matching, so this check is vacuous"
    )
    assert not missing, (
        f"the documented systemd unit runs --log-format {unit_format}, and these "
        f"records are quoted in the other format only: {missing}. An operator "
        "following the unit cannot grep for a line their deployment does not "
        "print — show the record in the unit's format too, or change the unit."
    )


def test_every_json_record_the_docs_quote_is_what_jsonformatter_emits() -> None:
    """Quoted JSON is checked by re-rendering it, not by eyeballing the shape.

    A block that is nearly the formatter's output is the failure mode a regex
    would wave through: a missing ``module``, a field nothing emits, a level
    spelled ``INFORMATION``.
    """
    checked = 0
    wrong: list[str] = []
    for page in _pages():
        for section in _sections(page.read_text(encoding="utf-8")):
            for payload in _json_records(section):
                if not payload.keys() >= _SCHEMA_FIELDS or payload["level"] not in _LEVELS:
                    wrong.append(f"{page.name}: not a JsonFormatter payload: {payload}")
                    continue
                checked += 1
                rendered = json.loads(JsonFormatter().format(_record_from(payload)))
                # `ts` is the moment the record was created; everything else is
                # a claim about the record itself.
                if {k: v for k, v in rendered.items() if k != "ts"} != {
                    k: v for k, v in payload.items() if k != "ts"
                }:
                    wrong.append(f"{page.name}: quoted {payload}, formatter emits {rendered}")
    assert checked, (
        "found no quoted JSON log record in deploy/README.md or docs/**.md — the "
        "parser stopped matching, so this check is vacuous"
    )
    assert not wrong, f"quoted JSON logs that JsonFormatter does not produce: {wrong}"


def test_the_text_log_shape_the_docs_quote_is_the_shape_textformatter_emits() -> None:
    """``LEVEL:logger:message`` is load-bearing across the documentation.

    Around fifty quoted lines are written in it, and every ``grep`` a procedure
    gives is written against it. A prefix added to :class:`TextFormatter` — a
    timestamp, a PID — stales all of them at once.
    """
    record = logging.LogRecord(
        name="nautilus.cli.serve",
        level=logging.INFO,
        pathname="serve.py",
        lineno=1,
        msg="SIGHUP: reloaded /etc/nautilus/nautilus.yaml (adopted sources)",
        args=None,
        exc_info=None,
    )
    assert TextFormatter().format(record) == (
        "INFO:nautilus.cli.serve:SIGHUP: reloaded /etc/nautilus/nautilus.yaml (adopted sources)"
    )


def test_the_startup_line_the_docs_read_a_pid_from_is_one_uvicorn_still_prints() -> None:
    """The non-systemd fallback depends on a third-party library's log string.

    ``docs/how-to/operator-guide.md`` tells an operator outside systemd to take
    the PID from ``INFO:     Started server process [N]``. Nothing in this
    project emits that; uvicorn does. It is the right line to use — it is the
    only one naming the PID, and uvicorn keeps its own handlers so
    ``--log-format json`` does not reshape it — but a documented procedure may
    only lean on someone else's string if a rename fails here rather than on a
    host during an incident.
    """
    import uvicorn.server

    template = "Started server process ["
    quoted = [
        (page.relative_to(REPO_ROOT).as_posix(), line.strip())
        for page in _pages()
        for line in page.read_text(encoding="utf-8").splitlines()
        if re.search(r"Started server process \[\d+\]", line)
    ]
    assert quoted, (
        "no page quotes uvicorn's startup line any more — drop this test with "
        "the procedure that needed it"
    )
    source = Path(uvicorn.server.__file__).read_text(encoding="utf-8")
    assert f'"{template}%d]"' in source, (
        f"the installed uvicorn ({uvicorn.__version__}) no longer logs "
        f"{template!r}, and these documented procedures read the broker's PID "
        f"out of it: {quoted}"
    )


def test_serve_asks_uvicorn_for_no_workers() -> None:
    """One process, so the startup line names the PID that answers ``SIGHUP``.

    With ``workers=N`` uvicorn forks and logs one ``Started server process``
    line per child, none of which is the process a signal should reach — the
    documented fallback would then hand the operator a worker PID.
    """
    source = (REPO_ROOT / "nautilus" / "cli" / "serve.py").read_text(encoding="utf-8")
    configs = [
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Config"
    ]
    assert configs, "no uvicorn.Config call in nautilus/cli/serve.py — this check is vacuous"
    workers = [c for c in configs if any(kw.arg == "workers" for kw in c.keywords)]
    assert not workers, (
        "nautilus/cli/serve.py asks uvicorn for workers. The operator guide's "
        "non-systemd reload reads the broker's PID from the single "
        "`Started server process [N]` line; with workers there are several and "
        "none of them is the one to signal."
    )
