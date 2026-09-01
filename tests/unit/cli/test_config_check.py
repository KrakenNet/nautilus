"""``nautilus config check`` answers the question ``serve`` answers at startup.

Nautilus has no config hot-reload (``docs/how-to/hardening.md``), so the only
pre-deploy question about a config is whether a process will come up on it.
``config check`` exists to ask that question without a restart, and it is only
worth having while its answer is ``serve``'s answer: a checker that blesses a
config ``serve`` then refuses is worse than no checker, because the operator
rolled the deployment on it.

So these compare the two directly — same file, same words on stderr, same exit
code — rather than asserting against a transcript of what the message is
believed to be.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from nautilus.cli import _build_parser, _cmd_serve, main  # pyright: ignore[reportPrivateUsage]

_GOOD = """\
sources:
  - id: orders
    type: static
    classification: unclassified
    data_types: [orders]
    rows:
      - {order_id: 1001}

agents:
  agent-alpha:
    id: agent-alpha
    clearance: confidential
    allowed_purposes: [support]

audit:
  path: ./audit.jsonl
"""

_BAD: dict[str, str] = {
    # YAML that does not parse.
    "yaml": "sources:\n  - id: x\n   type: static\n",
    # Parses, but the models reject unknown keys.
    "unknown-key": _GOOD.replace("audit:\n  path:", "audit:\n  paht:"),
    # Valid model, refused by the broker: 'internal' is not a level of the
    # classification hierarchy, so the source would publish to everyone.
    "bad-label": _GOOD.replace("classification: unclassified", "classification: internal"),
    # A source type with no adapter behind it.
    "unknown-type": _GOOD.replace("type: static", "type: sybase"),
}


@pytest.fixture
def restore_root_logging() -> Iterator[None]:
    """Both commands configure process-wide logging; put the root back after."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)


def _serve(config_path: Path) -> int:
    """``nautilus serve --config <path>`` up to the point it would bind."""
    return _cmd_serve(_build_parser().parse_args(["serve", "--config", str(config_path)]))


@pytest.mark.parametrize("case", sorted(_BAD))
def test_check_refuses_what_serve_refuses_in_the_same_words(
    case: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    restore_root_logging: None,
) -> None:
    """One bad config, two commands, one refusal."""
    config = tmp_path / "nautilus.yaml"
    config.write_text(_BAD[case], encoding="utf-8")

    check_code = main(["config", "check", str(config)])
    check_err = capsys.readouterr().err

    serve_code = _serve(config)
    serve_err = capsys.readouterr().err

    assert check_code == 2, f"{case}: check accepted a config serve refuses"
    assert serve_code == 2, f"{case}: fixture is not actually a bad config"
    assert check_err == serve_err, f"{case}: check and serve disagree on the reason"
    assert check_err.startswith("ERROR: "), check_err


def test_check_refuses_a_path_that_is_not_there_the_way_serve_does(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    restore_root_logging: None,
) -> None:
    """The commonest deploy-time mistake: the file is not where you said."""
    missing = tmp_path / "nope.yaml"

    assert main(["config", "check", str(missing)]) == 2
    check_err = capsys.readouterr().err

    assert _serve(missing) == 2
    assert capsys.readouterr().err == check_err
    assert check_err == f"ERROR: config path does not exist or is not a file: {missing}\n"


def test_check_passes_a_config_serve_starts_on_and_says_what_it_would_serve(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    restore_root_logging: None,
) -> None:
    """Exit 0, and the summary is drawn from the broker that was really built."""
    config = tmp_path / "nautilus.yaml"
    config.write_text(_GOOD, encoding="utf-8")

    assert main(["config", "check", str(config)]) == 0
    out = capsys.readouterr().out

    assert out.startswith(f"OK: {config} — serve would start on this config\n")
    assert "  bind:          127.0.0.1:8000   (api.host/api.port; serve --bind overrides)\n" in out
    assert "  sources:       1 (orders)\n" in out
    assert "  agents:        1 (agent-alpha)\n" in out
    assert f"  audit log:     {tmp_path / 'audit.jsonl'}\n" in out

    served: list[tuple[str, int]] = []

    async def _fake_run_rest(_broker: Any, host: str, port: int, _level: str = "info") -> None:
        served.append((host, port))

    monkeypatch.setattr("nautilus.cli._run_rest", _fake_run_rest)
    assert _serve(config) == 0, "check blessed a config serve does not start on"
    assert served == [("127.0.0.1", 8000)]
