"""Unit tests for the ``nautilus cost-caps`` CLI subcommand group (Task 21).

Coverage targets (AC-2.13, OQ-8, US-2):

    a. ``cost-caps show --help`` advertises the ``--source`` filter.
    b. ``cost-caps show`` (no filter) lists all sources with merged caps —
       per-source override fields win over the global default.
    c. ``cost-caps show --source <id>`` filters to a single row.
    d. ``cost-caps show --source <unknown>`` exits 2 with a stderr message.
    e. ``cost-caps show`` with no global caps + no per-source caps renders
       ``"-"`` in every numeric column and the ``"hard"`` enforcement default.

All cases drive :func:`nautilus.cli.main` in-process with an explicit
``argv``, monkeypatching :meth:`Broker.from_config` to a stub that
exposes a synchronous ``sources``/``_config`` seam — no Postgres, no
network. Mirrors ``test_cli_sources.py`` idioms.
"""
# pyright: reportPrivateUsage=false, reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus import cli
from nautilus.config.models import CostCapConfig, SourceConfig

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path) -> Path:
    """Write a minimal nautilus.yaml stub (the CLI only checks ``is_file()``)."""
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    return cfg


def _make_source(
    source_id: str,
    *,
    cost_caps: CostCapConfig | None = None,
) -> SourceConfig:
    """Build a minimal :class:`SourceConfig` for cost-caps merging."""
    return SourceConfig(
        id=source_id,
        type="postgres",
        description=f"test source {source_id}",
        classification="internal",
        data_types=["metrics"],
        connection="postgres://localhost/test",
        cost_caps=cost_caps,
    )


def _install_stub_broker(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sources: list[SourceConfig],
    global_cap: CostCapConfig | None,
) -> MagicMock:
    """Patch :meth:`Broker.from_config` to return a stub with sources + config."""
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()
    broker.sources = sources

    config = MagicMock()
    config.cost_caps = global_cap
    broker._config = config

    from nautilus.core import broker as broker_mod

    monkeypatch.setattr(
        broker_mod.Broker,
        "from_config",
        classmethod(lambda _cls, _p: broker),
    )
    return broker


# ---------------------------------------------------------------------------
# (a) cost-caps show --help
# ---------------------------------------------------------------------------


def test_cli_cost_caps_show_help_advertises_source_filter(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``cost-caps show --help`` must advertise ``--source`` and ``--config``."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["cost-caps", "show", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--source" in out
    assert "--config" in out


def test_cli_cost_caps_help_lists_show_operation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``cost-caps --help`` must list the ``show`` operation."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["cost-caps", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "show" in out


# ---------------------------------------------------------------------------
# (b) cost-caps show — merged caps per source
# ---------------------------------------------------------------------------


def test_cli_cost_caps_show_merges_global_and_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Global ``max_tokens=4000``; source A overrides to 2000 — row A reads 2000."""
    cfg = _write_config(tmp_path)
    global_cap = CostCapConfig(max_tokens=4000, enforcement="hard")
    sources = [
        _make_source("A", cost_caps=CostCapConfig(max_tokens=2000)),
        _make_source("B"),
        _make_source("C"),
    ]
    _install_stub_broker(monkeypatch, sources=sources, global_cap=global_cap)

    rc = cli.main(["cost-caps", "show", "--config", str(cfg)])
    assert rc == 0

    out = capsys.readouterr().out
    # Header columns all present.
    assert "source_id" in out
    assert "max_tokens" in out
    assert "max_duration_seconds" in out
    assert "max_tool_calls" in out
    assert "enforcement" in out
    # All three rows present.
    assert "A" in out
    assert "B" in out
    assert "C" in out
    # Per-row values — A overrides to 2000, B and C inherit 4000.
    lines = out.splitlines()
    row_a = next(line for line in lines if line.startswith("A "))
    row_b = next(line for line in lines if line.startswith("B "))
    row_c = next(line for line in lines if line.startswith("C "))
    assert "2000" in row_a
    assert "4000" in row_b
    assert "4000" in row_c
    # Enforcement defaults to "hard".
    assert "hard" in row_a


# ---------------------------------------------------------------------------
# (c) cost-caps show --source <id> — single-row filter
# ---------------------------------------------------------------------------


def test_cli_cost_caps_show_filters_to_single_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``--source A`` must render only source A's merged row."""
    cfg = _write_config(tmp_path)
    global_cap = CostCapConfig(max_tokens=4000)
    sources = [
        _make_source("A", cost_caps=CostCapConfig(max_tokens=2000)),
        _make_source("B"),
    ]
    _install_stub_broker(monkeypatch, sources=sources, global_cap=global_cap)

    rc = cli.main(["cost-caps", "show", "--source", "A", "--config", str(cfg)])
    assert rc == 0

    out = capsys.readouterr().out
    # Only A appears as a data row; B must not.
    data_lines = [
        line
        for line in out.splitlines()
        if line and not line.startswith("source_id") and not line.startswith("-")
    ]
    assert len(data_lines) == 1
    assert data_lines[0].startswith("A ")
    assert "2000" in data_lines[0]


# ---------------------------------------------------------------------------
# (d) cost-caps show --source <unknown> — exit 2
# ---------------------------------------------------------------------------


def test_cli_cost_caps_show_unknown_source_exits_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unknown ``--source`` id must exit 2 with a readable stderr message."""
    cfg = _write_config(tmp_path)
    sources = [_make_source("A"), _make_source("B")]
    _install_stub_broker(monkeypatch, sources=sources, global_cap=None)

    rc = cli.main(
        ["cost-caps", "show", "--source", "unknown", "--config", str(cfg)],
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown source id" in err
    assert "unknown" in err


# ---------------------------------------------------------------------------
# (e) no global caps + no per-source caps — all dashes + "hard" default
# ---------------------------------------------------------------------------


def test_cli_cost_caps_show_no_caps_renders_dashes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No global + no per-source caps: every numeric column ``-`` and enforcement ``hard``."""
    cfg = _write_config(tmp_path)
    sources = [_make_source("A"), _make_source("B")]
    _install_stub_broker(monkeypatch, sources=sources, global_cap=None)

    rc = cli.main(["cost-caps", "show", "--config", str(cfg)])
    assert rc == 0

    out = capsys.readouterr().out
    lines = out.splitlines()
    row_a = next(line for line in lines if line.startswith("A "))
    row_b = next(line for line in lines if line.startswith("B "))
    # All three numeric columns render "-" when cap is None.
    # The row looks like: "A    -    -    -    hard"
    a_tokens = row_a.split()
    b_tokens = row_b.split()
    # Tokens: source_id, max_tokens, max_duration_seconds, max_tool_calls, enforcement
    assert a_tokens[1] == "-"
    assert a_tokens[2] == "-"
    assert a_tokens[3] == "-"
    assert a_tokens[4] == "hard"
    assert b_tokens[1] == "-"
    assert b_tokens[4] == "hard"


# ---------------------------------------------------------------------------
# missing / malformed --config handling
# ---------------------------------------------------------------------------


def test_cli_cost_caps_show_missing_config_exits_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli.main(
        ["cost-caps", "show", "--config", "/definitely/not/a/real/nautilus.yaml"],
    )
    assert rc == 2
    assert "config path does not exist" in capsys.readouterr().err


def test_cli_cost_caps_show_always_closes_broker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Broker.aclose() must run even when rendering raises."""
    cfg = _write_config(tmp_path)
    broker = _install_stub_broker(
        monkeypatch,
        sources=[_make_source("A")],
        global_cap=None,
    )
    # Force a mid-flight failure: .sources raises when accessed.
    type(broker).sources = property(lambda _self: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(RuntimeError, match="boom"):
        cli.main(["cost-caps", "show", "--config", str(cfg)])

    broker.aclose.assert_awaited()
