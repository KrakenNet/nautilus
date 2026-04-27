"""Unit tests for the ``nautilus sources`` CLI subcommand group (Task 14).

Coverage targets (AC-3.9, US-3):

    a. ``sources --help`` lists the three operations.
    b. ``sources list`` renders the expected column header and a row.
    c. ``sources disable <id> --reason …`` calls ``set_enabled(..., enabled=False,
       reason=…, actor=…)`` exactly once.
    d. ``sources enable <id>`` calls ``set_enabled(..., enabled=True,
       reason=None, actor=…)`` exactly once.
    e. ``sources list`` with a memory-session-store config (no
       ``SourceStateStore``) exits 2 with a readable error on stderr.

All cases drive :func:`nautilus.cli.main` in-process with an explicit
``argv``, monkeypatching :meth:`Broker.from_config` to a stub that
exposes a synchronous ``_source_state_store`` seam — no Postgres, no
network. This mirrors the testing idiom used in ``test_cli_smoke.py``.
"""
# pyright: reportPrivateUsage=false, reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from nautilus import cli

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path) -> Path:
    """Write a minimal nautilus.yaml stub (the CLI only checks ``is_file()``)."""
    cfg = tmp_path / "nautilus.yaml"
    cfg.write_text("analysis: {mode: pattern}\n", encoding="utf-8")
    return cfg


def _make_state(
    source_id: str,
    *,
    enabled: bool,
    reason: str | None,
    actor: str,
) -> MagicMock:
    """Build a MagicMock mimicking :class:`SourceState` for table rendering."""
    state = MagicMock()
    state.source_id = source_id
    state.enabled = enabled
    state.reason = reason
    state.actor = actor
    state.changed_at = datetime(2026, 4, 23, 12, 0, 0, tzinfo=UTC)
    return state


def _install_stub_broker(
    monkeypatch: pytest.MonkeyPatch,
    *,
    load_all_rows: dict[str, Any] | None = None,
    store_is_none: bool = False,
) -> MagicMock:
    """Patch :meth:`Broker.from_config` to return a configurable stub.

    Returns the stub so tests may inspect call records on its
    ``_source_state_store`` attribute.
    """
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()

    if store_is_none:
        broker._source_state_store = None
    else:
        store = MagicMock()
        store.load_all = AsyncMock(return_value=load_all_rows or {})
        store.set_enabled = AsyncMock(return_value=MagicMock())
        broker._source_state_store = store

    from nautilus.core import broker as broker_mod

    monkeypatch.setattr(
        broker_mod.Broker,
        "from_config",
        classmethod(lambda _cls, _p: broker),
    )
    return broker


# ---------------------------------------------------------------------------
# (a) sources --help
# ---------------------------------------------------------------------------


def test_cli_sources_help_lists_three_operations(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sources --help`` must advertise list/disable/enable."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["sources", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "list" in out
    assert "disable" in out
    assert "enable" in out


# ---------------------------------------------------------------------------
# (b) sources list — table rendering
# ---------------------------------------------------------------------------


def test_cli_sources_list_renders_table(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    rows = {
        "src-a": _make_state("src-a", enabled=True, reason=None, actor="alice"),
        "src-b": _make_state("src-b", enabled=False, reason="maintenance", actor="bob"),
    }
    _install_stub_broker(monkeypatch, load_all_rows=rows)

    rc = cli.main(["sources", "list", "--config", str(cfg)])
    assert rc == 0

    out = capsys.readouterr().out
    # Column header columns all present.
    assert "source_id" in out
    assert "enabled" in out
    assert "reason" in out
    assert "actor" in out
    assert "changed_at" in out
    # Both rows present.
    assert "src-a" in out
    assert "src-b" in out
    assert "alice" in out
    assert "bob" in out
    # None reason rendered as "-".
    assert "true" in out
    assert "false" in out
    assert "maintenance" in out


def test_cli_sources_list_empty_store_renders_header_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    _install_stub_broker(monkeypatch, load_all_rows={})

    rc = cli.main(["sources", "list", "--config", str(cfg)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "source_id" in out
    assert "changed_at" in out


# ---------------------------------------------------------------------------
# (c) sources disable — single set_enabled(False) call
# ---------------------------------------------------------------------------


def test_cli_sources_disable_calls_set_enabled_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path)
    broker = _install_stub_broker(monkeypatch)

    rc = cli.main(
        [
            "sources",
            "disable",
            "foo",
            "--reason",
            "test",
            "--actor",
            "unit-tester",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 0

    store = broker._source_state_store
    store.set_enabled.assert_awaited_once_with(
        source_id="foo",
        enabled=False,
        reason="test",
        actor="unit-tester",
    )


def test_cli_sources_disable_defaults_actor_from_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path)
    monkeypatch.setenv("USER", "env-user")
    broker = _install_stub_broker(monkeypatch)

    rc = cli.main(
        ["sources", "disable", "foo", "--reason", "test", "--config", str(cfg)],
    )
    assert rc == 0
    broker._source_state_store.set_enabled.assert_awaited_once()
    call_kwargs = broker._source_state_store.set_enabled.await_args.kwargs
    assert call_kwargs["actor"] == "env-user"
    assert call_kwargs["enabled"] is False
    assert call_kwargs["reason"] == "test"


# ---------------------------------------------------------------------------
# (d) sources enable — single set_enabled(True) call
# ---------------------------------------------------------------------------


def test_cli_sources_enable_calls_set_enabled_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path)
    broker = _install_stub_broker(monkeypatch)

    rc = cli.main(
        [
            "sources",
            "enable",
            "foo",
            "--actor",
            "unit-tester",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 0

    store = broker._source_state_store
    store.set_enabled.assert_awaited_once_with(
        source_id="foo",
        enabled=True,
        reason=None,
        actor="unit-tester",
    )


# ---------------------------------------------------------------------------
# (e) missing SourceStateStore — clean error rather than NPE
# ---------------------------------------------------------------------------


def test_cli_sources_list_without_store_exits_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    _install_stub_broker(monkeypatch, store_is_none=True)

    rc = cli.main(["sources", "list", "--config", str(cfg)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no SourceStateStore is configured" in err


def test_cli_sources_disable_without_store_exits_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    _install_stub_broker(monkeypatch, store_is_none=True)

    rc = cli.main(
        [
            "sources",
            "disable",
            "foo",
            "--reason",
            "r",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 2
    assert "no SourceStateStore is configured" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# missing / malformed --config handling
# ---------------------------------------------------------------------------


def test_cli_sources_list_missing_config_exits_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = cli.main(
        ["sources", "list", "--config", "/definitely/not/a/real/nautilus.yaml"],
    )
    assert rc == 2
    assert "config path does not exist" in capsys.readouterr().err


def test_cli_sources_broker_aclose_always_awaited(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Broker.aclose() must run even when the op raises (pool cleanup)."""
    cfg = _write_config(tmp_path)
    broker = _install_stub_broker(monkeypatch)
    # Force the operation to raise mid-flight.
    broker._source_state_store.load_all.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        cli.main(["sources", "list", "--config", str(cfg)])

    broker.aclose.assert_awaited()
