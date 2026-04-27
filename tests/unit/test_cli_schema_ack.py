"""Unit tests for the ``nautilus sources schema-ack`` CLI op (Task 31).

Coverage targets (AC-4.10, US-4):

    a. ``sources schema-ack --help`` lists the new operation usage.
    b. ``sources schema-ack <id> --new-hash <hash>`` calls
       ``SchemaAckStore.set_ack(source_id=..., acked_hash=..., actor=...)``
       exactly once and prints a human-readable confirmation line.
    c. ``sources schema-ack <unknown> --new-hash <hash>`` exits 2 with a
       stderr message (source not registered).
    d. Missing ``--new-hash`` surfaces argparse's exit 2.

All cases drive :func:`nautilus.cli.main` in-process with an explicit
``argv``, monkeypatching :meth:`Broker.from_config` and
:class:`SchemaAckStore` to stubs — no Postgres, no network. This mirrors
the idiom in ``test_cli_sources.py`` (Task 14).
"""
# pyright: reportPrivateUsage=false, reportUnknownLambdaType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
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


def _install_stub_broker(
    monkeypatch: pytest.MonkeyPatch,
    *,
    source_ids: tuple[str, ...] = ("foo",),
    session_store_backend: str = "postgres",
    dsn: str | None = "postgres://stub/db",
    on_failure: str = "fail_closed",
) -> MagicMock:
    """Patch :meth:`Broker.from_config` to return a minimal stub.

    Returns the broker stub. Its ``_config.session_store`` exposes the
    backend / dsn / on_failure fields read by ``_run_sources_schema_ack``,
    and its ``sources`` property lists registered ids for membership checks.
    """
    broker = MagicMock()
    broker.setup = AsyncMock()
    broker.aclose = AsyncMock()

    sess_cfg = MagicMock()
    sess_cfg.backend = session_store_backend
    sess_cfg.dsn = dsn
    sess_cfg.on_failure = on_failure
    broker._config.session_store = sess_cfg

    broker.sources = [MagicMock(id=sid) for sid in source_ids]

    from nautilus.core import broker as broker_mod

    monkeypatch.setattr(
        broker_mod.Broker,
        "from_config",
        classmethod(lambda _cls, _p: broker),
    )
    return broker


def _install_stub_store(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Patch :class:`SchemaAckStore` with a MagicMock constructor/instance."""
    store_instance = MagicMock()
    store_instance.setup = AsyncMock()
    store_instance.aclose = AsyncMock()
    ack = MagicMock()
    ack.source_id = "foo"
    ack.acked_hash = "abc123def4567890" + "0" * 48
    ack.actor = "unit-tester"
    ack.acked_at = datetime(2026, 4, 23, 12, 0, 0, tzinfo=UTC)
    store_instance.set_ack = AsyncMock(return_value=ack)

    ctor = MagicMock(return_value=store_instance)
    from nautilus.ingest import schema_change as sc

    monkeypatch.setattr(sc, "SchemaAckStore", ctor)
    return store_instance


# ---------------------------------------------------------------------------
# (a) sources schema-ack --help
# ---------------------------------------------------------------------------


def test_cli_sources_schema_ack_help_advertises_usage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``sources schema-ack --help`` must advertise --new-hash and source_id."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["sources", "schema-ack", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "schema-ack" in out
    assert "--new-hash" in out
    assert "source_id" in out


def test_cli_sources_help_includes_schema_ack(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Parent ``sources --help`` must list the new subcommand."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["sources", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "schema-ack" in out


# ---------------------------------------------------------------------------
# (b) sources schema-ack — set_ack called once
# ---------------------------------------------------------------------------


def test_cli_sources_schema_ack_calls_set_ack_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    _install_stub_broker(monkeypatch, source_ids=("foo",))
    store = _install_stub_store(monkeypatch)

    rc = cli.main(
        [
            "sources",
            "schema-ack",
            "foo",
            "--new-hash",
            "abc123",
            "--actor",
            "unit-tester",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 0

    store.set_ack.assert_awaited_once_with(
        "foo",
        acked_hash="abc123",
        actor="unit-tester",
    )
    store.setup.assert_awaited_once()
    store.aclose.assert_awaited_once()

    out = capsys.readouterr().out
    assert "Schema acknowledgement recorded" in out
    assert "source=foo" in out
    assert "actor=unit-tester" in out


def test_cli_sources_schema_ack_defaults_actor_from_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg = _write_config(tmp_path)
    monkeypatch.setenv("USER", "env-user")
    _install_stub_broker(monkeypatch, source_ids=("foo",))
    store = _install_stub_store(monkeypatch)

    rc = cli.main(
        [
            "sources",
            "schema-ack",
            "foo",
            "--new-hash",
            "abc123",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 0
    store.set_ack.assert_awaited_once()
    call_kwargs = store.set_ack.await_args.kwargs
    assert call_kwargs["actor"] == "env-user"
    assert call_kwargs["acked_hash"] == "abc123"


# ---------------------------------------------------------------------------
# (c) unknown source id → exit 2
# ---------------------------------------------------------------------------


def test_cli_sources_schema_ack_unknown_source_exits_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    _install_stub_broker(monkeypatch, source_ids=("foo",))
    # Store should never be used when the id is unknown, but install it anyway
    # to ensure construction isn't what fails.
    store = _install_stub_store(monkeypatch)

    rc = cli.main(
        [
            "sources",
            "schema-ack",
            "unknown",
            "--new-hash",
            "abc123",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown source id" in err
    store.set_ack.assert_not_called()


# ---------------------------------------------------------------------------
# (d) missing --new-hash → argparse exit 2
# ---------------------------------------------------------------------------


def test_cli_sources_schema_ack_missing_new_hash_exits_2(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)

    with pytest.raises(SystemExit) as exc:
        cli.main(["sources", "schema-ack", "foo", "--config", str(cfg)])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    # argparse phrases this as "the following arguments are required: --new-hash".
    assert "--new-hash" in err


# ---------------------------------------------------------------------------
# session_store guards
# ---------------------------------------------------------------------------


def test_cli_sources_schema_ack_rejects_non_postgres_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    _install_stub_broker(
        monkeypatch,
        source_ids=("foo",),
        session_store_backend="memory",
    )

    rc = cli.main(
        [
            "sources",
            "schema-ack",
            "foo",
            "--new-hash",
            "abc123",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "session_store.backend=postgres" in err


def test_cli_sources_schema_ack_missing_dsn_exits_2(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = _write_config(tmp_path)
    monkeypatch.delenv("TEST_PG_DSN", raising=False)
    _install_stub_broker(monkeypatch, source_ids=("foo",), dsn=None)

    rc = cli.main(
        [
            "sources",
            "schema-ack",
            "foo",
            "--new-hash",
            "abc123",
            "--config",
            str(cfg),
        ],
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "session_store.dsn" in err
