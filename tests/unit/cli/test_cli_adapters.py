"""Unit tests for :mod:`nautilus.cli.adapters` (#21)."""

from __future__ import annotations

import argparse

import pytest

from nautilus.cli import adapters as cli_adapters

pytestmark = pytest.mark.unit


def test_ac_21_f_add_subparser_registers_adapters_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_adapters.add_subparser(sub)
    args = parser.parse_args(["adapters", "list"])
    assert args.cmd == "adapters"


def test_ac_21_g_schema_ack_without_yes_exits_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")
    args = argparse.Namespace(
        cmd="adapters",
        adapters_subcommand="schema-ack",
        name="postgres-1",
        reason="acked",
        yes=False,
    )
    rc = cli_adapters.dispatch(args)
    assert rc == 1
