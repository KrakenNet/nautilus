"""Unit tests for :mod:`nautilus.cli.rule` (#35.10)."""

from __future__ import annotations

import argparse

import pytest

from nautilus.cli import rule as cli_rule

pytestmark = pytest.mark.unit


def test_ac_35_10_a_add_subparser_registers_rule_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_rule.add_subparser(sub)
    args = parser.parse_args(["rule", "list"])
    assert args.cmd == "rule"


def test_ac_35_10_a_retract_without_yes_exits_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``rule retract`` without ``--yes`` MUST exit 1 (destructive guard)."""
    monkeypatch.setenv("NAUTILUS_REVIEWER", "alice@example.com")
    args = argparse.Namespace(
        cmd="rule", rule_subcommand="retract", name="some_rule",
        reason="cleanup", cascade=False, orphan_children=False, yes=False,
    )
    rc = cli_rule.dispatch(args)
    assert rc == 1
