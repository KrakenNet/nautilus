"""Unit tests for :mod:`nautilus.cli.rules` (#35.5 + #35.7)."""

from __future__ import annotations

import argparse

import pytest

from nautilus.cli import rules as cli_rules

pytestmark = pytest.mark.unit


def test_ac_35_5_a_add_subparser_registers_rules_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_rules.add_subparser(sub)
    args = parser.parse_args(["rules", "validate", "/tmp/no.yaml"])
    assert args.cmd == "rules"


def test_ac_35_5_a_validate_missing_file_exits_one() -> None:
    args = argparse.Namespace(
        cmd="rules", rules_subcommand="validate",
        file="/definitely/not/here.yaml", sandbox=False, replay_n=1000, json=False,
    )
    rc = cli_rules.dispatch(args)
    assert rc == 1
