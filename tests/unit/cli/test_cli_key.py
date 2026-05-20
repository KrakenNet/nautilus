"""Unit tests for :mod:`nautilus.cli.key` (#18)."""

from __future__ import annotations

import argparse

import pytest

from nautilus.cli import key as cli_key

pytestmark = pytest.mark.unit


def test_ac_18_e_add_subparser_registers_key_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_key.add_subparser(sub)
    args = parser.parse_args(["key", "list"])
    assert args.cmd == "key"


def test_ac_18_e_rotate_returns_int_exit_code() -> None:
    args = argparse.Namespace(
        cmd="key", key_subcommand="rotate", remove_old=False, yes=False, json=False,
    )
    rc = cli_key.dispatch(args)
    assert isinstance(rc, int)
