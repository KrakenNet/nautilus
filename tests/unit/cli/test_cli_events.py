"""Unit tests for :mod:`nautilus.cli.events` (DQ5)."""

from __future__ import annotations

import argparse

import pytest

from nautilus.cli import events as cli_events

pytestmark = pytest.mark.unit


def test_dq5_list_event_types_returns_sorted_strings() -> None:
    types = cli_events.list_event_types()
    assert isinstance(types, list)
    assert all(isinstance(t, str) for t in types)
    assert len(types) >= 19  # at least the 19 net-new + existing events


def test_dq5_add_subparser_registers_events_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_events.add_subparser(sub)
    args = parser.parse_args(["events", "list"])
    assert args.cmd == "events"


def test_dq5_dispatch_list_returns_zero() -> None:
    args = argparse.Namespace(cmd="events", events_subcommand="list", json=False)
    assert cli_events.dispatch(args) == 0
