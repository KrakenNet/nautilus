"""Unit tests for :mod:`nautilus.cli.rkm` (#35.9 + #35.10).

In-process tests via the ``add_subparser`` / ``dispatch`` pair (per OQ4
contract: each ``cli/<group>.py`` exports both).
"""

from __future__ import annotations

import argparse

import pytest

from nautilus.cli import rkm as cli_rkm

pytestmark = pytest.mark.unit


def test_ac_35_9_b_add_subparser_registers_queue_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_rkm.add_subparser(sub)
    args = parser.parse_args(["rkm", "queue", "list"])
    assert args.cmd == "rkm"


def test_ac_35_9_b_dispatch_returns_int_exit_code() -> None:
    args = argparse.Namespace(
        cmd="rkm",
        rkm_subcommand="queue",
        queue_subcommand="list",
        status=None,
        min_confidence=0.0,
        json=False,
    )
    rc = cli_rkm.dispatch(args)
    assert isinstance(rc, int)


def test_ac_35_9_b_dispatch_approve_requires_reviewer_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without ``NAUTILUS_REVIEWER`` set, ``approve`` exits 1 (DQ4)."""
    monkeypatch.delenv("NAUTILUS_REVIEWER", raising=False)
    args = argparse.Namespace(
        cmd="rkm",
        rkm_subcommand="queue",
        queue_subcommand="approve",
        proposal_id="prop_x",
        note=None,
        json=False,
    )
    rc = cli_rkm.dispatch(args)
    assert rc == 1
