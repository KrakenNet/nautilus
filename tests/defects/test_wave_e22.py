"""WAVE E22 — the same mistake answered with two different exit codes.

Nine group commands take a subcommand. Typing the group and stopping is one
mistake, and it got two answers: `rkm`, `rule`, `rules`, `adapters`, `audit` and
`serve` exited **2**, while `key`, `attestation` and `events` exited **1**. A
wrapper script branching on the code -- which is the entire reason the CLI
documents its codes -- treated three of them as something else.

The message was inconsistent in the same way: `no subcommand given (try: a, b)`
for some, `subcommand required (a, b).` for others, and a bare
`unknown rules subcommand` naming nothing to try.

Exit 2 wins because six of nine already used it, because it is what argparse
itself returns for a usage error, and because ``.forge/shared.md`` reserves 1 for
a user error the command actually attempted.
"""

from __future__ import annotations

import re
import subprocess
import sys

import pytest

pytestmark = [pytest.mark.integration]

# Every group command, with the subcommands its message must offer.
_GROUPS: list[tuple[str, list[str]]] = [
    ("rkm", ["queue", "lineage"]),
    ("rule", ["list", "retract", "lineage", "history", "rollback"]),
    ("rules", ["validate", "test", "history"]),
    ("adapters", ["new", "list", "schema"]),
    ("key", ["list", "rotate", "revoke"]),
    ("attestation", ["verify"]),
    ("events", ["list"]),
]

_SHAPE = re.compile(r"^ERROR: (?P<group>[a-z]+): no subcommand given \(try: (?P<subs>[^)]+)\)$")


def _run(group: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 — this interpreter, a literal argv
        [sys.executable, "-m", "nautilus", group],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(("group", "subs"), _GROUPS, ids=[g for g, _ in _GROUPS])
def test_e22_a_missing_subcommand_always_exits_2(group: str, subs: list[str]) -> None:
    """The pin. One mistake, one exit code, across every group command."""
    result = _run(group)

    assert result.returncode == 2, (
        f"`nautilus {group}` with no subcommand exited {result.returncode}; every "
        f"group command answers this same mistake with 2, so a wrapper branching "
        f"on the code mis-handles this one. stderr: {result.stderr.strip()[:200]}"
    )


@pytest.mark.parametrize(("group", "subs"), _GROUPS, ids=[g for g, _ in _GROUPS])
def test_e22_the_message_names_the_group_and_what_to_try(group: str, subs: list[str]) -> None:
    """The pin, second half. The text has to be one shape and has to be useful."""
    line = (_run(group).stderr or _run(group).stdout).strip().splitlines()[0]
    match = _SHAPE.match(line)

    assert match, (
        f"`nautilus {group}` printed {line!r}, which is not the documented shape "
        f"`ERROR: <group>: no subcommand given (try: ...)`"
    )
    assert match.group("group") == group, line
    offered = [s.strip() for s in match.group("subs").split(",")]
    missing = [s for s in subs if s not in offered]
    assert not missing, f"`nautilus {group}` does not offer {missing}: {line!r}"


def test_e22_a_real_subcommand_is_not_caught_by_this(tmp_path: object) -> None:
    """Control. The guard must fire on a missing subcommand, not on every failure."""
    result = subprocess.run(  # noqa: S603 — this interpreter, a literal argv
        [sys.executable, "-m", "nautilus", "key", "list"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert not _SHAPE.match((result.stderr or result.stdout).strip().splitlines()[0]), (
        f"`nautilus key list` named a subcommand and still got the no-subcommand "
        f"error: {result.stderr.strip()[:200]}"
    )
