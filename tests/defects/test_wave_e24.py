"""WAVE E24 -- sibling 404s disagreed about how to name what was missing.

A live-fire pass against a real server showed three neighbouring routes
answering the same class of mistake three different ways::

    approve 404    {"detail":"proposal 'nope' not found"}
    reject  404    {"detail":"proposal 'nope' not found"}
    retract 404    {"detail":"rule not found: 'nope'"}

An operator grepping logs, or a client matching on the message, has to know
which route it came from to know which shape to expect. Worse, the retract
route's *version* lookup answered a missing version with the name only::

    POST /v1/rules/live_rule/retract  {"version": 99}
      -> {"detail": "rule 'live_rule' not found"}

which is false: the rule exists, version 99 does not. `rollback` had said so
correctly all along and is the control for that pair.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

_SOURCE = Path(__file__).resolve().parents[2] / "nautilus" / "transport" / "fastapi_app.py"

# ``detail=f"..."`` on a line that mentions "not found", captured whole.
_DETAIL = re.compile(r'detail=f?"([^"]*not found[^"]*)"')


def _details() -> list[str]:
    found = _DETAIL.findall(_SOURCE.read_text(encoding="utf-8"))
    assert found, f"no 404 detail strings found in {_SOURCE} -- the regex went stale"
    return found


def test_e24_every_404_names_the_thing_before_not_found() -> None:
    """One shape for the whole surface: ``<noun> <name> not found``.

    ``not found: <name>`` is the shape that came from ``str(KeyError(...))``.
    Nothing on this surface should read that way any more.
    """
    trailing = [d for d in _details() if "not found:" in d]
    assert not trailing, (
        "these 404 bodies put the name after 'not found:', while their siblings "
        f"put it before: {trailing}"
    )


def test_e24_a_missing_version_says_the_version_is_missing() -> None:
    """Retract and rollback answer a missing version the same way.

    ``rollback`` is the control -- it already named the version. ``retract``
    reported a bad version as a missing *rule*, which is a different and false
    claim about the deployment.
    """
    versioned = [d for d in _details() if "version" in d]
    assert len(versioned) >= 2, (
        "retract and rollback should each name the version they could not find; "
        f"only found: {versioned}"
    )
    for detail in versioned:
        assert re.search(r"\{rule_name!r\} version \{\w+\} not found", detail), (
            f"a version-lookup 404 that does not name the version: {detail!r}"
        )
