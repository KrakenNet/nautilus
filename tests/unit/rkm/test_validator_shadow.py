"""Unit tests for :mod:`nautilus.rkm.validator.shadow` (#35.6)."""

from __future__ import annotations

import pytest

from nautilus.rkm.validator.shadow import ShadowFlag, shadow_check

pytestmark = pytest.mark.unit


def test_ac_35_6_a_subsumed_pair_is_flagged() -> None:
    proposed = {
        "name": "narrow_rule",
        "lhs": [{"template": "agent", "slots": {"id": "specific"}}],
        "rhs": [],
    }
    existing = [
        {
            "name": "broad_rule",
            "lhs": [{"template": "agent", "slots": {}}],
            "rhs": [],
        }
    ]
    flags = shadow_check(proposed, existing)
    assert any(f.relation == "subsumed_by" for f in flags)


def test_ac_35_6_a_distinct_rule_yields_no_flags() -> None:
    proposed = {
        "name": "unrelated",
        "lhs": [{"template": "session", "slots": {}}],
        "rhs": [],
    }
    existing = [
        {
            "name": "agent_rule",
            "lhs": [{"template": "agent", "slots": {}}],
            "rhs": [],
        }
    ]
    flags = shadow_check(proposed, existing)
    assert flags == ()


def test_ac_35_6_c_result_is_tuple_of_shadow_flags() -> None:
    proposed = {"name": "x", "lhs": [], "rhs": []}
    flags = shadow_check(proposed, [])
    assert isinstance(flags, tuple)
    for f in flags:
        assert isinstance(f, ShadowFlag)
