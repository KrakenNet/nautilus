"""Integration: pattern-tracker meta-rules (#35.3)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_ac_35_3_a_pattern_tracker_yaml_ships() -> None:
    from nautilus.rules import BUILT_IN_RULES_DIR

    meta = BUILT_IN_RULES_DIR / "meta" / "pattern-tracker.yaml"
    assert meta.is_file()


def test_ac_35_3_a_curator_module_yaml_ships() -> None:
    from nautilus.rules import BUILT_IN_RULES_DIR

    module = BUILT_IN_RULES_DIR / "modules" / "curator.yaml"
    assert module.is_file()


def test_ac_35_3_d_meta_rule_firings_emit_meta_rule_fired_event() -> None:
    """A meta-rule firing must appear in audit log as ``meta_rule_fired``
    with ``rule_module=curator``."""
    from nautilus.rkm import simulate_meta_rule_fire  # type: ignore[attr-defined]

    entries = simulate_meta_rule_fire("track-sequential-requests")
    assert any(
        e.event_type == "meta_rule_fired" and e.rule_module == "curator"
        for e in entries
    )
