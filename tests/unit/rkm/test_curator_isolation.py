"""Unit tests for :mod:`nautilus.rkm.curator.isolation` (AC-35.3.e, OQ2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nautilus.rkm.curator.isolation import (
    CuratorIsolationViolation,
    assert_module_isolation,
)

pytestmark = pytest.mark.unit


def test_ac_35_3_e_clean_meta_rule_passes(tmp_path: Path) -> None:
    """A meta-rule asserting into its own ``curator`` module passes."""
    yaml_path = tmp_path / "ok.yaml"
    yaml_path.write_text(
        "rules:\n"
        "  - name: track-sequential\n"
        "    module: curator\n"
        "    rhs:\n"
        "      - assert:\n"
        "          template: relationship_candidate\n"
        "          slots: {}\n"
    )
    # Must not raise.
    assert_module_isolation(yaml_path)


def test_ac_35_3_e_meta_rule_asserting_routing_template_raises(tmp_path: Path) -> None:
    """Asserting into the routing module's templates must be rejected."""
    yaml_path = tmp_path / "bad.yaml"
    yaml_path.write_text(
        "rules:\n"
        "  - name: bad-rule\n"
        "    module: curator\n"
        "    rhs:\n"
        "      - assert:\n"
        "          template: routing_decision\n"  # routing-module template
        "          slots: {}\n"
    )
    with pytest.raises(CuratorIsolationViolation):
        assert_module_isolation(yaml_path)
