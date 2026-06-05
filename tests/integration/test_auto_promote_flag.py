"""Integration: auto-promotion flag default OFF + relationship-only (#35.4)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_ac_35_4_d_auto_promote_default_off() -> None:
    """``rkm.auto_promote.enabled`` MUST default to False (Q1 LOCKED)."""
    from nautilus.config.models import NautilusConfig

    config = NautilusConfig()
    # Path will be (config.rkm.auto_promote.enabled) once schema lands.
    assert getattr(getattr(config, "rkm", None), "auto_promote", None) is not None
    assert config.rkm.auto_promote.enabled is False  # type: ignore[attr-defined]


def test_ac_35_4_a_routing_rules_are_statically_unreachable_from_auto_promote() -> None:
    """No auto-promote code path may produce a ``routing`` rule artifact."""
    from nautilus.rkm import auto_promote_eligible_artifacts  # type: ignore[attr-defined]

    eligible = auto_promote_eligible_artifacts()
    assert "rule" not in eligible or "routing" not in eligible.get("modules", [])
