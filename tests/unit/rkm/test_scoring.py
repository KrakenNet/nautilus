"""Unit tests for :mod:`nautilus.rkm.validator.scoring` (#35.8).

Pins the AC-35.8.a formula at boundaries 0.6, 0.9, and each individual
penalty term. Pure function — no I/O, no mocks.
"""

from __future__ import annotations

import pytest

from nautilus.rkm.validator.sandbox import SandboxResult
from nautilus.rkm.validator.scoring import score
from nautilus.rkm.validator.shadow import ShadowFlag

pytestmark = pytest.mark.unit


def _clean_sandbox(
    *,
    regressions: int = 0,
    relaxations: int = 0,
    cascade_max: int = 0,
    fire_rate_pct: float = 50.0,
) -> SandboxResult:
    fired = int(fire_rate_pct * 10)  # replayed_n=1000 → fire-rate=fired/1000
    return SandboxResult(
        replayed_n=1000,
        replayed_n_actual=1000,
        fired=fired,
        regressions=regressions,
        relaxations=relaxations,
        cascade_max=cascade_max,
        wm_growth_pct=0.0,
        insufficient_history=False,
        top_triggers=(),
    )


def test_ac_35_8_a_clean_sandbox_returns_base_score_one() -> None:
    breakdown = score(_clean_sandbox(), ())
    assert breakdown.base == 1.0
    assert breakdown.total == 1.0


def test_ac_35_8_a_regression_penalty_is_minus_0_3_each() -> None:
    breakdown = score(_clean_sandbox(regressions=1), ())
    assert breakdown.regression_penalty == pytest.approx(-0.3)
    assert breakdown.total == pytest.approx(0.7)


def test_ac_35_8_a_relaxation_penalty_is_minus_0_2_each() -> None:
    breakdown = score(_clean_sandbox(relaxations=1), ())
    assert breakdown.relaxation_penalty == pytest.approx(-0.2)


def test_ac_35_8_a_shadow_penalty_is_minus_0_1_each() -> None:
    flag = ShadowFlag(existing_rule="rule_a", relation="shadows")
    breakdown = score(_clean_sandbox(), (flag,))
    assert breakdown.shadow_penalty == pytest.approx(-0.1)


def test_ac_35_8_a_low_fire_rate_penalty_is_minus_0_1() -> None:
    breakdown = score(_clean_sandbox(fire_rate_pct=1.0), ())
    assert breakdown.fire_rate_penalty == pytest.approx(-0.1)


def test_ac_35_8_a_cascade_warn_penalty_is_minus_0_05_each() -> None:
    breakdown = score(_clean_sandbox(cascade_max=4), ())  # cascade > 3 = warn
    assert breakdown.cascade_penalty == pytest.approx(-0.05)


def test_ac_35_8_b_boundary_above_0_9_is_auto_promote_eligible() -> None:
    breakdown = score(_clean_sandbox(), ())
    assert breakdown.total > 0.9


def test_ac_35_8_c_boundary_0_6_to_0_9_routes_to_human_review() -> None:
    breakdown = score(_clean_sandbox(regressions=1), ())  # 1.0 - 0.3 = 0.7
    assert 0.6 <= breakdown.total <= 0.9


def test_ac_35_8_d_score_below_0_6_is_reject() -> None:
    breakdown = score(_clean_sandbox(regressions=2), ())  # 1.0 - 0.6 = 0.4
    assert breakdown.total < 0.6
