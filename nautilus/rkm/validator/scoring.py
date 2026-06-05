"""Confidence scoring — pure function with pinned boundaries (#35.8).

Formula (AC-35.8.a):
    base = 1.0
    -0.30 per regression
    -0.20 per relaxation
    -0.10 per shadow flag
    -0.10 if fire_rate < 5%
    -0.05 per cascade warn

Score interpretation:
- >0.9: eligible for auto-promotion (gated by ``rkm.auto_promote.enabled``)
- 0.6–0.9: human review queue
- <0.6: reject; originating meta-rule observation count NOT reset.

Unit tests pin boundaries 0.6 + 0.9 + each individual penalty.
"""

from __future__ import annotations

from nautilus.rkm.types import ConfidenceBreakdown
from nautilus.rkm.validator.sandbox import SandboxResult
from nautilus.rkm.validator.shadow import ShadowFlag


def score(sandbox: SandboxResult, shadow_flags: tuple[ShadowFlag, ...]) -> ConfidenceBreakdown:
    """Pure-function confidence score. AC-35.8.a."""
    base = 1.0

    regression_penalty = -0.3 * sandbox.regressions
    relaxation_penalty = -0.2 * sandbox.relaxations
    shadow_penalty = -0.1 * len(shadow_flags)

    replayed = sandbox.replayed_n_actual or sandbox.replayed_n
    fire_rate_pct = (sandbox.fired / replayed * 100.0) if replayed > 0 else 0.0
    fire_rate_penalty = -0.1 if fire_rate_pct < 5.0 else 0.0

    cascade_penalty = -0.05 if sandbox.cascade_max > 3 else 0.0

    raw = (
        base
        + regression_penalty
        + relaxation_penalty
        + shadow_penalty
        + fire_rate_penalty
        + cascade_penalty
    )
    total = max(0.0, min(1.0, raw))

    return ConfidenceBreakdown(
        base=base,
        regression_penalty=regression_penalty,
        relaxation_penalty=relaxation_penalty,
        shadow_penalty=shadow_penalty,
        fire_rate_penalty=fire_rate_penalty,
        cascade_penalty=cascade_penalty,
        total=total,
    )


__all__ = ["score"]
