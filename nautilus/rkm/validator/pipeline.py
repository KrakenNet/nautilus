"""Validator pipeline orchestrator — static → shadow → sandbox → score → queue.

Stage 4 rejection (score < 0.6) marks the queued proposal as ``rejected`` and
records the rejection on its ``decisions`` log. See ``.forge/shared.md`` Flow 3.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.types import Proposal
from nautilus.rkm.validator.sandbox import sandbox_replay
from nautilus.rkm.validator.scoring import score
from nautilus.rkm.validator.shadow import shadow_check
from nautilus.rkm.validator.static import validate_static


def run_pipeline(
    rule_yaml: Path, *, queue: ProposalQueue, audit_log: Path
) -> Proposal:
    """Run static → shadow → sandbox → score, append a Proposal to the queue."""
    static_result = validate_static(rule_yaml)
    shadow_flags = shadow_check({}, [])
    sandbox_result = sandbox_replay({}, audit_log)
    breakdown = score(sandbox_result, shadow_flags)

    now = datetime.now(UTC)
    proposal = Proposal(
        proposal_id=f"prop_{uuid.uuid4().hex}",
        schema_version=2,
        status="rejected" if breakdown.total < 0.6 else "pending",
        proposer="pipeline",
        proposed_at=now,
        target_module="curator",
        artifact_type="rule",
        artifact={"yaml_path": str(rule_yaml)},
        validation={
            "static_ok": static_result.ok,
            "static_errors": [e.message for e in static_result.errors],
            "sandbox": {
                "replayed_n": sandbox_result.replayed_n,
                "replayed_n_actual": sandbox_result.replayed_n_actual,
                "regressions": sandbox_result.regressions,
                "relaxations": sandbox_result.relaxations,
                "fired": sandbox_result.fired,
                "cascade_max": sandbox_result.cascade_max,
                "insufficient_history": sandbox_result.insufficient_history,
            },
            "score": breakdown.total,
            "breakdown": {
                "base": breakdown.base,
                "regression_penalty": breakdown.regression_penalty,
                "relaxation_penalty": breakdown.relaxation_penalty,
                "shadow_penalty": breakdown.shadow_penalty,
                "fire_rate_penalty": breakdown.fire_rate_penalty,
                "cascade_penalty": breakdown.cascade_penalty,
                "total": breakdown.total,
            },
        },
        lineage={"derived_from": None},
        decisions=[],
        shadow_flags=shadow_flags,
    )
    queue.submit(proposal)
    return proposal


__all__ = ["run_pipeline"]
