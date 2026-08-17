"""Validator pipeline orchestrator — static → shadow → sandbox → score → resolve → queue.

Stage 4 rejection (score < 0.6) marks the queued proposal as ``rejected`` and
records the rejection on its ``decisions`` log. See ``.forge/shared.md`` Flow 3.

Stage 5 (#129) resolves the conflict subset that provenance can settle: an
``auto_retire`` decision marks the proposal ``superseded`` at construction — the
same status-at-construction path stage 4 uses for ``rejected``, so the queue state
machine is untouched.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nautilus.rkm.lineage import LineageRecord, LineageStore
from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.types import Proposal, ProposalStatus
from nautilus.rkm.validator.resolve import RESOLVE_REVIEWER, apply_resolution, resolve
from nautilus.rkm.validator.sandbox import sandbox_replay
from nautilus.rkm.validator.scoring import score
from nautilus.rkm.validator.shadow import ShadowFlag, shadow_check
from nautilus.rkm.validator.static import validate_static


def _lineage_evidence(
    shadow_flags: tuple[ShadowFlag, ...],
    lineage: LineageStore | None,
) -> dict[str, LineageRecord]:
    """Latest lineage record for each flagged existing rule (empty without a store)."""
    if lineage is None:
        return {}
    evidence: dict[str, LineageRecord] = {}
    for flag in shadow_flags:
        record = lineage.get(flag.existing_rule)
        if record is not None:
            evidence[flag.existing_rule] = record
    return evidence


def run_pipeline(
    rule_yaml: Path,
    *,
    queue: ProposalQueue,
    audit_log: Path,
    lineage: LineageStore | None = None,
) -> Proposal:
    """Run static → shadow → sandbox → score → resolve, append a Proposal to the queue."""
    static_result = validate_static(rule_yaml)
    shadow_flags = shadow_check({}, [])
    sandbox_result = sandbox_replay({}, audit_log)
    breakdown = score(sandbox_result, shadow_flags)

    # ``proposed_rule`` stays unset until the artifact carries a rule identity (it is
    # ``{"yaml_path": ...}`` today), so ``apply_resolution`` below is a no-op and the
    # queue decision entry is the durable record of an auto-retire.
    resolution = resolve(shadow_flags, _lineage_evidence(shadow_flags, lineage))

    if breakdown.total < 0.6:
        status: ProposalStatus = "rejected"
    elif resolution.action == "auto_retire":
        status = "superseded"
    else:
        status = "pending"

    now = datetime.now(UTC)
    decisions: list[dict[str, Any]] = []
    if breakdown.total < 0.6:
        decisions.append(
            {
                "event": "auto_rejected",
                "to": status,
                "reviewer": "rkm:score",
                "at": now.isoformat(),
                "reason": f"score {breakdown.total:.3f} below 0.6 threshold",
                "score": breakdown.total,
                "threshold": 0.6,
            }
        )
    elif resolution.action == "auto_retire":
        decisions.append(
            {
                "event": "auto_resolved",
                "to": status,
                "reviewer": RESOLVE_REVIEWER,
                "at": now.isoformat(),
                "reason": resolution.reason,
                "superseded_by": resolution.superseded_by,
                "evidence": resolution.evidence,
            }
        )

    proposal = Proposal(
        proposal_id=f"prop_{uuid.uuid4().hex}",
        schema_version=2,
        status=status,
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
            "resolution": {
                "action": resolution.action,
                "reason": resolution.reason,
                "superseded_by": resolution.superseded_by,
                "evidence": resolution.evidence,
            },
        },
        lineage={"derived_from": None},
        decisions=decisions,
        shadow_flags=shadow_flags,
    )
    queue.submit(proposal)
    if resolution.action == "auto_retire" and lineage is not None:
        apply_resolution(resolution, lineage=lineage)
    return proposal


__all__ = ["run_pipeline"]
