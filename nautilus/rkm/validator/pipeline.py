"""Validator pipeline orchestrator — static → shadow → sandbox → score → queue.

Stage 4 rejection (score < 0.6) marks the queued proposal as ``rejected`` and
records the rejection on its ``decisions`` log. See ``.forge/shared.md`` Flow 3.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import yaml

from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.types import Proposal
from nautilus.rkm.validator.sandbox import (
    SandboxRegressionError,
    SandboxResult,
    SandboxRuleError,
    sandbox_replay,
)
from nautilus.rkm.validator.scoring import score
from nautilus.rkm.validator.shadow import shadow_check
from nautilus.rkm.validator.static import validate_static
from nautilus.rules import BUILT_IN_RULES_DIR


def load_proposed_rules(rule_yaml: Path) -> list[dict[str, Any]]:
    """Parse the rule bodies out of a proposal ruleset file.

    Each returned body carries the file-level ``module`` / ``ruleset`` /
    ``version`` envelope merged in, which is the shape the validators and
    ``nautilus rules validate`` both need.
    """
    document: Any = yaml.safe_load(rule_yaml.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return []
    body = cast("dict[str, Any]", document)
    envelope = {k: v for k, v in body.items() if k in {"module", "ruleset", "version"}}
    rules: list[Any] = body.get("rules") or []
    return [
        {**envelope, **cast("dict[str, Any]", rule)} for rule in rules if isinstance(rule, dict)
    ]


def _built_in_ruleset() -> list[dict[str, Any]]:
    """Every built-in rule body, for shadow/subsumption comparison."""
    bodies: list[dict[str, Any]] = []
    for path in sorted((BUILT_IN_RULES_DIR / "rules").glob("*.yaml")):
        bodies.extend(load_proposed_rules(path))
    return bodies


def run_pipeline(rule_yaml: Path, *, queue: ProposalQueue, audit_log: Path) -> Proposal:
    """Run static → shadow → sandbox → score, append a Proposal to the queue.

    Every stage receives the actual proposed rule. Previously ``shadow_check``
    and ``sandbox_replay`` were both called with ``{}``: an empty rule
    constrains nothing and asserts nothing, so shadow analysis compared against
    an empty ruleset and the sandbox scored a rule that was not the one being
    proposed. Every proposal scored identically regardless of its content.

    A proposal the engine rejects, or one that regresses the replay corpus, is
    queued as ``rejected`` with the reason recorded rather than raising — the
    caller asked for a validation verdict, and "it does not compile" is one.
    """
    static_result = validate_static(rule_yaml)
    proposed_rules = load_proposed_rules(rule_yaml)
    proposed = proposed_rules[0] if proposed_rules else {}

    shadow_flags = shadow_check(proposed, _built_in_ruleset())

    sandbox_error: str | None = None
    try:
        sandbox_result = sandbox_replay(proposed, audit_log)
    except SandboxRegressionError as exc:
        sandbox_error = str(exc)
        sandbox_result = exc.result or _empty_sandbox_result()
    except SandboxRuleError as exc:
        sandbox_error = str(exc)
        sandbox_result = _empty_sandbox_result()

    breakdown = score(sandbox_result, shadow_flags)

    now = datetime.now(UTC)
    rejected = sandbox_error is not None or breakdown.total < 0.6
    proposal = Proposal(
        proposal_id=f"prop_{uuid.uuid4().hex}",
        schema_version=2,
        status="rejected" if rejected else "pending",
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
                "skipped_no_input_facts": sandbox_result.skipped_no_input_facts,
                "skipped_drifted": sandbox_result.skipped_drifted,
                "top_triggers": list(sandbox_result.top_triggers),
                "error": sandbox_error,
            },
            # ``confidence`` / ``confidence_breakdown``, not ``score`` /
            # ``breakdown``: those are the names every reader uses (the REST
            # proposal detail, ``rkm queue list``, and the ``min_confidence``
            # filter), and the value's own type is ConfidenceBreakdown.
            "confidence": breakdown.total,
            "confidence_breakdown": {
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


def _empty_sandbox_result() -> SandboxResult:
    """Zeroed result for a proposal the sandbox could not score."""
    return SandboxResult(
        replayed_n=0,
        replayed_n_actual=0,
        fired=0,
        regressions=0,
        relaxations=0,
        cascade_max=0,
        wm_growth_pct=0.0,
        insufficient_history=True,
        top_triggers=(),
    )


__all__ = ["run_pipeline"]
