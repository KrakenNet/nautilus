"""Conflict resolution stage — deterministic auto-retire for the subsumed subset (#129).

The pipeline already *detects* conflicts (:mod:`.shadow`) and *scores* them
(:mod:`.scoring`), but detection alone leaves every proposal in the human queue.
This stage resolves the one conflict subclass that provenance can settle without
judgement, and routes everything else to a human.

Deterministic by construction: a pure function over flags + lineage records. It
never invokes an LLM, reads a clock, or touches the filesystem — the same inputs
always yield an equal :class:`ResolutionDecision`.

Why auto-retire only ever targets the *proposal*
------------------------------------------------
:func:`~nautilus.rkm.validator.shadow.shadow_check` emits ``subsumed_by`` in two
opposite situations (see its cases 2 and 4): the existing rule may be the broader
one, or the proposed rule may be. :class:`~nautilus.rkm.validator.shadow.ShadowFlag`
carries only ``existing_rule`` + ``relation``, so which side is redundant cannot be
recovered from a flag alone.

Rather than guess, this stage only ever retires the proposal — the un-promoted,
un-deployed side. That makes the ambiguity harmless in both directions: the worst
case discards a candidate a human can re-propose, whereas retiring a live rule on
ambiguous evidence would silently drop coverage. **The active rule base is never
mutated here.**

Fail-closed: anything this module cannot clear on explicit evidence becomes
``human_review``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from nautilus.rkm.lineage import LineageRecord, LineageStore
from nautilus.rkm.validator.shadow import ShadowFlag

ResolutionAction = Literal["no_conflict", "auto_retire", "human_review"]

# Relations that provenance cannot settle: a shadowed rule may still be wanted, and
# a salience inversion is a priority question, not a redundancy one.
_UNRESOLVABLE_RELATIONS = frozenset({"shadows", "salience_inverts"})

# Attributed reviewer for decisions this stage makes without a human.
RESOLVE_REVIEWER = "rkm:resolve"


@dataclass(frozen=True)
class ResolutionDecision:
    """Outcome of the resolve stage.

    ``retire_rule`` / ``retire_version`` name the *proposal* to retire and are set
    only for ``auto_retire`` (and only when the caller supplied a proposal
    identity). ``superseded_by`` names the existing rule whose coverage made the
    proposal redundant. ``evidence`` always carries the provenance actually
    observed, so a ``human_review`` outcome is as auditable as an auto-retire.
    """

    action: ResolutionAction
    reason: str
    retire_rule: str | None = None
    retire_version: int | None = None
    superseded_by: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict[str, Any])


def _provenance_evidence(record: LineageRecord | None) -> dict[str, Any]:
    """Summarise the provenance the decision was made on."""
    if record is None:
        return {"lineage_record": False}
    return {
        "lineage_record": True,
        "observation_count": len(record.observation_ids),
        "has_sandbox_results": bool(record.sandbox_results),
        "existing_retired": record.retired_at is not None,
    }


def resolve(
    shadow_flags: tuple[ShadowFlag, ...],
    lineage_evidence: Mapping[str, LineageRecord],
    *,
    proposed_rule: str | None = None,
    proposed_version: int = 1,
) -> ResolutionDecision:
    """Resolve ``shadow_flags`` against ``lineage_evidence``. Pure function.

    ``lineage_evidence`` maps an existing rule name to its latest
    :class:`~nautilus.rkm.lineage.LineageRecord`. ``proposed_rule`` /
    ``proposed_version`` identify the proposal so the decision can name a concrete
    retire target; without them an ``auto_retire`` still stands but carries no
    target, and :func:`apply_resolution` becomes a no-op.

    The ladder, in order — anything not explicitly cleared is ``human_review``:

    1. No flags at all → ``no_conflict``.
    2. Any ``shadows`` / ``salience_inverts`` flag → ``human_review``.
    3. More than one ``subsumed_by`` flag → ``human_review`` (no single target).
    4. Exactly one ``subsumed_by`` flag against existing rule ``E`` → ``auto_retire``
       only if ``E`` has a lineage record that is still live (``retired_at is None``)
       and carries both ``observation_ids`` and ``sandbox_results``.
    """
    if not shadow_flags:
        return ResolutionDecision(
            action="no_conflict",
            reason="no shadow flags raised",
        )

    blocking = [f for f in shadow_flags if f.relation in _UNRESOLVABLE_RELATIONS]
    if blocking:
        relations = sorted({f.relation for f in blocking})
        return ResolutionDecision(
            action="human_review",
            reason=f"unresolvable relation(s) present: {', '.join(relations)}",
            evidence={"relations": [f.relation for f in shadow_flags]},
        )

    subsumed = [f for f in shadow_flags if f.relation == "subsumed_by"]
    if len(subsumed) > 1:
        rules = sorted({f.existing_rule for f in subsumed})
        return ResolutionDecision(
            action="human_review",
            reason=f"{len(subsumed)} subsumed_by flags — no single deterministic target",
            evidence={"existing_rules": rules},
        )

    flag = subsumed[0]
    record = lineage_evidence.get(flag.existing_rule)
    evidence = _provenance_evidence(record)

    if record is None:
        return ResolutionDecision(
            action="human_review",
            reason=f"no lineage record for existing rule {flag.existing_rule!r}",
            superseded_by=flag.existing_rule,
            evidence=evidence,
        )

    # A retired rule no longer provides the coverage that would make the proposal
    # redundant, so retiring the proposal against it could drop coverage outright.
    if record.retired_at is not None:
        return ResolutionDecision(
            action="human_review",
            reason=f"existing rule {flag.existing_rule!r} is retired — coverage not guaranteed",
            superseded_by=flag.existing_rule,
            evidence=evidence,
        )

    missing = [
        name
        for name, present in (
            ("observation_ids", bool(record.observation_ids)),
            ("sandbox_results", bool(record.sandbox_results)),
        )
        if not present
    ]
    if missing:
        return ResolutionDecision(
            action="human_review",
            reason=(f"existing rule {flag.existing_rule!r} lacks provenance: {', '.join(missing)}"),
            superseded_by=flag.existing_rule,
            evidence=evidence,
        )

    return ResolutionDecision(
        action="auto_retire",
        reason=(
            f"proposal is subsumed by {flag.existing_rule!r}, which is live and carries "
            f"observation + sandbox provenance"
        ),
        retire_rule=proposed_rule,
        retire_version=proposed_version if proposed_rule is not None else None,
        superseded_by=flag.existing_rule,
        evidence=evidence,
    )


def apply_resolution(
    decision: ResolutionDecision,
    *,
    lineage: LineageStore,
    reviewer: str = RESOLVE_REVIEWER,
) -> str | None:
    """Record an ``auto_retire`` decision in ``lineage``; return the retired rule name.

    Returns ``None`` without raising for any non-``auto_retire`` decision, for a
    decision with no named target, and for a target that has no lineage record —
    the ordinary case for a proposal that was never promoted, where the queue
    decision entry is the durable record instead.

    ``cascade="none"``: retiring a redundant proposal must not touch anything
    derived from it.
    """
    if decision.action != "auto_retire" or decision.retire_rule is None:
        return None

    version = decision.retire_version if decision.retire_version is not None else 1
    if lineage.get(decision.retire_rule, version) is None:
        return None

    lineage.mark_retired(
        decision.retire_rule,
        version=version,
        reason=f"superseded by {decision.superseded_by}",
        reviewer=reviewer,
        cascade="none",
    )
    return decision.retire_rule


__all__ = [
    "RESOLVE_REVIEWER",
    "ResolutionAction",
    "ResolutionDecision",
    "apply_resolution",
    "resolve",
]
