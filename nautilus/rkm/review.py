"""Review-queue CLI backing — approval, rejection, and promotion orchestration (#35.9, #35.10).

Sits between :mod:`nautilus.cli.rkm` / :mod:`nautilus.cli.rule` and
the queue / lineage / Fathom-router substrate.

Promotion path: queue.approved → review.approve_proposal → fathom_router.reload_rule
                → lineage.insert → queue.transition("promoted").

Audit events are emitted out-of-band (CLI ops are outside Broker.arequest) via
:func:`nautilus.rkm.audit_emitter.emit_lifecycle_event`.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from nautilus.rkm.audit_emitter import emit_lifecycle_event
from nautilus.rkm.lineage import LineageRecord, LineageStore
from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.types import Proposal


class RulePromoter(Protocol):
    """The single capability approval needs from a router.

    :class:`~nautilus.core.fathom_router.FathomRouter` satisfies it; naming the
    capability rather than the class keeps promotion testable against any
    engine front-end and stops this module importing the router.
    """

    def reload_rule(self, rule_name: str, rule_yaml: str) -> None:
        """Load ``rule_yaml`` into the active engine under ``rule_name``."""
        ...


class AlreadyDecidedError(Exception):  # noqa: N818
    """Raised when a proposal already has a terminal decision (approve/reject).

    Maps to HTTP 409 per AC-35.9.e.
    """

    def __init__(self, proposal_id: str, current_status: str) -> None:
        super().__init__(f"proposal {proposal_id!r} already decided: status={current_status!r}")
        self.proposal_id = proposal_id
        self.current_status = current_status


class PromotionFailedError(Exception):
    """Raised when the FathomRouter fails to load the promoted rule.

    The proposal is marked ``promotion_failed`` in the queue before re-raise.
    """


@dataclass(frozen=True)
class ApprovalResult:
    """Outcome of a successful :func:`approve_proposal` call."""

    proposal_id: str
    reviewer: str
    approved_at: datetime
    promoted: bool


@dataclass(frozen=True)
class RejectionResult:
    """Outcome of a successful :func:`reject_proposal` call."""

    proposal_id: str
    reviewer: str
    rejected_at: datetime
    reason: str


@dataclass(frozen=True)
class RollbackResult:
    """Outcome of a successful :func:`rollback_rule` call."""

    rule_name: str
    restored_version: int
    new_version: int
    reviewer: str
    rolled_back_at: datetime
    reason: str


def approve_proposal(
    proposal_id: str,
    reviewer_identity: str,
    *,
    queue: ProposalQueue,
    lineage: LineageStore,
    router: RulePromoter | None = None,
    audit_logger: Any | None = None,
) -> ApprovalResult:
    """Approve a pending proposal and promote the rule into the active CLIPS env.

    Steps:
    1. Validate proposal exists and is ``pending`` (raises :class:`AlreadyDecidedError` if not).
    2. Transition queue to ``approved``.
    3. If ``router`` provided: call :meth:`RulePromoter.reload_rule`; on failure mark
       ``promotion_failed`` (via queue transition note) and re-raise.
    4. Insert :class:`LineageRecord` if ``lineage`` provided.
    5. Transition queue to ``promoted``.
    6. Emit ``proposal_approved``, then ``rule_promoted`` + ``proposal_promoted``
       on a successful promotion, if ``audit_logger`` provided.

    Callable from ``pending`` or from ``approved``. Re-approving an already
    approved proposal retries the promotion, which is the only way out of an
    approve that transitioned the queue but failed (or never attempted) the
    promotion. A decided proposal — rejected, promoted, expired, superseded —
    still raises :class:`AlreadyDecidedError` (AC-35.9.e / 409).

    Reviewer identity is accepted as a parameter; callers resolve ``NAUTILUS_REVIEWER``
    env and pass it in (pure function — no env reads here).
    """
    proposal = queue.get(proposal_id)
    if proposal is None:
        raise KeyError(f"proposal not found: {proposal_id!r}")

    if proposal.status not in ("pending", "approved"):
        raise AlreadyDecidedError(proposal_id, proposal.status)

    now = datetime.now(UTC)

    # Already-approved proposals are re-entering only to retry promotion; the
    # approval decision is already recorded and ``approved -> approved`` is
    # not a legal transition.
    if proposal.status == "pending":
        queue.transition(
            proposal_id,
            to="approved",
            reviewer=reviewer_identity,
            reason=None,
            note=None,
        )

    # Promote into CLIPS env.
    promoted = False
    if router is not None:
        rule_yaml = _extract_rule_yaml(proposal)
        try:
            router.reload_rule(proposal_id, rule_yaml)
            promoted = True
        except Exception as exc:
            # Leave the proposal in ``approved`` and re-raise. There is no
            # ``promotion_failed`` status; the recovery paths out of
            # ``approved`` are a re-approve (retries promotion) and a reject.
            raise PromotionFailedError(
                f"FathomRouter.reload_rule failed for proposal {proposal_id!r}: {exc}"
            ) from exc

    # Insert lineage record if promotion succeeded.
    if promoted:
        lineage.insert(_build_lineage_record(proposal, reviewer_identity, now))
        # Transition to promoted.
        queue.transition(
            proposal_id,
            to="promoted",
            reviewer=reviewer_identity,
            reason=None,
            note=None,
        )

    # Emit audit events out-of-band.
    if audit_logger is not None:
        emit_lifecycle_event(
            audit_logger,
            "proposal_approved",
            {
                "proposal_id": proposal_id,
                "reviewer": reviewer_identity,
                "timestamp": now.isoformat(),
            },
        )
        if promoted:
            # Two events, because they record two steps that can come apart:
            # ``rule_promoted`` is the engine load, ``proposal_promoted`` is
            # the queue reaching its terminal state. A crash between them
            # leaves a rule live with a proposal still marked ``approved``,
            # and only a log that separates them can show that.
            emit_lifecycle_event(
                audit_logger,
                "rule_promoted",
                {
                    "proposal_id": proposal_id,
                    "reviewer": reviewer_identity,
                    "timestamp": now.isoformat(),
                },
            )
            emit_lifecycle_event(
                audit_logger,
                "proposal_promoted",
                {
                    "proposal_id": proposal_id,
                    "reviewer": reviewer_identity,
                    "rule_name": proposal.artifact.get("name", proposal_id),
                    "timestamp": now.isoformat(),
                },
            )

    return ApprovalResult(
        proposal_id=proposal_id,
        reviewer=reviewer_identity,
        approved_at=now,
        promoted=promoted,
    )


def reject_proposal(
    proposal_id: str,
    reviewer_identity: str,
    reason: str,
    *,
    queue: ProposalQueue,
    audit_logger: Any | None = None,
) -> RejectionResult:
    """Reject a proposal that has not been promoted.

    Accepts ``pending`` and ``approved``: an approval whose promotion failed
    has to be backed out somehow, and rejection is that path. Raises
    :class:`AlreadyDecidedError` from any other status.
    Emits ``proposal_rejected`` audit event if ``audit_logger`` provided.
    """
    proposal = queue.get(proposal_id)
    if proposal is None:
        raise KeyError(f"proposal not found: {proposal_id!r}")

    if proposal.status not in ("pending", "approved"):
        raise AlreadyDecidedError(proposal_id, proposal.status)

    now = datetime.now(UTC)

    queue.transition(
        proposal_id,
        to="rejected",
        reviewer=reviewer_identity,
        reason=reason,
        note=None,
    )

    if audit_logger is not None:
        emit_lifecycle_event(
            audit_logger,
            "proposal_rejected",
            {
                "proposal_id": proposal_id,
                "reviewer": reviewer_identity,
                "reason": reason,
                "timestamp": now.isoformat(),
            },
        )

    return RejectionResult(
        proposal_id=proposal_id,
        reviewer=reviewer_identity,
        rejected_at=now,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Cascade retraction stub — AC-35.10.d (real CLI wiring in task-026 cli)
# ---------------------------------------------------------------------------


def retract_rule(
    rule_name: str,
    *,
    version: int,
    reason: str,
    reviewer: str,
    cascade: str,
    lineage: LineageStore,
    audit_logger: Any | None = None,
) -> list[str]:
    """Mark a rule retired in the lineage store and return affected descendants.

    ``cascade`` is one of ``"none"``, ``"cascade"``, or ``"orphan-children"``
    per AC-35.10.d. CLI subcommand wiring lives in task-026.
    """
    affected = lineage.mark_retired(
        rule_name,
        version=version,
        reason=reason,
        reviewer=reviewer,
        cascade=cascade,  # type: ignore[arg-type]
    )
    if audit_logger is not None:
        emit_lifecycle_event(
            audit_logger,
            "rule_retracted",
            {
                "rule_name": rule_name,
                "version": version,
                "reason": reason,
                "reviewer": reviewer,
                "affected_descendants": affected,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    return affected


def rollback_rule(
    rule_name: str,
    *,
    to_version: int,
    reason: str,
    reviewer: str,
    lineage: LineageStore,
    audit_logger: Any | None = None,
) -> RollbackResult:
    """Re-promote a prior version of a rule as a new lineage version.

    A rollback is append-only: the target record is re-inserted at
    ``latest + 1`` with a fresh approver and promotion time, so the history
    of what was live when stays readable.

    Lives here rather than in ``nautilus.cli.rule`` because a rollback is a
    governance decision, and this module is where those get audited — the CLI
    performed the lineage rewrite inline and wrote nothing at all.

    Raises :class:`KeyError` when ``to_version`` is not in the rule's lineage.

    The rolled-back rule is *not* reloaded into a running engine: this path
    has no router (the CLI constructs none), so a live broker keeps serving
    the newer rule until it is restarted.
    """
    target = lineage.get(rule_name, to_version)
    if target is None:
        raise KeyError(f"rule {rule_name!r} v{to_version} not found in lineage")

    latest = lineage.get(rule_name)
    new_version = (latest.version + 1) if latest is not None else to_version + 1
    now = datetime.now(UTC)

    lineage.insert(
        replace(
            target,
            version=new_version,
            approver=reviewer,
            promoted_at=now,
            retired_at=None,
            retire_reason=None,
            retire_reviewer=None,
        )
    )

    if audit_logger is not None:
        emit_lifecycle_event(
            audit_logger,
            "rule_rolled_back",
            {
                "rule_name": rule_name,
                "restored_version": to_version,
                "new_version": new_version,
                "reason": reason,
                "reviewer": reviewer,
                "timestamp": now.isoformat(),
            },
        )

    return RollbackResult(
        rule_name=rule_name,
        restored_version=to_version,
        new_version=new_version,
        reviewer=reviewer,
        rolled_back_at=now,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_rule_yaml(proposal: Proposal) -> str:
    """Extract the rule YAML a proposal is asking to promote.

    Rule proposals carry it either inline under ``artifact["yaml"]`` or by
    reference under ``artifact["yaml_path"]``; ``run_pipeline`` writes the
    latter. The previous fallback serialised the whole artifact dict to JSON
    and handed *that* to the compiler, which could only ever fail with "YAML
    file must contain a top-level 'rules' key" -- so an artifact carrying
    neither key is now a clear error instead.
    """
    artifact = proposal.artifact
    inline = artifact.get("yaml")
    if isinstance(inline, str):
        return inline
    path = artifact.get("yaml_path")
    if isinstance(path, str):
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise PromotionFailedError(
                f"proposal {proposal.proposal_id!r} references unreadable rule file {path!r}: {exc}"
            ) from exc
    raise PromotionFailedError(
        f"proposal {proposal.proposal_id!r} carries no rule YAML: artifact has neither "
        f"'yaml' nor 'yaml_path' (keys: {sorted(artifact)})"
    )


def _build_lineage_record(
    proposal: Proposal,
    approver: str,
    promoted_at: datetime,
) -> LineageRecord:
    """Build a :class:`LineageRecord` from an approved proposal."""
    # ``or`` rather than a dict default: run_pipeline writes
    # ``lineage={"derived_from": None}``, so the key is present and the
    # default never applies -- tuple(None) raised TypeError.
    derived_from: tuple[str, ...] = tuple(proposal.lineage.get("derived_from") or ())
    observation_ids: dict[str, Any] = dict(proposal.lineage.get("observation_ids") or {})
    sandbox_results: dict[str, Any] = dict(proposal.lineage.get("sandbox_results") or {})
    rule_name: str = proposal.artifact.get("name", proposal.proposal_id)
    version: int = int(proposal.artifact.get("version", 1))
    return LineageRecord(
        rule_name=rule_name,
        version=version,
        proposer=proposal.proposer,
        observation_ids=observation_ids,
        sandbox_results=sandbox_results,
        approver=approver,
        derived_from=derived_from,
        promoted_at=promoted_at,
    )


__all__ = [
    "AlreadyDecidedError",
    "ApprovalResult",
    "PromotionFailedError",
    "RejectionResult",
    "RollbackResult",
    "approve_proposal",
    "reject_proposal",
    "retract_rule",
    "rollback_rule",
]
