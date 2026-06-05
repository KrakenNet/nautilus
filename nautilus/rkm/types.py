"""Shared RKM dataclasses (proposal, validation error, confidence breakdown).

Lives in its own module so :mod:`nautilus.rkm.queue`,
:mod:`nautilus.rkm.lineage`, and :mod:`nautilus.rkm.validator` can import
without circular dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

ProposalStatus = Literal["pending", "approved", "rejected", "expired", "promoted", "superseded"]


@dataclass(frozen=True)
class Proposal:
    """Canonical proposal record (per ``.forge/interview/design.md`` 145-178).

    ``proposal_id`` format: ``prop_<uuid4_hex>`` (OQ6 LOCKED — no
    ``python-ulid`` dep). Ordering by ``proposed_at``.
    """

    proposal_id: str
    schema_version: int
    status: ProposalStatus
    proposer: str
    proposed_at: datetime
    target_module: str
    artifact_type: Literal["rule", "relationship_fact"]
    artifact: dict[str, Any]
    validation: dict[str, Any]
    lineage: dict[str, Any]
    decisions: list[dict[str, Any]]
    shadow_flags: tuple[Any, ...] = field(default_factory=tuple)  # AC-35.6.c


@dataclass(frozen=True)
class ValidationError:
    """Static-analysis error pointing at file:line. AC-35.5.d."""

    file: str
    line: int
    col: int
    message: str
    hint: str | None = None


@dataclass(frozen=True)
class ConfidenceBreakdown:
    """Per-term confidence breakdown (AC-35.8.a).

    Sum: ``total = base + regression_penalty + relaxation_penalty +
    shadow_penalty + fire_rate_penalty + cascade_penalty``. Penalties are
    *negative* numbers (subtractions).
    """

    base: float
    regression_penalty: float
    relaxation_penalty: float
    shadow_penalty: float
    fire_rate_penalty: float
    cascade_penalty: float
    total: float


__all__ = [
    "ConfidenceBreakdown",
    "Proposal",
    "ProposalStatus",
    "ValidationError",
]
