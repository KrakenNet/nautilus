"""Unit tests for :mod:`nautilus.rkm.queue` (#35.9 + DQ3)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nautilus.rkm.queue import InvalidTransition, ProposalQueue
from nautilus.rkm.types import Proposal

pytestmark = pytest.mark.unit


def _make_proposal(proposal_id: str = "prop_test_abc") -> Proposal:
    return Proposal(
        proposal_id=proposal_id,
        schema_version=2,
        status="pending",
        proposer="meta-rule:pattern-tracker",
        proposed_at=datetime(2025, 1, 1, tzinfo=UTC),
        target_module="suggestions",
        artifact_type="relationship_fact",
        artifact={"name": "test"},
        validation={},
        lineage={},
        decisions=[],
    )


def test_ac_35_9_a_submit_persists_to_jsonl(tmp_path: Path) -> None:
    queue = ProposalQueue(tmp_path)
    queue.submit(_make_proposal())
    # Round-trip via get() — survives restart by virtue of being on disk.
    restored = ProposalQueue(tmp_path).get("prop_test_abc")
    assert restored is not None
    assert restored.proposal_id == "prop_test_abc"


def test_ac_35_9_a_submit_is_idempotent_on_duplicate_id(tmp_path: Path) -> None:
    queue = ProposalQueue(tmp_path)
    queue.submit(_make_proposal())
    queue.submit(_make_proposal())  # second submit must not raise
    assert queue.depth() == 1


def test_ac_35_9_b_list_filters_by_status(tmp_path: Path) -> None:
    queue = ProposalQueue(tmp_path)
    queue.submit(_make_proposal())
    pending = queue.list(status="pending")
    approved = queue.list(status="approved")
    assert len(pending) == 1
    assert len(approved) == 0


def test_ac_35_9_d_approve_only_valid_from_pending(tmp_path: Path) -> None:
    queue = ProposalQueue(tmp_path)
    queue.submit(_make_proposal())
    queue.transition(
        "prop_test_abc",
        to="approved",
        reviewer="alice@example.com",
        reason=None,
        note="LGTM",
    )
    # Re-approving an already-approved proposal must surface as a
    # well-defined error (CLI exit 2 / REST 409 per shared.md exit-code table).
    with pytest.raises(InvalidTransition):
        queue.transition(
            "prop_test_abc",
            to="approved",
            reviewer="bob@example.com",
            reason=None,
            note=None,
        )


def test_ac_35_9_f_depth_and_oldest_age_metrics(tmp_path: Path) -> None:
    queue = ProposalQueue(tmp_path)
    assert queue.depth() == 0
    assert queue.oldest_age_seconds() == 0.0
    queue.submit(_make_proposal())
    assert queue.depth() == 1
    assert queue.oldest_age_seconds() >= 0.0
