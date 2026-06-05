"""Integration: queue lockf contention + restart survival (#35.9)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.types import Proposal

pytestmark = pytest.mark.integration


def _make(proposal_id: str) -> Proposal:
    return Proposal(
        proposal_id=proposal_id,
        schema_version=2,
        status="pending",
        proposer="meta-rule:pattern-tracker",
        proposed_at=datetime(2025, 1, 1, tzinfo=UTC),
        target_module="suggestions",
        artifact_type="relationship_fact",
        artifact={},
        validation={},
        lineage={},
        decisions=[],
    )


def test_ac_35_9_a_queue_survives_restart(tmp_path: Path) -> None:
    queue_dir = tmp_path / "queue"
    q1 = ProposalQueue(queue_dir)
    q1.submit(_make("prop_persist_a"))
    q1.submit(_make("prop_persist_b"))
    # New instance over the same dir = simulated restart.
    q2 = ProposalQueue(queue_dir)
    assert {p.proposal_id for p in q2.list()} == {
        "prop_persist_a",
        "prop_persist_b",
    }


def test_ac_35_9_b_reject_records_reviewer(tmp_path: Path) -> None:
    queue = ProposalQueue(tmp_path)
    queue.submit(_make("prop_rj"))
    updated = queue.transition(
        "prop_rj",
        to="rejected",
        reviewer="alice@example.com",
        reason="duplicate",
        note=None,
    )
    assert updated.status == "rejected"
    assert any(d.get("reviewer") == "alice@example.com" for d in updated.decisions)
