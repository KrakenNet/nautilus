"""Regressions for the RKM queue/review cluster.

Each class covers one defect that shipped:

- ``oldest_age_seconds`` used ``min`` over the pending ages, i.e. the age of
  the *newest* proposal, so any "awaiting review > N hours" alert stayed
  suppressed as long as new proposals kept arriving.
- ``list(min_confidence=...)`` declared and documented the filter and never
  applied it, making ``rkm queue list --min-confidence`` a silent no-op.
- ``run_pipeline`` wrote ``validation["score"]`` while every reader --
  the REST proposal detail, ``rkm queue list``, and the filter above --
  read ``validation["confidence"]``, so a 0.9 proposal displayed as 0.0.
- ``_extract_rule_yaml`` read ``artifact["yaml"]``, which nothing writes,
  and fell back to JSON-serialising the whole artifact wrapper into the
  rule compiler.
- ``_build_lineage_record`` and ``rkm queue diff`` both did
  ``.get("derived_from", [])`` against ``{"derived_from": None}``.
- An approve that failed to promote left the proposal in ``approved`` with
  no retry, no reject and no rollback.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from nautilus.rkm.lineage import LineageStore
from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.review import (  # noqa: SLF001
    AlreadyDecidedError,
    PromotionFailedError,
    _build_lineage_record,  # pyright: ignore[reportPrivateUsage]
    _extract_rule_yaml,  # pyright: ignore[reportPrivateUsage]
    approve_proposal,
    reject_proposal,
)
from nautilus.rkm.types import Proposal

pytestmark = pytest.mark.unit


def _proposal(
    proposal_id: str = "prop_a",
    *,
    age_seconds: float = 0.0,
    confidence: float | None = None,
    artifact: dict[str, Any] | None = None,
    lineage: dict[str, Any] | None = None,
) -> Proposal:
    validation: dict[str, Any] = {} if confidence is None else {"confidence": confidence}
    return Proposal(
        proposal_id=proposal_id,
        schema_version=2,
        status="pending",
        proposer="pipeline",
        proposed_at=datetime.now(UTC) - timedelta(seconds=age_seconds),
        target_module="curator",
        artifact_type="rule",
        artifact=artifact if artifact is not None else {"name": "r"},
        validation=validation,
        lineage=lineage if lineage is not None else {},
        decisions=[],
    )


class TestOldestAgeIsTheOldest:
    def test_a_fresh_proposal_does_not_mask_an_ancient_one(self, tmp_path: Path) -> None:
        queue = ProposalQueue(tmp_path)
        queue.submit(_proposal("prop_ancient", age_seconds=86_400))
        queue.submit(_proposal("prop_fresh", age_seconds=5))
        oldest = queue.oldest_age_seconds()
        assert oldest is not None
        assert 86_370 <= oldest <= 86_430


class TestMinConfidenceFilters:
    @pytest.fixture()
    def queue(self, tmp_path: Path) -> ProposalQueue:
        q = ProposalQueue(tmp_path)
        q.submit(_proposal("prop_low", confidence=0.10))
        q.submit(_proposal("prop_high", confidence=0.95))
        q.submit(_proposal("prop_unscored"))
        return q

    def test_zero_keeps_everything(self, queue: ProposalQueue) -> None:
        assert len(queue.list(min_confidence=0.0)) == 3

    def test_the_threshold_excludes_what_is_below_it(self, queue: ProposalQueue) -> None:
        assert [p.proposal_id for p in queue.list(min_confidence=0.9)] == ["prop_high"]

    def test_an_unreachable_threshold_returns_nothing(self, queue: ProposalQueue) -> None:
        assert queue.list(min_confidence=2.0) == []

    def test_an_unscored_proposal_does_not_clear_a_nonzero_bar(self, queue: ProposalQueue) -> None:
        assert "prop_unscored" not in [p.proposal_id for p in queue.list(min_confidence=0.01)]

    def test_the_filter_composes_with_status(self, queue: ProposalQueue) -> None:
        assert [p.proposal_id for p in queue.list(status="pending", min_confidence=0.9)] == [
            "prop_high"
        ]


class TestExtractRuleYaml:
    def test_inline_yaml_is_returned_verbatim(self) -> None:
        assert _extract_rule_yaml(_proposal(artifact={"yaml": "rules: []"})) == "rules: []"

    def test_yaml_path_is_read_from_disk(self, tmp_path: Path) -> None:
        rule = tmp_path / "candidate.yaml"
        rule.write_text("rules: []\n", encoding="utf-8")
        assert _extract_rule_yaml(_proposal(artifact={"yaml_path": str(rule)})) == "rules: []\n"

    def test_an_unreadable_path_is_a_promotion_failure(self, tmp_path: Path) -> None:
        missing = str(tmp_path / "gone.yaml")
        with pytest.raises(PromotionFailedError, match="unreadable"):
            _extract_rule_yaml(_proposal(artifact={"yaml_path": missing}))

    def test_an_artifact_with_neither_key_is_rejected_not_serialised(self) -> None:
        """The wrapper dict must never reach the rule compiler."""
        with pytest.raises(PromotionFailedError, match="no rule YAML"):
            _extract_rule_yaml(_proposal(artifact={"name": "r", "version": 1}))


class TestLineageRecordToleratesNull:
    def test_derived_from_none_does_not_raise(self) -> None:
        record = _build_lineage_record(
            _proposal(lineage={"derived_from": None}), "alice", datetime.now(UTC)
        )
        assert record.derived_from == ()

    def test_observation_ids_none_does_not_raise(self) -> None:
        record = _build_lineage_record(
            _proposal(lineage={"observation_ids": None, "sandbox_results": None}),
            "alice",
            datetime.now(UTC),
        )
        assert record.observation_ids == {}
        assert record.sandbox_results == {}


class _FailingRouter:
    def reload_rule(self, rule_name: str, rule_yaml: str) -> None:
        del rule_name, rule_yaml
        raise ValueError("compiler said no")


class _AcceptingRouter:
    def __init__(self) -> None:
        self.loaded: list[str] = []

    def reload_rule(self, rule_name: str, rule_yaml: str) -> None:
        del rule_yaml
        self.loaded.append(rule_name)


class TestFailedPromotionIsRecoverable:
    @pytest.fixture()
    def stores(self, tmp_path: Path) -> tuple[ProposalQueue, LineageStore]:
        queue = ProposalQueue(tmp_path / "q")
        rule = tmp_path / "candidate.yaml"
        rule.write_text("rules: []\n", encoding="utf-8")
        queue.submit(
            _proposal(
                artifact={"yaml_path": str(rule), "name": "r", "version": 1},
                lineage={"derived_from": None},
            )
        )
        return queue, LineageStore(tmp_path / "l")

    @staticmethod
    def _status(queue: ProposalQueue, proposal_id: str = "prop_a") -> str:
        proposal = queue.get(proposal_id)
        assert proposal is not None
        return proposal.status

    def _fail_once(self, queue: ProposalQueue, lineage: LineageStore) -> None:
        with pytest.raises(PromotionFailedError):
            approve_proposal(
                "prop_a", "alice", queue=queue, lineage=lineage, router=_FailingRouter()
            )
        assert self._status(queue) == "approved"

    def test_a_failed_promotion_can_be_retried(
        self, stores: tuple[ProposalQueue, LineageStore]
    ) -> None:
        queue, lineage = stores
        self._fail_once(queue, lineage)
        router = _AcceptingRouter()
        result = approve_proposal("prop_a", "alice", queue=queue, lineage=lineage, router=router)
        assert result.promoted is True
        assert router.loaded == ["prop_a"]
        assert self._status(queue) == "promoted"

    def test_a_failed_promotion_can_be_rejected(
        self, stores: tuple[ProposalQueue, LineageStore]
    ) -> None:
        queue, lineage = stores
        self._fail_once(queue, lineage)
        reject_proposal("prop_a", "alice", "cannot promote", queue=queue)
        assert self._status(queue) == "rejected"

    def test_a_promoted_proposal_stays_decided(
        self, stores: tuple[ProposalQueue, LineageStore]
    ) -> None:
        queue, lineage = stores
        approve_proposal("prop_a", "alice", queue=queue, lineage=lineage, router=_AcceptingRouter())
        with pytest.raises(AlreadyDecidedError):
            approve_proposal(
                "prop_a", "bob", queue=queue, lineage=lineage, router=_AcceptingRouter()
            )
        with pytest.raises(AlreadyDecidedError):
            reject_proposal("prop_a", "bob", "no", queue=queue)

    def test_a_rejected_proposal_stays_decided(
        self, stores: tuple[ProposalQueue, LineageStore]
    ) -> None:
        queue, lineage = stores
        reject_proposal("prop_a", "alice", "no", queue=queue)
        with pytest.raises(AlreadyDecidedError):
            approve_proposal(
                "prop_a", "bob", queue=queue, lineage=lineage, router=_AcceptingRouter()
            )

    def test_approving_twice_records_one_approval(
        self, stores: tuple[ProposalQueue, LineageStore]
    ) -> None:
        """The retry must not append a second `approved` transition."""
        queue, lineage = stores
        self._fail_once(queue, lineage)
        approve_proposal("prop_a", "alice", queue=queue, lineage=lineage, router=_AcceptingRouter())
        promoted = queue.get("prop_a")
        assert promoted is not None
        decisions = promoted.decisions
        assert [d.get("to") for d in decisions] == ["approved", "promoted"]
