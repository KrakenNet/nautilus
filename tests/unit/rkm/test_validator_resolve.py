"""Unit tests for :mod:`nautilus.rkm.validator.resolve` (#129).

Pins the fail-closed ladder: only a single ``subsumed_by`` flag backed by live,
provenance-rich lineage auto-retires; everything else routes to a human. Pure
function — no I/O, no mocks.

Imports only ``resolve`` / ``shadow`` / ``lineage`` on purpose: ``nautilus.rkm.queue``
pulls in POSIX-only ``fcntl``, so keeping it out leaves this suite runnable on every
platform.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from nautilus.rkm.lineage import LineageRecord, LineageStore
from nautilus.rkm.validator.resolve import ResolutionDecision, apply_resolution, resolve
from nautilus.rkm.validator.shadow import ShadowFlag

pytestmark = pytest.mark.unit


def _record(
    name: str,
    *,
    version: int = 1,
    observation_ids: dict[str, Any] | None = None,
    sandbox_results: dict[str, Any] | None = None,
    retired: bool = False,
) -> LineageRecord:
    """A lineage record that clears every provenance gate unless told otherwise."""
    return LineageRecord(
        rule_name=name,
        version=version,
        proposer="meta-rule:pattern-tracker",
        observation_ids={"start": 0, "end": 10} if observation_ids is None else observation_ids,
        sandbox_results={"replayed_n": 1000} if sandbox_results is None else sandbox_results,
        approver="alice@example.com",
        derived_from=(),
        promoted_at=datetime(2025, 1, 1, tzinfo=UTC),
        retired_at=datetime(2025, 6, 1, tzinfo=UTC) if retired else None,
        retire_reason="manual" if retired else None,
    )


def _subsumed(existing: str = "broad_rule") -> ShadowFlag:
    return ShadowFlag(existing_rule=existing, relation="subsumed_by")


# ---------------------------------------------------------------------------
# resolve() — the ladder
# ---------------------------------------------------------------------------


def test_no_flags_is_no_conflict() -> None:
    decision = resolve((), {})
    assert decision.action == "no_conflict"
    assert decision.retire_rule is None
    assert decision.superseded_by is None


def test_single_subsumed_by_with_live_rich_provenance_auto_retires() -> None:
    decision = resolve(
        (_subsumed(),),
        {"broad_rule": _record("broad_rule")},
        proposed_rule="narrow_rule",
        proposed_version=3,
    )
    assert decision.action == "auto_retire"
    assert decision.retire_rule == "narrow_rule"
    assert decision.retire_version == 3
    assert decision.superseded_by == "broad_rule"


def test_shadows_relation_routes_to_human_review() -> None:
    flag = ShadowFlag(existing_rule="broad_rule", relation="shadows")
    decision = resolve((flag,), {"broad_rule": _record("broad_rule")})
    assert decision.action == "human_review"


def test_salience_inverts_relation_routes_to_human_review() -> None:
    flag = ShadowFlag(existing_rule="broad_rule", relation="salience_inverts")
    decision = resolve((flag,), {"broad_rule": _record("broad_rule")})
    assert decision.action == "human_review"


def test_mixed_relations_route_to_human_review() -> None:
    """A resolvable flag alongside an unresolvable one must not auto-retire."""
    inverts = ShadowFlag(existing_rule="other_rule", relation="salience_inverts")
    decision = resolve(
        (_subsumed(), inverts),
        {"broad_rule": _record("broad_rule"), "other_rule": _record("other_rule")},
        proposed_rule="narrow_rule",
    )
    assert decision.action == "human_review"
    assert decision.retire_rule is None


def test_two_subsumed_by_flags_route_to_human_review() -> None:
    decision = resolve(
        (_subsumed("broad_a"), _subsumed("broad_b")),
        {"broad_a": _record("broad_a"), "broad_b": _record("broad_b")},
        proposed_rule="narrow_rule",
    )
    assert decision.action == "human_review"
    assert decision.retire_rule is None


def test_missing_lineage_record_routes_to_human_review() -> None:
    decision = resolve((_subsumed(),), {}, proposed_rule="narrow_rule")
    assert decision.action == "human_review"
    assert decision.evidence["lineage_record"] is False


def test_retired_existing_rule_routes_to_human_review() -> None:
    decision = resolve(
        (_subsumed(),),
        {"broad_rule": _record("broad_rule", retired=True)},
        proposed_rule="narrow_rule",
    )
    assert decision.action == "human_review"
    assert decision.evidence["existing_retired"] is True


def test_empty_observation_ids_routes_to_human_review() -> None:
    decision = resolve(
        (_subsumed(),),
        {"broad_rule": _record("broad_rule", observation_ids={})},
        proposed_rule="narrow_rule",
    )
    assert decision.action == "human_review"
    assert "observation_ids" in decision.reason


def test_empty_sandbox_results_routes_to_human_review() -> None:
    decision = resolve(
        (_subsumed(),),
        {"broad_rule": _record("broad_rule", sandbox_results={})},
        proposed_rule="narrow_rule",
    )
    assert decision.action == "human_review"
    assert "sandbox_results" in decision.reason


def test_auto_retire_never_targets_the_live_existing_rule() -> None:
    """Direction ambiguity guard: the retire target is always the proposal."""
    flag = _subsumed()
    decision = resolve(
        (flag,),
        {"broad_rule": _record("broad_rule")},
        proposed_rule="narrow_rule",
    )
    assert decision.action == "auto_retire"
    assert decision.retire_rule != flag.existing_rule


def test_auto_retire_without_proposal_identity_names_no_target() -> None:
    decision = resolve((_subsumed(),), {"broad_rule": _record("broad_rule")})
    assert decision.action == "auto_retire"
    assert decision.retire_rule is None
    assert decision.retire_version is None


def test_identical_inputs_produce_equal_decisions() -> None:
    args = ((_subsumed(),), {"broad_rule": _record("broad_rule")})
    first = resolve(*args, proposed_rule="narrow_rule")
    second = resolve(*args, proposed_rule="narrow_rule")
    assert first == second


# ---------------------------------------------------------------------------
# apply_resolution() — lineage recording
# ---------------------------------------------------------------------------


def test_apply_resolution_marks_target_retired_in_lineage() -> None:
    store = LineageStore()
    store.insert(_record("narrow_rule", version=2))
    decision = resolve(
        (_subsumed(),),
        {"broad_rule": _record("broad_rule")},
        proposed_rule="narrow_rule",
        proposed_version=2,
    )

    retired = apply_resolution(decision, lineage=store)

    assert retired == "narrow_rule"
    stored = store.get("narrow_rule", 2)
    assert stored is not None
    assert stored.retired_at is not None
    assert stored.retire_reason == "superseded by broad_rule"
    assert stored.retire_reviewer == "rkm:resolve"


def test_apply_resolution_is_a_noop_when_target_has_no_lineage_record() -> None:
    store = LineageStore()
    decision = resolve(
        (_subsumed(),),
        {"broad_rule": _record("broad_rule")},
        proposed_rule="never_promoted",
    )
    assert apply_resolution(decision, lineage=store) is None


def test_apply_resolution_ignores_human_review_decisions() -> None:
    store = LineageStore()
    store.insert(_record("narrow_rule"))
    decision = ResolutionDecision(
        action="human_review",
        reason="ambiguous",
        retire_rule="narrow_rule",
        retire_version=1,
    )

    assert apply_resolution(decision, lineage=store) is None
    stored = store.get("narrow_rule", 1)
    assert stored is not None
    assert stored.retired_at is None


def test_apply_resolution_ignores_no_conflict_decisions() -> None:
    store = LineageStore()
    store.insert(_record("narrow_rule"))
    assert apply_resolution(resolve((), {}), lineage=store) is None
    stored = store.get("narrow_rule", 1)
    assert stored is not None
    assert stored.retired_at is None
