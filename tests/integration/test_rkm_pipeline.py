"""Integration: static → shadow → sandbox → review → promote (#35.5–.10).

Exercises :func:`nautilus.rkm.validator.pipeline.run_pipeline` end-to-end.
Also iterates the hand-curated shadow-pair fixture suite (AC-35.6.a/b).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.validator.pipeline import run_pipeline
from nautilus.rkm.validator.shadow import ShadowFlag, shadow_check

pytestmark = pytest.mark.integration

_FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "rkm" / "shadow-pairs"


def test_pipeline_submits_proposal_to_queue(tmp_path: Path) -> None:
    rule_yaml = tmp_path / "ok.yaml"
    rule_yaml.write_text("rules: []\n")
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("")
    queue = ProposalQueue(tmp_path / "queue")
    proposal = run_pipeline(rule_yaml, queue=queue, audit_log=audit_log)
    assert proposal.proposal_id.startswith("prop_")
    assert queue.get(proposal.proposal_id) is not None


def _load_pair(pair_dir: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    rule_a: dict[str, Any] = yaml.safe_load((pair_dir / "rule_a.yaml").read_text())
    rule_b: dict[str, Any] = yaml.safe_load((pair_dir / "rule_b.yaml").read_text())
    expected = (pair_dir / "expected_relation.txt").read_text().strip()
    return rule_a, rule_b, expected


def _has_relation(flags: tuple[ShadowFlag, ...], relation: str) -> bool:
    return any(f.relation == relation for f in flags)


def _check_pair(
    rule_a: dict[str, Any], rule_b: dict[str, Any], expected: str, pair_name: str
) -> None:
    """Assert fixture pair yields expected relation. False-negatives are failures."""
    flags_ab = shadow_check(rule_b, [rule_a])  # is B subsumed/shadowed by A?
    flags_ba = shadow_check(rule_a, [rule_b])  # is A subsumed/shadowed by B?

    if expected == "none":
        assert flags_ab == (), f"{pair_name}: expected no flags (A vs B), got {flags_ab}"
        assert flags_ba == (), f"{pair_name}: expected no flags (B vs A), got {flags_ba}"
    elif expected == "a_subsumes_b":
        # A subsumes B => B is subsumed_by A
        assert _has_relation(flags_ab, "subsumed_by"), (
            f"{pair_name}: false-negative — expected subsumed_by, got {flags_ab}"
        )
    elif expected == "b_subsumes_a":
        # B subsumes A => A is subsumed_by B
        assert _has_relation(flags_ba, "subsumed_by"), (
            f"{pair_name}: false-negative — expected subsumed_by, got {flags_ba}"
        )
    elif expected == "a_shadows_b":
        # A shadows B => shadow_check(B, [A]) returns shadows
        assert _has_relation(flags_ab, "shadows"), (
            f"{pair_name}: false-negative — expected shadows, got {flags_ab}"
        )
    elif expected == "b_shadows_a":
        # B shadows A => shadow_check(A, [B]) returns shadows
        assert _has_relation(flags_ba, "shadows"), (
            f"{pair_name}: false-negative — expected shadows, got {flags_ba}"
        )
    elif expected == "salience_inversion":
        # At least one direction must return salience_inverts
        either = _has_relation(flags_ab, "salience_inverts") or _has_relation(
            flags_ba, "salience_inverts"
        )
        assert either, (
            f"{pair_name}: false-negative — expected salience_inverts in either direction, "
            f"got ab={flags_ab}, ba={flags_ba}"
        )
    else:
        pytest.fail(f"{pair_name}: unknown expected_relation '{expected}'")


def test_shadow_fixture_suite_no_false_negatives() -> None:
    """Iterate all hand-curated shadow pairs; fail on any false-negative (AC-35.6.b)."""
    pair_dirs = sorted(p for p in _FIXTURE_DIR.iterdir() if p.is_dir())
    assert len(pair_dirs) >= 20, (
        f"Fixture suite has only {len(pair_dirs)} pairs; need >= 20 (AC-35.6.a)"
    )
    for pair_dir in pair_dirs:
        rule_a, rule_b, expected = _load_pair(pair_dir)
        _check_pair(rule_a, rule_b, expected, pair_dir.name)


# ---------------------------------------------------------------------------
# The pipeline passes the actual proposal to every stage
# ---------------------------------------------------------------------------
#
# ``run_pipeline`` previously called ``shadow_check({}, [])`` and
# ``sandbox_replay({}, audit_log)``. An empty rule constrains nothing and
# asserts nothing, so every proposal — benign, regressive, or uncompilable —
# produced an identical validation record. These tests fail if that returns.


def _proposal_file(tmp_path: Path, name: str, body: dict[str, Any]) -> Path:
    path = tmp_path / f"{name}.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "module": "nautilus-routing",
                "ruleset": f"rkm-proposal-{name}",
                "version": "1.0",
                "rules": [body],
            },
            sort_keys=False,
        )
    )
    return path


def test_pipeline_rejects_a_regressive_proposal(tmp_path: Path) -> None:
    """A rule that withdraws granted access is rejected, with the reason recorded."""
    from tests.integration.test_rkm_sandbox import (  # noqa: SLF001
        DENY_ALL_PII,
        _write_audit_log,  # pyright: ignore[reportPrivateUsage]
    )

    audit_log = tmp_path / "audit.jsonl"
    _write_audit_log(audit_log, 5)
    queue = ProposalQueue(tmp_path / "queue")

    proposal = run_pipeline(
        _proposal_file(tmp_path, "regressive", DENY_ALL_PII),
        queue=queue,
        audit_log=audit_log,
    )
    assert proposal.status == "rejected"
    sandbox = proposal.validation["sandbox"]
    assert sandbox["error"], "rejection reason must be recorded on the proposal"
    assert sandbox["regressions"] == 5


def test_pipeline_distinguishes_proposals(tmp_path: Path) -> None:
    """Two different proposals produce different sandbox records.

    This is the discriminating check: with ``{}`` passed to every stage, a
    benign rule and a regressive one were indistinguishable in the queue.
    """
    from tests.integration.test_rkm_sandbox import (  # noqa: SLF001
        DEAD_RULE,
        DENY_ALL_PII,
        _write_audit_log,  # pyright: ignore[reportPrivateUsage]
    )

    audit_log = tmp_path / "audit.jsonl"
    _write_audit_log(audit_log, 5)
    queue = ProposalQueue(tmp_path / "queue")

    benign = run_pipeline(
        _proposal_file(tmp_path, "benign", DEAD_RULE), queue=queue, audit_log=audit_log
    )
    regressive = run_pipeline(
        _proposal_file(tmp_path, "regressive", DENY_ALL_PII),
        queue=queue,
        audit_log=audit_log,
    )

    assert benign.validation["sandbox"] != regressive.validation["sandbox"]
    assert benign.status != regressive.status


def test_pipeline_rejects_an_uncompilable_proposal(tmp_path: Path) -> None:
    """A rule the engine will not accept must not be queued as pending."""
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("")
    queue = ProposalQueue(tmp_path / "queue")

    proposal = run_pipeline(
        _proposal_file(tmp_path, "broken", {"name": "broken", "when": "not-a-list"}),
        queue=queue,
        audit_log=audit_log,
    )
    assert proposal.status == "rejected"
    assert proposal.validation["sandbox"]["error"]


def test_the_pipeline_writes_the_key_its_readers_read(tmp_path: Path) -> None:
    """`confidence`, not `score`.

    The pipeline wrote ``validation["score"]`` while the REST proposal
    detail, ``rkm queue list`` and ``ProposalQueue.list(min_confidence=...)``
    all read ``validation["confidence"]``, so a scored proposal displayed as
    0.0 on every human-review surface and no confidence filter could match.
    """
    from tests.integration.test_rkm_sandbox import (  # noqa: SLF001
        ROUTE_VULN_DB,
        _write_audit_log,  # pyright: ignore[reportPrivateUsage]
    )

    audit_log = tmp_path / "audit.jsonl"
    _write_audit_log(audit_log, 5)
    queue = ProposalQueue(tmp_path / "queue")

    proposal = run_pipeline(
        _proposal_file(tmp_path, "benign", ROUTE_VULN_DB),
        queue=queue,
        audit_log=audit_log,
    )
    confidence = proposal.validation["confidence"]
    assert isinstance(confidence, float)
    assert proposal.validation["confidence_breakdown"]["total"] == confidence
    # Reachable through the filter the CLI flag feeds.
    assert [p.proposal_id for p in queue.list(min_confidence=confidence)] == [proposal.proposal_id]
    assert queue.list(min_confidence=confidence + 0.01) == []
