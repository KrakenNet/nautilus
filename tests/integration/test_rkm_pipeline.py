"""Integration: static → shadow → sandbox → review → promote (#35.5–.10).

Exercises :func:`nautilus.rkm.validator.pipeline.run_pipeline` end-to-end.
Also iterates the hand-curated shadow-pair fixture suite (AC-35.6.a/b).
"""

from __future__ import annotations

from pathlib import Path

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


def _load_pair(pair_dir: Path) -> tuple[dict, dict, str]:
    rule_a = yaml.safe_load((pair_dir / "rule_a.yaml").read_text())
    rule_b = yaml.safe_load((pair_dir / "rule_b.yaml").read_text())
    expected = (pair_dir / "expected_relation.txt").read_text().strip()
    return rule_a, rule_b, expected


def _has_relation(flags: tuple[ShadowFlag, ...], relation: str) -> bool:
    return any(f.relation == relation for f in flags)


def _check_pair(rule_a: dict, rule_b: dict, expected: str, pair_name: str) -> None:
    """Assert fixture pair yields expected relation. False-negatives are failures."""
    flags_ab = shadow_check(rule_b, [rule_a])  # is B subsumed/shadowed by A?
    flags_ba = shadow_check(rule_a, [rule_b])  # is A subsumed/shadowed by B?

    if expected == "none":
        assert flags_ab == (), (
            f"{pair_name}: expected no flags (A vs B), got {flags_ab}"
        )
        assert flags_ba == (), (
            f"{pair_name}: expected no flags (B vs A), got {flags_ba}"
        )
    elif expected == "a_subsumes_b":
        # A subsumes B => B is subsumed_by A
        assert _has_relation(flags_ab, "subsumed_by"), (
            f"{pair_name}: false-negative — expected subsumed_by, "
            f"got {flags_ab}"
        )
    elif expected == "b_subsumes_a":
        # B subsumes A => A is subsumed_by B
        assert _has_relation(flags_ba, "subsumed_by"), (
            f"{pair_name}: false-negative — expected subsumed_by, "
            f"got {flags_ba}"
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
