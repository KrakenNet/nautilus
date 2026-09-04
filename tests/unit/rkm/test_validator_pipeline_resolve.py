"""Unit tests for the resolve stage's wiring into ``run_pipeline`` (#129).

Kept separate from :mod:`tests.unit.rkm.test_validator_resolve` (which stays
import-light and runs everywhere) because importing the pipeline pulls in
``nautilus.rkm.queue`` and its POSIX-only ``fcntl`` dependency.

Marked ``unit`` rather than ``integration`` deliberately: CI runs ``pytest -m unit``,
so an integration marker here would mean the wiring is never actually executed.
``run_pipeline`` now feeds ``shadow_check`` the real proposed rule, so a flag is
monkeypatched in to exercise each relation without authoring a conflicting ruleset.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from fathom.audit import FileSink

from nautilus.audit.logger import AuditLogger
from nautilus.rkm.lineage import LineageRecord, LineageStore
from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.types import ConfidenceBreakdown
from nautilus.rkm.validator import pipeline as pipeline_mod
from nautilus.rkm.validator.pipeline import run_pipeline
from nautilus.rkm.validator.sandbox import SandboxResult
from nautilus.rkm.validator.shadow import ShadowFlag

pytestmark = pytest.mark.unit


# A rule the engine actually compiles. ``rules: []`` was enough while
# ``run_pipeline`` fed ``sandbox_replay({}, ...)`` and ignored the file; it now
# replays the real proposal, and an empty body fails to compile, which rejects
# the proposal before stage 5 is reached.
_COMPILING_RULE: dict[str, Any] = {
    "module": "nautilus-routing",
    "ruleset": "rkm-proposal-resolve",
    "version": "1.0",
    "rules": [
        {
            "name": "resolve-stage-probe",
            "salience": 100,
            "when": [
                {
                    "template": "source",
                    "conditions": [
                        {"slot": "id", "bind": "?sid"},
                        {"test": '(eq ?sid "vuln_db")'},
                    ],
                }
            ],
            "then": {
                "action": "route",
                "reason": "resolve stage probe",
                "assert": [
                    {
                        "template": "routing_decision",
                        "slots": {"source_id": "?sid", "reason": "resolve stage probe"},
                    }
                ],
            },
        }
    ],
}


def _setup(tmp_path: Path) -> tuple[Path, Path, ProposalQueue, AuditLogger]:
    rule_yaml = tmp_path / "ok.yaml"
    rule_yaml.write_text(yaml.safe_dump(_COMPILING_RULE, sort_keys=False))
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("")
    # ``run_pipeline`` takes the writer rather than opening its own: under
    # ``audit.chained`` the log has exactly one writer, and a second sink over
    # it forks the hash chain.
    logger = AuditLogger(sink=FileSink(path=tmp_path / "events.jsonl"))
    return rule_yaml, audit_log, ProposalQueue(tmp_path / "queue"), logger


def _live_record(name: str, *, version: int = 1) -> LineageRecord:
    return LineageRecord(
        rule_name=name,
        version=version,
        proposer="meta-rule:pattern-tracker",
        observation_ids={"start": 0, "end": 10},
        sandbox_results={"replayed_n": 1000},
        approver="alice@example.com",
        derived_from=(),
        promoted_at=datetime(2025, 1, 1, tzinfo=UTC),
    )


def _force_flag(monkeypatch: pytest.MonkeyPatch, relation: str) -> None:
    """Feed the pipeline a flag, since run_pipeline still calls shadow_check({}, [])."""
    flag = ShadowFlag(existing_rule="broad_rule", relation=relation)  # type: ignore[arg-type]

    def _stub(_proposed: dict[str, Any], _ruleset: list[dict[str, Any]]) -> tuple[ShadowFlag, ...]:
        return (flag,)

    monkeypatch.setattr(pipeline_mod, "shadow_check", _stub)


def test_resolution_is_recorded_on_every_proposal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no flags the stage still runs and records its verdict."""
    rule_yaml, audit_log, queue, logger = _setup(tmp_path)

    proposal = run_pipeline(rule_yaml, queue=queue, audit_log=audit_log, audit_logger=logger)

    assert proposal.validation["resolution"]["action"] == "no_conflict"
    assert proposal.status == "pending"
    assert proposal.decisions == []


def test_auto_retire_marks_proposal_superseded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rule_yaml, audit_log, queue, logger = _setup(tmp_path)
    lineage = LineageStore()
    lineage.insert(_live_record("broad_rule"))
    _force_flag(monkeypatch, "subsumed_by")

    proposal = run_pipeline(
        rule_yaml, queue=queue, audit_log=audit_log, audit_logger=logger, lineage=lineage
    )

    assert proposal.status == "superseded"
    resolution = proposal.validation["resolution"]
    assert resolution["action"] == "auto_retire"
    assert resolution["superseded_by"] == "broad_rule"
    assert resolution["evidence"]["observation_count"] == 2

    # The decision is auditable and attributed to the stage, not a human.
    assert len(proposal.decisions) == 1
    assert proposal.decisions[0]["reviewer"] == "rkm:resolve"
    assert proposal.decisions[0]["superseded_by"] == "broad_rule"

    # Terminal status survives the JSONL round-trip.
    stored = queue.get(proposal.proposal_id)
    assert stored is not None
    assert stored.status == "superseded"


def test_auto_retire_never_retires_the_live_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stage resolves conflicts without ever mutating the active rule base."""
    rule_yaml, audit_log, queue, logger = _setup(tmp_path)
    lineage = LineageStore()
    lineage.insert(_live_record("broad_rule"))
    _force_flag(monkeypatch, "subsumed_by")

    run_pipeline(rule_yaml, queue=queue, audit_log=audit_log, audit_logger=logger, lineage=lineage)

    still_live = lineage.get("broad_rule", 1)
    assert still_live is not None
    assert still_live.retired_at is None


@pytest.mark.parametrize("relation", ["shadows", "salience_inverts"])
def test_ambiguous_relations_stay_pending_for_a_human(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relation: str
) -> None:
    rule_yaml, audit_log, queue, logger = _setup(tmp_path)
    lineage = LineageStore()
    lineage.insert(_live_record("broad_rule"))
    _force_flag(monkeypatch, relation)

    proposal = run_pipeline(
        rule_yaml, queue=queue, audit_log=audit_log, audit_logger=logger, lineage=lineage
    )

    assert proposal.status == "pending"
    assert proposal.validation["resolution"]["action"] == "human_review"


def test_thin_provenance_stays_pending_for_a_human(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A subsumed_by flag with no lineage evidence must not auto-retire."""
    rule_yaml, audit_log, queue, logger = _setup(tmp_path)
    _force_flag(monkeypatch, "subsumed_by")

    proposal = run_pipeline(
        rule_yaml, queue=queue, audit_log=audit_log, audit_logger=logger, lineage=LineageStore()
    )

    assert proposal.status == "pending"
    assert proposal.validation["resolution"]["action"] == "human_review"


def test_score_rejection_takes_precedence_over_auto_retire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A proposal failing the 0.6 score gate is rejected, not superseded."""
    rule_yaml, audit_log, queue, logger = _setup(tmp_path)
    lineage = LineageStore()
    lineage.insert(_live_record("broad_rule"))
    _force_flag(monkeypatch, "subsumed_by")
    # Equivalent to two sandbox regressions: 1.0 - 0.6 = 0.4, below the 0.6 gate.
    failing = ConfidenceBreakdown(
        base=1.0,
        regression_penalty=-0.6,
        relaxation_penalty=0.0,
        shadow_penalty=0.0,
        fire_rate_penalty=0.0,
        cascade_penalty=0.0,
        total=0.4,
    )

    def _stub_score(_sandbox: SandboxResult, _flags: tuple[ShadowFlag, ...]) -> ConfidenceBreakdown:
        return failing

    monkeypatch.setattr(pipeline_mod, "score", _stub_score)

    proposal = run_pipeline(
        rule_yaml, queue=queue, audit_log=audit_log, audit_logger=logger, lineage=lineage
    )

    assert proposal.status == "rejected"
