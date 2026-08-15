"""Every governance decision made outside ``Broker.arequest`` reaches the log.

Approve, reject, retract and rollback are the changes the audit log exists to
record. Each one shipped with ``audit_logger=None`` hard-coded at its CLI call
site -- rollback did not go through :mod:`nautilus.rkm.review` at all -- so a
rule could be retired or restored with nothing written anywhere. Four of the
declared ``event_type`` values had no producer for the same reason.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fathom.audit import FileSink

from nautilus.audit.logger import NAUTILUS_METADATA_KEY, AuditLogger
from nautilus.cli import rkm as cli_rkm
from nautilus.cli import rule as cli_rule
from nautilus.rkm.lineage import LineageRecord, LineageStore
from nautilus.rkm.queue import ProposalQueue
from nautilus.rkm.review import RollbackResult, rollback_rule
from nautilus.rkm.types import Proposal

pytestmark = pytest.mark.unit

REVIEWER = "alice@example.com"


def _events(audit_log: Path) -> list[dict[str, Any]]:
    """The sparse lifecycle events written to ``audit_log``, in order."""
    if not audit_log.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line).get("metadata", {}).get(NAUTILUS_METADATA_KEY)
        if payload is not None:
            out.append(json.loads(payload))
    return out


def _types(audit_log: Path) -> list[str]:
    return [str(e.get("event_type")) for e in _events(audit_log)]


def _rule_yaml(path: Path) -> Path:
    """A rule the compiler accepts, so approve actually promotes."""
    path.write_text(
        "module: nautilus-routing\n"
        "ruleset: cand\n"
        'version: "1.0"\n'
        "rules:\n"
        "  - name: gov_audit_probe\n"
        "    description: probe\n"
        "    salience: 100\n"
        "    when:\n"
        "      - template: source\n"
        "        conditions:\n"
        "          - slot: id\n"
        "            bind: ?sid\n"
        "    then:\n"
        "      action: route\n"
        '      reason: "probe"\n'
        "      assert:\n"
        "        - template: routing_decision\n"
        '          slots: {source_id: "?sid", reason: "probe"}\n',
        encoding="utf-8",
    )
    return path


def _pending(queue_dir: Path, rule_path: Path) -> ProposalQueue:
    queue = ProposalQueue(queue_dir)
    queue.submit(
        Proposal(
            proposal_id="prop_gov",
            schema_version=2,
            status="pending",
            proposer="pipeline",
            proposed_at=datetime.now(UTC),
            target_module="curator",
            artifact_type="rule",
            artifact={"name": "gov_audit_probe", "version": 1, "yaml_path": str(rule_path)},
            validation={"confidence": 0.9},
            lineage={"derived_from": None},
            decisions=[],
        )
    )
    return queue


def _record(rule_name: str = "gov_audit_probe", version: int = 1) -> LineageRecord:
    return LineageRecord(
        rule_name=rule_name,
        version=version,
        proposer="pipeline",
        observation_ids={},
        sandbox_results={},
        approver=REVIEWER,
        derived_from=(),
        promoted_at=datetime.now(UTC),
    )


@pytest.fixture()
def cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run the CLI in a scratch cwd: queue, lineage and audit log are all relative."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NAUTILUS_REVIEWER", REVIEWER)
    return tmp_path


class TestTheQueueDecisionsAreAudited:
    def test_approve_records_the_decision_and_the_promotion(self, cwd: Path) -> None:
        _pending(Path(".nautilus/rkm/queue"), _rule_yaml(cwd / "cand.yaml"))
        args = argparse.Namespace(
            cmd="rkm",
            rkm_subcommand="queue",
            queue_subcommand="approve",
            proposal_id="prop_gov",
            note=None,
            json=False,
            config=None,
        )
        assert cli_rkm.dispatch(args) == 0
        assert _types(cwd / "audit.jsonl") == ["proposal_approved"]

    def test_reject_records_the_reason(self, cwd: Path) -> None:
        _pending(Path(".nautilus/rkm/queue"), _rule_yaml(cwd / "cand.yaml"))
        args = argparse.Namespace(
            cmd="rkm",
            rkm_subcommand="queue",
            queue_subcommand="reject",
            proposal_id="prop_gov",
            reason="too broad",
            json=False,
            config=None,
        )
        assert cli_rkm.dispatch(args) == 0
        events = _events(cwd / "audit.jsonl")
        assert [e["event_type"] for e in events] == ["proposal_rejected"]
        assert events[0]["reason"] == "too broad"
        assert events[0]["reviewer"] == REVIEWER

    def test_a_promotion_writes_both_the_engine_load_and_the_queue_state(self, cwd: Path) -> None:
        """``rule_promoted`` and ``proposal_promoted`` mark two separate steps."""
        from nautilus.rkm import review

        queue = _pending(Path(".nautilus/rkm/queue"), _rule_yaml(cwd / "cand.yaml"))
        lineage = LineageStore(Path(".nautilus/rkm/lineage"))

        class _AcceptingRouter:
            def reload_rule(self, rule_name: str, rule_yaml: str) -> None:
                return None

        result = review.approve_proposal(
            "prop_gov",
            REVIEWER,
            queue=queue,
            lineage=lineage,
            router=_AcceptingRouter(),
            audit_logger=AuditLogger(sink=FileSink(path=cwd / "audit.jsonl")),
        )
        assert result.promoted is True
        assert _types(cwd / "audit.jsonl") == [
            "proposal_approved",
            "rule_promoted",
            "proposal_promoted",
        ]


class TestTheRuleLifecycleIsAudited:
    def test_retract_records_the_retirement(self, cwd: Path) -> None:
        LineageStore(Path(".nautilus/rkm/lineage")).insert(_record())
        args = argparse.Namespace(
            cmd="rule",
            rule_subcommand="retract",
            name="gov_audit_probe",
            reason="superseded",
            cascade=False,
            orphan_children=False,
            yes=True,
            config=None,
        )
        assert cli_rule.dispatch(args) == 0
        events = _events(cwd / "audit.jsonl")
        assert [e["event_type"] for e in events] == ["rule_retracted"]
        assert events[0]["reason"] == "superseded"

    def test_rollback_records_the_restore(self, cwd: Path) -> None:
        store = LineageStore(Path(".nautilus/rkm/lineage"))
        store.insert(_record(version=1))
        store.insert(_record(version=2))
        args = argparse.Namespace(
            cmd="rule",
            rule_subcommand="rollback",
            name="gov_audit_probe",
            to_version=1,
            reason="v2 regressed",
            yes=True,
            config=None,
        )
        assert cli_rule.dispatch(args) == 0
        events = _events(cwd / "audit.jsonl")
        assert [e["event_type"] for e in events] == ["rule_rolled_back"]
        assert events[0]["restored_version"] == 1
        assert events[0]["new_version"] == 3
        assert events[0]["reviewer"] == REVIEWER

    def test_rollback_still_appends_the_restored_version(self, cwd: Path) -> None:
        store = LineageStore(Path(".nautilus/rkm/lineage"))
        store.insert(_record(version=1))
        store.insert(_record(version=2))
        result = rollback_rule(
            "gov_audit_probe",
            to_version=1,
            reason="v2 regressed",
            reviewer=REVIEWER,
            lineage=store,
        )
        assert isinstance(result, RollbackResult)
        latest = store.get("gov_audit_probe")
        assert latest is not None
        assert latest.version == 3
        assert latest.retired_at is None

    def test_rolling_back_to_a_version_that_never_existed_is_an_error(self, cwd: Path) -> None:
        store = LineageStore(Path(".nautilus/rkm/lineage"))
        store.insert(_record(version=1))
        with pytest.raises(KeyError):
            rollback_rule(
                "gov_audit_probe",
                to_version=9,
                reason="typo",
                reviewer=REVIEWER,
                lineage=store,
            )
        args = argparse.Namespace(
            cmd="rule",
            rule_subcommand="rollback",
            name="gov_audit_probe",
            to_version=9,
            reason="typo",
            yes=True,
            config=None,
        )
        assert cli_rule.dispatch(args) == 1
        assert _events(cwd / "audit.jsonl") == []


class TestTheSinkFollowsTheConfig:
    def test_config_audit_path_receives_the_record(self, cwd: Path) -> None:
        (cwd / "nautilus.yaml").write_text(
            "version: 1\naudit:\n  path: ./ops/decisions.jsonl\nsources: []\n",
            encoding="utf-8",
        )
        LineageStore(Path(".nautilus/rkm/lineage")).insert(_record())
        args = argparse.Namespace(
            cmd="rule",
            rule_subcommand="retract",
            name="gov_audit_probe",
            reason="superseded",
            cascade=False,
            orphan_children=False,
            yes=True,
            config=str(cwd / "nautilus.yaml"),
        )
        assert cli_rule.dispatch(args) == 0
        assert _types(cwd / "ops" / "decisions.jsonl") == ["rule_retracted"]
        assert not (cwd / "audit.jsonl").is_file()

    def test_an_unreadable_config_still_records_the_decision(
        self, cwd: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        LineageStore(Path(".nautilus/rkm/lineage")).insert(_record())
        args = argparse.Namespace(
            cmd="rule",
            rule_subcommand="retract",
            name="gov_audit_probe",
            reason="superseded",
            cascade=False,
            orphan_children=False,
            yes=True,
            config=str(cwd / "does-not-exist.yaml"),
        )
        assert cli_rule.dispatch(args) == 0
        assert _types(cwd / "audit.jsonl") == ["rule_retracted"]
        assert "WARN" in capsys.readouterr().err


class TestThePipelineIsAudited:
    def test_a_validated_proposal_leaves_both_lifecycle_events(self, tmp_path: Path) -> None:
        from nautilus.rkm.validator.pipeline import run_pipeline

        audit_log = tmp_path / "audit.jsonl"
        audit_log.write_text("", encoding="utf-8")
        queue = ProposalQueue(tmp_path / "queue")
        proposal = run_pipeline(
            _rule_yaml(tmp_path / "cand.yaml"), queue=queue, audit_log=audit_log
        )
        events = _events(audit_log)
        assert [e["event_type"] for e in events] == ["proposal_emitted", "proposal_validated"]
        assert all(e["proposal_id"] == proposal.proposal_id for e in events)
        assert events[1]["status"] == proposal.status
        assert events[1]["confidence"] == proposal.validation["confidence"]
