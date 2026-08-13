"""Integration: sandbox audit-log replay harness (#35.7).

The previous version of this file could not detect a broken sandbox. It fed
``{"lhs": [], "rhs": [{"deny": True}]}`` — a schema the rule compiler rejects —
against a hand-written audit line ``{"allowed": true}``, a key nothing has ever
written. Both were fictions the harness happened to agree with, so the tests
passed while the harness was wrong on 46.6% of real trials.

These build a real audit log by routing real requests, then replay real rules.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fathom.audit import FileSink

from nautilus.audit.logger import AuditLogger
from nautilus.config.models import SourceConfig
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import AuditEntry, IntentAnalysis
from nautilus.rkm.validator.sandbox import (
    SandboxRegressionError,
    SandboxResult,
    SandboxRuleError,
    sandbox_replay,
)
from nautilus.rules import BUILT_IN_RULES_DIR

pytestmark = pytest.mark.integration

SOURCES = [
    SourceConfig(
        id="pii_db",
        type="rest",
        description="d",
        classification="confidential",
        data_types=["pii"],
        allowed_purposes=["audit"],
        connection="memory://",
    ),
    SourceConfig(
        id="vuln_db",
        type="rest",
        description="d",
        classification="unclassified",
        data_types=["vulnerability"],
        allowed_purposes=["audit"],
        connection="memory://",
    ),
]


def _write_audit_log(path: Path, n: int) -> None:
    """Route ``n`` real requests and persist them as a real audit log."""
    router = FathomRouter(built_in_rules_dir=BUILT_IN_RULES_DIR, user_rules_dirs=[])
    logger = AuditLogger(FileSink(path))
    for i in range(n):
        result = router.route(
            agent_id=f"agent-{i}",
            context={"clearance": "secret", "purpose": "audit"},
            intent=IntentAnalysis(raw_intent="pull", data_types_needed=["pii"], entities=[]),
            sources=SOURCES,
            session={"session_id": f"s{i}"},
        )
        logger.emit(
            AuditEntry(
                timestamp=AuditLogger.utcnow(),
                request_id=f"req-{i}",
                agent_id=f"agent-{i}",
                facts_asserted_summary=result.facts_asserted_summary,
                routing_decisions=result.routing_decisions,
                denial_records=result.denial_records,
                error_records=[],
                rule_trace=result.rule_trace,
                sources_queried=[r.source_id for r in result.routing_decisions],
                sources_denied=[d.source_id for d in result.denial_records],
                sources_errored=[],
                duration_ms=1,
                input_facts=result.input_facts,
            )
        )


# A rule that denies every source the baseline routes: pure regression.
DENY_ALL_PII = {
    "name": "sandbox-deny-pii",
    "salience": 195,
    "when": [
        {
            "template": "source",
            "conditions": [
                {"slot": "id", "bind": "?sid"},
                {"slot": "data_types", "bind": "?dts"},
                {"test": '(python-function overlaps ?dts "pii")'},
            ],
        },
    ],
    "then": {
        "action": "deny",
        "reason": "sandbox test denial",
        "assert": [
            {
                "template": "denial_record",
                "slots": {
                    "source_id": "?sid",
                    "reason": "sandbox test denial",
                    "rule_name": "sandbox-deny-pii",
                },
            }
        ],
    },
}

# A rule that routes a source the baseline never routed: pure relaxation.
ROUTE_VULN_DB = {
    "name": "sandbox-route-vuln",
    "salience": 100,
    "when": [
        {
            "template": "source",
            "conditions": [
                {"slot": "id", "bind": "?sid"},
                {"test": '(eq ?sid "vuln_db")'},
            ],
        },
    ],
    "then": {
        "action": "route",
        "reason": "sandbox test route",
        "assert": [
            {
                "template": "routing_decision",
                "slots": {
                    "source_id": "?sid",
                    "reason": "sandbox test route",
                },
            }
        ],
    },
}

# Syntactically fine, but its condition can never hold.
DEAD_RULE = {
    "name": "sandbox-dead",
    "salience": 100,
    "when": [
        {
            "template": "source",
            "conditions": [
                {"slot": "classification", "bind": "?cls"},
                {"test": '(eq ?cls "no-such-classification")'},
            ],
        },
    ],
    "then": {"action": "route", "reason": "never fires"},
}


class TestSandboxReplay:
    def test_ac_35_7_a_replay_returns_sandbox_result(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        result = sandbox_replay(DEAD_RULE, log, replay_n=10, min_entries=1)
        assert isinstance(result, SandboxResult)
        assert result.replayed_n_actual == 5

    def test_ac_35_7_c_regression_raises(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        with pytest.raises(SandboxRegressionError) as exc:
            sandbox_replay(DENY_ALL_PII, log, replay_n=10, min_entries=1)
        assert exc.value.result is not None
        assert exc.value.result.regressions == 5, (
            "regression count must reflect the whole replay, not the first hit; "
            f"got {exc.value.result.regressions}"
        )

    def test_relaxation_is_observable(self, tmp_path: Path) -> None:
        """A rule that grants new access is counted, and does not raise.

        Relaxations were structurally impossible before: the heuristic could
        only move a decision from allowed to denied, so this counter was always
        zero no matter what the rule did.
        """
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        result = sandbox_replay(ROUTE_VULN_DB, log, replay_n=10, min_entries=1)
        assert result.relaxations == 5
        assert result.regressions == 0

    def test_dead_rule_never_fires(self, tmp_path: Path) -> None:
        """fired == 0 for a rule whose condition cannot hold.

        The heuristic reported a non-empty-LHS rule as firing whenever the
        entry carried the named slots, so a dead rule scored as fully live.
        """
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        assert sandbox_replay(DEAD_RULE, log, replay_n=10, min_entries=1).fired == 0

    def test_firing_rule_fires_on_every_matching_request(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        result = sandbox_replay(ROUTE_VULN_DB, log, replay_n=10, min_entries=1)
        assert result.fired == 5

    def test_ac_35_7_f_insufficient_history_flag_set(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        result = sandbox_replay(DEAD_RULE, log, replay_n=1000, min_entries=100)
        assert result.insufficient_history is True

    def test_uncompilable_rule_is_rejected(self, tmp_path: Path) -> None:
        """A rule the engine rejects must not report a clean sandbox record.

        The old ``lhs``/``rhs`` proposal shape lands here: it is not a schema
        the compiler accepts, and previously it was scored as an
        unconditionally-firing rule instead of being refused.
        """
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        with pytest.raises(SandboxRuleError):
            sandbox_replay(
                {"name": "legacy", "lhs": [], "rhs": [{"deny": True}]},
                log,
                replay_n=10,
                min_entries=1,
            )


class TestUnreplayableEntries:
    """Entries that cannot be replayed are reported, not silently scored."""

    def test_entries_without_input_facts_are_skipped_and_counted(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 5)
        # Strip input_facts from every line, as a pre-input_facts log would be.
        stripped = []
        for line in log.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            payload = json.loads(record["metadata"]["nautilus_audit_entry"])
            payload.pop("input_facts", None)
            record["metadata"]["nautilus_audit_entry"] = json.dumps(payload)
            stripped.append(json.dumps(record))
        log.write_text("\n".join(stripped) + "\n", encoding="utf-8")

        result = sandbox_replay(DENY_ALL_PII, log, replay_n=10, min_entries=1)
        assert result.skipped_no_input_facts == 5
        assert result.replayed_n_actual == 0
        assert result.regressions == 0, (
            "a log with nothing replayable must not report a clean regression "
            "record as if it had been checked"
        )

    def test_drifted_entries_are_not_attributed_to_the_proposal(self, tmp_path: Path) -> None:
        """An entry whose recorded outcome the baseline cannot reproduce is skipped.

        Otherwise a change in the production rules since the entry was written
        would be charged to the proposed rule.
        """
        log = tmp_path / "audit.jsonl"
        _write_audit_log(log, 3)
        rewritten = []
        for line in log.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            payload = json.loads(record["metadata"]["nautilus_audit_entry"])
            payload["routing_decisions"] = [
                {"source_id": "ghost_db", "reason": "recorded under older rules"}
            ]
            record["metadata"]["nautilus_audit_entry"] = json.dumps(payload)
            rewritten.append(json.dumps(record))
        log.write_text("\n".join(rewritten) + "\n", encoding="utf-8")

        result = sandbox_replay(DENY_ALL_PII, log, replay_n=10, min_entries=1)
        assert result.skipped_drifted == 3
        assert result.replayed_n_actual == 0


def test_ac_35_7_e_replay_completes_within_budget(tmp_path: Path) -> None:
    """AC-35.7.e: N=1000 under 60s. Two engine evaluations per entry."""
    import time

    log = tmp_path / "audit.jsonl"
    _write_audit_log(log, 1000)
    start = time.monotonic()
    result = sandbox_replay(DEAD_RULE, log, replay_n=1000, min_entries=100)
    elapsed = time.monotonic() - start
    assert result.replayed_n_actual == 1000
    assert elapsed < 60.0, f"replay of 1000 entries took {elapsed:.1f}s"
