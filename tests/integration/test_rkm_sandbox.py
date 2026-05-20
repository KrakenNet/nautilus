"""Integration: sandbox audit-log replay harness (#35.7)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nautilus.rkm.validator.sandbox import (
    SandboxRegressionError,
    SandboxResult,
    sandbox_replay,
)

pytestmark = pytest.mark.integration


def test_ac_35_7_a_replay_returns_sandbox_result(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("")
    rule = {"name": "noop", "module": "suggestions", "lhs": [], "rhs": []}
    result = sandbox_replay(rule, audit_log, replay_n=10, min_entries=1)
    assert isinstance(result, SandboxResult)


def test_ac_35_7_c_regression_raises(tmp_path: Path) -> None:
    """A rule that denies a previously-allowed request must reject."""
    audit_log = tmp_path / "audit.jsonl"
    # Seed the audit log with one previously-allowed request.
    audit_log.write_text('{"event_type":"request","allowed":true}\n')
    regressive_rule = {
        "name": "deny_all",
        "module": "suggestions",
        "lhs": [],
        "rhs": [{"deny": True}],
    }
    with pytest.raises(SandboxRegressionError):
        sandbox_replay(regressive_rule, audit_log, replay_n=1, min_entries=1)


def test_ac_35_7_f_insufficient_history_flag_set(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("")
    rule = {"name": "noop", "module": "suggestions", "lhs": [], "rhs": []}
    result = sandbox_replay(rule, audit_log, replay_n=1000, min_entries=100)
    assert result.insufficient_history is True
