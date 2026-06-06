"""Unit tests for :mod:`nautilus.cli.rules` (#35.5 + #35.7 + #34)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from nautilus.cli import rules as cli_rules

pytestmark = pytest.mark.unit


def test_ac_35_5_a_add_subparser_registers_rules_group() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_rules.add_subparser(sub)
    args = parser.parse_args(["rules", "validate", "/tmp/no.yaml"])
    assert args.cmd == "rules"


def test_ac_35_5_a_validate_missing_file_exits_one() -> None:
    args = argparse.Namespace(
        cmd="rules",
        rules_subcommand="validate",
        file="/definitely/not/here.yaml",
        sandbox=False,
        replay_n=1000,
        json=False,
    )
    rc = cli_rules.dispatch(args)
    assert rc == 1


# ---------------------------------------------------------------------------
# rules test (#34)
# ---------------------------------------------------------------------------

_FIXTURE_RULE = """\
module: demo
rules:
  - name: demo-scope-rule
    salience: 10
    lhs:
      - template: agent
        conditions:
          - slot: agent_id
"""

_FIXTURE_SHADOWED = """\
module: demo
rules:
  - name: broad-rule
    salience: 20
    lhs:
      - template: agent
        slots: {}
  - name: narrow-rule
    salience: 10
    lhs:
      - template: agent
        slots: {}
"""

_FIXTURE_DENY = """\
module: demo
rules:
  - name: deny-everything
    lhs: []
    rhs:
      - action: deny
"""


def _write_audit_log(path: Path, n: int = 120) -> Path:
    """Write n allowed audit entries carrying an agent_id slot."""
    lines = [json.dumps({"allowed": True, "agent_id": f"agent-{i}"}) for i in range(n)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _test_args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "cmd": "rules",
        "rules_subcommand": "test",
        "file": "/definitely/not/here.yaml",
        "audit_log": None,
        "threshold": 0.6,
        "json": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_ac_34_parser_accepts_test_subcommand() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    cli_rules.add_subparser(sub)
    args = parser.parse_args(
        ["rules", "test", "--file", "/tmp/no.yaml", "--audit-log", "/tmp/a.jsonl"]
    )
    assert args.rules_subcommand == "test"
    assert args.threshold == 0.6
    assert args.audit_log == "/tmp/a.jsonl"


def test_ac_34_missing_file_exits_one(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli_rules.dispatch(_test_args())
    assert rc == 1
    assert "ERROR" in capsys.readouterr().err


def test_ac_34_missing_audit_log_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    rc = cli_rules.dispatch(_test_args(file=str(rule_file), audit_log="/definitely/not/a.jsonl"))
    assert rc == 1
    assert "audit log not found" in capsys.readouterr().err


def test_ac_34_static_failure_exits_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text(
        "module: demo\nrules:\n  - name: r1\n    lhs:\n      - template: not_a_template\n",
        encoding="utf-8",
    )
    rc = cli_rules.dispatch(_test_args(file=str(rule_file)))
    assert rc == 1
    assert "Unknown template" in capsys.readouterr().err


def test_ac_34_pass_with_audit_log(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl")
    rc = cli_rules.dispatch(_test_args(file=str(rule_file), audit_log=str(audit_log)))
    captured = capsys.readouterr()
    assert rc == 0
    assert "OK:" in captured.out
    assert "score=1.00" in captured.out


def test_ac_34_no_audit_log_warns_insufficient_history(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    rc = cli_rules.dispatch(_test_args(file=str(rule_file)))
    captured = capsys.readouterr()
    # Fire-rate penalty only (-0.1) -> 0.9 >= default threshold.
    assert rc == 0
    assert "insufficient audit history" in captured.err


def test_ac_34_below_threshold_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule_file = tmp_path / "shadowed.yaml"
    rule_file.write_text(_FIXTURE_SHADOWED, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl")
    rc = cli_rules.dispatch(
        _test_args(file=str(rule_file), audit_log=str(audit_log), threshold=0.95)
    )
    captured = capsys.readouterr()
    assert rc == 2
    assert "shadow finding" in captured.err
    assert "below threshold" in captured.err


def test_ac_34_sandbox_regression_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule_file = tmp_path / "deny.yaml"
    rule_file.write_text(_FIXTURE_DENY, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl")
    rc = cli_rules.dispatch(_test_args(file=str(rule_file), audit_log=str(audit_log)))
    captured = capsys.readouterr()
    assert rc == 1
    assert "Regression detected" in captured.err


def test_ac_34_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl")
    rc = cli_rules.dispatch(_test_args(file=str(rule_file), audit_log=str(audit_log), json=True))
    captured = capsys.readouterr()
    assert rc == 0
    payload = json.loads(captured.out)
    assert payload["passed"] is True
    assert payload["score"] == 1.0
    assert payload["threshold"] == 0.6
    assert payload["rules"][0]["name"] == "demo-scope-rule"
    assert payload["rules"][0]["sandbox"]["replayed_n_actual"] == 120
    assert payload["rules"][0]["sandbox"]["fired"] == 120
    assert payload["rules"][0]["shadow_flags"] == []
