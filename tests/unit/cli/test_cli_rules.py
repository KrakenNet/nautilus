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

# Real rules, in the schema the compiler accepts. These fixtures were
# previously written with ``lhs:``/``rhs:`` keys and empty ``slots: {}`` maps —
# a schema no Nautilus rule uses and the compiler rejects. They passed only
# because the sandbox and shadow heuristics read that same invented schema, so
# the tests and the code under test agreed with each other and with nothing else.

_FIXTURE_RULE = """\
module: nautilus-routing
ruleset: demo-scope
version: "1.0"
rules:
  - name: demo-scope-rule
    salience: 140
    when:
      - template: agent
        conditions:
          - slot: purpose
            bind: ?purpose
      - template: source
        conditions:
          - slot: id
            bind: ?sid
          - slot: classification
            bind: ?cls
          - test: '(eq ?cls "confidential")'
    then:
      action: route
      reason: "demo scope"
      assert:
        - template: scope_constraint
          slots:
            source_id: "?sid"
            field: "purpose"
            operator: '(sym-cat "=")'
            value: "?purpose"
"""

# Two rules constraining the same slots, the broader at higher salience.
_FIXTURE_SHADOWED = """\
module: nautilus-routing
ruleset: demo-shadowed
version: "1.0"
rules:
  - name: broad-rule
    salience: 20
    when:
      - template: agent
        conditions:
          - slot: purpose
            bind: ?purpose
    then:
      action: route
      reason: "broad"
  - name: narrow-rule
    salience: 10
    when:
      - template: agent
        conditions:
          - slot: purpose
            bind: ?purpose
    then:
      action: route
      reason: "narrow"
"""

# Denies every source the baseline routes.
_FIXTURE_DENY = """\
module: nautilus-routing
ruleset: demo-deny
version: "1.0"
rules:
  - name: deny-everything
    salience: 195
    when:
      - template: source
        conditions:
          - slot: id
            bind: ?sid
    then:
      action: deny
      reason: "deny everything"
      assert:
        - template: denial_record
          slots:
            source_id: "?sid"
            reason: "deny everything"
            rule_name: "deny-everything"
"""


def _write_audit_log(path: Path, n: int = 120) -> Path:
    """Write ``n`` real audit entries by routing real requests.

    The previous helper wrote ``{"allowed": true, "agent_id": ...}`` lines — a
    shape nothing in Nautilus emits or reads. Replay needs ``input_facts``, so
    these go through the router and the real audit logger.
    """
    from tests.integration.test_rkm_sandbox import (  # noqa: SLF001
        _write_audit_log as _real,  # pyright: ignore[reportPrivateUsage]
    )

    _real(path, n)
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
        """\
module: nautilus-routing
ruleset: bad
version: "1.0"
rules:
  - name: r1
    when:
      - template: not_a_template
        conditions: []
    then:
      action: route
      reason: r
""",
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


# ---------------------------------------------------------------------------
# Declared flags are honoured
# ---------------------------------------------------------------------------
#
# ``--sandbox``, ``--replay-n``, ``--json`` and ``--audit-log`` were declared on
# the ``rules validate`` parser and read by nothing: ``--sandbox`` ran no
# sandbox, ``--json`` printed human text. ``rules test`` used bare sandbox
# defaults, so ``rkm.sandbox.min_entries`` could not be honoured either.


def _validate_args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "cmd": "rules",
        "rules_subcommand": "validate",
        "file": "/definitely/not/here.yaml",
        "sandbox": False,
        "replay_n": 1000,
        "audit_log": None,
        "json": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_validate_json_flag_emits_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    rc = cli_rules.dispatch(_validate_args(file=str(rule_file), json=True))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True


def test_validate_sandbox_flag_runs_the_sandbox(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl", n=10)
    rc = cli_rules.dispatch(
        _validate_args(file=str(rule_file), sandbox=True, audit_log=str(audit_log), json=True)
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sandbox"], "--sandbox must produce a sandbox report"
    assert payload["sandbox"][0]["replayed"] == 10


def test_validate_sandbox_reports_a_regression(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rule_file = tmp_path / "deny.yaml"
    rule_file.write_text(_FIXTURE_DENY, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl", n=10)
    rc = cli_rules.dispatch(
        _validate_args(file=str(rule_file), sandbox=True, audit_log=str(audit_log))
    )
    assert rc == 1
    assert "Regression detected" in capsys.readouterr().err


def test_validate_replay_n_is_honoured(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--replay-n bounds the corpus; ignoring it would replay all 10."""
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl", n=10)
    rc = cli_rules.dispatch(
        _validate_args(
            file=str(rule_file),
            sandbox=True,
            audit_log=str(audit_log),
            replay_n=3,
            json=True,
        )
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["sandbox"][0]["replayed"] == 3


def test_test_min_entries_is_honoured(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--min-entries drives insufficient_history rather than the bare default."""
    rule_file = tmp_path / "rule.yaml"
    rule_file.write_text(_FIXTURE_RULE, encoding="utf-8")
    audit_log = _write_audit_log(tmp_path / "audit.jsonl", n=10)

    rc = cli_rules.dispatch(
        _test_args(file=str(rule_file), audit_log=str(audit_log), min_entries=5, replay_n=1000)
    )
    assert rc == 0
    assert "insufficient audit history" not in capsys.readouterr().err

    rc = cli_rules.dispatch(
        _test_args(file=str(rule_file), audit_log=str(audit_log), min_entries=50, replay_n=1000)
    )
    assert rc == 0
    assert "insufficient audit history" in capsys.readouterr().err
