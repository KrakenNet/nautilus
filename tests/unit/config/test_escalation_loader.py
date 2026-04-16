"""Unit tests for :mod:`nautilus.config.escalation` (Task 3.1).

Covers ``load_escalation_packs`` and :class:`EscalationRule` parsing
(FR-7, AC-3.2, design §3.4):

* (a) The built-in default pack (``nautilus/rules/escalation/``) parses
  into exactly one :class:`EscalationRule`.
* (b) Multiple YAML files under one directory are merged and ordering is
  deterministic (sorted by filename).
* (c) An invalid ``action`` value is rejected by pydantic at
  ``model_validate`` time, surfaced as :class:`pydantic.ValidationError`
  via the wrapper logic.
"""

from __future__ import annotations

from pathlib import Path

import pydantic
import pytest

import nautilus.rules.escalation as escalation_pkg
from nautilus.config.escalation import EscalationRule, load_escalation_packs

pytestmark = pytest.mark.unit


def test_default_pack_produces_single_escalation_rule() -> None:
    """(a) The shipped default pack yields exactly one rule (pii-aggregation)."""
    pack_dir = Path(escalation_pkg.__file__).resolve().parent
    assert pack_dir.is_dir(), f"default pack dir missing: {pack_dir}"

    rules = load_escalation_packs([pack_dir])

    assert len(rules) == 1
    (only,) = rules
    assert isinstance(only, EscalationRule)
    assert only.id == "pii-aggregation-confidential"
    assert only.action == "escalate"
    assert only.resulting_level == "confidential"
    # Trigger combination is the multislot-encoded space-separated string.
    assert set(only.trigger_combination.split()) == {"email", "phone", "dob", "ssn"}


def test_multiple_yaml_files_in_one_dir_load_and_merge(tmp_path: Path) -> None:
    """(b) Rules from every ``*.yaml`` in a dir are concatenated in sorted order."""
    first = tmp_path / "a_first.yaml"
    first.write_text(
        """\
- id: rule-one
  trigger_combination: "email phone"
  resulting_level: confidential
  action: notify
- id: rule-two
  trigger_combination: "ssn dob"
  resulting_level: confidential
  action: escalate
""",
        encoding="utf-8",
    )

    second = tmp_path / "b_second.yaml"
    second.write_text(
        """\
- id: rule-three
  trigger_combination: "ip_address user_agent"
  resulting_level: secret
  action: deny
""",
        encoding="utf-8",
    )

    # A non-yaml sibling must be ignored.
    (tmp_path / "README.md").write_text("ignore me", encoding="utf-8")

    rules = load_escalation_packs([tmp_path])

    assert [r.id for r in rules] == ["rule-one", "rule-two", "rule-three"]
    assert [r.action for r in rules] == ["notify", "escalate", "deny"]
    # Every entry is a fully-validated EscalationRule (not a raw dict).
    assert all(isinstance(r, EscalationRule) for r in rules)


def test_invalid_action_raises_pydantic_validation_error(tmp_path: Path) -> None:
    """(c) ``action`` must be one of {deny, escalate, notify}; anything else rejects."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        """\
- id: bogus-rule
  trigger_combination: "email"
  resulting_level: confidential
  action: launch_nuke
""",
        encoding="utf-8",
    )

    with pytest.raises(pydantic.ValidationError) as excinfo:
        load_escalation_packs([tmp_path])

    message = str(excinfo.value)
    # The offending value and the field name should both surface.
    assert "action" in message
    assert "launch_nuke" in message
