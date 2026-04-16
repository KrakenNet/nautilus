"""Unit tests for ``information-flow-violation`` (AC-4.3).

Defined in ``nautilus/rules/rules/handoff.yaml`` at salience 250, the rule
fires on a ``data_handoff`` fact when the declaring (source) agent's
clearance dominates the handoff classification but the receiving agent's
clearance does NOT — i.e. the handoff would exfiltrate data above the
receiver's authorized level.

Two cases exercised:

- positive fire — ``from_clearance=secret`` dominates ``classification=
  confidential`` but ``to_clearance=cui`` does not → one ``denial_record``
  with ``rule_name="information-flow-violation"``.
- negative control — both clearances dominate the classification → no
  denial emitted.

Engine construction mirrors the Phase-1 integration smoke test's load order
so the hierarchy registry is populated before rule build.
"""

from __future__ import annotations

import pytest
from fathom import Engine

from nautilus.rules import BUILT_IN_RULES_DIR
from nautilus.rules.functions import (
    register_contains_all,
    register_not_in_list,
    register_overlaps,
)


def _build_engine() -> Engine:
    """Construct a fresh Engine with Nautilus templates/modules/rules loaded."""
    engine = Engine()
    engine.load_templates(str(BUILT_IN_RULES_DIR / "templates"))
    engine.load_modules(str(BUILT_IN_RULES_DIR / "modules"))
    register_overlaps(engine)
    register_not_in_list(engine)
    register_contains_all(engine)
    engine.load_functions(str(BUILT_IN_RULES_DIR / "functions"))
    engine.load_rules(str(BUILT_IN_RULES_DIR / "rules"))
    return engine


@pytest.mark.unit
def test_information_flow_violation_fires_when_receiver_cannot_dominate() -> None:
    """From-clearance dominates classification; to-clearance does not → fire (AC-4.3).

    ``secret`` (rank 3) dominates ``confidential`` (rank 2) — the source agent
    may hold the data. ``cui`` (rank 1) does NOT dominate ``confidential`` —
    so handing the data off to the receiver would be an information-flow
    violation. Expect one ``denial_record`` with source_id equal to the
    handoff's session identifier.
    """
    engine = _build_engine()
    engine.assert_fact(
        "data_handoff",
        {
            "from_agent": "alice",
            "to_agent": "bob",
            "session_id": "handoff-1",
            "classification": "confidential",
            "from_clearance": "secret",
            "to_clearance": "cui",
        },
    )

    result = engine.evaluate()

    denials = engine.query("denial_record")
    info_flow_denials = [d for d in denials if d["rule_name"] == "information-flow-violation"]
    assert len(info_flow_denials) == 1, f"expected 1 information-flow-violation, got {denials!r}"
    assert info_flow_denials[0]["source_id"] == "handoff-1"
    assert info_flow_denials[0]["reason"] == (
        "receiving agent clearance does not dominate declared classification"
    )
    assert "nautilus-routing::information-flow-violation" in result.rule_trace


@pytest.mark.unit
def test_information_flow_violation_does_not_fire_when_receiver_dominates() -> None:
    """Both clearances dominate the classification → no fire (negative control).

    Guards against a regression where the second ``(not (fathom-dominates ...))``
    clause is inverted or dropped — a handoff where every party holds
    sufficient clearance must NOT emit the violation.
    """
    engine = _build_engine()
    engine.assert_fact(
        "data_handoff",
        {
            "from_agent": "alice",
            "to_agent": "bob",
            "session_id": "handoff-2",
            "classification": "cui",
            "from_clearance": "secret",
            "to_clearance": "secret",
        },
    )

    result = engine.evaluate()

    denials = engine.query("denial_record")
    info_flow_denials = [d for d in denials if d["rule_name"] == "information-flow-violation"]
    assert info_flow_denials == [], (
        f"expected no information-flow-violation, got {info_flow_denials!r}"
    )
    assert "nautilus-routing::information-flow-violation" not in result.rule_trace
