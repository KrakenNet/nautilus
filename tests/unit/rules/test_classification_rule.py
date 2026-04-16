"""Unit tests for ``default-classification-deny`` (AC-1.1, AC-1.3).

The rule is defined in ``nautilus/rules/rules/classification.yaml`` at
salience 150 and fires when the requesting agent's clearance does NOT
dominate the source's classification under the ``classification``
hierarchy.

Three cases exercised:

- salience metadata check — the rule is registered at salience 150.
- positive fire — ``clearance=cui`` + ``classification=secret`` emits
  one ``denial_record`` with ``rule_name="default-classification-deny"``
  and the rule appears in the evaluation trace.
- negative control — ``clearance=secret`` + ``classification=cui`` does
  NOT fire the default-classification denial (reflexive/upwards dominance).

Engine construction mirrors the integration smoke test's load order
(templates → modules → externals → functions → rules); hierarchies are
resolved at ``load_functions`` time via ``classification_scope.yaml``.
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
    """Construct a fresh Engine with Nautilus templates/modules/rules loaded.

    Load order is load-bearing — externals MUST be registered BEFORE
    ``load_rules`` because rule LHS expressions reference ``fathom-dominates``
    (hierarchy-aware) and the ``overlaps`` / ``not-in-list`` / ``contains-all``
    functions at build time. See ``tests/integration/test_fathom_smoke.py``
    for the canonical order.
    """
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
def test_default_classification_deny_has_salience_150() -> None:
    """Rule metadata: salience 150 (AC-1.3).

    Sits between the routing rule (100) and the purpose-mismatch denial (200)
    so classification denials fire after the purpose guard but before routing
    decisions — design §3.1.
    """
    engine = _build_engine()
    rule = engine.rule_registry["default-classification-deny"]
    assert rule.salience == 150, f"expected salience 150, got {rule.salience!r}"


@pytest.mark.unit
def test_default_classification_deny_fires_when_clearance_below_classification() -> None:
    """Agent ``clearance=cui`` vs source ``classification=secret`` → fire (AC-1.1).

    ``cui`` is rank 1 and ``secret`` is rank 3 under the default classification
    hierarchy, so the agent's clearance does NOT dominate the source — the
    default-deny rule emits a ``denial_record`` and the trace surfaces the
    module-qualified rule name.
    """
    engine = _build_engine()
    engine.assert_fact(
        "agent",
        {"id": "a1", "clearance": "cui", "purpose": "audit", "compartments": ""},
    )
    engine.assert_fact(
        "source",
        {
            "id": "secret-db",
            "type": "postgres",
            "classification": "secret",
            "data_types": "pii",
            "allowed_purposes": "",
            "compartments": "",
        },
    )
    engine.assert_fact(
        "intent",
        {"raw": "show pii", "data_types_needed": "pii", "entities": ""},
    )
    engine.assert_fact("session", {"id": "s1", "pii_sources_accessed": 0})

    result = engine.evaluate()

    denials = engine.query("denial_record")
    classification_denials = [d for d in denials if d["rule_name"] == "default-classification-deny"]
    assert len(classification_denials) == 1, (
        f"expected 1 default-classification-deny record, got {denials!r}"
    )
    assert classification_denials[0]["source_id"] == "secret-db"
    assert "nautilus-routing::default-classification-deny" in result.rule_trace


@pytest.mark.unit
def test_default_classification_deny_does_not_fire_when_clearance_dominates() -> None:
    """Agent ``clearance=secret`` vs source ``classification=cui`` → no fire.

    Negative control: ``secret`` (rank 3) dominates ``cui`` (rank 1) under the
    default classification hierarchy, so the default-deny rule must stay
    silent. Guards against a regression where the rule fires spuriously when
    the hierarchy ordering is mis-wired.
    """
    engine = _build_engine()
    engine.assert_fact(
        "agent",
        {"id": "a2", "clearance": "secret", "purpose": "audit", "compartments": ""},
    )
    engine.assert_fact(
        "source",
        {
            "id": "cui-db",
            "type": "postgres",
            "classification": "cui",
            "data_types": "pii",
            "allowed_purposes": "",
            "compartments": "",
        },
    )
    engine.assert_fact(
        "intent",
        {"raw": "show pii", "data_types_needed": "pii", "entities": ""},
    )
    engine.assert_fact("session", {"id": "s2", "pii_sources_accessed": 0})

    result = engine.evaluate()

    denials = engine.query("denial_record")
    classification_denials = [d for d in denials if d["rule_name"] == "default-classification-deny"]
    assert classification_denials == [], (
        f"expected no default-classification-deny, got {classification_denials!r}"
    )
    assert "nautilus-routing::default-classification-deny" not in result.rule_trace
