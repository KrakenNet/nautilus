"""Integration smoke test for the Nautilus Fathom rules tree (Task 1.12 SPIKE).

Purpose: prove that the YAML tree under ``nautilus/rules/`` loads into a
``fathom.Engine`` and that the two default rules
(``match-sources-by-data-type`` salience 100,
``deny-purpose-mismatch`` salience 200) fire end-to-end against realistic
fact inputs and populate the ``routing_decision`` / ``denial_record``
templates via the ``then.assert`` (fathom-rules >= 0.3.0) path.

The rules are now expressed as native YAML rule files under
``nautilus/rules/rules/``, using the fathom-rules 0.3.0 ``ConditionEntry.test``
escape hatch to invoke the ``overlaps`` and ``not-in-list`` Python externals
on the LHS. Because they are loaded via ``load_rules`` they appear in the
``Engine.rule_registry`` and (when fired with a ``then.action``) in
``EvaluationResult.rule_trace``.

Loading order (must not change — externals must be registered BEFORE
``load_functions`` / ``load_rules`` or CLIPS ``build`` errors with EXPRNPSR3):

  1. templates
  2. modules
  3. register_overlaps + register_not_in_list
  4. functions (no-op — directory holds no function YAMLs anymore)
  5. rules (loads routing.yaml + denial.yaml)
"""

from __future__ import annotations

import pytest
from fathom import Engine

from nautilus.rules import BUILT_IN_RULES_DIR
from nautilus.rules.functions import register_not_in_list, register_overlaps


def _load_nautilus_engine() -> Engine:
    """Construct a fresh Engine with Nautilus templates/module/rules loaded."""
    engine = Engine()
    engine.load_templates(str(BUILT_IN_RULES_DIR / "templates"))
    engine.load_modules(str(BUILT_IN_RULES_DIR / "modules"))
    # Externals MUST be registered before load_rules — the YAML rule LHS
    # references (overlaps ...) and (not-in-list ...) at build time.
    register_overlaps(engine)
    register_not_in_list(engine)
    engine.load_functions(str(BUILT_IN_RULES_DIR / "functions"))
    engine.load_rules(str(BUILT_IN_RULES_DIR / "rules"))
    return engine


@pytest.mark.integration
def test_engine_constructs_from_builtin_tree() -> None:
    """The Nautilus rules tree loads into a fathom.Engine without raising."""
    engine = _load_nautilus_engine()

    # All 7 design-§5.1 templates registered.
    expected_templates = {
        "agent",
        "intent",
        "source",
        "session",
        "routing_decision",
        "scope_constraint",
        "denial_record",
    }
    assert expected_templates <= set(engine.template_registry.keys())

    # nautilus-routing module registered (plus implicit MAIN).
    assert "nautilus-routing" in engine.module_registry

    # Both default rules registered via load_rules.
    assert {"match-sources-by-data-type", "deny-purpose-mismatch"} <= set(
        engine.rule_registry.keys()
    )


@pytest.mark.integration
def test_routing_rule_asserts_routing_decision_for_matching_sources() -> None:
    """``match-sources-by-data-type`` fires once per source whose data_types
    overlap the intent's data_types_needed, and only for those sources."""
    engine = _load_nautilus_engine()

    engine.assert_fact(
        "agent",
        {"id": "agent-1", "clearance": "secret", "purpose": "audit"},
    )
    engine.assert_fact(
        "intent",
        {
            "raw": "show me vulnerabilities",
            "data_types_needed": "vulnerability",
            "entities": "",
        },
    )
    # Matching source: data_types overlaps ("vulnerability").
    engine.assert_fact(
        "source",
        {
            "id": "vuln-db",
            "type": "postgres",
            "classification": "secret",
            "data_types": "vulnerability asset",
            "allowed_purposes": "audit research",
        },
    )
    # Non-matching source: data_types disjoint.
    engine.assert_fact(
        "source",
        {
            "id": "metrics-db",
            "type": "postgres",
            "classification": "secret",
            "data_types": "log metric",
            "allowed_purposes": "audit research",
        },
    )
    engine.assert_fact("session", {"id": "sess-1", "pii_sources_accessed": 0})

    result = engine.evaluate()

    routing = engine.query("routing_decision")
    assert len(routing) == 1, f"expected 1 routing_decision, got {routing!r}"
    assert routing[0]["source_id"] == "vuln-db"
    assert routing[0]["reason"] == "data_types overlap"

    # rule_trace surfaces the fired rule (module-qualified).
    assert "nautilus-routing::match-sources-by-data-type" in result.rule_trace


@pytest.mark.integration
def test_denial_rule_asserts_denial_record_on_purpose_mismatch() -> None:
    """``deny-purpose-mismatch`` fires only when a source's allowed_purposes
    is non-empty AND does not include the agent's purpose."""
    engine = _load_nautilus_engine()

    engine.assert_fact(
        "agent",
        {"id": "agent-2", "clearance": "secret", "purpose": "marketing"},
    )
    engine.assert_fact(
        "intent",
        {
            "raw": "show me pii",
            "data_types_needed": "pii",
            "entities": "",
        },
    )
    # Disallowed: agent.purpose=marketing is not in allowed_purposes.
    engine.assert_fact(
        "source",
        {
            "id": "pii-db",
            "type": "postgres",
            "classification": "secret",
            "data_types": "pii",
            "allowed_purposes": "audit research",
        },
    )
    # No restriction (allowed_purposes=""): denial MUST NOT fire.
    engine.assert_fact(
        "source",
        {
            "id": "open-db",
            "type": "postgres",
            "classification": "secret",
            "data_types": "pii",
            "allowed_purposes": "",
        },
    )
    engine.assert_fact("session", {"id": "sess-2", "pii_sources_accessed": 0})

    result = engine.evaluate()

    denials = engine.query("denial_record")
    assert len(denials) == 1, f"expected 1 denial_record, got {denials!r}"
    assert denials[0]["source_id"] == "pii-db"
    assert denials[0]["rule_name"] == "deny-purpose-mismatch"
    assert denials[0]["reason"] == "purpose not authorized"

    # rule_trace surfaces the fired denial rule (module-qualified).
    assert "nautilus-routing::deny-purpose-mismatch" in result.rule_trace
