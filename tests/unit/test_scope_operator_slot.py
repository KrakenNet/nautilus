"""A rule can write a scope-constraint operator literally (UPSTREAM.md:224).

``scope_constraint.operator`` was declared ``type: symbol``. fathom's compiler
emits every literal slot value as a quoted CLIPS string (``Compiler.
_emit_slot_value``), so a symbol slot could only be filled by a CLIPS
expression: ``operator: "="`` failed the build with ``[CSTRNCHK1]`` and every
rule that wanted a scope constraint had to spell ``operator: '(sym-cat "=")'``.

The slot is now ``type: string`` with the operator allowlist attached, so the
engine enforces the same vocabulary :data:`ScopeOperator` pins in Python.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, get_args

import pytest
import yaml

from nautilus.config.models import SourceConfig
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import IntentAnalysis, ScopeOperator
from nautilus.rules import BUILT_IN_RULES_DIR

pytestmark = pytest.mark.unit

TEMPLATES = BUILT_IN_RULES_DIR / "templates" / "nautilus.yaml"

_RULE = """module: nautilus-routing
ruleset: operator-literal-probe
version: "1.0"
rules:
  - name: operator-literal-probe
    description: "Scope every source, writing the operator as a literal."
    salience: 140
    when:
      - template: source
        conditions:
          - slot: id
            bind: ?sid
    then:
      action: route
      reason: "probe"
      assert:
        - template: routing_decision
          slots: {{source_id: "?sid", reason: "probe"}}
        - template: scope_constraint
          slots:
            source_id: "?sid"
            field: "purpose"
            operator: "{operator}"
            value: "analytics"
"""


def _router(tmp_path: Path, operator: str) -> FathomRouter:
    (tmp_path / "probe.yaml").write_text(_RULE.format(operator=operator), encoding="utf-8")
    return FathomRouter(built_in_rules_dir=BUILT_IN_RULES_DIR, user_rules_dirs=[tmp_path])


def _source() -> SourceConfig:
    return SourceConfig(
        id="src",
        type="rest",
        description="d",
        classification="confidential",
        data_types=["pii"],
        allowed_purposes=["analytics"],
        connection="https://example.invalid",
    )


def _operator_slot() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(TEMPLATES.read_text(encoding="utf-8"))
    for template in document["templates"]:
        if template["name"] == "scope_constraint":
            for slot in template["slots"]:
                if slot["name"] == "operator":
                    return slot
    raise AssertionError("scope_constraint.operator is not declared")


class TestTheSlotDeclaration:
    def test_the_operator_slot_is_a_string(self) -> None:
        # A symbol slot cannot be written literally by any rule.
        assert _operator_slot()["type"] == "string"

    def test_the_engine_allowlist_matches_the_python_one(self) -> None:
        # Two vocabularies for one field is how the pair drifts apart.
        assert _operator_slot()["allowed_values"] == list(get_args(ScopeOperator))


class TestALiteralOperatorCompiles:
    @pytest.mark.parametrize("operator", list(get_args(ScopeOperator)))
    def test_every_allowed_operator_builds(self, operator: str, tmp_path: Path) -> None:
        _router(tmp_path, operator)

    def test_the_constraint_reaches_the_route_result(self, tmp_path: Path) -> None:
        result = _router(tmp_path, "=").route(
            agent_id="a1",
            context={"clearance": "secret", "purpose": "analytics"},
            intent=IntentAnalysis(raw_intent="r", data_types_needed=["pii"], entities=[]),
            sources=[_source()],
            session={},
        )
        constraints = result.scope_constraints["src"]
        assert [(c.field, c.operator, c.value) for c in constraints] == [
            ("purpose", "=", "analytics")
        ]

    def test_an_operator_outside_the_allowlist_is_refused_at_build(self, tmp_path: Path) -> None:
        # The engine is the last line: a rule author who invents an operator
        # the adapters cannot translate must not get a live rule.
        with pytest.raises(Exception, match="CSTRNCHK|allowed"):
            _router(tmp_path, "=~")
