"""Static analysis validator (#35.5) — runs the rule through the compiler.

Performance budget: <500ms per rule (AC-35.5.c). Errors carry
file:line:col + optional remediation ``hint`` (AC-35.5.d).

This gate used to check YAML shape, template names and duplicate names and
stop there, so a rule using condition keys the compiler forbids was reported
``OK`` and then refused to let the broker start. It now parses and compiles
every rule with the same ``fathom.compiler.Compiler`` the engine uses, and
additionally checks the ``then`` block's asserts — template name and required
slots — which compile cleanly and raise ``ConsistencyError`` on the first
matching request.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

import yaml
from fathom.compiler import CompilationError, Compiler
from fathom.models import RuleDefinition, TemplateDefinition

from nautilus.rkm.types import ValidationError
from nautilus.rules import BUILT_IN_RULES_DIR


@lru_cache(maxsize=1)
def _template_registry() -> dict[str, TemplateDefinition]:
    """Templates shipped with Nautilus, keyed by name.

    Read from ``nautilus/rules/templates/`` rather than hardcoded, so a
    template added to the YAML is known to the validator on the same commit.
    """
    compiler = Compiler()
    registry: dict[str, TemplateDefinition] = {}
    for path in sorted((BUILT_IN_RULES_DIR / "templates").glob("*.yaml")):
        for template in compiler.parse_template_file(path):
            registry[template.name] = template
    return registry


def _known_templates() -> frozenset[str]:
    return frozenset(_template_registry())


@dataclass(frozen=True)
class StaticResult:
    """Static-analysis result tuple (AC-35.5.a)."""

    ok: bool
    errors: tuple[ValidationError, ...]


def validate_static(rule_yaml_path: Path) -> StaticResult:
    """Run static analysis on a single rule YAML. AC-35.5.a–d.

    Detects (AC-35.5.b):
    - YAML parse errors
    - Missing ``rules`` / ``module`` top-level keys per rule
    - Unknown template references in ``lhs`` patterns
    - Duplicate rule names within the file

    Returns a :class:`StaticResult` with ``ok=True`` and empty ``errors``
    on success, or ``ok=False`` with populated ``errors`` on failure.
    """
    file_str = str(rule_yaml_path)
    errors: list[ValidationError] = []

    try:
        text = rule_yaml_path.read_text(encoding="utf-8")
    except OSError as exc:
        return StaticResult(
            ok=False,
            errors=(
                ValidationError(
                    file=file_str,
                    line=1,
                    col=1,
                    message=f"Cannot read file: {exc}",
                    hint="Check that the file path is correct and readable.",
                ),
            ),
        )

    # Parse YAML and capture a node tree for line-number extraction.
    try:
        loader = yaml.SafeLoader(text)
        root_node = loader.get_single_node()
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        line = 1
        col = 1
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            line = int(mark.line) + 1
            col = int(mark.column) + 1
        return StaticResult(
            ok=False,
            errors=(
                ValidationError(
                    file=file_str,
                    line=line,
                    col=col,
                    message=f"YAML parse error: {exc}",
                    hint="Verify the file is valid YAML.",
                ),
            ),
        )

    if not isinstance(data, dict) or "rules" not in data:
        return StaticResult(
            ok=False,
            errors=(
                ValidationError(
                    file=file_str,
                    line=1,
                    col=1,
                    message="Missing top-level 'rules' key.",
                    hint="The rule YAML must have a top-level 'rules' list.",
                ),
            ),
        )

    data_dict = cast("dict[str, Any]", data)
    rules_raw: Any = data_dict["rules"]
    if not isinstance(rules_raw, list):
        return StaticResult(
            ok=False,
            errors=(
                ValidationError(
                    file=file_str,
                    line=1,
                    col=1,
                    message="'rules' must be a list.",
                    hint="Provide 'rules' as a YAML sequence.",
                ),
            ),
        )
    rules = cast("list[Any]", rules_raw)

    # Build a node-lookup helper for line numbers.
    _node_lookup = _NodeLookup(root_node)

    seen_names: set[str] = set()

    for rule_idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            line = _node_lookup.rule_line(rule_idx)
            errors.append(
                ValidationError(
                    file=file_str,
                    line=line,
                    col=1,
                    message=f"Rule at index {rule_idx} is not a mapping.",
                    hint="Each rule must be a YAML mapping with 'name', 'module', 'lhs', 'rhs'.",
                )
            )
            continue

        rule_dict = cast("dict[str, Any]", rule)
        rule_name: str = str(rule_dict.get("name", f"<unnamed-{rule_idx}>"))
        name_line = _node_lookup.rule_field_line(rule_idx, "name")

        # Duplicate rule name check (AC-35.5.b).
        if rule_name in seen_names:
            errors.append(
                ValidationError(
                    file=file_str,
                    line=name_line,
                    col=1,
                    message=f"Duplicate rule name '{rule_name}'.",
                    hint="Rule names must be unique within a module.",
                )
            )
        seen_names.add(rule_name)

        # Unknown template references in the rule's LHS (AC-35.5.b).
        # Product rules author patterns under ``when:``; ``lhs:`` is accepted
        # for the older proposal shape. Reading only ``lhs`` meant this check
        # never inspected a real rule — an unknown template in a ``when:``
        # pattern passed static validation and failed later in the compiler.
        lhs: Any = rule_dict.get("lhs") or rule_dict.get("when") or []
        if isinstance(lhs, list):
            lhs_list = cast("list[Any]", lhs)
            for pattern_idx, pattern in enumerate(lhs_list):
                if not isinstance(pattern, dict):
                    continue
                pattern_dict = cast("dict[str, Any]", pattern)
                tmpl: Any = pattern_dict.get("template")
                if tmpl is not None and tmpl not in _known_templates():
                    tmpl_line = _node_lookup.lhs_template_line(rule_idx, pattern_idx)
                    errors.append(
                        ValidationError(
                            file=file_str,
                            line=tmpl_line,
                            col=1,
                            message=(f"Unknown template '{tmpl}' in rule '{rule_name}'."),
                            hint=(
                                f"Known templates: "
                                f"{', '.join(sorted(_known_templates()))}. "
                                "Register custom templates before referencing them."
                            ),
                        )
                    )

    if errors:
        return StaticResult(ok=False, errors=tuple(errors))

    # Compile. Everything above inspects the YAML's shape; only the compiler
    # knows whether the rule the engine will be handed is a rule at all.
    errors.extend(_compile_errors(rule_yaml_path, file_str, _node_lookup, rules))

    if errors:
        return StaticResult(ok=False, errors=tuple(errors))
    return StaticResult(ok=True, errors=())


def _compile_errors(
    rule_yaml_path: Path,
    file_str: str,
    node_lookup: _NodeLookup,
    rules: list[Any],
) -> list[ValidationError]:
    """Parse and compile the ruleset, plus check every ``then`` assert."""
    compiler = Compiler()
    try:
        ruleset = compiler.parse_rule_file(rule_yaml_path)
    except CompilationError as exc:
        detail = getattr(exc, "__cause__", None)
        return [
            ValidationError(
                file=file_str,
                line=1,
                col=1,
                message=f"Rule file does not compile: {exc}{f' — {detail}' if detail else ''}",
                hint=(
                    "Each 'when' condition takes slot + one of expression/bind/test. "
                    "'operator:'/'value:' are not condition keys."
                ),
            )
        ]

    templates = _template_registry()
    errors: list[ValidationError] = []
    for rule_idx, defn in enumerate(ruleset.rules):
        line = node_lookup.rule_field_line(rule_idx, "name") if rule_idx < len(rules) else 1
        try:
            compiler.compile_rule(defn, ruleset.module, templates)
        except CompilationError as exc:
            errors.append(
                ValidationError(
                    file=file_str,
                    line=line,
                    col=1,
                    message=f"Rule '{defn.name}' does not compile: {exc}",
                    hint="Check the condition operators and the 'then' action.",
                )
            )
            continue
        errors.extend(_assert_errors(defn, templates, file_str, line))
    return errors


def _assert_errors(
    defn: RuleDefinition,
    templates: dict[str, TemplateDefinition],
    file_str: str,
    line: int,
) -> list[ValidationError]:
    """Check the templates and required slots the rule's RHS asserts.

    The compiler emits an assert for whatever slots the author listed; a
    missing required slot is only caught by the engine's consistency checks on
    the first request that makes the rule fire. ``denial_record.rule_name`` is
    the case that matters: omit it and the rule passes every documented gate,
    then raises ``ConsistencyError: denial_missing_linkage`` in production.
    """
    errors: list[ValidationError] = []
    for spec in defn.then.asserts:
        template = templates.get(spec.template)
        if template is None:
            errors.append(
                ValidationError(
                    file=file_str,
                    line=line,
                    col=1,
                    message=(f"Rule '{defn.name}' asserts unknown template '{spec.template}'."),
                    hint=f"Known templates: {', '.join(sorted(templates))}.",
                )
            )
            continue
        missing = sorted(
            slot.name for slot in template.slots if slot.required and slot.name not in spec.slots
        )
        if missing:
            errors.append(
                ValidationError(
                    file=file_str,
                    line=line,
                    col=1,
                    message=(
                        f"Rule '{defn.name}' asserts '{spec.template}' without required "
                        f"slot(s): {', '.join(missing)}."
                    ),
                    hint=(
                        "The rule loads and then raises a consistency error on the first "
                        "request that matches it. Add the slot to the 'then' assert."
                    ),
                )
            )
    return errors


# ---------------------------------------------------------------------------
# Internal helper — YAML node tree line extractor
# ---------------------------------------------------------------------------


class _NodeLookup:
    """Walks the YAML MappingNode tree to extract start-mark line numbers."""

    def __init__(self, root: yaml.Node | None) -> None:
        self._root = root

    def _rules_seq(self) -> list[yaml.Node] | None:
        if self._root is None or not isinstance(self._root, yaml.MappingNode):
            return None
        for k, v in self._root.value:
            if k.value == "rules" and isinstance(v, yaml.SequenceNode):
                return v.value  # type: ignore[return-value]
        return None

    def rule_line(self, rule_idx: int) -> int:
        seq = self._rules_seq()
        if seq and rule_idx < len(seq):
            return seq[rule_idx].start_mark.line + 1
        return 1

    def rule_field_line(self, rule_idx: int, field: str) -> int:
        seq = self._rules_seq()
        if not seq or rule_idx >= len(seq):
            return 1
        rule_node = seq[rule_idx]
        if not isinstance(rule_node, yaml.MappingNode):
            return rule_node.start_mark.line + 1
        for k, v in rule_node.value:
            if k.value == field:
                return v.start_mark.line + 1
        return rule_node.start_mark.line + 1

    def lhs_template_line(self, rule_idx: int, pattern_idx: int) -> int:
        seq = self._rules_seq()
        if not seq or rule_idx >= len(seq):
            return 1
        rule_node = seq[rule_idx]
        if not isinstance(rule_node, yaml.MappingNode):
            return 1
        # Find the LHS key ('when' on product rules, 'lhs' on proposals).
        for k, v in rule_node.value:
            if k.value in {"lhs", "when"} and isinstance(v, yaml.SequenceNode):
                lhs_items = v.value
                if pattern_idx < len(lhs_items):
                    pattern_node = lhs_items[pattern_idx]
                    if isinstance(pattern_node, yaml.MappingNode):
                        for pk, pv in pattern_node.value:
                            if pk.value == "template":
                                return pv.start_mark.line + 1
                    return pattern_node.start_mark.line + 1
        return 1


__all__ = ["StaticResult", "validate_static"]
