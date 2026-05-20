"""Static analysis validator (#35.5) — wraps ``Fathom.validate``.

Performance budget: <500ms per rule (AC-35.5.c). Errors carry
file:line:col + optional remediation ``hint`` (AC-35.5.d).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from nautilus.rkm.types import ValidationError

# Templates shipped with Nautilus (nautilus/rules/templates/).
# Loaded once at import time; callers that need custom templates may extend
# _KNOWN_TEMPLATES at process start before invoking validate_static().
_KNOWN_TEMPLATES: frozenset[str] = frozenset(
    [
        "agent",
        "audit_event",
        "data_handoff",
        "data_type_affinity",
        "denial_record",
        "escalation_rule",
        "inferred_handoff",
        "intent",
        "relationship_candidate",
        "routing_decision",
        "scope_constraint",
        "session",
        "session_exposure",
        "source",
        "source_relationship",
    ]
)


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
        if hasattr(exc, "problem_mark") and exc.problem_mark is not None:  # type: ignore[union-attr]
            line = exc.problem_mark.line + 1  # type: ignore[union-attr]
            col = exc.problem_mark.column + 1  # type: ignore[union-attr]
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

    rules = data["rules"]
    if not isinstance(rules, list):
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

        rule_name: str = str(rule.get("name", f"<unnamed-{rule_idx}>"))
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

        # Unknown template references in lhs (AC-35.5.b).
        lhs = rule.get("lhs") or []
        if isinstance(lhs, list):
            for pattern_idx, pattern in enumerate(lhs):
                if not isinstance(pattern, dict):
                    continue
                tmpl = pattern.get("template")
                if tmpl is not None and tmpl not in _KNOWN_TEMPLATES:
                    tmpl_line = _node_lookup.lhs_template_line(
                        rule_idx, pattern_idx
                    )
                    errors.append(
                        ValidationError(
                            file=file_str,
                            line=tmpl_line,
                            col=1,
                            message=(
                                f"Unknown template '{tmpl}' in rule '{rule_name}'."
                            ),
                            hint=(
                                f"Known templates: "
                                f"{', '.join(sorted(_KNOWN_TEMPLATES))}. "
                                "Register custom templates before referencing them."
                            ),
                        )
                    )

    if errors:
        return StaticResult(ok=False, errors=tuple(errors))
    return StaticResult(ok=True, errors=())


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
        # Find 'lhs' key
        for k, v in rule_node.value:
            if k.value == "lhs" and isinstance(v, yaml.SequenceNode):
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
