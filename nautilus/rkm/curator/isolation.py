"""Parse-time curator-module isolation check (OQ2 resolution, AC-35.3.e).

Walks the RHS of every meta-rule in ``meta_rule_yaml`` and rejects if
any ``assert`` / ``modify`` / ``retract`` action targets a template
registered in the ``nautilus-routing`` module's template set. Fathom
doesn't expose runtime cross-module assertion hooks; parse-time is the
conservative, testable option. Wired into
:func:`nautilus.rkm.validator.static.validate_static` so violations
surface via ``nautilus rules validate``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

# Templates shipped by nautilus.yaml are owned by nautilus-routing.
# Compute once at import time from the canonical template file.
_NAUTILUS_TEMPLATES_FILE = Path(__file__).parents[2] / "rules" / "templates" / "nautilus.yaml"


def _routing_owned_templates() -> frozenset[str]:
    """Return template names owned by the nautilus-routing module."""
    raw = yaml.safe_load(_NAUTILUS_TEMPLATES_FILE.read_text())
    return frozenset(t["name"] for t in raw.get("templates", []))


class CuratorIsolationViolation(Exception):  # noqa: N818
    """Raised when a meta-rule asserts/modifies a routing-module template.

    ``location`` is ``file:line`` style.
    """

    def __init__(self, location: str, message: str) -> None:
        super().__init__(f"{location}: {message}")
        self.location: str = location


def assert_module_isolation(meta_rule_yaml: Path, module: str = "curator") -> None:  # noqa: ARG001
    """Raise :class:`CuratorIsolationViolation` on isolation breach. AC-35.3.e.

    Walks every rule RHS for ``assert`` / ``modify`` / ``retract`` actions
    that target a routing-owned template and raises on first violation.
    ``location`` is formatted as ``file:line`` (approximate — line numbers
    from yaml.safe_load are only available for mappings with a Loader that
    tracks marks; we use rule index as a proxy).
    """
    routing_templates = _routing_owned_templates()
    raw: Any = yaml.safe_load(meta_rule_yaml.read_text())
    raw_dict = cast("dict[str, Any]", raw) if isinstance(raw, dict) else {}
    rules: list[Any] = raw_dict.get("rules", [])

    for rule_idx, rule in enumerate(rules):
        rule_dict = cast("dict[str, Any]", rule)
        rule_name: str = str(rule_dict.get("name", f"rule[{rule_idx}]"))
        rhs: Any = rule_dict.get("rhs", []) or rule_dict.get("then", {})

        # Normalise: ``rhs`` can be a list of action dicts OR a single dict.
        rhs_list: list[Any] = [rhs] if isinstance(rhs, dict) else rhs

        for action in rhs_list:
            if not isinstance(action, dict):
                continue
            action_dict = cast("dict[str, Any]", action)
            for op in ("assert", "modify", "retract"):
                target: Any = action_dict.get(op)
                if target is None:
                    continue
                template: str | None = None
                if isinstance(target, dict):
                    template = cast("dict[str, Any]", target).get("template")
                elif isinstance(target, str):
                    template = target
                if template and template in routing_templates:
                    location = f"{meta_rule_yaml}:{rule_name}"
                    raise CuratorIsolationViolation(
                        location,
                        f"rule {rule_name!r} targets routing-owned template {template!r}",
                    )


__all__ = ["CuratorIsolationViolation", "assert_module_isolation"]
