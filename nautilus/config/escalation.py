"""Escalation-pack YAML loader (design §3.4, FR-7).

Escalation packs are declarative lists of :class:`EscalationRule` loaded from
``nautilus/rules/escalation/*.yaml`` (the built-in default pack) plus any
operator-specified directories. Each YAML file is expected to contain a
top-level *list* of mappings; each mapping parses into one ``EscalationRule``.

The loader tolerates non-existent directories (returns ``[]`` for that dir) so
callers can pass a mix of present and absent paths without special-casing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, cast

import yaml
from pydantic import BaseModel


class EscalationRule(BaseModel):
    """One declarative escalation trigger (design §3.4).

    Fired by a rule that tests ``(contains-all trigger_combination
    session_data_types_seen)``. ``action`` selects the downstream effect:
    ``deny`` asserts a :class:`DenialRecord`, ``escalate`` raises the effective
    classification to ``resulting_level``, ``notify`` emits an audit notice.
    """

    id: str
    trigger_combination: str  # space-separated multislot encoding
    resulting_level: str
    action: Literal["deny", "escalate", "notify"]


def load_escalation_packs(dirs: list[Path]) -> list[EscalationRule]:
    """Load and concatenate escalation packs from every ``*.yaml`` under ``dirs``.

    Each YAML file must contain a top-level list of mappings. Missing
    directories are silently skipped. Rules are returned in directory order,
    then sorted-filename order within each directory (``Path.glob`` ordering is
    platform-dependent, so we sort to keep fact-assertion order deterministic).
    """
    rules: list[EscalationRule] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        for yaml_path in sorted(directory.glob("*.yaml")):
            raw_text = yaml_path.read_text(encoding="utf-8")
            raw: object = yaml.safe_load(raw_text)
            if raw is None:
                continue
            if not isinstance(raw, list):
                raise ValueError(
                    f"Escalation pack '{yaml_path}' must contain a top-level list, "
                    f"got {type(raw).__name__}"
                )
            for entry in cast(list[object], raw):
                if not isinstance(entry, dict):
                    raise ValueError(f"Each escalation entry in '{yaml_path}' must be a mapping")
                rules.append(EscalationRule.model_validate(cast(dict[str, Any], entry)))
    return rules


__all__ = ["EscalationRule", "load_escalation_packs"]
