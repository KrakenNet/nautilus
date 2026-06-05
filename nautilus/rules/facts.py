"""Manual relationship-fact loader for the RKM substrate (#35.2.b, #35.2.e).

Reads ``*.yaml`` files under a ``facts/relationships/`` directory, validates
each entry, and either returns them as plain dicts (standalone) or asserts
them into a Fathom broker environment (broker integration path).

Valid ``relationship_type`` values:
    sequential, co-located, complementary, alternative, overlaps

``confidence`` and ``strength`` must be floats in [0.0, 1.0].
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

VALID_RELATIONSHIP_TYPES: frozenset[str] = frozenset(
    ["sequential", "co-located", "complementary", "alternative", "overlaps"]
)


def load_relationship_facts(facts_dir: Path) -> list[dict[str, Any]]:
    """Read and validate relationship YAML files; return a flat list of fact dicts.

    Each YAML file may contain a top-level ``source_relationship`` key mapping
    to a list of relationship entries.  Entries are validated for:

    - ``relationship_type`` must be one of :data:`VALID_RELATIONSHIP_TYPES`.
    - ``confidence`` (if present) must be a float in ``[0.0, 1.0]``.
    - ``strength`` (if present) must be a float in ``[0.0, 1.0]``.

    On validation failure a :class:`ValueError` is raised with a structured
    ``path:line`` style message.

    Returns a list of validated fact dicts (one per relationship entry).
    """
    facts: list[dict[str, Any]] = []
    for yaml_file in sorted(facts_dir.glob("*.yaml")):
        content = yaml_file.read_text(encoding="utf-8")
        try:
            doc: Any = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValueError(f"{yaml_file}:1: YAML parse error: {exc}") from exc
        if doc is None:
            continue
        relationships: list[Any] = doc.get("source_relationship") or []
        for idx, entry in enumerate(relationships):
            _validate_relationship_entry(entry, yaml_file, idx)
            facts.append(dict(entry))
    return facts


def _validate_relationship_entry(entry: Any, path: Path, idx: int) -> None:
    """Validate a single relationship entry dict; raise ValueError on failure."""
    # Approximate line number from index (1-based, account for YAML list header)
    approx_line = idx + 2

    rel_type: Any = entry.get("relationship_type")
    if rel_type not in VALID_RELATIONSHIP_TYPES:
        valid = ", ".join(sorted(VALID_RELATIONSHIP_TYPES))
        raise ValueError(
            f"{path}:{approx_line}: invalid relationship_type={rel_type!r}; "
            f"must be one of [{valid}]"
        )

    for float_slot in ("confidence", "strength"):
        value: Any = entry.get(float_slot)
        if value is None:
            continue
        try:
            fval = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"{path}:{approx_line}: {float_slot} must be a float, got {value!r}"
            ) from exc
        if not (0.0 <= fval <= 1.0):
            raise ValueError(f"{path}:{approx_line}: {float_slot}={fval} out of range [0.0, 1.0]")


def load_manual_relationships(broker_env: Any, facts_dir: Path) -> int:
    """Load relationship facts from ``facts_dir`` and assert into ``broker_env``.

    ``broker_env`` is expected to be a ``fathom.Engine`` instance exposing
    ``assert_fact(template_name, slots_dict)``.  Each validated relationship
    entry is asserted as a ``source_relationship`` fact.

    Returns the count of facts asserted.  Raises :class:`ValueError` on
    validation failure (see :func:`load_relationship_facts`).
    """
    facts = load_relationship_facts(facts_dir)
    for fact in facts:
        broker_env.assert_fact("source_relationship", fact)
    return len(facts)
