"""Drift guard: ``AuditEntry.event_type`` Literal vs ``nautilus events list``.

Mirrors :mod:`tests.unit.test_operator_allowlist_drift`. Pairs the
Pydantic Literal at ``nautilus/core/models.py:218`` with the runtime
list returned by :func:`nautilus.cli.events.list_event_types`.
"""

from __future__ import annotations

from typing import get_args

import pytest

pytestmark = pytest.mark.unit


def _literal_event_types() -> set[str]:
    from nautilus.core.models import AuditEntry

    field = AuditEntry.model_fields["event_type"]
    args = get_args(field.annotation)
    # Args may be (Literal[...], NoneType) on optional fields.
    flat: set[str] = set()
    for arg in args:
        if arg is type(None):
            continue
        if hasattr(arg, "__args__"):
            for sub in arg.__args__:  # type: ignore[attr-defined]
                if isinstance(sub, str):
                    flat.add(sub)
        elif isinstance(arg, str):
            flat.add(arg)
    return flat


def test_event_type_literal_and_cli_enumeration_agree() -> None:
    from nautilus.cli.events import list_event_types

    cli_set = set(list_event_types())
    literal_set = _literal_event_types()
    assert cli_set == literal_set, (
        f"event_type drift: CLI={cli_set - literal_set} Literal={literal_set - cli_set}"
    )


def _sources() -> dict[str, str]:
    """Every shipped source file that could produce an event, by path."""
    from pathlib import Path

    import nautilus

    root = Path(nautilus.__file__).resolve().parent
    # The two files that *declare* the vocabulary cannot also be evidence
    # that something emits it.
    declarations = {root / "cli" / "events.py", root / "core" / "models.py"}
    paths = [
        p for pattern in ("*.py", "*.yaml") for p in root.rglob(pattern) if p not in declarations
    ]
    return {str(p): p.read_text(encoding="utf-8", errors="ignore") for p in paths}


# Declared event types that nothing in the shipped tree writes, each with the
# reason it is still declared. An entry leaves this set by gaining a producer,
# not by being deleted: the Literal is the audit vocabulary consumers match on.
NOT_YET_EMITTED = {
    # The curator meta-ruleset that would observe relationships is a stub
    # (`nautilus/rules/meta/pattern-tracker.yaml`, `rules: []`): its bodies
    # need negation CEs and slot `value:` pinning, which fathom-rules 0.5
    # still does not model. Re-enabling the ruleset is what gives this an
    # emitter.
    "relationship_observed",
    # `nautilus rkm` runs the validator pipeline and `nautilus rule
    # rollback` rewrites lineage, and neither takes a `--config`, so neither
    # has an audit sink to write to. Wiring one is the fix; until then these
    # three name lifecycle steps that happen without a record.
    "proposal_emitted",
    "proposal_validated",
    "proposal_promoted",
    "rule_rolled_back",
}


def test_every_declared_event_type_has_a_producer_or_a_documented_reason() -> None:
    from nautilus.cli.events import list_event_types

    texts = _sources().values()
    unproduced = {
        event
        for event in list_event_types()
        if not any(f'"{event}"' in t or f"'{event}'" in t for t in texts)
    }
    assert unproduced == NOT_YET_EMITTED, (
        "event_type producer drift: "
        f"newly unproduced={unproduced - NOT_YET_EMITTED} "
        f"now produced={NOT_YET_EMITTED - unproduced} (drop it from NOT_YET_EMITTED)"
    )
