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
        f"event_type drift: CLI={cli_set - literal_set} "
        f"Literal={literal_set - cli_set}"
    )
