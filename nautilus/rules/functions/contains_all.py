"""``contains-all`` CLIPS external for escalation trigger matching.

Mirrors ``overlaps`` / ``not-in-list`` (see :mod:`nautilus.rules.functions.overlaps`)
— a Python callable registered via ``Engine.register_function`` so the YAML
rule LHS can invoke ``(contains-all ?trigger-combination ?session-types)``.

Both arguments are CLIPS space-separated strings (Nautilus encodes multislot
values with :func:`nautilus.core.clips_encoding.encode_multislot`). The
external returns ``TRUE`` iff every token in the *first* argument appears in
the *second* (order-independent, set semantics).

Edge cases (design §3.4, AC-3.4):

- ``contains-all([], [x])`` → ``TRUE`` (empty first is contained in any second).
- ``contains-all([a], [])`` → ``FALSE`` (non-empty first cannot be contained in empty second).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fathom import Engine


def _split(value: object) -> list[str]:
    """Split a CLIPS-supplied space-separated string into tokens."""
    return str(value).split()


def register_contains_all(engine: Engine) -> None:
    """Register ``contains-all(sub_set, super_set) -> bool`` on *engine*.

    ``contains-all(a, b)`` returns ``TRUE`` iff every token in ``a`` appears in
    ``b`` (set containment, order-independent). Used by the PII-aggregation
    escalation rule (design §3.4) to check whether the session's accumulated
    ``data_types_seen`` covers an ``escalation_rule``'s ``trigger_combination``.

    Example (from a rule LHS)::

        (test (contains-all ?trigger ?seen))
    """

    def contains_all(sub_set: object, super_set: object) -> bool:
        """Return ``True`` iff every token of ``sub_set`` appears in ``super_set``."""
        return set(_split(sub_set)).issubset(set(_split(super_set)))

    engine.register_function("contains-all", contains_all)
