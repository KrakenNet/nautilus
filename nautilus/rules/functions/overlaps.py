"""Python-backed CLIPS external functions for Nautilus routing rules.

Both externals operate on space-separated string multislots because the
Fathom YAML template layer does not yet expose CLIPS ``multislot`` slots
(see project-fathom rule-assertions research.md, UQ-5). The router encodes
``list[str]`` fields as space-separated strings before fact assertion and
these helpers decompose them on the rule side.

Registration uses ``Engine.register_function`` (fathom-rules >= 0.2.0), which
binds a Python callable as a CLIPS external invokable from rule LHS or RHS.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fathom import Engine


def _split(value: object) -> list[str]:
    """Split a CLIPS-supplied space-separated string into tokens."""
    return str(value).split()


def register_overlaps(engine: Engine) -> None:
    """Register ``overlaps(list_a, list_b) -> bool`` on *engine*.

    ``overlaps(a, b)`` returns ``TRUE`` iff the set of tokens in ``a``
    intersects the set of tokens in ``b``. Used by the
    ``match-sources-by-data-type`` rule to check whether a source's
    advertised ``data_types`` overlap the intent's ``data_types_needed``.

    Example (from a rule LHS):
        ``(test (overlaps ?needed ?have))``
    """

    def overlaps(a: object, b: object) -> bool:
        """Return ``True`` iff the token sets of ``a`` and ``b`` intersect."""
        return bool(set(_split(a)) & set(_split(b)))

    engine.register_function("overlaps", overlaps)


def register_not_in_list(engine: Engine) -> None:
    """Register ``not-in-list(item, list_str) -> bool`` on *engine*.

    Returns ``TRUE`` iff ``item`` is NOT a member of the space-separated
    tokens in ``list_str``. Used by the ``deny-purpose-mismatch`` rule to
    check whether an agent's purpose is absent from a source's
    ``allowed_purposes``.

    Example (from a rule LHS):
        ``(test (not-in-list ?purpose ?allowed))``
    """

    def not_in_list(item: object, list_str: object) -> bool:
        """Return ``True`` iff ``item`` is absent from ``list_str``'s tokens."""
        return str(item) not in _split(list_str)

    engine.register_function("not-in-list", not_in_list)
