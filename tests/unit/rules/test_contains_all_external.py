"""Unit tests for the ``contains-all`` Fathom external (AC-3.4).

The external is a Python callable registered on a ``fathom.Engine`` via
:func:`nautilus.rules.functions.contains_all.register_contains_all`. Because
the callable is a local closure inside the register function, we capture it
through a minimal stand-in engine that records ``register_function`` calls
and exercise the raw Python callable directly — no CLIPS round-trip needed
for set-containment semantics.

Four cases exercised per design §3.4:

- (a) empty subset ⊆ any superset → ``TRUE``.
- (b) full overlap → ``TRUE``.
- (c) partial overlap → ``FALSE``.
- (d) disjoint → ``FALSE``.

Inputs are the space-separated strings produced by
``nautilus.core.clips_encoding.encode_multislot``; the callable splits on
whitespace and uses set containment (order-independent).
"""

from __future__ import annotations

from typing import Any

import pytest

from nautilus.rules.functions.contains_all import register_contains_all


class _CapturingEngine:
    """Minimal ``Engine``-shaped stand-in that captures registered functions.

    Mirrors the one method ``register_contains_all`` uses on the engine so we
    can intercept the closure without constructing a real CLIPS environment.
    """

    def __init__(self) -> None:
        self.registered: dict[str, Any] = {}

    def register_function(self, name: str, fn: Any) -> None:
        self.registered[name] = fn


def _load_contains_all() -> Any:
    """Return the ``contains-all`` Python callable registered by the module."""
    engine = _CapturingEngine()
    register_contains_all(engine)  # pyright: ignore[reportArgumentType]
    return engine.registered["contains-all"]


@pytest.mark.unit
def test_contains_all_empty_subset_is_true() -> None:
    """Empty subset ⊆ any superset — vacuously TRUE (AC-3.4 case a)."""
    contains_all = _load_contains_all()
    assert contains_all("", "a b c") is True


@pytest.mark.unit
def test_contains_all_full_overlap_is_true() -> None:
    """Every subset token appears in the superset — TRUE (AC-3.4 case b).

    Order-independent: ``"a b"`` is contained in ``"b a c"`` because set
    semantics apply.
    """
    contains_all = _load_contains_all()
    assert contains_all("a b", "b a c") is True


@pytest.mark.unit
def test_contains_all_partial_overlap_is_false() -> None:
    """A subset token missing from superset — FALSE (AC-3.4 case c)."""
    contains_all = _load_contains_all()
    assert contains_all("a b c", "a b") is False


@pytest.mark.unit
def test_contains_all_disjoint_is_false() -> None:
    """No subset token appears in superset — FALSE (AC-3.4 case d)."""
    contains_all = _load_contains_all()
    assert contains_all("x y", "a b c") is False
