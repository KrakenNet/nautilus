"""Drift guard: ``ScopeConstraint.operator`` Literal vs runtime allowlist (Task 3.14).

The Pydantic-level operator enforcement lives on
``ScopeConstraint.operator: Literal[...]`` in ``nautilus/core/models.py``
(design §6.1). The adapter layer re-enforces the same set at runtime via
``_OPERATOR_ALLOWLIST`` in ``nautilus/adapters/base.py`` so that any code path
that skips Pydantic validation (e.g. constraints assembled by a Fathom rule
author at runtime) still fails closed.

Design §17 calls out the risk of these two sides drifting silently — one gets
a new operator while the other does not, and the new operator either bypasses
the Pydantic check or is rejected at the adapter without the model knowing.
This module pins both sides to the same set so a single-sided edit fails CI.
"""

from __future__ import annotations

from typing import get_args, get_type_hints

import pytest

from nautilus.adapters.base import _OPERATOR_ALLOWLIST  # pyright: ignore[reportPrivateUsage]
from nautilus.core.models import ScopeConstraint


def _literal_operators() -> frozenset[str]:
    """Extract operator strings from the ``Literal[...]`` annotation.

    ``get_type_hints`` resolves the annotation to the underlying
    ``typing.Literal`` object; ``get_args`` returns the tuple of literal
    values, which we normalise to a frozenset for set-equality comparison.
    """
    hints = get_type_hints(ScopeConstraint)
    return frozenset(get_args(hints["operator"]))


@pytest.mark.unit
def test_literal_and_runtime_allowlist_are_equal() -> None:
    """Both sides MUST contain exactly the same operator strings."""
    literal_ops = _literal_operators()
    runtime_ops = frozenset(_OPERATOR_ALLOWLIST)

    assert literal_ops == runtime_ops, (
        "Operator drift detected between "
        "ScopeConstraint.operator Literal and _OPERATOR_ALLOWLIST. "
        f"Only in Literal: {sorted(literal_ops - runtime_ops)}; "
        f"only in runtime allowlist: {sorted(runtime_ops - literal_ops)}."
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "operator",
    sorted(_OPERATOR_ALLOWLIST),
)
def test_every_runtime_operator_is_in_literal(operator: str) -> None:
    """Each runtime-allowlisted operator must also appear in the Literal."""
    assert operator in _literal_operators(), (
        f"Runtime allowlist contains '{operator}' but ScopeConstraint.operator Literal does not."
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "operator",
    sorted(_literal_operators()),
)
def test_every_literal_operator_is_in_runtime(operator: str) -> None:
    """Each Literal operator must also appear in the runtime allowlist."""
    assert operator in _OPERATOR_ALLOWLIST, (
        f"ScopeConstraint.operator Literal contains '{operator}' but _OPERATOR_ALLOWLIST does not."
    )
