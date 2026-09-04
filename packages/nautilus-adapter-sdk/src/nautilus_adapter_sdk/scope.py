"""Scope validation helpers for adapter implementations."""

from __future__ import annotations

from typing import Any

from nautilus_adapter_sdk.exceptions import ScopeEnforcementError

# The operators the broker actually sends, i.e. the ``operator`` Literal on
# ``nautilus.core.models.ScopeConstraint``. A separate symbolic vocabulary
# ("eq", "not_in", …) meant an adapter that validated against this set
# rejected every constraint it was ever handed.
VALID_OPERATORS: set[str] = {
    "=",
    "!=",
    "IN",
    "NOT IN",
    "<",
    ">",
    "<=",
    ">=",
    "LIKE",
    "BETWEEN",
    "IS NULL",
}


def validate_operator(operator: str) -> None:
    """Validate that *operator* is a recognised scope operator.

    Raises:
        ScopeEnforcementError: If *operator* is not in the allowed set.
    """
    if operator not in VALID_OPERATORS:
        raise ScopeEnforcementError(
            f"Invalid operator '{operator}'. Must be one of: {', '.join(sorted(VALID_OPERATORS))}"
        )


def validate_field(field: str, allowed_fields: set[str]) -> None:
    """Validate that *field* is in the *allowed_fields* set.

    Raises:
        ScopeEnforcementError: If *field* is not allowed.
    """
    if field not in allowed_fields:
        raise ScopeEnforcementError(
            f"Field '{field}' is not allowed. Must be one of: {', '.join(sorted(allowed_fields))}"
        )


def render_field(field: str, operator: str, value: Any) -> str:
    """Render a human-readable scope constraint string.

    Returns a string like ``"field eq 'value'"``.
    """
    return f"{field} {operator} '{value}'"
