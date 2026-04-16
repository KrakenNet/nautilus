"""Scope validation helpers for adapter implementations."""

from __future__ import annotations

from typing import Any

from nautilus_adapter_sdk.exceptions import ScopeEnforcementError

VALID_OPERATORS: set[str] = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "not_contains",
}


def validate_operator(operator: str) -> None:
    """Validate that *operator* is a recognised scope operator.

    Raises:
        ScopeEnforcementError: If *operator* is not in the allowed set.
    """
    if operator not in VALID_OPERATORS:
        raise ScopeEnforcementError(
            f"Invalid operator '{operator}'. "
            f"Must be one of: {', '.join(sorted(VALID_OPERATORS))}"
        )


def validate_field(field: str, allowed_fields: set[str]) -> None:
    """Validate that *field* is in the *allowed_fields* set.

    Raises:
        ScopeEnforcementError: If *field* is not allowed.
    """
    if field not in allowed_fields:
        raise ScopeEnforcementError(
            f"Field '{field}' is not allowed. "
            f"Must be one of: {', '.join(sorted(allowed_fields))}"
        )


def render_field(field: str, operator: str, value: Any) -> str:
    """Render a human-readable scope constraint string.

    Returns a string like ``"field eq 'value'"``.
    """
    return f"{field} {operator} '{value}'"
