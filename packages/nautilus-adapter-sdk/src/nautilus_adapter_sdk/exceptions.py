"""Adapter SDK exception hierarchy."""


class AdapterError(Exception):
    """Base exception for all adapter errors."""


class ScopeEnforcementError(AdapterError):
    """Raised when a scope constraint is violated."""
