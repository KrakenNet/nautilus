"""Nautilus Adapter SDK — public API.

Re-exports all public types, protocols, configuration models, scope
helpers, and exceptions so consumers can import directly from
``nautilus_adapter_sdk``.
"""

__version__ = "0.1.0"

from .config import SourceConfig
from .exceptions import AdapterError, ScopeEnforcementError
from .protocols import Adapter, Embedder
from .scope import render_field, validate_field, validate_operator
from .types import (
    AdapterResult,
    AuthConfig,
    EndpointSpec,
    ErrorRecord,
    IntentAnalysis,
    ScopeConstraint,
)

__all__ = [
    "Adapter",
    "AdapterError",
    "AdapterResult",
    "AuthConfig",
    "Embedder",
    "EndpointSpec",
    "ErrorRecord",
    "IntentAnalysis",
    "ScopeConstraint",
    "ScopeEnforcementError",
    "SourceConfig",
    "render_field",
    "validate_field",
    "validate_operator",
]
