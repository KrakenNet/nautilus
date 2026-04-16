"""Adapter SDK Pydantic models — independent copies of nautilus core types.

These are standalone mirrors so adapter packages have zero import dependency
on the ``nautilus`` core library.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class IntentAnalysis(BaseModel):
    """Structured intent analysis forwarded to adapters by the broker.

    Contains the parsed user intent, requested data types, stated purpose,
    and a confidence score used for routing decisions.
    """

    raw_intent: str
    normalized_intent: str
    data_types: list[str]
    purpose: str
    confidence: float


class ScopeConstraint(BaseModel):
    """Per-source WHERE-clause fragment passed to :meth:`Adapter.execute`.

    Adapters use these constraints to restrict query results at the
    data-source level (e.g., field-level redaction, row filtering).
    """

    source_id: str
    operator: str
    field: str
    value: Any
    expires_at: str | None = None
    valid_from: str | None = None


class AdapterResult(BaseModel):
    """Result returned by an adapter after executing a scoped query.

    The ``metadata`` dict should include provenance info such as row
    counts, query duration, or classification tags.
    """

    source_id: str
    data: Any
    metadata: dict[str, Any]


class ErrorRecord(BaseModel):
    """Structured error report emitted when an adapter fails.

    Captured by the broker for audit logging and operator dashboards.
    """

    source_id: str
    error: str
    error_type: str


class AuthConfig(BaseModel):
    """Authentication credentials for connecting to a data source.

    The ``auth_type`` field selects the authentication strategy
    (e.g., ``"bearer"``, ``"basic"``, ``"api_key"``).
    """

    auth_type: str
    credentials: dict[str, Any]


class EndpointSpec(BaseModel):
    """HTTP endpoint specification for REST-based adapters.

    Provides URL, method, optional headers, and a per-request timeout.
    """

    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    timeout_s: float = 30.0
