"""Adapter SDK Pydantic models — independent copies of nautilus core types.

These are standalone mirrors so adapter packages have zero import dependency
on the ``nautilus`` core library. Mirror means *field for field*: the broker
reads these objects directly, so a field that differs from
``nautilus.core.models`` is a runtime failure in every adapter written the
documented way, not a stylistic difference. ``tests/defects/test_blockers.py``
pins the two shapes together.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class IntentAnalysis(BaseModel):
    """Structured intent analysis forwarded to adapters by the broker.

    Mirrors :class:`nautilus.core.models.IntentAnalysis`. The stated purpose
    is not here: it travels in the ``context`` dict passed to
    :meth:`Adapter.execute`, not on the intent.
    """

    raw_intent: str
    data_types_needed: list[str]
    entities: list[str]
    temporal_scope: str | None = None
    estimated_sensitivity: str | None = None


class ScopeConstraint(BaseModel):
    """Per-source WHERE-clause fragment passed to :meth:`Adapter.execute`.

    Adapters use these constraints to restrict query results at the
    data-source level (e.g., field-level redaction, row filtering).
    """

    source_id: str
    field: str
    # ``str``, not the core ``Literal`` allowlist: the compliance suite feeds
    # a deliberately invalid operator to prove the adapter rejects it, which
    # a Literal would block at construction instead of at the adapter.
    operator: str
    value: Any
    expires_at: str | None = None
    valid_from: str | None = None


class ErrorRecord(BaseModel):
    """Structured error report emitted when an adapter fails.

    Mirrors :class:`nautilus.core.models.ErrorRecord`. ``trace_id``
    correlates back to the request id; adapters may leave it empty and the
    broker fills it in.
    """

    source_id: str
    error_type: str
    message: str
    trace_id: str = ""


class AdapterResult(BaseModel):
    """Result returned by an adapter after executing a scoped query.

    Mirrors :class:`nautilus.core.models.AdapterResult`, which the broker
    reads as ``res.rows`` and ``res.error``. Success populates ``rows`` and
    leaves ``error`` ``None``; failure returns empty ``rows`` with ``error``
    set, so the broker can bucket the source into ``sources_errored`` without
    raising.

    There is deliberately no response-hash field: the per-source
    chain-of-custody digest is computed by the broker over ``rows``, because
    an adapter-supplied digest would be an unverifiable trust channel into
    the signed attestation.
    """

    source_id: str
    rows: list[dict[str, Any]]
    duration_ms: int
    error: ErrorRecord | None = None


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
