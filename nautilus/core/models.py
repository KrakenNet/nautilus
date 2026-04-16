"""Nautilus shared core Pydantic models.

Mirrors design §4.2–§4.9 verbatim. The ``ScopeConstraint.operator`` allowlist is
pinned via ``typing.Literal`` per design §6.1 (UQ-6); drift between the model
allowlist and the adapter runtime validator is caught by pyright + a dedicated
drift-guard test.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class IntentAnalysis(BaseModel):
    """Structured output of :class:`IntentAnalyzer.analyze` (design §4.2).

    Carries the raw agent intent plus derived routing inputs (data-type
    tags, extracted entities, optional temporal / sensitivity hints).
    """

    raw_intent: str
    data_types_needed: list[str]
    entities: list[str]
    temporal_scope: str | None = None
    estimated_sensitivity: str | None = None


class BrokerRequest(BaseModel):
    """Public input to :meth:`Broker.arequest` (research §5).

    Carries the caller's ``agent_id``, their free-form ``intent`` string,
    and an open ``context`` dict that the router inspects for optional
    hints (e.g. ``session_id``, transport metadata, prior-turn facts).
    """

    agent_id: str
    intent: str
    context: dict[str, Any] = Field(default_factory=dict)


class RoutingDecision(BaseModel):
    """One (source_id, reason) pair emitted by the Fathom router (design §4.3).

    Rule LHS asserts one ``routing_decision`` fact per matched source; the
    broker consumes the list to decide which adapters to invoke.
    """

    source_id: str
    reason: str


class ScopeConstraint(BaseModel):
    """Per-source WHERE-clause fragment produced by the router (design §4.4).

    The ``operator`` allowlist is pinned via ``typing.Literal`` so pyright
    catches drift between the Pydantic model and the adapter-runtime
    validator in :mod:`nautilus.adapters.base` (design §6.1, UQ-6).
    """

    source_id: str
    field: str
    operator: Literal[
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
    ]
    value: Any  # validated by operator-specific rules
    expires_at: str | None = None
    valid_from: str | None = None


class DenialRecord(BaseModel):
    """Per-source denial emitted by the router (design §4.5).

    Captures the rule name + human-readable reason so the broker can
    exclude the source from routing and surface the detail in the
    audit entry.
    """

    source_id: str
    reason: str
    rule_name: str


class RouteResult(BaseModel):
    """Output of ``FathomRouter.route`` — design §3.4.

    Promoted from an inline dataclass in ``nautilus/core/fathom_router.py``
    (Task 2.1). ``duration_us`` is integer microseconds per design §3.4
    (timestamps/durations normalised to ``int`` microseconds across the
    core models module).
    """

    routing_decisions: list[RoutingDecision]
    scope_constraints: dict[str, list[ScopeConstraint]]
    denial_records: list[DenialRecord]
    rule_trace: list[str]
    duration_us: int = 0
    facts_asserted_summary: dict[str, int] = Field(default_factory=dict)


class ErrorRecord(BaseModel):
    """Per-source adapter/broker failure record (design §4.6).

    ``trace_id`` correlates back to the request id so operators can
    cross-reference the JSONL audit entry.
    """

    source_id: str
    error_type: str  # e.g. "ScopeEnforcementError", "AdapterError"
    message: str
    trace_id: str  # correlation to request_id


class AdapterResult(BaseModel):
    """Single adapter's ``execute()`` output (design §4.7).

    Success case populates ``rows`` and leaves ``error`` ``None``; failure
    case returns an empty ``rows`` list with ``error`` set so the broker
    can bucket it into ``sources_errored`` without raising.
    """

    source_id: str
    rows: list[dict[str, Any]]
    duration_ms: int
    error: ErrorRecord | None = None


class BrokerResponse(BaseModel):
    """Public result of :meth:`Broker.arequest` (design §4.8).

    Aggregates per-source successes, denials, skips, and errors plus the
    optional attestation JWT. ``data`` maps each successful ``source_id``
    to the list of returned rows.
    """

    request_id: str
    data: dict[str, list[dict[str, Any]]]
    sources_queried: list[str]
    sources_denied: list[str]
    sources_skipped: list[str]
    sources_errored: list[ErrorRecord]
    scope_restrictions: dict[str, list[ScopeConstraint]]
    attestation_token: str | None
    duration_ms: int


class HandoffDecision(BaseModel):
    """Structured outcome of a handoff evaluation (design §3.10).

    Emitted when an agent declares a handoff to a downstream agent and
    the broker evaluates allow/deny/escalate against the combined
    scope + escalation rule set.
    """

    handoff_id: str
    action: Literal["allow", "deny", "escalate"]
    denial_records: list[DenialRecord] = Field(default_factory=list[DenialRecord])
    rule_trace: list[str] = Field(default_factory=list[str])


class AuditEntry(BaseModel):
    """Flat, loss-less audit record for one request (design §4.9).

    Persisted once per request — success OR failure — by
    :meth:`AuditLogger.emit`. Consumers can round-trip the on-disk JSONL
    line back into this model via :func:`decode_nautilus_entry`.

    Phase 2 adds a block of strictly optional fields (LLM provenance,
    scope-hash versioning, session-id sourcing, session-store mode,
    event-type + handoff linkage) — all default ``None`` so Phase-1
    writers and on-disk JSONL lines round-trip unchanged (NFR-5).
    """

    timestamp: datetime  # UTC ISO8601
    request_id: str
    agent_id: str
    session_id: str | None = None
    raw_intent: str = ""
    intent_analysis: IntentAnalysis | None = None
    facts_asserted_summary: dict[str, int]  # template -> count
    routing_decisions: list[RoutingDecision] = Field(default_factory=list[RoutingDecision])
    scope_constraints: list[ScopeConstraint] = Field(default_factory=list[ScopeConstraint])
    denial_records: list[DenialRecord]
    error_records: list[ErrorRecord]
    rule_trace: list[str]
    sources_queried: list[str]
    sources_denied: list[str]
    sources_skipped: list[str] = Field(default_factory=list[str])
    sources_errored: list[str]  # source IDs only; full error detail lives in error_records
    attestation_token: str | None = None
    duration_ms: int
    # Phase 2 — all optional, all default None (NFR-5 round-trip guarantee).
    llm_provider: str | None = None
    llm_model: str | None = None
    llm_version: str | None = None
    raw_response_hash: str | None = None
    prompt_version: str | None = None
    fallback_used: bool | None = None
    scope_hash_version: Literal["v1", "v2"] | None = None
    session_id_source: Literal["context", "transport", "stdio_request_id"] | None = None
    session_store_mode: Literal["primary", "degraded_memory"] | None = None
    event_type: Literal["request", "handoff_declared"] | None = None
    handoff_id: str | None = None
    handoff_decision: HandoffDecision | None = None
    trace_id: str | None = None


class InferredHandoff(BaseModel):
    """Forensic-inferred handoff between two agents (design §3.7, FR-11).

    Emitted by the offline forensic worker when heuristics fire on a pair of
    audit entries (shared session, overlapping sources, classification delta
    — see ``nautilus/rules/forensics/handoff.yaml``). Unlike
    :class:`HandoffDecision` (which is a *declared* broker-time outcome),
    ``InferredHandoff`` is a *post-hoc* inference with an explicit
    ``confidence`` in ``[0.0, 1.0]`` and the list of heuristic ``signals``
    that contributed to it.
    """

    session_id: str
    source_agent: str
    receiving_agent: str
    confidence: float
    signals: list[str]
    inferred_at: datetime
