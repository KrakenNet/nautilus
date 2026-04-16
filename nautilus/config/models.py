"""Nautilus configuration Pydantic models.

Mirrors design §4.1 and §4.10 verbatim, extended with Phase-2 additive fields
(design §3.5, §3.11): multi-adapter ``SourceConfig`` (elasticsearch/rest/neo4j/
servicenow), endpoint specs, auth discriminated union, agent registry records,
and top-level ``api`` / ``session_store`` / ``analysis`` / ``attestation``
subsections. All new fields have defaults so Phase-1 YAML fixtures continue to
load unchanged (NFR-5, AC-1.4).
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Phase 2 auth discriminated union (design §3.5).
# ---------------------------------------------------------------------------


class BearerAuth(BaseModel):
    """Bearer-token auth config; token is resolved from env via interpolation."""

    type: Literal["bearer"] = "bearer"
    token: str


class BasicAuth(BaseModel):
    """HTTP Basic auth config."""

    type: Literal["basic"] = "basic"
    username: str
    password: str


class MtlsAuth(BaseModel):
    """Mutual-TLS auth config; paths are filesystem locations."""

    type: Literal["mtls"] = "mtls"
    cert_path: str
    key_path: str
    ca_path: str | None = None


class NoneAuth(BaseModel):
    """Explicit no-auth marker."""

    type: Literal["none"] = "none"


AuthConfig = Annotated[
    BearerAuth | BasicAuth | MtlsAuth | NoneAuth,
    Field(discriminator="type"),
]


# ---------------------------------------------------------------------------
# Phase 2 endpoint specs (design §3.5, REST/ServiceNow adapters).
# ---------------------------------------------------------------------------


class EndpointSpec(BaseModel):
    """Named REST/ServiceNow endpoint descriptor."""

    path: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path_params: list[str] = Field(default_factory=list)
    query_params: list[str] = Field(default_factory=list)
    operator_templates: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# SourceConfig (Phase 1 fields + Phase 2 additive fields).
# ---------------------------------------------------------------------------


class SourceConfig(BaseModel):
    """Per-source YAML entry (design §4.1, extended §3.5, §3.11).

    Carries the adapter kind, classification metadata, connection DSN/base-URL
    (already env-interpolated), pgvector-only query shape options, and Phase-2
    additive fields for elasticsearch/rest/neo4j/servicenow adapters.
    """

    id: str
    type: Literal[
        "postgres",
        "pgvector",
        "elasticsearch",
        "rest",
        "neo4j",
        "servicenow",
    ]
    description: str
    classification: str
    data_types: list[str]
    allowed_purposes: list[str] | None = None
    connection: str  # post-interpolation DSN / base URL
    # pgvector-only
    table: str | None = None
    embedding_column: str | None = None
    metadata_column: str | None = None
    distance_operator: Literal["<=>", "<->", "<#>"] | None = "<=>"
    top_k: int = 10
    embedder: str | None = None  # name of registered embedder
    # Phase 2 additive fields (design §3.5, §3.11).
    index: str | None = None
    label: str | None = None
    endpoints: list[EndpointSpec] | None = None
    auth: AuthConfig | None = None
    compartments: str = ""
    sub_category: str = ""
    like_style: Literal["starts_with", "regex"] = "starts_with"


# ---------------------------------------------------------------------------
# Agent registry records (design §3.5, FR-9).
# ---------------------------------------------------------------------------


class AgentRecord(BaseModel):
    """Single agent identity declared in ``nautilus.yaml`` under ``agents``."""

    id: str
    clearance: str
    compartments: list[str] = Field(default_factory=list)
    default_purpose: str | None = None


# ---------------------------------------------------------------------------
# Top-level subsections.
# ---------------------------------------------------------------------------


class NullSinkSpec(BaseModel):
    """No-op attestation sink (default, preserves NFR-5 backwards compat)."""

    type: Literal["null"] = "null"


class FileSinkSpec(BaseModel):
    """Append-only JSONL attestation sink with per-emit flush + fsync (AC-14.2)."""

    type: Literal["file"] = "file"
    path: str


class RetryPolicySpec(BaseModel):
    """Retry schedule for :class:`HttpAttestationSink` (design §3.14, AC-14.3).

    Mirrors :class:`nautilus.core.attestation_sink.RetryPolicy` one-for-one; the
    HTTP sink accepts either (both are structural ``BaseModel``\\ s with the
    same field names) so YAML-loaded ``RetryPolicySpec`` flows straight into
    the sink constructor without a conversion step.
    """

    max_retries: int = 3
    initial_backoff_s: float = 0.1
    max_backoff_s: float = 5.0


class HttpSinkSpec(BaseModel):
    """HTTP POST attestation sink with retry + dead-letter spill (AC-14.3).

    ``url`` is the verifier's ingest endpoint; ``retry_policy`` defaults match
    :class:`~nautilus.core.attestation_sink.RetryPolicy`. ``dead_letter_path``
    is optional — when omitted, exhausted retries log a WARN only; when set,
    the sink wraps a :class:`~nautilus.core.attestation_sink.FileAttestationSink`
    for the spill so dead-lettered payloads are durable-before-ack (NFR-16).
    """

    type: Literal["http"] = "http"
    url: str
    retry_policy: RetryPolicySpec = Field(default_factory=RetryPolicySpec)
    dead_letter_path: str | None = None


AttestationSinkSpec = Annotated[
    NullSinkSpec | FileSinkSpec | HttpSinkSpec,
    Field(discriminator="type"),
]


class AttestationConfig(BaseModel):
    """Attestation subsection of ``nautilus.yaml`` (design §4.10, §3.14).

    ``sink`` selects the store-and-forward destination for signed payloads
    (FR-28). Phase-1 YAML without an ``attestation.sink`` entry resolves to
    :class:`NullSinkSpec` → :class:`NullAttestationSink`, so existing
    fixtures continue to load unchanged (NFR-5).
    """

    private_key_path: str | None = None
    enabled: bool = True
    sink: AttestationSinkSpec = Field(default_factory=NullSinkSpec)


class RulesConfig(BaseModel):
    """Routing-rules subsection of ``nautilus.yaml`` (design §4.10)."""

    user_rules_dirs: list[str] = Field(default_factory=list)


class AuditConfig(BaseModel):
    """Audit-log subsection of ``nautilus.yaml`` (design §4.10)."""

    path: str = "./audit.jsonl"


class AnthropicProviderSpec(BaseModel):
    """``analysis.provider`` spec selecting :class:`AnthropicProvider` (design §3.8)."""

    type: Literal["anthropic"] = "anthropic"
    api_key_env: str
    model: str = "claude-sonnet-4-5"
    timeout_s: float = 2.0


class OpenAIProviderSpec(BaseModel):
    """``analysis.provider`` spec selecting :class:`OpenAIProvider` (design §3.8)."""

    type: Literal["openai"] = "openai"
    api_key_env: str
    model: str = "gpt-4o-mini"
    timeout_s: float = 2.0


class LocalInferenceProviderSpec(BaseModel):
    """``analysis.provider`` spec selecting :class:`LocalInferenceProvider` (design §3.8)."""

    type: Literal["local"] = "local"
    base_url: str
    model: str
    api_key_env: str | None = None
    timeout_s: float = 2.0


AnalysisProviderSpec = Annotated[
    AnthropicProviderSpec | OpenAIProviderSpec | LocalInferenceProviderSpec,
    Field(discriminator="type"),
]


class AnalysisConfig(BaseModel):
    """Intent-analyzer subsection of ``nautilus.yaml`` (design §4.10, §3.8).

    ``mode`` selects how :meth:`Broker.arequest` resolves the intent
    analyzer (FR-13, FR-14, AC-6.2):

    - ``"pattern"`` (default) → :class:`PatternMatchingIntentAnalyzer` only;
      preserves Phase-1 byte-identical attestation payloads (NFR-5/NFR-6).
    - ``"llm-first"`` → :class:`FallbackIntentAnalyzer` over the configured
      provider; falls through to the pattern analyzer on timeout / provider
      error / schema drift (AC-6.3).
    - ``"llm-only"`` → :class:`FallbackIntentAnalyzer` that re-raises on any
      primary failure; the broker fails-closed with a structured error audit.
    """

    keyword_map: dict[str, list[str]] = Field(default_factory=dict)
    mode: Literal["pattern", "llm-first", "llm-only"] = "pattern"
    provider: AnalysisProviderSpec | None = None
    timeout_s: float = 2.0


class ApiConfig(BaseModel):
    """FastAPI/MCP API subsection of ``nautilus.yaml`` (design §3.11).

    Phase-2 shell extended for Phase-5 VE surface (FR-26, D-11):
    ``keys`` holds the API-key allow-list consumed by
    :func:`nautilus.transport.auth.verify_api_key`. An empty list fails
    closed (no caller accepted) which matches the auth-dependency
    behaviour in :mod:`nautilus.transport.fastapi_app`.
    """

    host: str = "127.0.0.1"
    port: int = 8080
    keys: list[str] = Field(default_factory=list)


class MCPConfig(BaseModel):
    """MCP transport subsection of ``nautilus.yaml`` (design §3.13).

    ``expose_declare_handoff`` (default ``False``) gates the optional
    ``nautilus_declare_handoff`` tool (D-12). Keeping the default off
    preserves backwards compatibility and prevents unintended exposure
    of the reasoning-only handoff surface through MCP clients.
    """

    expose_declare_handoff: bool = False


class SessionStoreConfig(BaseModel):
    """Session-store subsection of ``nautilus.yaml`` (design §3.11, §3.2).

    ``backend: postgres`` selects :class:`~nautilus.core.session_pg.PostgresSessionStore`.
    ``dsn`` is post-interpolation (``${VAR}`` already resolved); if omitted, the
    broker falls back to the ``TEST_PG_DSN`` env var so integration fixtures
    can reuse the existing pg_container DSN without duplicating YAML plumbing.
    ``on_failure`` mirrors :attr:`PostgresSessionStore._on_failure` (NFR-7).
    """

    backend: Literal["memory", "redis", "postgres"] = "memory"
    ttl_seconds: int = 3600
    dsn: str | None = None
    on_failure: Literal["fail_closed", "fallback_memory"] = "fail_closed"


# ---------------------------------------------------------------------------
# Root config document.
# ---------------------------------------------------------------------------


class NautilusConfig(BaseModel):
    """Root ``nautilus.yaml`` document (design §4.1, §4.10, extended §3.11)."""

    sources: list[SourceConfig]
    agents: dict[str, AgentRecord] = Field(default_factory=dict)
    attestation: AttestationConfig = Field(default_factory=AttestationConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    session_store: SessionStoreConfig = Field(default_factory=SessionStoreConfig)
