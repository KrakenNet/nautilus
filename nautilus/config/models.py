"""Nautilus configuration Pydantic models.

Mirrors design §4.1 and §4.10 verbatim, extended with Phase-2 additive fields
(design §3.5, §3.11): multi-adapter ``SourceConfig`` (elasticsearch/rest/neo4j/
servicenow), endpoint specs, auth discriminated union, agent registry records,
and top-level ``api`` / ``session_store`` / ``analysis`` / ``attestation``
subsections. All new fields have defaults so Phase-1 YAML fixtures continue to
load unchanged (NFR-5, AC-1.4).
"""

from __future__ import annotations

from ipaddress import ip_network
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _Strict(BaseModel):
    """Base for every config model: a key no field declares is an error.

    ``nautilus.yaml`` is the operator's document, and until now it accepted
    anything: ``sesion_store:`` validated, ran the in-memory session store in
    production, and reported nothing. Silence about a key that changes what
    runs is the opposite of the fail-closed handling the rest of the config
    already has (an unknown clearance aborts load; ``auto_promote: true`` is
    refused rather than ignored).
    """

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Phase 2 auth discriminated union (design §3.5).
# ---------------------------------------------------------------------------


class BearerAuth(_Strict):
    """Bearer-token auth config; token is resolved from env via interpolation."""

    type: Literal["bearer"] = "bearer"
    token: str


class BasicAuth(_Strict):
    """HTTP Basic auth config."""

    type: Literal["basic"] = "basic"
    username: str
    password: str


class MtlsAuth(_Strict):
    """Mutual-TLS auth config; paths are filesystem locations."""

    type: Literal["mtls"] = "mtls"
    cert_path: str
    key_path: str
    ca_path: str | None = None


class NoneAuth(_Strict):
    """Explicit no-auth marker."""

    type: Literal["none"] = "none"


AuthConfig = Annotated[
    BearerAuth | BasicAuth | MtlsAuth | NoneAuth,
    Field(discriminator="type"),
]


# ---------------------------------------------------------------------------
# Phase 2 endpoint specs (design §3.5, REST/ServiceNow adapters).
# ---------------------------------------------------------------------------


class EndpointSpec(_Strict):
    """Named REST/ServiceNow endpoint descriptor."""

    path: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path_params: list[str] = Field(default_factory=list)
    query_params: list[str] = Field(default_factory=list)
    operator_templates: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# SourceConfig (Phase 1 fields + Phase 2 additive fields).
# ---------------------------------------------------------------------------


# Fields a built-in adapter's ``connect()`` hard-requires. ``SourceConfig`` is
# one flat model with everything optional, so a source missing its mandatory
# field used to load cleanly: the broker started, ``/healthz`` and ``/readyz``
# went green (neither touches an adapter), and the source failed on every
# request for the life of the process. Checked here rather than in the loader so
# a programmatically built config fails the same way.
#
# ``rest`` is deliberately absent: ``endpoints`` is optional by design and the
# adapter falls back to the base URL with an empty path (NFR-5, AC-1.4).
_REQUIRED_BY_TYPE: dict[str, str] = {
    "postgres": "table",
    "pgvector": "table",
    "servicenow": "table",
    "elasticsearch": "index",
    "neo4j": "label",
    "llm": "model",
    "static": "rows",
}

# Built-in types whose adapter dials something: ``connection`` is the DSN, base
# URL or endpoint it dials, so an empty one is a source that cannot serve. It
# defaults to empty for ``static`` (whose data is in the config) and for
# third-party types, whose adapters this model cannot know anything about.
_CONNECTS_OUT: frozenset[str] = frozenset(
    {
        "postgres",
        "pgvector",
        "elasticsearch",
        "rest",
        "neo4j",
        "servicenow",
        "influxdb",
        "s3",
        "llm",
    }
)


class SourceConfig(_Strict):
    """Per-source YAML entry (design §4.1, extended §3.5, §3.11).

    Carries the adapter kind, classification metadata, connection DSN/base-URL
    (already env-interpolated), pgvector-only query shape options, and Phase-2
    additive fields for elasticsearch/rest/neo4j/servicenow adapters.
    """

    id: str
    # Open string (not a closed Literal) so entry-point-discovered and
    # local-path adapters (#17) can be referenced from source blocks.
    # Unknown types still fail closed: the loader pre-validates against
    # built-ins + declared adapter types, and Broker._build_adapter raises
    # ConfigError for any type missing from the merged registry.
    type: str
    # Documentation for a human reading the config; nothing reads it, so it is
    # not worth failing a first config over.
    description: str = ""
    classification: str
    data_types: list[str]
    allowed_purposes: list[str] | None = None
    # Largest set of rows this source may return, in canonical-JSON bytes. The
    # only cap used to be a row count (1000, in the postgres adapter), which is
    # not a bound when a row can be any size: a table of wide text values turned
    # one request into a 65 MB response and ~115 MB of process memory, and eight
    # concurrent requests SIGKILLed the pod under the shipped
    # ``limits.memory: 1Gi`` -- clients got a dropped socket, not a 413 or a
    # 503, and both probes went unreachable because there was no process left.
    # Rows are dropped whole and the source is named in ``truncated_sources``.
    # ``None`` removes the bound. 8 MiB matches the ceilings the REST and S3
    # adapters already apply to a response body.
    max_response_bytes: int | None = Field(default=8_388_608, gt=0)
    connection: str = ""  # post-interpolation DSN / base URL
    # ``static`` only: the rows this source serves, straight from the YAML.
    rows: list[dict[str, Any]] = Field(default_factory=list[dict[str, Any]])
    # pgvector-only
    table: str | None = None
    embedding_column: str | None = None
    metadata_column: str | None = None
    distance_operator: Literal["<=>", "<->", "<#>"] | None = "<=>"
    top_k: int = 10
    # Only ``default`` (the broker-wide embedder) resolves: there is no
    # embedder registry, so any other name silently did nothing and every
    # request to the source failed later with EmbeddingUnavailableError.
    # Rejecting it at config load makes that a startup error with a reason.
    embedder: Literal["default"] | None = None
    # Phase 2 additive fields (design §3.5, §3.11).
    index: str | None = None
    label: str | None = None
    endpoints: list[EndpointSpec] | None = None
    auth: AuthConfig | None = None
    compartments: str = ""
    sub_category: str = ""
    # Column carrying the purpose a row was collected for. The shipped
    # compliance packs scope on it; they cannot know an operator's schema, so
    # they used to assert a literal ``purpose`` column and every covered
    # request died with ``UndefinedColumnError``. Undeclared, a pack that
    # scopes by purpose denies the source rather than over-returning it.
    purpose_field: str = ""
    like_style: Literal["starts_with", "regex"] = "starts_with"
    # llm-only (#43): model name sent to the OpenAI-compatible endpoint at
    # ``connection``. Required for ``type: llm`` (enforced by LLMAdapter).
    model: str | None = None
    # 4.18 -- wall-clock budget for one connect+execute of this source. There
    # was no deadline anywhere: an unresponsive source held the request, its
    # session write and its audit entry open forever, and every healthy
    # co-queried source finished and was held with it. Raise it for sources
    # that are legitimately slow (a large LLM), or set ``null`` to wait
    # indefinitely and own that choice explicitly.
    timeout_s: float | None = 15.0

    @model_validator(mode="after")
    def _require_adapter_mandatory_field(self) -> SourceConfig:
        """Reject a source whose adapter can never serve a request."""
        required = _REQUIRED_BY_TYPE.get(self.type)
        if required is not None and not getattr(self, required, None):
            raise ValueError(
                f"source '{self.id}' has type '{self.type}' but no '{required}'. "
                f"The {self.type} adapter requires it, so every request to this "
                f"source would fail at runtime."
            )
        if self.type in _CONNECTS_OUT and not self.connection:
            raise ValueError(
                f"source '{self.id}' has type '{self.type}' but no 'connection'. "
                f"The {self.type} adapter has nothing to dial, so every request "
                f"to this source would fail at runtime."
            )
        return self


# ---------------------------------------------------------------------------
# Agent registry records (design §3.5, FR-9).
# ---------------------------------------------------------------------------


class AgentRecord(_Strict):
    """Single agent identity declared in ``nautilus.yaml`` under ``agents``."""

    id: str
    clearance: str
    compartments: list[str] = Field(default_factory=list)
    default_purpose: str | None = None
    # The identity an authenticating proxy forwards for this agent — an SPIFFE
    # id, an OIDC subject, a certificate CN. Matched against ``X-Forwarded-User``
    # under ``api.auth.mode: proxy_trust``; without it the header names an agent
    # nothing has bound, and any caller past the proxy can ask as anyone.
    subject: str | None = None
    # What this agent may claim as its ``purpose``. Empty means unrestricted,
    # which is the shape every existing config has. ``purpose`` is a live
    # authorization input (``deny-purpose-mismatch``, the HIPAA pack) that the
    # caller types, so an operator needs somewhere to bound it.
    allowed_purposes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level subsections.
# ---------------------------------------------------------------------------


class NullSinkSpec(_Strict):
    """No-op attestation sink (default, preserves NFR-5 backwards compat)."""

    type: Literal["null"] = "null"


class FileSinkSpec(_Strict):
    """Append-only JSONL attestation sink with per-emit flush + fsync (AC-14.2).

    ``chained: true`` upgrades the sink to a hash-chained, JWS-signed log
    (:class:`fathom.chained_log.ChainedAttestationLog`): each line carries
    ``prev_sha256`` linkage plus an EdDSA signature, so deletion, reordering,
    or edits are detectable offline via ``nautilus attestation verify``.
    Requires ``attestation.enabled`` with a signing key. ``checkpoint_interval``
    (>0) appends a signed checkpoint record every N emissions for
    tail-truncation anchoring.
    """

    type: Literal["file"] = "file"
    path: str
    chained: bool = False
    checkpoint_interval: int = 0


class RetryPolicySpec(_Strict):
    """Retry schedule for :class:`HttpAttestationSink` (design §3.14, AC-14.3).

    Mirrors :class:`nautilus.core.attestation_sink.RetryPolicy` one-for-one; the
    HTTP sink accepts either (both are structural ``BaseModel``\\ s with the
    same field names) so YAML-loaded ``RetryPolicySpec`` flows straight into
    the sink constructor without a conversion step.
    """

    max_retries: int = 3
    initial_backoff_s: float = 0.1
    max_backoff_s: float = 5.0


class HttpSinkSpec(_Strict):
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


class AttestationConfig(_Strict):
    """Attestation subsection of ``nautilus.yaml`` (design §4.10, §3.14).

    ``sink`` selects the store-and-forward destination for signed payloads
    (FR-28). Phase-1 YAML without an ``attestation.sink`` entry resolves to
    :class:`NullSinkSpec` → :class:`NullAttestationSink`, so existing
    fixtures continue to load unchanged (NFR-5).
    """

    private_key_path: str | None = None
    enabled: bool = True
    sink: AttestationSinkSpec = Field(default_factory=NullSinkSpec)


class RulesConfig(_Strict):
    """Routing-rules subsection of ``nautilus.yaml`` (design §4.10)."""

    user_rules_dirs: list[str] = Field(default_factory=list)
    # Rule packs by ``fathom.packs`` entry-point name (e.g. ``data-routing-nist``).
    # Resolved by name rather than path so an installed third-party pack loads
    # the same way a shipped one does.
    packs: list[str] = Field(default_factory=list)
    # #27 — post-run engine-output consistency checks (v1 hardening,
    # roadmap §05:432). On by default; opt out for performance-sensitive
    # deployments.
    consistency_checks: bool = True


class AuditConfig(_Strict):
    """Audit-log subsection of ``nautilus.yaml`` (design §4.10).

    ``chained: true`` upgrades the log to the same hash-chained, JWS-signed
    format the attestation sink can use (:class:`fathom.chained_log.
    ChainedAttestationLog`): every line commits to its predecessor, so a
    deleted or edited entry is detectable offline rather than leaving no
    trace. Requires ``attestation.enabled`` with a signing key, and — like
    every chain — a single writer.
    """

    path: str = "./audit.jsonl"
    chained: bool = False
    checkpoint_interval: int = 0


class AnthropicProviderSpec(_Strict):
    """``analysis.provider`` spec selecting :class:`AnthropicProvider` (design §3.8)."""

    type: Literal["anthropic"] = "anthropic"
    api_key_env: str
    model: str = "claude-sonnet-4-5"
    timeout_s: float = 2.0


class OpenAIProviderSpec(_Strict):
    """``analysis.provider`` spec selecting :class:`OpenAIProvider` (design §3.8)."""

    type: Literal["openai"] = "openai"
    api_key_env: str
    model: str = "gpt-4o-mini"
    timeout_s: float = 2.0


class LocalInferenceProviderSpec(_Strict):
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


class AnalysisConfig(_Strict):
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


# What a credential is allowed to do. ``query`` is the broker itself; the other
# three are the surfaces that change what the broker will do or attest to.
CAPABILITIES = ("query", "audit_read", "govern", "keys")


class UIConfig(_Strict):
    """``ui`` — the browser-facing admin console (design §3.13).

    Off by default. The console is a second front door to the same broker: it
    authenticates a browser with a cookie and, through the playground, runs
    real queries against real sources. Mounting it on every deployment gives an
    operator who never asked for one a login page on their production port, and
    a login page is an invitation to guess at the key. When it is off the
    routes are not registered at all, so ``/admin`` is a 404 rather than a
    prompt.
    """

    enabled: bool = False


class ApiKeyEntry(_Strict):
    """One API key, bound to an agent and scoped to a set of capabilities.

    The bare-string form (``keys: ["s3cret"]``) still loads and still means
    "root": bound to no agent, holding every capability. It is what every
    shipped example uses, so it keeps working — and warns at startup, because a
    key that can rotate the signing key merely by existing is worth saying out
    loud once.
    """

    key: str
    # The only ``agent_id`` this key may ask as. ``None`` is the bare-key
    # behaviour: the caller names its own agent and the registry hands that
    # name its clearance.
    agent_id: str | None = None
    capabilities: list[str] = Field(default_factory=lambda: ["query"])

    @model_validator(mode="after")
    def _known_capabilities(self) -> ApiKeyEntry:
        unknown = [c for c in self.capabilities if c not in CAPABILITIES]
        if unknown:
            raise ValueError(
                f"api.keys entry declares unknown capabilities {unknown}. "
                f"Known capabilities: {list(CAPABILITIES)}"
            )
        return self


class ApiAuthConfig(_Strict):
    """``api.auth`` — how the HTTP surfaces identify a caller (design §3.12, D-11).

    ``proxy_trust`` was documented in the operator guide and implemented on
    REST, MCP and the admin UI, and ``ApiConfig`` had no ``auth`` field, so no
    config could select it. Under that mode ``X-Forwarded-User`` *is* the
    credential, which makes it an identity only if nobody but the proxy can
    set it — hence ``trusted_proxies``, and hence the refusal to start without
    it.
    """

    mode: Literal["api_key", "proxy_trust"] = "api_key"
    # CIDR blocks (or bare addresses) the forwarded identity is accepted from.
    trusted_proxies: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _proxy_trust_needs_a_trusted_peer(self) -> ApiAuthConfig:
        """Refuse ``proxy_trust`` with no peer restriction."""
        if self.mode == "proxy_trust" and not self.trusted_proxies:
            raise ValueError(
                "api.auth.mode 'proxy_trust' requires api.auth.trusted_proxies. "
                "Without it, X-Forwarded-User is settable by anyone who can reach "
                "the port, so every caller can assert every identity."
            )
        for entry in self.trusted_proxies:
            try:
                ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"api.auth.trusted_proxies entry {entry!r} is not an address "
                    f"or CIDR block: {exc}"
                ) from exc
        return self


class ApiConfig(_Strict):
    """FastAPI/MCP API subsection of ``nautilus.yaml`` (design §3.11).

    Phase-2 shell extended for Phase-5 VE surface (FR-26, D-11):
    ``keys`` holds the API-key allow-list consumed by
    :func:`nautilus.transport.auth.verify_api_key`. An empty list fails
    closed (no caller accepted) which matches the auth-dependency
    behaviour in :mod:`nautilus.transport.fastapi_app`.
    """

    # Matches ``nautilus serve``'s --bind default. These went unread until
    # now, so the old 8080 default described nothing; every doc, example and
    # the CLI itself say 8000.
    host: str = "127.0.0.1"
    port: int = 8000
    keys: list[str | ApiKeyEntry] = Field(default_factory=list["str | ApiKeyEntry"])
    auth: ApiAuthConfig = Field(default_factory=ApiAuthConfig)
    # Largest request body the HTTP surface will read, in bytes. There was no
    # limit at any layer -- uvicorn applies none -- and the audit entry stores
    # the raw intent three times, so one authenticated key could drive tens of
    # MB/s onto the audit volume. The audit sink is the fail-closed path
    # (``/readyz`` reports 503 when ``audit_logger.probe()`` complains), so
    # filling it drains every replica rather than degrading one. ``None``
    # removes the limit.
    max_request_bytes: int | None = Field(default=1_048_576, gt=0)
    # How many requests the HTTP surface will have in flight at once. Past it,
    # callers get 503 + Retry-After instead of joining an unbounded queue.
    # Measured at 512 concurrent clients: throughput flat, an 8.5-second p50,
    # and a 100% success rate -- so nothing in front of the broker could tell a
    # saturated one from a healthy one, and retries joined the same queue.
    # Probes are never gated: a full queue must not take the pod out of
    # rotation. ``None`` removes the limit.
    max_concurrent_requests: int | None = Field(default=64, gt=0)


class MCPConfig(_Strict):
    """MCP transport subsection of ``nautilus.yaml`` (design §3.13).

    ``expose_declare_handoff`` (default ``False``) gates the optional
    ``nautilus_declare_handoff`` tool (D-12). Keeping the default off
    preserves backwards compatibility and prevents unintended exposure
    of the reasoning-only handoff surface through MCP clients.

    ``max_response_bytes`` bounds one ``nautilus_request`` result. An MCP tool
    result is read straight into a model's context window and the SDK puts the
    payload on the wire twice -- once as text content, once as
    ``structuredContent`` -- so an unbounded one spends the caller's context
    and money on rows it did not ask for. Adapters cap each source at 1000
    rows, so a config with several sources multiplies from there. Rows are
    dropped whole and every source touched is named in ``truncated_sources``.

    The number bounds the *serialized broker response*. The SDK then re-encodes
    it indented and sends it twice, so measured wire cost is about 2.1x this --
    262144 here put 553 040 bytes on the pipe. ``None`` removes the bound; REST
    is unaffected either way, because an HTTP client streams to a file rather
    than into a context window.
    """

    expose_declare_handoff: bool = False
    max_response_bytes: int | None = Field(default=262_144, gt=0)


class SessionStoreConfig(_Strict):
    """Session-store subsection of ``nautilus.yaml`` (design §3.11, §3.2).

    ``backend: postgres`` selects :class:`~nautilus.core.session_pg.PostgresSessionStore`.
    ``dsn`` is post-interpolation (``${VAR}`` already resolved); if omitted, the
    broker falls back to the ``TEST_PG_DSN`` env var so integration fixtures
    can reuse the existing pg_container DSN without duplicating YAML plumbing.
    ``on_failure`` mirrors :attr:`PostgresSessionStore._on_failure` (NFR-7).

    ``redis`` was accepted and silently served in-memory. Cumulative exposure
    is what escalation rules read, so an operator who configured a store shared
    across replicas and got a per-process one had replicas that each saw a
    fraction of a caller's history, with nothing said about it. It is refused
    by name until there is a Redis store to select.
    """

    backend: Literal["memory", "postgres", "sqlite"] = "memory"

    @field_validator("backend", mode="before")
    @classmethod
    def _no_unimplemented_backend(cls, value: Any) -> Any:
        """Name what happened to ``redis`` rather than listing it as a typo."""
        if value == "redis":
            raise ValueError(
                "session_store.backend: redis has no implementation. It used to "
                "load and serve sessions from memory instead, which gives "
                "replicas a per-process view of cumulative exposure and no "
                "signal that this is happening. Use postgres for a store shared "
                "across replicas, or sqlite for a durable single-node one."
            )
        return value

    ttl_seconds: int = 3600
    # Lifetime of a session's declared purpose, feeding the session fact's
    # ``purpose_ttl_seconds`` slot. 0 disables the window, matching the
    # ``(> ?ttl 0.0)`` guard in the shipped ``purpose-expired-deny`` rule so
    # existing deployments see no new denials.
    purpose_ttl_seconds: int = 0
    dsn: str | None = None
    on_failure: Literal["fail_closed", "fallback_memory", "fallback_sqlite"] = "fail_closed"
    # #26 — database file for ``backend: sqlite`` and the
    # ``on_failure: fallback_sqlite`` degradation target.
    sqlite_path: str = "./.nautilus/sessions.db"
    # ``backend: postgres`` only. Two pools: ``pool_max_size`` sizes the short
    # ledger reads and writes, ``lock_pool_max_size`` the ledger locks, which are
    # held for the length of a request and so set the store's real concurrency
    # ceiling. They are separate because a request holding a lock has to be able
    # to acquire the connection it needs to finish. ``acquire_timeout_s`` bounds
    # the wait on either — without it a deployment past its pool size simply
    # stopped answering.
    pool_min_size: int = 1
    pool_max_size: int = 10
    lock_pool_max_size: int = 32
    acquire_timeout_s: float = 10.0
    # How long a request will wait for the exposure-ledger lock before giving
    # up. Every request from one caller takes the same lock and holds it across
    # the source query -- that serialisation is deliberate, because two
    # requests that both read the ledger empty both pass a cumulative cap. What
    # was missing is a budget: ``SourceConfig.timeout_s`` is entered after the
    # lock is won, so the queueing sat outside every deadline the config had
    # and a caller measured 32 seconds to an HTTP 200. Applies to every
    # backend, not just postgres -- the in-process lock is where the queue
    # forms. ``None`` restores the unbounded wait.
    lock_timeout_s: float | None = Field(default=30.0, gt=0)


class SessionTokenConfig(_Strict):
    """Session-provenance token subsection of ``nautilus.yaml`` (#18, AC-18.a–g).

    ``enabled: true`` makes the broker mint an EdDSA JWS on the first
    request in a session (returned via ``BrokerResponse.session_token``)
    and verify ``context["session_token"]`` on subsequent requests —
    fail-closed on tampered/expired tokens. Default OFF preserves the
    Phase-1 audit JSONL byte-for-byte (NFR-5).
    """

    enabled: bool = False
    ttl_seconds: int = 3600
    # Where the signing ring persists. Unset keeps it in-process, which is fine
    # for one broker and wrong for two: replicas with their own rings reject
    # each other's tokens with ``unknown_kid``. Point every replica at one path
    # (a shared volume or mounted secret) to run more than one.
    key_ring_path: str | None = None
    # Which broker a token says minted it. The check exists so a token cannot
    # be replayed against an unrelated broker that shares key material, so it
    # must be identical across the replicas of one deployment and different
    # between deployments. Unset with a shared ``key_ring_path`` means one
    # deployment and resolves to a constant; unset without one falls back to a
    # per-process id, which is correct for a single broker only.
    broker_instance_id: str | None = None


# ---------------------------------------------------------------------------
# Root config document.
# ---------------------------------------------------------------------------


class AutoPromoteConfig(_Strict):
    """``rkm.auto_promote`` sub-section (AC-35.4.d).

    Default OFF is a permanent safety gate in v2.0.  When ``enabled`` is
    ``False`` every promotion candidate routes to the human-review queue
    regardless of observation count or artifact kind.

    ``True`` is refused rather than accepted-and-ignored: nothing reads this
    flag, so a deployment that set it believed proposals were skipping human
    review when in fact none were being promoted at all.  Silence on a knob
    that claims to bypass review is the wrong failure mode.
    """

    enabled: bool = False

    @model_validator(mode="after")
    def _reject_unimplemented_auto_promotion(self) -> AutoPromoteConfig:
        if self.enabled:
            raise ValueError(
                "rkm.auto_promote.enabled: auto-promotion is not implemented. "
                "Every proposal routes to the human-review queue "
                "(`nautilus rkm queue`, `POST /v1/rkm/queue/{id}/approve`); "
                "remove the key or set it to false."
            )
        return self


class SandboxConfig(_Strict):
    """``rkm.sandbox`` sub-section (AC-35.7.f).

    ``min_entries`` is the minimum number of audit-log entries required
    before the sandbox reports a meaningful result.  Below this threshold
    :func:`~nautilus.rkm.validator.sandbox.sandbox_replay` sets
    ``SandboxResult.insufficient_history = True``.
    """

    min_entries: int = 100


class RkmConfig(_Strict):
    """``rkm`` subsection of ``nautilus.yaml`` (AC-35.4)."""

    auto_promote: AutoPromoteConfig = Field(default_factory=AutoPromoteConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)


class LocalAdapterConfig(_Strict):
    """One local-path adapter entry under top-level ``adapters:`` (#17).

    Loads an :class:`~nautilus.adapters.base.Adapter` subclass from a
    single-file Python module on disk, for in-repo / private adapters that
    don't warrant a published entry-point package. Relative ``module_path``
    resolves against the config-file directory (same convention as the
    ``facts/`` dir and ``session_store.sqlite_path``).

    ``source_type`` is declared explicitly so the config loader can
    validate source blocks without importing the module; the broker
    fails closed if it doesn't match the class's ``source_type`` ClassVar.

    Security: the referenced module is executed at broker start with the
    broker's privileges — treat ``adapters:`` entries with the same trust
    as installed packages, and keep the config file operator-writable only.
    """

    module_path: str
    class_name: str = Field(alias="class")
    source_type: str


class NautilusConfig(_Strict):
    """Root ``nautilus.yaml`` document (design §4.1, §4.10, extended §3.11)."""

    @model_validator(mode="before")
    @classmethod
    def _drop_anchor_blocks(cls, data: object) -> object:
        """Ignore top-level ``x-``/``_`` keys — the YAML anchor idiom.

        Shared fragments are declared as a top-level key and referenced with
        ``*alias``; the key itself is not config. Every other unknown key is
        rejected, here and in every nested model.
        """
        if not isinstance(data, dict):
            return data
        items = cast("dict[object, object]", data).items()
        return {
            key: value
            for key, value in items
            if not (isinstance(key, str) and key.startswith(("x-", "_")))
        }

    sources: list[SourceConfig] = Field(default_factory=list[SourceConfig])
    adapters: list[LocalAdapterConfig] = Field(default_factory=list[LocalAdapterConfig])
    agents: dict[str, AgentRecord] = Field(default_factory=dict)
    attestation: AttestationConfig = Field(default_factory=AttestationConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    session_store: SessionStoreConfig = Field(default_factory=SessionStoreConfig)
    session_tokens: SessionTokenConfig = Field(default_factory=SessionTokenConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    # Where Nautilus writes state of its own -- today the schema-drift
    # baselines under ``.nautilus/adapters/fingerprints/``. Defaults to the
    # config file's directory, which every shipped deployment mounts
    # read-only, so a container or a Kubernetes Pod needs this pointed at a
    # writable volume for drift baselines to survive a restart. Relative paths
    # resolve against the config file's directory.
    state_dir: str | None = None
    rkm: RkmConfig = Field(default_factory=RkmConfig)
