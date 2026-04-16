"""``Broker`` — the public Nautilus facade (design §3.1, §8, §9).

Wires every Phase 1 collaborator (``SourceRegistry``,
:class:`PatternMatchingIntentAnalyzer`, :class:`FathomRouter`, per-source
``Adapter``, :class:`BasicSynthesizer`, :class:`AuditLogger`,
``AttestationService``, :class:`InMemorySessionStore`) behind a sync
``request`` / async ``arequest`` surface.

Key design points:
- Event-loop guard (design §8): sync ``request`` raises ``RuntimeError``
  with a pointer to ``arequest`` if called inside a running loop.
- Single audit entry per request — success OR failure (NFR-8, §9.2).
- Adapter runtime exceptions are caught per-source and surfaced in
  ``sources_errored``; Fathom/engine failures raise ``PolicyEngineError``
  to the caller after emitting the audit entry (design §10).
- Attestation auto-generates an Ed25519 keypair unless
  ``attestation.private_key_path`` is set; disabled via
  ``attestation.enabled: false`` — token is ``None`` in that case (§9.4).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib.metadata
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal

from fathom.attestation import AttestationService
from fathom.audit import FileSink

from nautilus.adapters.base import Adapter, AdapterError, ScopeEnforcementError
from nautilus.adapters.elasticsearch import ElasticsearchAdapter
from nautilus.adapters.embedder import Embedder, NoopEmbedder
from nautilus.adapters.influxdb import InfluxDBAdapter
from nautilus.adapters.neo4j import Neo4jAdapter
from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.adapters.rest import RestAdapter
from nautilus.adapters.s3 import S3Adapter
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.analysis.fallback import FallbackIntentAnalyzer
from nautilus.analysis.llm.base import LLMIntentProvider, LLMProvenance
from nautilus.analysis.pattern_matching import PatternMatchingIntentAnalyzer
from nautilus.audit.logger import AuditLogger
from nautilus.config.agent_registry import AgentRegistry, UnknownAgentError
from nautilus.config.loader import ConfigError, load_config
from nautilus.config.models import (
    AnalysisProviderSpec,
    AnthropicProviderSpec,
    FileSinkSpec,
    HttpSinkSpec,
    LocalInferenceProviderSpec,
    NautilusConfig,
    NullSinkSpec,
    OpenAIProviderSpec,
    SourceConfig,
)
from nautilus.config.registry import SourceRegistry
from nautilus.core import PolicyEngineError
from nautilus.core.attestation_payload import build_payload
from nautilus.core.attestation_sink import (
    AttestationPayload,
    AttestationSink,
    FileAttestationSink,
    HttpAttestationSink,
    NullAttestationSink,
    RetryPolicy,
)
from nautilus.core.fathom_router import FathomRouter
from nautilus.core.models import (
    AdapterResult,
    AuditEntry,
    BrokerResponse,
    DenialRecord,
    ErrorRecord,
    HandoffDecision,
    IntentAnalysis,
    RoutingDecision,
    ScopeConstraint,
)
from nautilus.core.session import AsyncSessionStore, InMemorySessionStore, SessionStore
from nautilus.core.session_pg import PostgresSessionStore
from nautilus.core.temporal import TemporalFilter
from nautilus.observability.metrics import NautilusMetrics
from nautilus.observability.spans import (
    SPAN_ADAPTER_FAN_OUT,
    SPAN_ATTESTATION_SIGN,
    SPAN_AUDIT_EMIT,
    SPAN_BROKER_REQUEST,
    SPAN_FATHOM_ROUTING,
    SPAN_INTENT_ANALYSIS,
    SPAN_SYNTHESIS,
    broker_span,
    build_request_attributes,
)
from nautilus.rules import BUILT_IN_RULES_DIR
from nautilus.synthesis.basic import BasicSynthesizer

_metrics = NautilusMetrics()

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Adapter registry — static built-ins + entry-point discovery (design §3.5)
# ---------------------------------------------------------------------------

ADAPTER_REGISTRY: dict[str, type[Adapter]] = {
    "postgres": PostgresAdapter,
    "pgvector": PgVectorAdapter,
    "elasticsearch": ElasticsearchAdapter,
    "rest": RestAdapter,
    "neo4j": Neo4jAdapter,
    "servicenow": ServiceNowAdapter,
    "influxdb": InfluxDBAdapter,
    "s3": S3Adapter,
}


def _discover_adapters() -> dict[str, type[Adapter]]:
    """Load adapter classes advertised via ``nautilus.adapters`` entry points.

    Each entry point name is the ``source_type`` key and must resolve to an
    :class:`Adapter` subclass.  Broken plugins are logged and skipped so one
    bad third-party package can never take down the broker.

    Returns a dict that can be merged over :data:`ADAPTER_REGISTRY`.
    """
    discovered: dict[str, type[Adapter]] = {}
    eps = importlib.metadata.entry_points(group="nautilus.adapters")
    for ep in eps:
        try:
            obj: object = ep.load()
            if not isinstance(obj, type):
                log.warning(
                    "adapter entry-point '%s' resolved to non-class %s; skipping",
                    ep.name,
                    type(obj).__name__,
                )
                continue
            if not issubclass(obj, Adapter):  # type: ignore[arg-type]  # runtime_checkable Protocol w/ ClassVar
                log.warning(
                    "adapter entry-point '%s' resolved to %s, not an Adapter subclass; skipping",
                    ep.name,
                    obj.__name__,
                )
                continue
            discovered[ep.name] = obj
            log.debug("discovered adapter entry-point %s -> %s", ep.name, obj)
        except Exception:  # noqa: BLE001
            log.warning(
                "failed to load adapter entry-point '%s' (%s); skipping",
                ep.name,
                ep.value,
                exc_info=True,
            )
    return discovered


if TYPE_CHECKING:
    from nautilus.analysis.base import IntentAnalyzer
    from nautilus.core.fathom_router import RouteResult
    from nautilus.synthesis.base import Synthesizer


@dataclass
class _RequestState:
    """Mutable per-request scratchpad shared by ``arequest`` helpers.

    Pre-declared so the broker's except blocks can still emit a best-effort
    audit entry even when the pipeline fails mid-flight (design §9.2).
    """

    request_id: str
    session_id: str
    started: float
    intent: str
    intent_analysis: IntentAnalysis
    routing_decisions: list[RoutingDecision] = field(default_factory=list[RoutingDecision])
    scope_by_source: dict[str, list[ScopeConstraint]] = field(
        default_factory=dict[str, list[ScopeConstraint]]
    )
    denial_records: list[Any] = field(default_factory=list[Any])
    rule_trace: list[str] = field(default_factory=list[str])
    facts_summary: dict[str, int] = field(default_factory=dict[str, int])
    sources_queried: list[str] = field(default_factory=list[str])
    sources_denied: list[str] = field(default_factory=list[str])
    sources_skipped: list[str] = field(default_factory=list[str])
    errored: list[ErrorRecord] = field(default_factory=list[ErrorRecord])
    data: dict[str, list[dict[str, Any]]] = field(default_factory=dict[str, list[dict[str, Any]]])
    attestation_token: str | None = None
    scope_hash_version: Literal["v1", "v2"] | None = None  # set by `_sign`
    # LLM provenance — populated only when the wired analyzer is a
    # :class:`FallbackIntentAnalyzer`. Phase-1 pipelines leave this ``None``
    # so the resulting :class:`AuditEntry` round-trips byte-identically
    # (NFR-5/NFR-6).
    llm_provenance: LLMProvenance | None = None

    def apply_route_result(self, route_result: RouteResult) -> None:
        """Copy router output into the mutable request state."""
        self.routing_decisions = route_result.routing_decisions
        self.scope_by_source = route_result.scope_constraints
        self.denial_records = route_result.denial_records
        self.rule_trace = list(route_result.rule_trace)
        self.facts_summary = dict(route_result.facts_asserted_summary)

    def duration_ms(self) -> int:
        """Integer millisecond delta since ``started`` (design §4.1)."""
        return int((time.perf_counter() - self.started) * 1000)


def _new_request_state(context: dict[str, Any], intent: str) -> _RequestState:
    """Factory for a fresh per-request scratchpad."""
    return _RequestState(
        request_id=str(uuid.uuid4()),
        session_id=str(context.get("session_id", "")),
        started=time.perf_counter(),
        intent=intent,
        intent_analysis=IntentAnalysis(raw_intent=intent, data_types_needed=[], entities=[]),
    )


def _broker_error(exc: BaseException, request_id: str) -> ErrorRecord:
    """Wrap an unexpected broker-level exception as an :class:`ErrorRecord`."""
    return ErrorRecord(
        source_id="<broker>",
        error_type=type(exc).__name__,
        message=str(exc),
        trace_id=request_id,
    )


def _source_error(source_id: str, error_type: str, message: str, request_id: str) -> ErrorRecord:
    """Build a per-source :class:`ErrorRecord` tagged with the request trace id."""
    return ErrorRecord(
        source_id=source_id,
        error_type=error_type,
        message=message,
        trace_id=request_id,
    )


def _build_audit_entry(
    agent_id: str,
    state: _RequestState,
    attestation_token: str | None,
    session_store_mode: Literal["primary", "degraded_memory"] | None,
) -> AuditEntry:
    """Materialize a flat :class:`AuditEntry` from pipeline state (design §4.9)."""
    prov = state.llm_provenance
    return AuditEntry(
        timestamp=AuditLogger.utcnow(),
        request_id=state.request_id,
        agent_id=agent_id,
        session_id=state.session_id or None,
        raw_intent=state.intent,
        intent_analysis=state.intent_analysis,
        facts_asserted_summary=state.facts_summary,
        routing_decisions=state.routing_decisions,
        scope_constraints=[c for cs in state.scope_by_source.values() for c in cs],
        denial_records=state.denial_records,
        error_records=state.errored,
        rule_trace=state.rule_trace,
        sources_queried=state.sources_queried,
        sources_denied=state.sources_denied,
        sources_skipped=state.sources_skipped,
        sources_errored=[e.source_id for e in state.errored],
        attestation_token=attestation_token,
        duration_ms=state.duration_ms(),
        scope_hash_version=state.scope_hash_version,
        session_store_mode=session_store_mode,
        event_type="request",
        # AC-6.5 — copy LLM provenance into the audit entry. Left ``None``
        # in Phase-1 / pattern-only mode so existing JSONL fixtures
        # round-trip unchanged (NFR-5).
        llm_provider=prov.provider if prov is not None else None,
        llm_model=prov.model if prov is not None else None,
        llm_version=prov.version if prov is not None else None,
        prompt_version=prov.prompt_version if prov is not None else None,
        raw_response_hash=prov.raw_response_hash if prov is not None else None,
        fallback_used=prov.fallback_used if prov is not None else None,
    )


class Broker:
    """Public Nautilus facade — the sole entry point per design §3.1.

    Construct via :meth:`from_config` for the normal flow; the constructor
    is kept public for unit tests that wire collaborators directly.
    """

    def __init__(
        self,
        *,
        config: NautilusConfig,
        registry: SourceRegistry,
        intent_analyzer: IntentAnalyzer | FallbackIntentAnalyzer,
        router: FathomRouter,
        adapters: dict[str, Adapter],
        synthesizer: Synthesizer,
        audit_logger: AuditLogger,
        attestation: AttestationService | None,
        session_store: SessionStore | AsyncSessionStore,
        agent_registry: AgentRegistry | None = None,
        attestation_sink: AttestationSink | None = None,
    ) -> None:
        self._config = config
        self._registry = registry
        self._intent_analyzer = intent_analyzer
        self._router = router
        self._adapters = adapters
        self._synthesizer = synthesizer
        self._audit_logger = audit_logger
        self._attestation = attestation
        self._session_store = session_store
        # Phase-1 YAML (no ``agents:``) yields an empty registry — preserves
        # NFR-5 backwards compatibility. Threaded into ``FathomRouter.route``
        # per design §2.2; the Phase-2 agent-fact enrichment rules consume it,
        # Phase-1 rules ignore it and materialize ``agent`` from ``context``.
        self._agent_registry: AgentRegistry = agent_registry or AgentRegistry({})
        # Attestation sink default is :class:`NullAttestationSink` so Phase-1
        # YAML without ``attestation.sink`` preserves NFR-5 backwards compat.
        # The token is still signed and returned on ``BrokerResponse``;
        # ``NullAttestationSink`` only skips the store-and-forward hop
        # (AC-14.4).
        self._attestation_sink: AttestationSink = attestation_sink or NullAttestationSink()
        self._closed: bool = False
        # Tracks which adapter ids have already been ``connect()``-ed so
        # ``arequest`` can lazy-connect on first use and skip on subsequent
        # calls (design §3.5 — adapter lifecycle is owned by the broker).
        self._connected_adapters: set[str] = set()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path) -> Broker:
        """Build a fully-wired :class:`Broker` from a ``nautilus.yaml`` path.

        Order of operations mirrors design §15 build sequence:
        1. Load + validate config.
        2. Build :class:`SourceRegistry`.
        3. Build :class:`PatternMatchingIntentAnalyzer` from
           ``analysis.keyword_map``.
        4. Build :class:`FathomRouter` against the built-in rules tree +
           any configured user rules.
        5. Build per-source :class:`Adapter` instances (NOT connected —
           ``connect()`` is async; first ``arequest`` is responsible).
        6. Build :class:`AuditLogger` over ``FileSink(audit.path)``.
        7. Build :class:`AttestationService` (auto-generate unless
           ``private_key_path``; return ``None`` if disabled).
        8. Build :class:`InMemorySessionStore`.

        Raises :class:`ConfigError` on bad YAML / missing env vars and
        :class:`PolicyEngineError` on engine construction failure.
        """
        config = load_config(path)

        registry = SourceRegistry(config.sources)
        agent_registry = AgentRegistry(config.agents)

        pattern_analyzer = PatternMatchingIntentAnalyzer(
            keyword_map=config.analysis.keyword_map,
        )
        intent_analyzer = cls._build_intent_analyzer(config, pattern_analyzer)

        attestation = cls._build_attestation(config)
        attestation_sink = cls._build_attestation_sink(config)

        user_rules_dirs = [Path(d) for d in config.rules.user_rules_dirs]
        router = FathomRouter(
            built_in_rules_dir=BUILT_IN_RULES_DIR,
            user_rules_dirs=user_rules_dirs,
            attestation=attestation,
        )

        # Broker-default embedder: strict NoopEmbedder (design §3.10 — fail
        # loudly on missing embedder rather than silent zero vectors).
        broker_default_embedder: Embedder = NoopEmbedder(strict=True)

        # Merge static registry with entry-point discovered plugins.
        adapter_registry = {**ADAPTER_REGISTRY, **_discover_adapters()}

        adapters: dict[str, Adapter] = {}
        for source in registry:
            adapters[source.id] = cls._build_adapter(
                source, broker_default_embedder, adapter_registry
            )

        audit_path = Path(config.audit.path)
        audit_logger = AuditLogger(sink=FileSink(path=audit_path))

        session_store = cls._build_session_store(config)

        synthesizer = BasicSynthesizer()

        return cls(
            config=config,
            registry=registry,
            intent_analyzer=intent_analyzer,
            router=router,
            adapters=adapters,
            synthesizer=synthesizer,
            audit_logger=audit_logger,
            attestation=attestation,
            session_store=session_store,
            agent_registry=agent_registry,
            attestation_sink=attestation_sink,
        )

    @classmethod
    def _build_intent_analyzer(
        cls,
        config: NautilusConfig,
        pattern_analyzer: PatternMatchingIntentAnalyzer,
    ) -> IntentAnalyzer | FallbackIntentAnalyzer:
        """Construct the wired intent analyzer per ``config.analysis.mode``.

        - ``"pattern"`` (default) → return ``pattern_analyzer`` unchanged so
          the broker hot path stays sync and Phase-1 audit JSONL round-trips
          byte-identically (NFR-5/NFR-6).
        - ``"llm-first"`` / ``"llm-only"`` → wrap a provider built from
          ``config.analysis.provider`` in :class:`FallbackIntentAnalyzer`
          with ``pattern_analyzer`` as the deterministic fallback (FR-14,
          AC-6.2).

        Raises :class:`ConfigError` when an LLM mode is requested without a
        provider spec (AC-6.4 surfaces the same failure under the CLI's
        ``--air-gapped`` override).
        """
        analysis = config.analysis
        if analysis.mode == "pattern":
            return pattern_analyzer
        if analysis.provider is None:
            raise ConfigError(
                f"analysis.mode={analysis.mode!r} requires analysis.provider to be set"
            )
        provider = cls._build_llm_provider(analysis.provider)
        return FallbackIntentAnalyzer(
            primary=provider,
            fallback=pattern_analyzer,
            timeout_s=analysis.timeout_s,
            mode=analysis.mode,
        )

    @staticmethod
    def _build_llm_provider(spec: AnalysisProviderSpec) -> LLMIntentProvider:
        """Instantiate an :class:`LLMIntentProvider` from a config spec (design §3.8).

        Discriminated-union dispatch on ``spec.type``; provider modules are
        imported lazily so optional extras (``llm-anthropic`` /
        ``llm-openai``) only blow up when actually requested.
        """
        if isinstance(spec, AnthropicProviderSpec):
            from nautilus.analysis.llm.anthropic_provider import AnthropicProvider

            return AnthropicProvider(
                api_key_env=spec.api_key_env,
                model=spec.model,
                timeout_s=spec.timeout_s,
            )
        if isinstance(spec, OpenAIProviderSpec):
            from nautilus.analysis.llm.openai_provider import OpenAIProvider

            return OpenAIProvider(
                api_key_env=spec.api_key_env,
                model=spec.model,
                timeout_s=spec.timeout_s,
            )
        # Discriminated union — only the local spec remains.
        assert isinstance(spec, LocalInferenceProviderSpec)
        from nautilus.analysis.llm.local_provider import LocalInferenceProvider

        return LocalInferenceProvider(
            base_url=spec.base_url,
            model=spec.model,
            api_key_env=spec.api_key_env,
            timeout_s=spec.timeout_s,
        )

    @staticmethod
    def _build_session_store(config: NautilusConfig) -> SessionStore | AsyncSessionStore:
        """Construct the session store per ``config.session_store.backend``.

        - ``memory`` (default) → :class:`InMemorySessionStore` (Phase-1 compat,
          NFR-5).
        - ``postgres`` → :class:`PostgresSessionStore` over ``dsn`` (or
          ``TEST_PG_DSN`` env var when ``dsn`` is unset, so integration
          fixtures reuse pg_container without duplicating YAML plumbing);
          ``on_failure`` flips between ``fail_closed`` and ``fallback_memory``
          (NFR-7).
        - ``redis`` → reserved; falls back to in-memory until Phase 2 lands a
          Redis adapter (intentional soft-land per design §3.11).
        """
        sess_cfg = config.session_store
        if sess_cfg.backend == "postgres":
            import os

            dsn = sess_cfg.dsn or os.environ.get("TEST_PG_DSN")
            if not dsn:
                raise ConfigError(
                    "session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var"
                )
            return PostgresSessionStore(dsn, on_failure=sess_cfg.on_failure)
        return InMemorySessionStore()

    @staticmethod
    def _build_attestation_sink(config: NautilusConfig) -> AttestationSink:
        """Construct the attestation sink per design §3.14 / FR-28.

        Selects the concrete :class:`AttestationSink` implementation based on
        ``config.attestation.sink.type``:

        - ``"null"`` (default) → :class:`NullAttestationSink` — no-op; preserves
          NFR-5 for Phase-1 YAML fixtures with no ``attestation.sink`` entry.
        - ``"file"`` → :class:`FileAttestationSink` — append-only JSONL with
          per-emit ``flush`` + ``os.fsync`` (AC-14.2).
        - ``"http"`` → :class:`HttpAttestationSink` — POST to verifier URL with
          retry + dead-letter spill (AC-14.3).
        """
        sink_spec = config.attestation.sink
        if isinstance(sink_spec, FileSinkSpec):
            return FileAttestationSink(Path(sink_spec.path))
        if isinstance(sink_spec, HttpSinkSpec):
            rp_spec = sink_spec.retry_policy
            retry_policy = RetryPolicy(
                max_retries=rp_spec.max_retries,
                initial_backoff_s=rp_spec.initial_backoff_s,
                max_backoff_s=rp_spec.max_backoff_s,
            )
            dead_letter = Path(sink_spec.dead_letter_path) if sink_spec.dead_letter_path else None
            return HttpAttestationSink(
                url=sink_spec.url,
                retry_policy=retry_policy,
                dead_letter_path=dead_letter,
            )
        # Must be NullSinkSpec by virtue of the pydantic discriminated union.
        assert isinstance(sink_spec, NullSinkSpec)
        return NullAttestationSink()

    @staticmethod
    def _build_attestation(config: NautilusConfig) -> AttestationService | None:
        """Construct the attestation service per design §9.4.

        - ``enabled: false`` → ``None`` (token omitted on every response).
        - ``private_key_path`` set → load PEM from path.
        - Otherwise → generate an ephemeral Ed25519 keypair.
        """
        if not config.attestation.enabled:
            return None
        key_path = config.attestation.private_key_path
        if key_path:
            key_bytes = Path(key_path).read_bytes()
            return AttestationService.from_private_key_bytes(key_bytes)
        return AttestationService.generate_keypair()

    @staticmethod
    def _build_adapter(
        source: SourceConfig,
        broker_default_embedder: Embedder,
        adapter_registry: dict[str, type[Adapter]] | None = None,
    ) -> Adapter:
        """Instantiate the right adapter class for ``source.type``.

        Looks up ``source.type`` in the merged adapter registry (static
        built-ins + entry-point discovered plugins).  ``pgvector`` is
        special-cased because it requires the broker-default embedder.
        """
        registry = adapter_registry if adapter_registry is not None else ADAPTER_REGISTRY

        # pgvector needs the embedder kwarg — special-case it.
        if source.type == "pgvector":
            return PgVectorAdapter(broker_default_embedder=broker_default_embedder)

        adapter_cls = registry.get(source.type)
        if adapter_cls is None:
            raise ConfigError(f"Unsupported source type '{source.type}' for id='{source.id}'")
        return adapter_cls()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def sources(self) -> list[SourceConfig]:
        """Registered source configs (identifier + metadata) — design §3.1."""
        return self._registry.sources

    @property
    def agent_registry(self) -> AgentRegistry:
        """Registered agent identities (design §3.5, FR-9)."""
        return self._agent_registry

    @property
    def session_store(self) -> SessionStore | AsyncSessionStore:
        """Active session store (sync or async surface) — design §3.2 / §3.9.

        Exposed so transports (``/readyz`` probe in :mod:`nautilus.transport.
        fastapi_app`) can call ``aget`` / ``get`` against the backing
        store without reaching into private state.
        """
        return self._session_store

    def request(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any] | None = None,
    ) -> BrokerResponse:
        """Sync request: guards against nested event loops, then runs pipeline.

        Per design §8, calling this while inside a running event loop
        raises :class:`RuntimeError` whose message mentions ``arequest``
        (UQ-4, AC-8.5). Outside a loop, we delegate to
        :meth:`arequest` via ``asyncio.run``.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — safe to take ownership of a fresh one.
            pass
        else:
            raise RuntimeError(
                "Broker.request() called inside a running event loop. "
                "Use Broker.arequest() (async) from async contexts."
            )
        return asyncio.run(self.arequest(agent_id, intent, context))

    async def arequest(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any] | None = None,
    ) -> BrokerResponse:
        """Async request pipeline (design §3.1, §8, §9).

        Linear sequence of awaits; heavy lifting lives in private helpers
        (`_run_pipeline`, `_build_adapter_jobs`, `_gather_adapter_results`,
        `_build_response`, `_emit_audit`). On policy-engine or unexpected
        failure, a single audit entry is still emitted before re-raising.
        """
        context = dict(context) if context else {}
        state = _new_request_state(context, intent)
        _started = time.perf_counter()
        with broker_span(SPAN_BROKER_REQUEST, build_request_attributes(agent_id)):
            _metrics.requests_total.add(1)
            try:
                await self._run_pipeline(agent_id, intent, context, state)
            except PolicyEngineError:
                with broker_span(SPAN_AUDIT_EMIT):
                    self._emit_audit(agent_id, state, None)
                raise
            except Exception as exc:  # noqa: BLE001 — any unexpected error must still audit
                state.errored.append(_broker_error(exc, state.request_id))
                with broker_span(SPAN_AUDIT_EMIT):
                    self._emit_audit(agent_id, state, None)
                raise
            with broker_span(SPAN_AUDIT_EMIT):
                self._emit_audit(agent_id, state, state.attestation_token)
            _metrics.request_duration.record(
                time.perf_counter() - _started,
            )
        return self._build_response(state)

    async def declare_handoff(
        self,
        *,
        source_agent_id: str,
        receiving_agent_id: str,
        session_id: str,
        data_classifications: list[str],
        rule_trace_refs: list[str] | None = None,
        data_compartments: list[str] | None = None,
    ) -> HandoffDecision:
        """Declare an agent-to-agent handoff and evaluate the handoff rule pack.

        Pure reasoning-only path (design §3.6, FR-8, FR-10, AC-4.1): zero
        adapter calls, zero session-store mutation. Flow:

        1. Resolve both agents via :class:`AgentRegistry`. An unknown id
           short-circuits to ``action="deny"`` with a synthetic
           ``unknown-agent`` :class:`DenialRecord` (AC-4.2).
        2. Assert one ``data_handoff`` fact per declared classification
           with ``from_clearance`` / ``to_clearance`` read from the
           registered :class:`AgentRecord` entries.
        3. Call :meth:`fathom.Engine.evaluate` — the
           ``information-flow-violation`` default rule + any user rules
           matching ``data_handoff`` fire here.
        4. Collect ``denial_record`` facts; ``action`` is ``"allow"``
           when none fired, ``"deny"`` otherwise. ``"escalate"`` is
           reserved for escalation-pack-driven denials and is not
           produced by the default rule set (AC-4.3).
        5. Emit exactly one :class:`AuditEntry` with
           ``event_type="handoff_declared"`` and the populated
           :class:`HandoffDecision`; never more (AC-4.4, NFR-15
           parallel).

        ``rule_trace_refs`` and ``data_compartments`` are accepted for
        forward-compat with the Phase-3 forensic worker + compartment-
        aware handoff rules; the default rule pack ignores both (empty
        compartments in the ``fathom-dominates`` calls).
        """
        del rule_trace_refs, data_compartments  # Phase-3 / forensic forward-compat.
        started = time.perf_counter()
        handoff_id = str(uuid.uuid4())

        # AC-4.2 — unknown-agent short-circuit: resolve BOTH agents before
        # touching the engine so a bogus id never asserts facts.
        try:
            source_agent = self._agent_registry.get(source_agent_id)
            receiving_agent = self._agent_registry.get(receiving_agent_id)
        except UnknownAgentError as exc:
            decision = HandoffDecision(
                handoff_id=handoff_id,
                action="deny",
                denial_records=[
                    DenialRecord(
                        source_id=session_id,
                        reason=str(exc),
                        rule_name="unknown-agent",
                    )
                ],
                rule_trace=[],
            )
            self._emit_handoff_audit(
                source_agent_id=source_agent_id,
                receiving_agent_id=receiving_agent_id,
                session_id=session_id,
                data_classifications=data_classifications,
                decision=decision,
                started=started,
            )
            return decision

        # Assert one data_handoff per declared classification, run engine,
        # and collect any denial_record facts. The engine is shared with
        # arequest() so we guard it with the same PolicyEngineError shape.
        engine = self._router.engine
        try:
            engine.clear_facts()
            for classification in data_classifications:
                engine.assert_fact(
                    "data_handoff",
                    {
                        "from_agent": source_agent_id,
                        "to_agent": receiving_agent_id,
                        "session_id": session_id,
                        "classification": classification,
                        "from_clearance": source_agent.clearance,
                        "to_clearance": receiving_agent.clearance,
                    },
                )
            eval_result = engine.evaluate()
            raw_denials = engine.query("denial_record")
        except Exception as exc:  # noqa: BLE001 — re-wrap as PolicyEngineError per §3.4
            raise PolicyEngineError(
                f"Broker.declare_handoff() failed for source={source_agent_id!r}"
                f" receiving={receiving_agent_id!r}: {exc}"
            ) from exc

        denials = [
            DenialRecord(
                source_id=str(d["source_id"]),
                reason=str(d["reason"]),
                rule_name=str(d["rule_name"]),
            )
            for d in raw_denials
        ]
        rule_trace = list(getattr(eval_result, "rule_trace", []) or [])
        action: Literal["allow", "deny", "escalate"] = "deny" if denials else "allow"

        decision = HandoffDecision(
            handoff_id=handoff_id,
            action=action,
            denial_records=denials,
            rule_trace=rule_trace,
        )
        self._emit_handoff_audit(
            source_agent_id=source_agent_id,
            receiving_agent_id=receiving_agent_id,
            session_id=session_id,
            data_classifications=data_classifications,
            decision=decision,
            started=started,
        )
        return decision

    def _emit_handoff_audit(
        self,
        *,
        source_agent_id: str,
        receiving_agent_id: str,
        session_id: str,
        data_classifications: list[str],
        decision: HandoffDecision,
        started: float,
    ) -> None:
        """Write the single ``event_type="handoff_declared"`` audit entry (AC-4.4).

        Uses the same :class:`AuditLogger` as ``arequest`` so operators
        see one JSONL stream. Non-handoff fields collapse to their
        zero values: no ``intent``, no ``routing_decisions``, no
        adapter-touching ``sources_*`` buckets. ``handoff_id`` and
        ``handoff_decision`` carry the full payload.
        """
        duration_ms = int((time.perf_counter() - started) * 1000)
        entry = AuditEntry(
            timestamp=AuditLogger.utcnow(),
            request_id=decision.handoff_id,
            agent_id=source_agent_id,
            session_id=session_id or None,
            raw_intent="",
            intent_analysis=None,
            facts_asserted_summary={"data_handoff": len(data_classifications)},
            routing_decisions=[],
            scope_constraints=[],
            denial_records=list(decision.denial_records),
            error_records=[],
            rule_trace=list(decision.rule_trace),
            sources_queried=[],
            sources_denied=[],
            sources_skipped=[],
            sources_errored=[],
            attestation_token=None,
            duration_ms=duration_ms,
            session_store_mode=self._session_store_mode(),
            event_type="handoff_declared",
            handoff_id=decision.handoff_id,
            handoff_decision=decision,
        )
        # receiving_agent_id is carried implicitly via handoff_decision context
        # on the surrounding AuditEntry; no dedicated column at this phase.
        del receiving_agent_id
        self._audit_logger.emit(entry)

    async def _analyze_intent(
        self,
        intent: str,
        context: dict[str, Any],
        state: _RequestState,
    ) -> None:
        """Run the wired intent analyzer; stamp LLM provenance when present.

        Two code paths (design §3.8, AC-6.5):

        * **Pattern-only (Phase-1 default).** ``self._intent_analyzer`` is a
          plain :class:`IntentAnalyzer` (sync ``analyze``). State carries a
          ``None`` :attr:`_RequestState.llm_provenance`, and the audit entry
          omits all LLM fields — preserving Phase-1 byte-identical JSONL
          (NFR-5/NFR-6).
        * **Fallback (``analysis.mode in {"llm-first","llm-only"}``).**
          ``self._intent_analyzer`` is a :class:`FallbackIntentAnalyzer`
          whose async ``analyze`` returns a ``(IntentAnalysis, LLMProvenance)``
          tuple. The provenance is stashed on ``state`` so
          :func:`_build_audit_entry` can copy each field onto the audit
          entry (FR-14, AC-6.5).
        """
        analyzer = self._intent_analyzer
        if isinstance(analyzer, FallbackIntentAnalyzer):
            analysis, provenance = await analyzer.analyze(intent, context)
            state.intent_analysis = analysis
            state.llm_provenance = provenance
            return
        state.intent_analysis = analyzer.analyze(intent, context)

    async def _run_pipeline(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any],
        state: _RequestState,
    ) -> None:
        """Happy-path pipeline body — mutates ``state`` in place."""
        with broker_span(SPAN_INTENT_ANALYSIS):
            await self._analyze_intent(intent, context, state)
        with broker_span(SPAN_FATHOM_ROUTING):
            await self._route(agent_id, context, state)
            _metrics.routing_decisions_total.add(1)
        self._merge_context_scope_constraints(context, state)
        self._apply_temporal_filter(state)
        with broker_span(SPAN_ADAPTER_FAN_OUT):
            tasks, task_source_ids = await self._build_adapter_jobs(state, context)
            successful = await self._gather_adapter_results(
                state,
                tasks,
                task_source_ids,
            )
        with broker_span(SPAN_SYNTHESIS):
            state.data = self._synthesizer.merge(successful)
        if self._attestation is not None:
            with broker_span(SPAN_ATTESTATION_SIGN):
                token, scope_hash_version, nautilus_payload = self._sign(
                    request_id=state.request_id,
                    agent_id=agent_id,
                    sources_queried=state.sources_queried,
                    scope_by_source=state.scope_by_source,
                    rule_trace=state.rule_trace,
                    session_id=state.session_id,
                )
            state.attestation_token = token
            state.scope_hash_version = scope_hash_version
            await self._emit_attestation(token, nautilus_payload)
        await self._update_session(state)

    async def _emit_attestation(
        self,
        token: str,
        nautilus_payload: dict[str, Any],
    ) -> None:
        """Store-and-forward the attestation payload; NEVER fails the hot path.

        Wraps ``self._attestation_sink.emit(...)`` in ``try/except Exception``
        and logs at WARNING on failure (AC-14.5, NFR-16). The audit entry is
        emitted regardless — the audit-first invariant means a sink outage
        cannot gate the request response. Per design §3.14 the token is
        still returned on :class:`BrokerResponse` (AC-14.4).
        """
        payload = AttestationPayload(
            token=token,
            nautilus_payload=nautilus_payload,
            emitted_at=datetime.now(tz=UTC),
        )
        try:
            await self._attestation_sink.emit(payload)
        except Exception as exc:  # noqa: BLE001 — audit-first invariant (AC-14.5)
            log.warning("attestation_sink.emit failed: %s", exc)

    @staticmethod
    def _merge_context_scope_constraints(
        context: dict[str, Any],
        state: _RequestState,
    ) -> None:
        """Fold ``context["scope_constraints"]`` into ``state.scope_by_source``.

        Additive channel so callers (notably the POC integration test) can
        attach row-level predicates that carry ``expires_at`` / ``valid_from``
        windows without a dedicated rule. Values must be
        :class:`ScopeConstraint` instances (or dicts coercible into one); the
        merge is a straight append per source_id so router-emitted constraints
        are preserved. A missing / empty key is a no-op (NFR-5).
        """
        raw: Any = context.get("scope_constraints")
        if not raw:
            return
        items: list[Any] = list(raw) if isinstance(raw, (list, tuple)) else [raw]  # pyright: ignore[reportUnknownArgumentType]
        for item in items:
            constraint = (
                item if isinstance(item, ScopeConstraint) else ScopeConstraint.model_validate(item)
            )
            state.scope_by_source.setdefault(constraint.source_id, []).append(constraint)

    def _apply_temporal_filter(self, state: _RequestState) -> None:
        """Drop expired / not-yet-valid scope constraints before adapter fan-out.

        Wires :meth:`TemporalFilter.apply` into ``arequest`` per design
        §3.9 / FR-17. Dropped constraints produce ``scope-expired``
        :class:`DenialRecord` entries that are appended to
        ``state.denial_records`` so they surface in the audit trail and
        the response's ``sources_denied`` aggregation.
        """
        filtered, temporal_denials = TemporalFilter.apply(
            state.scope_by_source,
            now=datetime.now(tz=UTC),
        )
        state.scope_by_source = filtered
        if temporal_denials:
            self._record_temporal_denials(state, temporal_denials)

    @staticmethod
    def _record_temporal_denials(
        state: _RequestState,
        denials: list[DenialRecord],
    ) -> None:
        """Fold temporal-filter denials into request state without re-denying sources.

        ``scope-expired`` only drops *individual constraints* — the source
        itself may still be routable under its remaining (non-expired)
        scope. We append the denial records to ``state.denial_records``
        for audit coverage but leave ``state.sources_denied`` untouched
        (that aggregator reflects whole-source denials from router rules).
        """
        state.denial_records = list(state.denial_records) + list(denials)

    async def _route(self, agent_id: str, context: dict[str, Any], state: _RequestState) -> None:
        """Invoke the Fathom router and classify sources into queried/denied/skipped.

        Prefers the async :meth:`AsyncSessionStore.aget` when the implementer
        provides it (design §3.2 — Phase-2 broker prefers async).
        """
        session_state = await self._session_get(state.session_id) if state.session_id else {}
        if state.session_id:
            session_state.setdefault("id", state.session_id)
        route_result = self._router.route(
            agent_id=agent_id,
            context=context,
            intent=state.intent_analysis,
            sources=self._registry.sources,
            session=session_state,
            agent_registry=self._agent_registry,
        )
        state.apply_route_result(route_result)
        state.sources_denied = sorted({d.source_id for d in state.denial_records})
        selected_ids = {rd.source_id for rd in state.routing_decisions}
        denied_ids = set(state.sources_denied)
        state.sources_skipped = sorted(
            s.id for s in self._registry if s.id not in selected_ids and s.id not in denied_ids
        )

    async def _update_session(self, state: _RequestState) -> None:
        """Cumulative-exposure bookkeeping (design §3.9 — update at end).

        Prefers :meth:`AsyncSessionStore.aupdate` when available; falls back
        to the sync Phase-1 surface for :class:`InMemorySessionStore`.
        """
        if not state.session_id:
            return
        entry = {
            "last_request_id": state.request_id,
            "last_sources_queried": state.sources_queried,
        }
        if hasattr(self._session_store, "aupdate"):
            await self._session_store.aupdate(state.session_id, entry)  # type: ignore[attr-defined]
            return
        # Sync fallback — only reachable when the store implements the Phase-1
        # :class:`SessionStore` Protocol (``update``). The union type widens to
        # include :class:`AsyncSessionStore` so pyright needs the explicit cast.
        sync_store: SessionStore = self._session_store  # type: ignore[assignment]
        sync_store.update(state.session_id, entry)

    async def _session_get(self, session_id: str) -> dict[str, Any]:
        """Read session state — async path when the store provides it."""
        if hasattr(self._session_store, "aget"):
            return await self._session_store.aget(session_id)  # type: ignore[attr-defined]
        sync_store: SessionStore = self._session_store  # type: ignore[assignment]
        return sync_store.get(session_id)

    async def _build_adapter_jobs(
        self,
        state: _RequestState,
        context: dict[str, Any],
    ) -> tuple[list[asyncio.Task[AdapterResult]], list[str]]:
        """Lazy-connect + spawn one task per routing decision (design §3.1)."""
        tasks: list[asyncio.Task[AdapterResult]] = []
        task_source_ids: list[str] = []
        for rd in state.routing_decisions:
            adapter = await self._prepare_adapter(rd.source_id, state)
            if adapter is None:
                continue
            scope = state.scope_by_source.get(rd.source_id, [])
            tasks.append(
                asyncio.create_task(
                    self._execute_adapter(
                        adapter, rd.source_id, state.intent_analysis, scope, context
                    )
                )
            )
            task_source_ids.append(rd.source_id)
        return tasks, task_source_ids

    async def _prepare_adapter(self, source_id: str, state: _RequestState) -> Adapter | None:
        """Resolve and lazy-connect the adapter for ``source_id``.

        Records per-source :class:`ErrorRecord`\\ s on lookup / connect failure
        and returns ``None`` so the caller can skip this source.
        """
        adapter = self._adapters.get(source_id)
        if adapter is None:
            state.errored.append(
                _source_error(
                    source_id,
                    "AdapterError",
                    f"No adapter registered for source '{source_id}'",
                    state.request_id,
                )
            )
            return None
        if source_id in self._connected_adapters:
            return adapter
        try:
            await adapter.connect(self._registry.get(source_id))
        except Exception as exc:  # noqa: BLE001 — surface as per-source error
            state.errored.append(
                _source_error(
                    source_id, type(exc).__name__, f"connect() failed: {exc}", state.request_id
                )
            )
            return None
        self._connected_adapters.add(source_id)
        return adapter

    async def _gather_adapter_results(
        self,
        state: _RequestState,
        tasks: list[asyncio.Task[AdapterResult]],
        task_source_ids: list[str],
    ) -> list[AdapterResult]:
        """Await ``tasks`` and split into successes / errors (into state)."""
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        successful: list[AdapterResult] = []
        for source_id, res in zip(task_source_ids, raw, strict=True):
            if isinstance(res, BaseException):
                state.errored.append(
                    _source_error(source_id, type(res).__name__, str(res), state.request_id)
                )
                continue
            if res.error is not None:
                state.errored.append(res.error)
                continue
            successful.append(res)
            state.sources_queried.append(source_id)
        return successful

    def _build_response(self, state: _RequestState) -> BrokerResponse:
        """Materialize the user-facing :class:`BrokerResponse` from ``state``."""
        return BrokerResponse(
            request_id=state.request_id,
            data=state.data,
            sources_queried=sorted(state.sources_queried),
            sources_denied=state.sources_denied,
            sources_skipped=state.sources_skipped,
            sources_errored=state.errored,
            scope_restrictions=state.scope_by_source,
            attestation_token=state.attestation_token,
            duration_ms=state.duration_ms(),
        )

    def _emit_audit(
        self,
        agent_id: str,
        state: _RequestState,
        attestation_token: str | None,
    ) -> None:
        """Build and hand the :class:`AuditEntry` to the logger (NFR-8, §9.2)."""
        self._audit_logger.emit(
            _build_audit_entry(agent_id, state, attestation_token, self._session_store_mode())
        )

    def _session_store_mode(self) -> Literal["primary", "degraded_memory"] | None:
        """Surface the session-store mode for the audit entry (NFR-7, design §3.2).

        :class:`PostgresSessionStore` exposes a ``mode`` property; the Phase-1
        in-memory store does not — Phase-1 audit lines therefore continue to
        carry ``session_store_mode: null`` (NFR-5 round-trip).
        """
        mode: Any = getattr(self._session_store, "mode", None)
        if mode in ("primary", "degraded_memory"):
            return mode  # type: ignore[no-any-return]
        return None

    async def _execute_adapter(
        self,
        adapter: Adapter,
        source_id: str,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Run one adapter; catch scope/adapter errors into a typed AdapterResult."""
        try:
            return await adapter.execute(intent, scope, context)
        except ScopeEnforcementError as exc:
            return AdapterResult(
                source_id=source_id,
                rows=[],
                duration_ms=0,
                error=ErrorRecord(
                    source_id=source_id,
                    error_type="ScopeEnforcementError",
                    message=str(exc),
                    trace_id="",  # filled in by caller via sources_errored
                ),
            )
        except AdapterError as exc:
            return AdapterResult(
                source_id=source_id,
                rows=[],
                duration_ms=0,
                error=ErrorRecord(
                    source_id=source_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    trace_id="",
                ),
            )

    def _sign(
        self,
        *,
        request_id: str,
        agent_id: str,
        sources_queried: list[str],
        scope_by_source: dict[str, list[ScopeConstraint]],
        rule_trace: list[str],
        session_id: str,
    ) -> tuple[str, Literal["v1", "v2"], dict[str, Any]]:
        """Compose the Nautilus attestation payload and sign it (design §9.3).

        Uses :func:`nautilus.core.attestation_payload.build_payload` so the
        ``scope_hash`` / ``rule_trace_hash`` derivation is deterministic
        (NFR-14) and unit-testable in isolation.

        ``AttestationService.sign()`` expects a Fathom ``EvaluationResult``;
        we shim one together (duck-typed via ``SimpleNamespace``) whose
        ``decision`` field carries a Nautilus marker. The Nautilus payload
        itself is passed via ``input_facts`` so the JWT's ``input_hash``
        covers the full (``scope_hash``, ``rule_trace_hash``, …) claim set.

        Returns ``(token, scope_hash_version, nautilus_payload)`` so callers
        can (1) stamp the version into :attr:`AuditEntry.scope_hash_version`
        (D-7, FR-19) and (2) hand the signed claim set to the attestation
        sink (design §3.14). The internal ``scope_by_source`` dict is passed
        straight to :func:`build_payload` so temporal-slot detection sees the
        raw :class:`ScopeConstraint` attributes; the v1 path flattens it
        back to the Phase-1 4-key shape in the legacy iteration order so
        Phase-1 tokens remain bit-for-bit reproducible (NFR-6).
        """
        if self._attestation is None:
            # pragma: no cover — caller guards on self._attestation
            raise RuntimeError("attestation is disabled")

        nautilus_payload, scope_hash_version = build_payload(
            request_id,
            agent_id,
            sources_queried,
            scope_by_source,
            list(rule_trace),
        )

        # Nautilus-specific decision marker; the Fathom JWT carries this as
        # the ``decision`` claim. The request_id and agent_id are embedded
        # so downstream verifiers don't need a separate Nautilus payload.
        decision = f"nautilus:{request_id}:agent={agent_id}"

        result = SimpleNamespace(
            decision=decision,
            rule_trace=list(rule_trace),
        )
        # Pass the full Nautilus payload as a single synthetic fact so the
        # JWT's ``input_hash`` binds both ``scope_hash`` and
        # ``rule_trace_hash`` (plus request_id / agent_id / sources_queried).
        input_facts: list[dict[str, Any]] = [nautilus_payload]
        session_ref = session_id or request_id
        token = self._attestation.sign(
            result=result,  # type: ignore[arg-type]
            session_id=session_ref,
            input_facts=input_facts,
        )
        return token, scope_hash_version, nautilus_payload

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """Idempotent async setup — stand up persistent session schema.

        Calls :meth:`PostgresSessionStore.setup` when the broker is wired with
        a Postgres-backed session store (design §3.2, UQ-1 / D-2). No-op for
        the Phase-1 :class:`~nautilus.core.session.InMemorySessionStore`.
        Safe to call multiple times; each implementer owns its own idempotency.
        """
        if isinstance(self._session_store, PostgresSessionStore):
            await self._session_store.setup()

    def close(self) -> None:
        """Idempotent sync close — FR-17, AC-8.6."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "Broker.close() called inside a running event loop. "
                "Use Broker.aclose() (async) from async contexts."
            )
        asyncio.run(self.aclose())

    async def aclose(self) -> None:
        """Idempotent async close. Safe to call multiple times (FR-17).

        Ordering contract (D-8, design §3.14, AC-14.6):
        ``session_store.aclose()`` → ``attestation_sink.close()`` →
        adapter-pool release. Session-store flush must precede sink close
        (session writes during request must land before sink teardown);
        adapter release comes last so in-flight emits can still reference
        pooled connections above. Any close is best-effort (one failing
        backend must not prevent others from closing).
        """
        if self._closed:
            return
        self._closed = True
        # 1. Session store: flush any in-flight writes before downstream close.
        if hasattr(self._session_store, "aclose"):
            with contextlib.suppress(Exception):
                await self._session_store.aclose()  # type: ignore[attr-defined]
        # 2. Attestation sink: release the store-and-forward handle AFTER
        #    session writes have flushed but BEFORE adapter pools go down —
        #    in-flight emits from step 1's session-state finalization may
        #    still reference adapter connections.
        with contextlib.suppress(Exception):
            await self._attestation_sink.close()
        # 3. Adapters — release pools last so in-flight attestation can still
        #    reference their connections above.
        for adapter in self._adapters.values():
            try:
                await adapter.close()
            except Exception:  # noqa: BLE001 — close is best-effort
                continue
        self._router.close()

    # ------------------------------------------------------------------
    # Hashing helpers (exposed for tests / §9.3 verifiers)
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_scope(scope_by_source: dict[str, list[ScopeConstraint]]) -> str:
        """SHA-256 of the stringified scope constraints — design §9.3."""
        buf: list[str] = []
        for source_id in sorted(scope_by_source):
            for c in scope_by_source[source_id]:
                buf.append(f"{source_id}|{c.field}|{c.operator}|{c.value!r}")
        return hashlib.sha256("\n".join(buf).encode()).hexdigest()


__all__ = ["Broker", "BrokerResponse"]
