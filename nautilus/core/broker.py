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
import importlib.util
import logging
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal, cast

from fathom.attestation import AttestationService
from fathom.audit import FileSink

from nautilus.adapters.base import Adapter, AdapterError, ScopeEnforcementError
from nautilus.adapters.elasticsearch import ElasticsearchAdapter
from nautilus.adapters.embedder import Embedder, NoopEmbedder
from nautilus.adapters.influxdb import InfluxDBAdapter
from nautilus.adapters.llm import LLMAdapter
from nautilus.adapters.neo4j import Neo4jAdapter
from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.adapters.rest import RestAdapter
from nautilus.adapters.s3 import S3Adapter
from nautilus.adapters.schema import SchemaFingerprintStore, classify_drift
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.analysis.fallback import FallbackIntentAnalyzer
from nautilus.analysis.llm.base import LLMIntentProvider, LLMProvenance
from nautilus.analysis.pattern_matching import (
    PatternMatchingIntentAnalyzer,
    build_keyword_map,
)
from nautilus.attestation.key_ring import KeyRing
from nautilus.attestation.session_token import (
    SessionTokenClaims,
    SessionTokenError,
    SessionTokenService,
)
from nautilus.audit.logger import AuditLogger
from nautilus.config.agent_registry import AgentRegistry, UnknownAgentError
from nautilus.config.loader import ConfigError, load_config
from nautilus.config.models import (
    AgentRecord,
    AnalysisProviderSpec,
    AnthropicProviderSpec,
    FileSinkSpec,
    HttpSinkSpec,
    LocalAdapterConfig,
    LocalInferenceProviderSpec,
    NautilusConfig,
    NullSinkSpec,
    OpenAIProviderSpec,
    SourceConfig,
)
from nautilus.config.registry import SourceRegistry
from nautilus.core import PolicyEngineError
from nautilus.core.attestation_payload import build_payload, compute_response_hash
from nautilus.core.attestation_sink import (
    AttestationPayload,
    AttestationSink,
    ChainedFileAttestationSink,
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
from nautilus.core.session_sqlite import SqliteSessionStore
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
from nautilus.rules.facts import load_manual_relationships
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
    "llm": LLMAdapter,
}


def _adapter_protocol_gaps(obj: type) -> list[str]:
    """Names of :class:`Adapter` protocol members missing from ``obj``.

    ``issubclass(obj, Adapter)`` raises ``TypeError`` because the protocol
    carries the non-method ``source_type`` ClassVar, so conformance is
    checked structurally: the three lifecycle methods must be callable and
    ``source_type`` must be present.
    """
    gaps = [m for m in ("connect", "execute", "close") if not callable(getattr(obj, m, None))]
    if not isinstance(getattr(obj, "source_type", None), str):
        gaps.append("source_type")
    return gaps


def _discover_adapters() -> dict[str, type[Adapter]]:
    """Load adapter classes advertised via ``nautilus.adapters`` entry points.

    Each entry point name is the ``source_type`` key and must resolve to an
    :class:`Adapter` implementation.  Broken plugins are logged and skipped
    so one bad third-party package can never take down the broker.

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
            gaps = _adapter_protocol_gaps(obj)
            if gaps:
                log.warning(
                    "adapter entry-point '%s' resolved to %s, which is missing Adapter "
                    "protocol members %s; skipping",
                    ep.name,
                    obj.__name__,
                    gaps,
                )
                continue
            discovered[ep.name] = cast("type[Adapter]", obj)
            log.debug("discovered adapter entry-point %s -> %s", ep.name, obj)
        except Exception:  # noqa: BLE001
            log.warning(
                "failed to load adapter entry-point '%s' (%s); skipping",
                ep.name,
                ep.value,
                exc_info=True,
            )
    return discovered


def _load_local_adapters(
    adapter_configs: list[LocalAdapterConfig],
    *,
    base_dir: Path,
) -> dict[str, type[Adapter]]:
    """Load adapter classes from local-path ``adapters:`` config entries (#17).

    Unlike entry-point discovery (best-effort: broken third-party plugins
    are skipped), local-path entries are explicit operator config — any
    failure raises :class:`ConfigError` so a typo'd path or class name
    can't be silently masked.

    Relative ``module_path`` resolves against ``base_dir`` (the config-file
    directory). The declared ``source_type`` must match the class's
    ``source_type`` ClassVar.

    Security note: the module is executed with the broker's privileges.
    ``adapters:`` entries carry the same trust as installed packages; the
    config file must only be writable by the operator.
    """
    loaded: dict[str, type[Adapter]] = {}
    registered: list[str] = []  # sys.modules names to roll back on failure
    try:
        for i, cfg in enumerate(adapter_configs):
            module_path = Path(cfg.module_path)
            if not module_path.is_absolute():
                module_path = base_dir / module_path
            if not module_path.is_file():
                raise ConfigError(
                    f"adapters[{i}]: module_path does not exist or is not a file: {module_path}"
                )

            module_name = f"nautilus_local_adapter_{i}_{module_path.stem}"
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                raise ConfigError(f"adapters[{i}]: cannot import module from {module_path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            registered.append(module_name)
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                raise ConfigError(f"adapters[{i}]: error executing {module_path}: {exc}") from exc

            obj: object = getattr(module, cfg.class_name, None)
            if obj is None:
                raise ConfigError(
                    f"adapters[{i}]: class '{cfg.class_name}' not found in {module_path}"
                )
            if not isinstance(obj, type):
                raise ConfigError(
                    f"adapters[{i}]: '{cfg.class_name}' in {module_path} is not a class"
                )
            gaps = _adapter_protocol_gaps(obj)
            if gaps:
                raise ConfigError(
                    f"adapters[{i}]: '{cfg.class_name}' in {module_path} does not implement "
                    f"the Adapter protocol (missing: {gaps})"
                )
            actual_type = getattr(obj, "source_type", None)
            if actual_type != cfg.source_type:
                raise ConfigError(
                    f"adapters[{i}]: declared source_type='{cfg.source_type}' does not match "
                    f"{cfg.class_name}.source_type={actual_type!r} in {module_path}"
                )

            loaded[cfg.source_type] = cast("type[Adapter]", obj)
            log.info(
                "loaded local adapter %s from %s as source type '%s'",
                cfg.class_name,
                module_path,
                cfg.source_type,
            )
    except ConfigError:
        # Fail closed without residue: a half-loaded adapter list must not
        # leave earlier modules registered in sys.modules.
        for name in registered:
            sys.modules.pop(name, None)
        raise
    return loaded


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
    # Per-source chain-of-custody digests (issue #19, design §5.7). Computed by
    # the broker over each source's returned rows in ``_gather_adapter_results``
    # (never supplied by the adapter, issue #56 review); threaded into the signed
    # attestation as the ``source_response_hashes`` claim. Non-deterministic
    # adapters (llm) omit their entry so the broker still signs
    # ``hash_skipped=True`` (AC-19.g).
    source_response_hashes: dict[str, str] = field(default_factory=dict[str, str])
    attestation_token: str | None = None
    scope_hash_version: Literal["v1", "v2"] | None = None  # set by `_sign`
    # Session-provenance JWS (#18) — echoed/minted by `_process_session_token`
    # when session tokens are enabled; `None` otherwise (NFR-5).
    session_token: str | None = None
    # LLM provenance — populated only when the wired analyzer is a
    # :class:`FallbackIntentAnalyzer`. Phase-1 pipelines leave this ``None``
    # so the resulting :class:`AuditEntry` round-trips byte-identically
    # (NFR-5/NFR-6).
    llm_provenance: LLMProvenance | None = None
    # Caller-supplied fact-set hash echoed back on the response so client
    # session stores can pin a request to a specific fact snapshot.
    fact_set_hash: str | None = None

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
    session_store_mode: Literal["primary", "degraded_memory", "degraded_sqlite"] | None,
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
        # Per-source chain-of-custody digests on the canonical request entry so
        # they are verifiable from a single audit record — and are recorded even
        # when attestation/JWT signing is disabled (issue #56 review findings #1/#2).
        source_response_hashes=state.source_response_hashes or None,
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
        key_ring: KeyRing | None = None,
        session_token_ttl_s: int = 3600,
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
        # Adapters quarantined due to major schema drift (AC-21.e, PM Q3 LOCKED).
        # Requests targeting a quarantined adapter surface as ADAPTER_QUARANTINED
        # error records instead of routing to the adapter. Other adapters keep
        # serving normally — quarantine is per-adapter, NOT broker-wide.
        self._quarantined_adapters: set[str] = set()
        # Session-provenance tokens (#18, AC-18.a–g). Active iff a KeyRing is
        # injected — ``from_config`` passes one only when
        # ``session_tokens.enabled: true``, so Phase-1 YAML keeps the token
        # path (and its audit events) entirely off (NFR-5). ``_instance_id``
        # scopes minted tokens to this broker (AC-18.d
        # broker_instance_mismatch); the KeyRing is in-memory, so transports
        # MUST share this ring (via :attr:`key_ring`) for verification to work.
        self._instance_id: str = str(uuid.uuid4())
        self._key_ring: KeyRing | None = key_ring
        self._session_tokens: SessionTokenService | None = (
            SessionTokenService(
                key_ring=key_ring,
                broker_instance_id=self._instance_id,
                ttl_seconds=session_token_ttl_s,
            )
            if key_ring is not None
            else None
        )

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, path: str | Path) -> Broker:
        """Build a fully-wired :class:`Broker` from a ``nautilus.yaml`` path.

        Order of operations mirrors design §15 build sequence:
        1. Load + validate config.
        2. Build :class:`SourceRegistry`.
        3. Build :class:`PatternMatchingIntentAnalyzer` from the keyword map
           auto-generated from each source's ``data_types`` (#24), overlaid
           with explicit ``analysis.keyword_map`` entries.
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

        # Auto-generate base intent vocabulary from each source's declared
        # ``data_types`` (#24); explicit ``analysis.keyword_map`` entries
        # overlay and win on key collision.
        keyword_map = build_keyword_map(registry.sources, config.analysis.keyword_map)
        pattern_analyzer = PatternMatchingIntentAnalyzer(
            keyword_map=keyword_map,
        )
        intent_analyzer = cls._build_intent_analyzer(config, pattern_analyzer)

        attestation = cls._build_attestation(config)
        attestation_sink = cls._build_attestation_sink(config, attestation)

        user_rules_dirs = [Path(d) for d in config.rules.user_rules_dirs]
        router = FathomRouter(
            built_in_rules_dir=BUILT_IN_RULES_DIR,
            user_rules_dirs=user_rules_dirs,
            attestation=attestation,
            check_consistency=config.rules.consistency_checks,
        )

        # AC-35.2.b/d — load manual relationship facts into the engine at
        # startup; re-reading on every broker construction gives restart
        # persistence. The directory is optional: missing = no-op.
        _facts_dir = Path(path).parent / "facts" / "relationships"
        if _facts_dir.is_dir():
            load_manual_relationships(router.engine, _facts_dir)

        # Broker-default embedder: strict NoopEmbedder (design §3.10 — fail
        # loudly on missing embedder rather than silent zero vectors).
        broker_default_embedder: Embedder = NoopEmbedder(strict=True)

        # Merge static registry with entry-point discovered plugins and
        # local-path adapters (#17). Explicit config wins over discovery.
        adapter_registry = {
            **ADAPTER_REGISTRY,
            **_discover_adapters(),
            **_load_local_adapters(config.adapters, base_dir=Path(path).parent),
        }

        adapters: dict[str, Adapter] = {}
        for source in registry:
            adapters[source.id] = cls._build_adapter(
                source, broker_default_embedder, adapter_registry
            )

        audit_path = Path(config.audit.path)
        audit_logger = AuditLogger(sink=FileSink(path=audit_path))

        session_store = cls._build_session_store(config, base_dir=Path(path).parent)

        synthesizer = BasicSynthesizer()

        # Session-provenance tokens (#18) — KeyRing only when enabled, so
        # Phase-1 YAML keeps the token path entirely off (NFR-5).
        key_ring = KeyRing() if config.session_tokens.enabled else None

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
            key_ring=key_ring,
            session_token_ttl_s=config.session_tokens.ttl_seconds,
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
    def _build_session_store(
        config: NautilusConfig, *, base_dir: Path
    ) -> SessionStore | AsyncSessionStore:
        """Construct the session store per ``config.session_store.backend``.

        - ``memory`` (default) → :class:`InMemorySessionStore` (Phase-1 compat,
          NFR-5).
        - ``postgres`` → :class:`PostgresSessionStore` over ``dsn`` (or
          ``TEST_PG_DSN`` env var when ``dsn`` is unset, so integration
          fixtures reuse pg_container without duplicating YAML plumbing);
          ``on_failure`` selects ``fail_closed``, ``fallback_memory``, or
          ``fallback_sqlite`` at ``sqlite_path`` (NFR-7, #26).
        - ``sqlite`` → :class:`SqliteSessionStore` at ``sqlite_path`` —
          durable single-node store, no Postgres required (#26).
        - ``redis`` → reserved; falls back to in-memory until Phase 2 lands a
          Redis adapter (intentional soft-land per design §3.11).

        A relative ``sqlite_path`` is resolved against ``base_dir`` (the
        config file's directory — same convention as the ``facts/`` dir)
        so the database location does not depend on the process CWD; a
        restart from a different working directory must reopen the SAME
        store, not silently mint an empty one.
        """
        sess_cfg = config.session_store
        sqlite_path = Path(sess_cfg.sqlite_path)
        if not sqlite_path.is_absolute():
            sqlite_path = base_dir / sqlite_path
        if sess_cfg.backend == "postgres":
            import os

            dsn = sess_cfg.dsn or os.environ.get("TEST_PG_DSN")
            if not dsn:
                raise ConfigError(
                    "session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var"
                )
            return PostgresSessionStore(
                dsn,
                on_failure=sess_cfg.on_failure,
                sqlite_path=sqlite_path,
            )
        if sess_cfg.backend == "sqlite":
            return SqliteSessionStore(sqlite_path)
        return InMemorySessionStore()

    @staticmethod
    def _build_attestation_sink(
        config: NautilusConfig, attestation: AttestationService | None
    ) -> AttestationSink:
        """Construct the attestation sink per design §3.14 / FR-28.

        Selects the concrete :class:`AttestationSink` implementation based on
        ``config.attestation.sink.type``:

        - ``"null"`` (default) → :class:`NullAttestationSink` — no-op; preserves
          NFR-5 for Phase-1 YAML fixtures with no ``attestation.sink`` entry.
        - ``"file"`` → :class:`FileAttestationSink` — append-only JSONL with
          per-emit ``flush`` + ``os.fsync`` (AC-14.2); with ``chained: true``,
          :class:`ChainedFileAttestationSink` — hash-chained + JWS-signed
          lines verifiable offline via ``nautilus attestation verify``.
        - ``"http"`` → :class:`HttpAttestationSink` — POST to verifier URL with
          retry + dead-letter spill (AC-14.3).
        """
        sink_spec = config.attestation.sink
        if isinstance(sink_spec, FileSinkSpec):
            if sink_spec.chained:
                if attestation is None:
                    msg = "attestation.sink.chained requires attestation.enabled with a signing key"
                    raise ValueError(msg)
                return ChainedFileAttestationSink(
                    Path(sink_spec.path),
                    attestation,
                    checkpoint_interval=sink_spec.checkpoint_interval,
                )
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

    @property
    def instance_id(self) -> str:
        """Per-process broker identity baked into session-token claims (#18).

        Tokens minted by this broker carry ``broker_instance_id`` and fail
        verification (``broker_instance_mismatch``) against any other
        instance (AC-18.d).
        """
        return self._instance_id

    @property
    def key_ring(self) -> KeyRing | None:
        """Signing/verification key ring for session tokens (#18, AC-18.e).

        ``None`` when ``session_tokens.enabled`` is false. The ring is
        in-memory — transports MUST reuse this instance (not construct a
        fresh :class:`KeyRing`) or token verification cannot succeed.
        """
        return self._key_ring

    @property
    def session_tokens(self) -> SessionTokenService | None:
        """Active :class:`SessionTokenService`, or ``None`` when disabled (#18)."""
        return self._session_tokens

    def issue_session_token(
        self,
        *,
        session_id: str,
        agent_id: str,
        purpose: str,
        clearance: str,
    ) -> str:
        """Mint a session token + emit ``session_token_issued`` audit (AC-18.f).

        Public surface for transports (``POST /v1/sessions``) so token
        issuance is always audited through the broker's single JSONL stream.

        Raises:
            RuntimeError: when session tokens are disabled.
        """
        if self._session_tokens is None:
            raise RuntimeError("session tokens are disabled (session_tokens.enabled: false)")
        token = self._session_tokens.issue(
            session_id=session_id,
            agent_id=agent_id,
            purpose=purpose,
            clearance=clearance,
        )
        self._emit_session_token_event(
            "session_token_issued",
            agent_id=agent_id,
            session_id=session_id,
            request_id=str(uuid.uuid4()),
        )
        return token

    def verify_session_token(self, token: str) -> SessionTokenClaims:
        """Verify a session token; audit failures (AC-18.d + AC-18.f).

        Returns the decoded claims on success. On failure, emits a
        ``session_token_verification_failed`` audit entry carrying the
        ``reason_code`` as an :class:`ErrorRecord` and re-raises the
        :class:`SessionTokenError` (fail-closed).

        Raises:
            RuntimeError: when session tokens are disabled.
            SessionTokenError: tampered / expired / unknown-kid /
                wrong-instance token.
        """
        if self._session_tokens is None:
            raise RuntimeError("session tokens are disabled (session_tokens.enabled: false)")
        try:
            return self._session_tokens.verify(token)
        except SessionTokenError as exc:
            request_id = str(uuid.uuid4())
            self._emit_session_token_event(
                "session_token_verification_failed",
                agent_id="",
                session_id="",
                request_id=request_id,
                errors=[
                    ErrorRecord(
                        source_id="<broker>",
                        error_type=exc.reason_code,
                        message=str(exc),
                        trace_id=request_id,
                    )
                ],
            )
            raise

    def rotate_signing_key(self, *, reviewer: str) -> str:
        """Rotate the session-token signing key on a LIVE broker (#25).

        Mints a new primary in the shared :class:`KeyRing`; the previous
        primary moves to ``rotating-out`` so in-flight tokens keep
        verifying (grace window). Agents presenting old-kid tokens are
        lazily re-signed on their next request (see
        :meth:`_process_session_token`). The grace window is closed
        explicitly via :meth:`revoke_signing_key`.

        Emits a ``signing_key_rotated`` audit entry recording the reviewer
        and the previous/new kid linkage.

        Returns:
            The new primary kid.

        Raises:
            RuntimeError: when session tokens are disabled.
        """
        if self._key_ring is None:
            raise RuntimeError("session tokens are disabled (session_tokens.enabled: false)")
        previous = self._key_ring.primary().kid
        new_entry = self._key_ring.rotate()
        self._emit_session_token_event(
            "signing_key_rotated",
            agent_id="",
            session_id="",
            request_id=str(uuid.uuid4()),
            trace=[
                f"reviewer={reviewer}",
                f"previous_kid={previous}",
                f"new_kid={new_entry.kid}",
            ],
        )
        return new_entry.kid

    def revoke_signing_key(self, kid: str, *, reason: str, reviewer: str) -> None:
        """Revoke a signing key immediately on a LIVE broker (#25).

        Tokens signed by ``kid`` stop verifying at once —
        :meth:`SessionTokenService.verify` rejects revoked entries — so
        this is the explicit end of a rotation's grace window.

        Emits a ``signing_key_revoked`` audit entry.

        Raises:
            RuntimeError: when session tokens are disabled.
            KeyError: when ``kid`` is not in the ring.
            ValueError: when ``kid`` is the current primary — revoking it
                would make :meth:`KeyRing.primary` silently auto-generate
                an unaudited replacement (security review C1). Rotate
                first, then revoke the rotated-out key.
        """
        if self._key_ring is None:
            raise RuntimeError("session tokens are disabled (session_tokens.enabled: false)")
        if self._key_ring.verifier_for(kid) is None:
            raise KeyError(kid)
        if kid == self._key_ring.primary().kid:
            raise ValueError(f"kid {kid!r} is the current primary; rotate first, then revoke")
        self._key_ring.revoke(kid, reason=reason, reviewer=reviewer)
        self._emit_session_token_event(
            "signing_key_revoked",
            agent_id="",
            session_id="",
            request_id=str(uuid.uuid4()),
            trace=[f"reviewer={reviewer}", f"kid={kid}", f"reason={reason}"],
        )

    def request(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any] | None = None,
        *,
        fact_set_hash: str | None = None,
    ) -> BrokerResponse:
        """Sync request: guards against nested event loops, then runs pipeline.

        Per design §8, calling this while inside a running event loop
        raises :class:`RuntimeError` whose message mentions ``arequest``
        (UQ-4, AC-8.5). Outside a loop, we delegate to
        :meth:`arequest` via ``asyncio.run``.

        ``fact_set_hash`` (US-6 / FR-62 opaque round-trip) is accepted
        and echoed onto :attr:`BrokerResponse.fact_set_hash`; populating
        the audit/cost-cap pipeline that consumes it is staged work.
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
        return asyncio.run(self.arequest(agent_id, intent, context, fact_set_hash=fact_set_hash))

    async def arequest(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any] | None = None,
        *,
        fact_set_hash: str | None = None,
    ) -> BrokerResponse:
        """Async request pipeline (design §3.1, §8, §9).

        Linear sequence of awaits; heavy lifting lives in private helpers
        (`_run_pipeline`, `_build_adapter_jobs`, `_gather_adapter_results`,
        `_build_response`, `_emit_audit`). On policy-engine or unexpected
        failure, a single audit entry is still emitted before re-raising.
        """
        context = dict(context) if context else {}
        state = _new_request_state(context, intent)
        state.fact_set_hash = fact_set_hash
        # Session-provenance gate (#18) — verify a presented token (fail-closed
        # with its own audit entry) or mint one for a fresh session, BEFORE the
        # pipeline runs so adapters see the token in ``context`` (AC-18.b).
        if self._session_tokens is not None:
            self._process_session_token(agent_id, context, state)
        _started = time.perf_counter()
        with broker_span(SPAN_BROKER_REQUEST, build_request_attributes(agent_id)):
            _metrics.requests_total.add(1)
            try:
                await self._run_pipeline(agent_id, intent, context, state)
            except PolicyEngineError as exc:
                # #27 — record the engine failure (e.g. ConsistencyError
                # check name) on the audit entry before failing closed.
                state.errored.append(_broker_error(exc, state.request_id))
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
        session_token: str | None = None,
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

        # #18 — when session tokens are enabled, a handoff REQUIRES the
        # originating agent's token; missing/invalid/mismatched tokens deny
        # before any agent resolution or engine work. The verified-token
        # trace marker lands in ``rule_trace`` so the handoff audit entry
        # records the token reference (kid + session) alongside both agent
        # ids (AC: "audit entry records both agent_ids and the token
        # reference").
        token_trace: list[str] = []
        if self._session_tokens is not None:
            token_denial = self._gate_handoff_token(
                session_token, source_agent_id, session_id, token_trace
            )
            if token_denial is not None:
                decision = HandoffDecision(
                    handoff_id=handoff_id,
                    action="deny",
                    denial_records=[token_denial],
                    rule_trace=list(token_trace),
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
                rule_trace=list(token_trace),
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
        rule_trace = token_trace + list(getattr(eval_result, "rule_trace", []) or [])
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

    def _gate_handoff_token(
        self,
        session_token: str | None,
        source_agent_id: str,
        session_id: str,
        token_trace: list[str],
    ) -> DenialRecord | None:
        """Validate the originating agent's token for a handoff (#18).

        Returns a :class:`DenialRecord` when the handoff must be denied
        (missing / invalid / agent-mismatched token), or ``None`` when the
        token verifies — in which case a ``session-token:verified`` marker
        (kid + agent + session) is appended to ``token_trace`` so the
        handoff audit entry carries the token reference.
        """
        assert self._session_tokens is not None  # noqa: S101 — caller gates
        if not session_token:
            return DenialRecord(
                source_id=session_id,
                reason="handoff requires the originating agent's session token",
                rule_name="session-token-required",
            )
        try:
            claims = self._session_tokens.verify(session_token)
        except SessionTokenError as exc:
            request_id = str(uuid.uuid4())
            self._emit_session_token_event(
                "session_token_verification_failed",
                agent_id=source_agent_id,
                session_id=session_id,
                request_id=request_id,
                errors=[
                    ErrorRecord(
                        source_id="<broker>",
                        error_type=exc.reason_code,
                        message=str(exc),
                        trace_id=request_id,
                    )
                ],
            )
            return DenialRecord(
                source_id=session_id,
                reason=f"session token rejected: {exc.reason_code}",
                rule_name="session-token-invalid",
            )
        if claims.agent_id != source_agent_id:
            return DenialRecord(
                source_id=session_id,
                reason=(
                    f"session token agent {claims.agent_id!r} does not match "
                    f"declared source agent {source_agent_id!r}"
                ),
                rule_name="session-token-agent-mismatch",
            )
        token_trace.append(
            f"session-token:verified kid={claims.kid} "
            f"agent={claims.agent_id} session={claims.session_id}"
        )
        return None

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
                    response=state.data or None,
                    source_response_hashes=state.source_response_hashes or None,
                )
            state.attestation_token = token
            state.scope_hash_version = scope_hash_version
            await self._emit_attestation(token, nautilus_payload, state.request_id)
        await self._update_session(state)

    async def _emit_attestation(
        self,
        token: str,
        nautilus_payload: dict[str, Any],
        request_id: str,
    ) -> None:
        """Store-and-forward the attestation payload; NEVER fails the hot path.

        Wraps ``self._attestation_sink.emit(...)`` in ``try/except Exception``
        and logs at WARNING on failure (AC-14.5, NFR-16). The audit entry is
        emitted regardless — the audit-first invariant means a sink outage
        cannot gate the request response. Per design §3.14 the token is
        still returned on :class:`BrokerResponse` (AC-14.4).

        Emits an ``attestation_emitted`` audit event (AC-19.b) after a
        successful sink write attempt. The event is schema_version=2 per
        design §4.9 / shared.md line 799.
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
        # AC-19.b — emit attestation_emitted audit event regardless of sink outcome.
        response_hash: str | None = nautilus_payload.get("response_hash")
        hash_skipped: bool = bool(nautilus_payload.get("hash_skipped", False))
        legacy: bool = response_hash is None and not hash_skipped
        # AC-19 / issue #56 review — persist the per-source digests so the
        # ``source_response_hashes`` claim is independently verifiable from the
        # audit log, not only from the signed JWT.
        source_response_hashes: dict[str, str] | None = nautilus_payload.get(
            "source_response_hashes"
        )
        self._audit_logger.emit(
            AuditEntry(
                timestamp=AuditLogger.utcnow(),
                request_id=request_id,
                agent_id="",
                facts_asserted_summary={},
                denial_records=[],
                error_records=[],
                rule_trace=[],
                sources_queried=[],
                sources_denied=[],
                sources_errored=[],
                duration_ms=0,
                event_type="attestation_emitted",
                schema_version=2,
                trace_id=request_id,
                raw_response_hash=response_hash if not legacy else None,
                source_response_hashes=source_response_hashes,
            )
        )

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

        Quarantined adapters return an ADAPTER_QUARANTINED error record so the
        broker never silently routes to a drifted adapter (AC-21.e, PM Q3).
        """
        if source_id in self._quarantined_adapters:
            state.errored.append(
                _source_error(
                    source_id,
                    "ADAPTER_QUARANTINED",
                    f"Adapter '{source_id}' is quarantined due to major schema drift. "
                    "Operator must acknowledge drift via schema-ack before resuming.",
                    state.request_id,
                )
            )
            return None

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
            # Per-source chain-of-custody hash (issue #19, AC-19), computed
            # centrally by the broker over each source's raw rows at this
            # pre-synthesis boundary. The digest is ALWAYS derived from the rows
            # the broker actually returns and attests; the adapter does not (and
            # cannot) supply it, so a malicious or buggy adapter cannot inject an
            # arbitrary hash into the signed attestation token (issue #56 review).
            # Non-deterministic adapters (llm) declare the ``non_deterministic``
            # capability and are omitted so ``_sign`` still emits
            # ``hash_skipped=True`` (AC-19.g).
            if not self._is_non_deterministic(source_id):
                state.source_response_hashes[source_id] = compute_response_hash(res.rows)
        return successful

    def _is_non_deterministic(self, source_id: str) -> bool:
        """True iff ``source_id``'s adapter declares the ``non_deterministic``
        capability (e.g. the llm adapter); such sources are never hashed (AC-19.g).
        """
        return "non_deterministic" in getattr(
            self._adapters.get(source_id), "capabilities", set[str]()
        )

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
            fact_set_hash=state.fact_set_hash,
            session_token=state.session_token,
        )

    def _process_session_token(
        self,
        agent_id: str,
        context: dict[str, Any],
        state: _RequestState,
    ) -> None:
        """Verify or mint the session-provenance token for this request (#18).

        Presented token (``context["session_token"]``):
        - invalid → emit ``session_token_verification_failed`` audit entry
          (ErrorRecord.error_type = reason_code) and re-raise
          :class:`SessionTokenError` — fail-closed, no pipeline run (AC-18.d).
        - valid → the token's ``session_id`` claim OVERRIDES any
          caller-declared session id. This is the core property: exposure
          tracking cannot be reset by declaring a fresh ``session_id``
          while presenting an old token (issue #18 "Why it matters").

        No token → mint one bound to (session_id, agent_id, purpose,
        clearance-from-registry), emit ``session_token_issued`` (AC-18.f),
        and inject it into ``context`` so adapters can forward it
        downstream (AC-18.b).
        """
        assert self._session_tokens is not None  # noqa: S101 — caller gates
        presented = context.get("session_token")
        if presented is not None:
            # Only the ABSENT key means "no token". Any present value —
            # including falsy ones like 0 / False / "" — goes through the
            # verification path so a caller can never suppress verification
            # (and force a session-resetting re-mint) by sending junk.
            try:
                if not isinstance(presented, str):
                    raise SessionTokenError("missing", "session_token must be a string")
                claims = self._session_tokens.verify(presented)
            except SessionTokenError as exc:
                state.errored.append(
                    ErrorRecord(
                        source_id="<broker>",
                        error_type=exc.reason_code,
                        message=str(exc),
                        trace_id=state.request_id,
                    )
                )
                self._emit_session_token_event(
                    "session_token_verification_failed",
                    agent_id=agent_id,
                    session_id=state.session_id,
                    request_id=state.request_id,
                    errors=list(state.errored),
                )
                raise
            state.session_id = claims.session_id
            state.session_token = presented
            # #25 lazy re-sign: a token signed by a rotating-out key still
            # verifies (grace window), but we hand back a fresh primary-signed
            # token on the response so agents converge on the new key without
            # a push channel — tokens are bearer credentials. The re-signed
            # token keeps the ORIGINAL expiry (security review C2): re-keying
            # must not extend the session's lifetime.
            assert self._key_ring is not None  # noqa: S101 — service implies ring
            if claims.kid != self._key_ring.primary().kid:
                fresh = self._session_tokens.issue(
                    session_id=claims.session_id,
                    agent_id=claims.agent_id,
                    purpose=claims.purpose,
                    clearance=claims.clearance,
                    expires_at=claims.expires_at,
                )
                state.session_token = fresh
                context["session_token"] = fresh
                self._emit_session_token_event(
                    "session_token_issued",
                    agent_id=claims.agent_id,
                    session_id=claims.session_id,
                    request_id=state.request_id,
                    trace=[f"resigned-from-kid={claims.kid}"],
                )
            return
        # First request in the session — mint a token. A missing session_id
        # gets a broker-generated one so the token always pins a session.
        if not state.session_id:
            state.session_id = str(uuid.uuid4())
            context["session_id"] = state.session_id
        record: AgentRecord | None
        try:
            record = self._agent_registry.get(agent_id)
        except UnknownAgentError:
            record = None
        purpose = str(context.get("purpose") or "") or (
            (record.default_purpose or "") if record is not None else ""
        )
        clearance = record.clearance if record is not None else ""
        token = self._session_tokens.issue(
            session_id=state.session_id,
            agent_id=agent_id,
            purpose=purpose,
            clearance=clearance,
        )
        state.session_token = token
        context["session_token"] = token
        self._emit_session_token_event(
            "session_token_issued",
            agent_id=agent_id,
            session_id=state.session_id,
            request_id=state.request_id,
        )

    def _emit_session_token_event(
        self,
        event_type: Literal[
            "session_token_issued",
            "session_token_verification_failed",
            "signing_key_rotated",
            "signing_key_revoked",
        ],
        *,
        agent_id: str,
        session_id: str,
        request_id: str,
        errors: list[ErrorRecord] | None = None,
        trace: list[str] | None = None,
    ) -> None:
        """Minimal audit entry for token/key lifecycle events (AC-18.f, #25).

        Mirrors the ``attestation_emitted`` pattern in
        :meth:`_emit_attestation` — non-request fields collapse to zero
        values; ``trace_id`` correlates back to the triggering request.
        ``trace`` markers (reviewer, kid linkage) land in ``rule_trace``.
        """
        self._audit_logger.emit(
            AuditEntry(
                timestamp=AuditLogger.utcnow(),
                request_id=request_id,
                agent_id=agent_id,
                session_id=session_id or None,
                facts_asserted_summary={},
                denial_records=[],
                error_records=list(errors) if errors else [],
                rule_trace=list(trace) if trace else [],
                sources_queried=[],
                sources_denied=[],
                sources_errored=[],
                duration_ms=0,
                event_type=event_type,
                schema_version=2,
                trace_id=request_id,
            )
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

    def _session_store_mode(
        self,
    ) -> Literal["primary", "degraded_memory", "degraded_sqlite"] | None:
        """Surface the session-store mode for the audit entry (NFR-7, design §3.2).

        :class:`PostgresSessionStore` exposes a ``mode`` property; the Phase-1
        in-memory store does not — Phase-1 audit lines therefore continue to
        carry ``session_store_mode: null`` (NFR-5 round-trip).
        """
        mode: Any = getattr(self._session_store, "mode", None)
        if mode in ("primary", "degraded_memory", "degraded_sqlite"):
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
        response: dict[str, Any] | None = None,
        source_response_hashes: dict[str, str] | None = None,
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

        # AC-19.g — if any queried adapter declares non-deterministic capability,
        # skip the *whole-response* hash and sign a hash_skipped=True claim
        # instead (DQ2 LOCKED). Adapters without a ``capabilities`` attribute
        # default to deterministic. Note: in a MIXED request (some deterministic
        # sources + an llm source) this is True yet ``source_response_hashes``
        # still carries the deterministic sources' per-source digests — see the
        # coexistence contract documented in ``build_payload``.
        hash_skipped = any(self._is_non_deterministic(sid) for sid in sources_queried)
        # AC-19.a — compute response hash; omit for non-deterministic adapters
        # and for legacy path (response=None, e.g. no data returned).
        if hash_skipped or response is None:
            response_hash: str | None = None
        else:
            response_hash = compute_response_hash(response)

        nautilus_payload, scope_hash_version = build_payload(
            request_id,
            agent_id,
            sources_queried,
            scope_by_source,
            list(rule_trace),
            response_hash=response_hash,
            hash_skipped=hash_skipped,
            source_response_hashes=source_response_hashes,
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

        Also runs schema fingerprint checks for all registered adapters per
        AC-21.c/e. Adapters with major drift are quarantined.
        """
        if isinstance(self._session_store, (PostgresSessionStore, SqliteSessionStore)):
            await self._session_store.setup()
        await self._check_schema_fingerprints()

    async def _check_schema_fingerprints(self) -> None:
        """Check schema drift for all adapters; quarantine on major drift.

        Called from :meth:`setup`. Each adapter's :meth:`get_schema` is invoked
        (if the adapter is already connected) or deferred (not yet connected).
        Connected adapters get their schema fetched; unconnected adapters are
        skipped (drift checked lazily at first connect).

        AC-21.c: record fingerprint on first registration.
        AC-21.e: emit schema_drift_detected; quarantine on major drift.
        """
        fingerprint_store = SchemaFingerprintStore()
        for source_id, adapter in self._adapters.items():
            if not hasattr(adapter, "get_schema"):
                continue
            # Only attempt schema fetch if the adapter is already connected.
            if source_id not in self._connected_adapters:
                continue
            try:
                schema = await adapter.get_schema()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                log.warning(
                    "schema fetch failed for adapter '%s'; skipping fingerprint check",
                    source_id,
                )
                continue

            current_fp = schema.fingerprint()
            stored_fp = fingerprint_store.get(source_id)
            if stored_fp is None:
                # First registration — record baseline.
                fingerprint_store.record(source_id, current_fp)
                continue

            if stored_fp == current_fp:
                continue

            # Drift detected — classify severity.
            # We need the previous schema to diff properly; without it we treat
            # any fingerprint mismatch as major to be fail-closed (AC-21.e).
            drift_entries = classify_drift(schema, schema)  # sentinel: schema vs schema = []
            # Since we don't have the prior schema object, any fp mismatch = major.
            is_major = True
            _ = drift_entries  # classified as major regardless

            log.warning(
                "schema drift detected for adapter '%s' (previous=%s current=%s severity=major)",
                source_id,
                stored_fp[:16],
                current_fp[:16],
            )
            self._audit_logger.emit(
                AuditEntry(
                    timestamp=AuditLogger.utcnow(),
                    request_id=str(uuid.uuid4()),
                    agent_id="<broker>",
                    session_id=None,
                    raw_intent="",
                    intent_analysis=IntentAnalysis(
                        raw_intent="", data_types_needed=[], entities=[]
                    ),
                    facts_asserted_summary={},
                    routing_decisions=[],
                    scope_constraints=[],
                    denial_records=[],
                    error_records=[],
                    rule_trace=[],
                    sources_queried=[],
                    sources_denied=[],
                    sources_skipped=[],
                    sources_errored=[],
                    attestation_token=None,
                    duration_ms=0,
                    event_type="schema_drift_detected",
                )
            )
            if is_major:
                self._quarantined_adapters.add(source_id)

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
