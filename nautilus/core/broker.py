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
import ssl
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Coroutine, Iterable, Iterator, Mapping
from contextlib import AbstractAsyncContextManager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, TypeVar, cast
from urllib.parse import urlsplit

from fathom.attestation import AttestationService
from pydantic import ValidationError

from nautilus.adapters import ADAPTER_REGISTRY as _ADAPTER_REGISTRY
from nautilus.adapters.base import Adapter, AdapterError, ScopeEnforcementError, bounded_rows
from nautilus.adapters.embedder import Embedder, NoopEmbedder
from nautilus.adapters.schema import SchemaFingerprintStore
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
from nautilus.audit.sink import build_audit_sink
from nautilus.config.agent_registry import AgentRegistry, UnknownAgentError
from nautilus.config.loader import ConfigError, load_config
from nautilus.config.models import (
    AgentRecord,
    AnalysisProviderSpec,
    AnthropicProviderSpec,
    ApiConfig,
    FileSinkSpec,
    HttpSinkSpec,
    LocalAdapterConfig,
    LocalInferenceProviderSpec,
    NautilusConfig,
    NullSinkSpec,
    OpenAIProviderSpec,
    SourceConfig,
    redact_connection,
)
from nautilus.config.registry import SourceRegistry
from nautilus.core import (
    BrokerBusyError,
    PolicyEngineError,
    PurposeNotPermittedError,
    SessionNotOwnedError,
)
from nautilus.core.attestation_payload import (
    build_payload,
    canonical_input_hash,
    compute_response_hash,
)
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
    AdapterEventType,
    AdapterResult,
    AuditEntry,
    BrokerResponse,
    DenialRecord,
    ErrorRecord,
    HandoffDecision,
    IntentAnalysis,
    ReloadEventType,
    RoutingDecision,
    ScopeConstraint,
    SkipRecord,
    SourceInfo,
)
from nautilus.core.principal import derive_principal_id, ledger_identity
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


def prime_metrics() -> None:
    """Publish every counter at zero. Called once the meter provider exists.

    See :meth:`NautilusMetrics.prime` for why: a counter is not exported until
    its first ``add``, and an alert written against a series that does not
    exist reads as healthy.
    """
    _metrics.prime()


_T = TypeVar("_T")

log = logging.getLogger(__name__)


class SourceProbe(NamedTuple):
    """What :meth:`Broker.aprobe_source` found at one source's address.

    ``reachable`` is tri-state on purpose: ``None`` means *nothing was dialled*
    -- there is no address, or the connection string names no port and the
    scheme implies none -- and is never conflated with ``True``.
    """

    endpoint: str | None
    reachable: bool | None
    detail: str | None


# Longest one source probe may spend dialling. The source's own ``timeout_s``
# is the budget when it is smaller; ``timeout_s: null`` means "wait
# indefinitely", which is not a thing an HTTP probe may do.
_PROBE_TIMEOUT_CEILING_S = 5.0

# Port a scheme implies when the connection string omits one. Covers what the
# shipped adapters dial; anything else probes nothing rather than guessing an
# address and reporting on it.
_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "postgres": 5432,
    "postgresql": 5432,
    "bolt": 7687,
    "bolt+s": 7687,
    "bolt+ssc": 7687,
    "neo4j": 7687,
    "neo4j+s": 7687,
    "neo4j+ssc": 7687,
}

# Schemes whose probe is wrapped in TLS. The handshake is itself a round trip,
# so it answers the liveness question even where there is no hello to send.
_TLS_SCHEMES = frozenset({"https", "bolt+s", "bolt+ssc", "neo4j+s", "neo4j+ssc"})

# What to say so the server has to say something back.
#
# Completing the TCP handshake is not evidence that anything is alive behind
# it: a ``docker pause``d ``postgres:16`` still accepts the connection in 0.00s,
# because the kernel finishes the handshake into a backlog the frozen process
# never drains. Measured -- that is the exact shape of the failure this probe
# exists to report, so the probe waits for a reply.
#
# All three hellos are pre-authentication and carry no credential:
# - HTTP/1.0 ``HEAD /`` asks for no body; any status line is an answer.
# - libpq's 8-byte SSLRequest is what a Postgres server answers with a single
#   ``S`` or ``N`` before it has asked who you are.
# - Bolt's four magic bytes plus four 4-byte version proposals; the server
#   answers with the version it chose, or four zeros to say it shares none.
#
# Every scheme in ``_DEFAULT_PORTS`` needs an entry here. TLS is not a
# substitute: ``bolt+s`` reached this table through neither, so a graph
# listener that accepted and never answered was reported reachable -- the
# precise failure the paragraph above says this probe exists to report.
# ``tests/defects/test_wave_16_probe_and_provenance`` holds the two tables to
# the same key set.
_BOLT_HELLO = b"\x60\x60\xb0\x17" + b"\x00\x00\x00\x05" + b"\x00" * 12

_PROBE_HELLO: dict[str, bytes] = {
    "http": b"HEAD / HTTP/1.0\r\n\r\n",
    "https": b"HEAD / HTTP/1.0\r\n\r\n",
    "postgres": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    "postgresql": b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    "bolt": _BOLT_HELLO,
    "bolt+s": _BOLT_HELLO,
    "bolt+ssc": _BOLT_HELLO,
    "neo4j": _BOLT_HELLO,
    "neo4j+s": _BOLT_HELLO,
    "neo4j+ssc": _BOLT_HELLO,
}


async def _dial(host: str, port: int, scheme: str) -> str | None:
    """Open ``host:port``, send the scheme's hello, and require a reply.

    Returns a note qualifying an answered dial, or ``None`` when the dial
    answered with nothing to qualify. Raises whatever the dial raised; the
    caller owns the deadline.
    """
    tls = scheme in _TLS_SCHEMES
    try:
        # Verification is left on. A certificate this process will not accept
        # is still a *reply* -- the server sent its Certificate message before
        # we refused it -- so it answers the liveness question and is reported
        # as reachable rather than as an outage. Turning verification off to
        # "make the probe work" would hand a probe that reads bytes off the
        # wire to anyone who can get in the middle of it, to learn something
        # the handshake failure already told us.
        reader, writer = await asyncio.open_connection(
            host, port, ssl=ssl.create_default_context() if tls else None
        )
    except ssl.SSLError as exc:
        # Reachable, and unusable by this process. Reporting the first half and
        # dropping the second gave an operator an unqualified green for a source
        # no query will ever reach, which is the harder outage to find. Name the
        # handshake, not a cause: this class also carries WRONG_VERSION_NUMBER
        # (TLS spoken at a plaintext port) and a server-side mTLS rejection,
        # neither of which is this process refusing a certificate. The error's
        # own text says which one it was.
        return f"answered, but the TLS handshake failed: {exc}"
    try:
        hello = _PROBE_HELLO.get(scheme)
        if hello is None:
            # Reachable, and not marked unreachable-by-construction: a DSN that
            # names an explicit port never consults ``_DEFAULT_PORTS``, so any
            # scheme at all can land here. Say that nothing was asked rather
            # than reporting a green on a completed TCP handshake.
            return "connected; no hello is defined for this scheme, so nothing was asked"
        writer.write(hello)
        await writer.drain()
        if not await reader.read(1):
            raise ConnectionResetError("accepted the connection and closed it without answering")
    finally:
        writer.close()
        with contextlib.suppress(OSError, asyncio.CancelledError):
            await writer.wait_closed()
    return None


# ---------------------------------------------------------------------------
# Adapter registry — static built-ins + entry-point discovery (design §3.5)
# ---------------------------------------------------------------------------

# Re-exported, not redefined: ``nautilus.adapters`` owns the mapping and this
# module's copy had drifted from it. ``from nautilus.core.broker import
# ADAPTER_REGISTRY`` keeps working.
ADAPTER_REGISTRY = _ADAPTER_REGISTRY


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


def _entry_point_distribution(entry_point: Any) -> str:
    """The installed distribution an entry point came from, or ``"unknown"``."""
    return str(getattr(getattr(entry_point, "dist", None), "name", None) or "unknown")


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
            if ep.name in ADAPTER_REGISTRY and obj is not ADAPTER_REGISTRY[ep.name]:
                # The discovered map is merged OVER the built-ins, so this used
                # to replace one. Scope enforcement lives in the adapter -- it
                # is the adapter that pushes the predicate into the query -- so
                # installing an unrelated package could take over ``postgres``
                # and return rows the policy engine scoped out, while the audit
                # entry and its signature still recorded the constraint. The
                # receipt said the control ran. Replacing a built-in on purpose
                # is what the config's ``adapters`` block is for: an operator
                # writes that one.
                #
                # Identity, not the name alone: nautilus advertises its own
                # optional adapters through this same group, and an entry point
                # that resolves to the built-in it "collides" with is that
                # built-in.
                log.error(
                    "refusing adapter entry-point %r from distribution %r: it "
                    "would replace the built-in %s. Register it under a source "
                    "type of its own, or name it explicitly in the config's "
                    "'adapters' block.",
                    ep.name,
                    _entry_point_distribution(ep),
                    ADAPTER_REGISTRY[ep.name].__name__,
                )
                continue
            if not isinstance(obj, type):
                log.warning(
                    "adapter entry-point %r resolved to non-class %s; skipping",
                    ep.name,
                    type(obj).__name__,
                )
                continue
            gaps = _adapter_protocol_gaps(obj)
            if gaps:
                log.warning(
                    "adapter entry-point %r resolved to %s, which is missing Adapter "
                    "protocol members %s; skipping",
                    ep.name,
                    obj.__name__,
                    gaps,
                )
                continue
            discovered[ep.name] = cast("type[Adapter]", obj)
            # INFO, not DEBUG: which code answers a source type is provenance,
            # and nothing else on the operational surface reports it.
            log.info(
                "discovered adapter entry-point %r -> %s (from %r)",
                ep.name,
                obj.__name__,
                _entry_point_distribution(ep),
            )
        except Exception:  # noqa: BLE001
            log.warning(
                "failed to load adapter entry-point %r (%s); skipping",
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
                "loaded local adapter %s from %s as source type %r",
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


def _busy_message(what: str, budget: float | None, endpoint: str | None) -> str:
    """What to tell a caller that could not take the exposure ledger in time.

    Only what the timeout actually proves. The wait covers two things — the
    in-process lock another request from this caller may be holding, and the
    round trip to the session store that takes the shared advisory lock — and
    nothing here distinguishes them. Naming only contention sent operators
    looking for load that was not there: a single uncontended request against a
    store that had stopped answering timed out with the same message.

    It used to end "Check /readyz to tell the two apart", which is advice that
    fails on exactly the failure it is given for: when the store wedges,
    ``/readyz`` is the probe that has just failed too, it answers ``reason:
    session_store_timeout`` — a reason, not an address — and its first response
    after the wedge takes 12.0s. So the tiebreaker now travels in the message:
    the store's own ``scheme://host[:port]``, which an operator can dial from
    anywhere without logging into a node. Both causes stay named; naming the
    address is what makes it possible to rule one out.
    """
    where = (
        f"the session store is {endpoint}, so reach it from here to rule that one out"
        if endpoint
        else "this store publishes no address to dial — see session_store in nautilus.yaml"
    )
    return (
        f"Broker busy: waited {budget}s to take the exposure ledger on {what!r} "
        f"and did not get it. Either another request from this caller still "
        f"holds it — requests from one caller are served one at a time so "
        f"cumulative exposure is counted once — or the session store is slow or "
        f"unreachable. This timeout does not tell the two apart: {where}. "
        f"Retry, or raise session_store.lock_timeout_s."
    )


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
    # Session-store key the caller's cumulative exposure accumulates under, so
    # a caller-chosen ``session_id`` cannot start a clean ledger (§4.15).
    principal_id: str = ""
    # Set by ``_gate_session_ownership`` when this caller reached a session it
    # does not own through a declared handoff, so the write path records the
    # join instead of re-checking the handoff on every later request.
    session_joining: bool = False
    # Whether this request arrived over a transport that identified its caller.
    # Only those are gated by session ownership; see ``arequest``.
    caller_bound: bool = False
    routing_decisions: list[RoutingDecision] = field(default_factory=list[RoutingDecision])
    scope_by_source: dict[str, list[ScopeConstraint]] = field(
        default_factory=dict[str, list[ScopeConstraint]]
    )
    denial_records: list[Any] = field(default_factory=list[Any])
    input_facts: list[Any] = field(default_factory=list[Any])
    rule_trace: list[str] = field(default_factory=list[str])
    facts_summary: dict[str, int] = field(default_factory=dict[str, int])
    sources_queried: list[str] = field(default_factory=list[str])
    # Sources whose adapter capped the row set (AdapterResult.truncated).
    truncated_sources: list[str] = field(default_factory=list[str])
    sources_denied: list[str] = field(default_factory=list[str])
    sources_skipped: list[str] = field(default_factory=list[str])
    skip_records: list[SkipRecord] = field(default_factory=list[SkipRecord])
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
    # Session state as it was read at routing time. ``_update_session`` folds
    # this request's exposure into it, so the accumulation must start from the
    # same snapshot the rules evaluated against.
    session_state: dict[str, Any] = field(default_factory=dict[str, Any])
    # The two ledgers as they were read, before ``_merge_exposure`` unioned them
    # into ``session_state``. Kept apart so each is written back holding what it
    # actually accumulated: the union belongs in the policy input, not in the
    # per-session row, which an operator reads as "what this session did".
    session_row: dict[str, Any] = field(default_factory=dict[str, Any])
    principal_row: dict[str, Any] = field(default_factory=dict[str, Any])

    def apply_route_result(self, route_result: RouteResult) -> None:
        """Copy router output into the mutable request state."""
        self.routing_decisions = route_result.routing_decisions
        self.scope_by_source = route_result.scope_constraints
        self.denial_records = route_result.denial_records
        self.rule_trace = list(route_result.rule_trace)
        self.facts_summary = dict(route_result.facts_asserted_summary)
        self.input_facts = list(route_result.input_facts)

    def duration_ms(self) -> int:
        """Integer millisecond delta since ``started`` (design §4.1)."""
        return int((time.perf_counter() - self.started) * 1000)


# A source is PII-bearing when its declared ``data_types`` carry this marker.
# It is the same vocabulary the ``session`` template names its counter after
# (``pii_sources_accessed``) and that the fixtures already use.
_PII_DATA_TYPE = "pii"


def _merge_unique(prior: Any, incoming: list[str]) -> list[str]:
    """Append ``incoming`` to ``prior`` preserving order, dropping repeats.

    ``prior`` arrives as a JSONB array from the Postgres store, a list from
    the in-memory store, or a pre-encoded space-separated string from a
    Phase-1 session; all three coerce the same way the router coerces them.
    """
    if isinstance(prior, str):
        merged = prior.split()
    elif isinstance(prior, Iterable) and not isinstance(prior, (bytes, Mapping)):
        merged = [str(v) for v in cast("Iterable[object]", prior)]
    else:
        # ``None`` from an absent slot, or a scalar a caller wrote by mistake:
        # start empty rather than raising inside session bookkeeping.
        merged = []
    for value in incoming:
        if value not in merged:
            merged.append(value)
    return merged


_EXPOSURE_KEYS = ("sources_visited", "data_types_seen", "pii_sources_accessed_list")


def _merge_exposure(principal: dict[str, Any], session: dict[str, Any]) -> dict[str, Any]:
    """Union the principal's cumulative exposure into one session's state.

    Only the exposure slots are merged: everything else on the session record
    (its id, purpose window, last request) belongs to that session alone.
    """
    merged = dict(session)
    for key in _EXPOSURE_KEYS:
        union = _merge_unique(principal.get(key), list(session.get(key) or []))
        if union:
            merged[key] = union
    merged["pii_sources_accessed"] = len(merged.get("pii_sources_accessed_list") or [])
    return merged


def _new_request_state(context: dict[str, Any], intent: str) -> _RequestState:
    """Factory for a fresh per-request scratchpad."""
    return _RequestState(
        request_id=str(uuid.uuid4()),
        session_id=str(context.get("session_id", "")),
        started=time.perf_counter(),
        intent=intent,
        intent_analysis=IntentAnalysis(raw_intent=intent, data_types_needed=[], entities=[]),
    )


def _coerce_adapter_result(res: object) -> AdapterResult | None:
    """Accept a structurally identical result from a foreign class.

    ``nautilus-adapter-sdk`` mirrors ``AdapterResult`` rather than importing
    it, precisely so an adapter package needs no dependency on the core
    library. An adapter written the documented way therefore returns a
    different class with the same fields, and an ``isinstance`` check alone
    would refuse every SDK-built adapter. Anything that does not validate is
    a genuine contract break and returns ``None``.
    """
    dump = getattr(res, "model_dump", None)
    if not callable(dump):
        return None
    try:
        return AdapterResult.model_validate(dump())
    except (ValidationError, TypeError):
        return None


def _validate_classification_labels(config: NautilusConfig, router: FathomRouter) -> None:
    """Reject any classification/clearance string the loaded hierarchy rejects.

    ``fathom.engine.dominates`` ranks an unknown level -1 -- strictly below
    ``unclassified`` -- so every clearance dominates it and the
    default-classification-deny rule never fires. Nothing downstream can
    recover from that, which makes config load the only place to catch it.

    A no-op when no ``classification`` hierarchy is registered: a deployment
    that loads no hierarchy has no ladder to check against, and failing
    startup there would be a different bug.
    """
    levels = router.hierarchy_levels()
    if not levels:
        return
    known = ", ".join(levels)
    errors: list[str] = []
    for source in config.sources:
        if source.classification not in levels:
            errors.append(f"sources[{source.id!r}].classification={source.classification!r}")
    for agent_id, agent in config.agents.items():
        if agent.clearance not in levels:
            errors.append(f"agents[{agent_id!r}].clearance={agent.clearance!r}")
    for rule in router.escalation_rules:
        if rule.resulting_level not in levels:
            errors.append(f"escalation rule {rule.id!r}.resulting_level={rule.resulting_level!r}")
    if errors:
        raise ConfigError(
            "classification labels are not levels of the 'classification' "
            f"hierarchy ({known}): " + "; ".join(errors)
        )


def _broker_error(exc: BaseException, request_id: str) -> ErrorRecord:
    """Wrap an unexpected broker-level exception as an :class:`ErrorRecord`.

    The choke point for the path that *fails* a request, the way
    :meth:`Broker._fail_source` is the choke point for the path that survives
    one. Both answer the same operator question -- *which dependency broke?* --
    and only this one used to answer ``null``: a caller that got a 503 for a
    wedged session store had to open ``nautilus.yaml`` to learn which host that
    was, while a caller that got a 200 with a dead source was told the address.

    ``endpoint`` is read off the exception rather than guessed here, because
    only the raiser knows whether the failure had a remote dependency at all.
    ``BrokerBusyError`` from the exposure ledger and
    ``SessionStoreUnavailableError`` carry the session store's
    ``scheme://host[:port]``; a policy-engine failure, a cancelled request or
    an in-process session-token rejection carry nothing, and stay ``None``
    rather than borrowing an address they never dialled.
    """
    endpoint = getattr(exc, "endpoint", None)
    record = ErrorRecord(
        source_id="<broker>",
        error_type=type(exc).__name__,
        message=str(exc),
        trace_id=request_id,
        endpoint=endpoint if isinstance(endpoint, str) else None,
    )
    # The 503 left nothing on any ``nautilus.*`` logger, so a request that
    # failed was invisible in the process log while a request that merely lost
    # a source got a WARNING. Same shape as ``_fail_source``'s.
    log.warning(
        "request %r failed at the broker (error_type=%s, endpoint=%s): %s",
        request_id,
        record.error_type,
        record.endpoint or "-",
        record.message,
    )
    return record


def _source_error(source_id: str, error_type: str, message: str, request_id: str) -> ErrorRecord:
    """Build a per-source :class:`ErrorRecord` tagged with the request trace id.

    Every per-source failure the broker raises itself is constructed here, so
    this is also where ``adapter_errors_total`` is incremented — counting at
    the call sites instead would miss the connect-time path, which never
    reaches ``_gather_adapter_results``.
    """
    _metrics.adapter_errors_total.add(1, {"source_id": source_id, "error_type": error_type})
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
    ruleset_hash: str | None = None,
) -> AuditEntry:
    """Materialize a flat :class:`AuditEntry` from pipeline state (design §4.9)."""
    prov = state.llm_provenance
    return AuditEntry(
        timestamp=AuditLogger.utcnow(),
        request_id=state.request_id,
        agent_id=agent_id,
        principal_id=state.principal_id or None,
        session_id=state.session_id or None,
        raw_intent=state.intent,
        intent_analysis=state.intent_analysis,
        facts_asserted_summary=state.facts_summary,
        input_facts=state.input_facts or None,
        routing_decisions=state.routing_decisions,
        scope_constraints=[c for cs in state.scope_by_source.values() for c in cs],
        denial_records=state.denial_records,
        error_records=state.errored,
        rule_trace=state.rule_trace,
        ruleset_hash=ruleset_hash,
        sources_queried=state.sources_queried,
        sources_denied=state.sources_denied,
        sources_skipped=state.sources_skipped,
        sources_errored=[e.source_id for e in state.errored],
        truncated_sources=sorted(state.truncated_sources) or None,
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


# Keys a running broker re-reads on SIGHUP. Everything else in
# ``nautilus.yaml`` is startup-only; see ``_restart_only_changes`` for what
# happens when one of them changes under a running process.
RELOADABLE_TOP_LEVEL_KEYS: tuple[str, ...] = ("sources", "rules")
"""Top-level ``nautilus.yaml`` stanzas :meth:`Broker.reload` adopts in full."""

RELOADABLE_SESSION_STORE_KEYS: tuple[str, ...] = ("lock_timeout_s", "purpose_ttl_seconds")
"""The two ``session_store`` keys the request path reads per request.

Every other key in the stanza is consumed when the store object is built --
``backend``, ``dsn``, ``sqlite_path``, ``ttl_seconds`` and the pool sizes are
constructor arguments to a store a reload does not replace -- so adopting them
would publish a config that describes a store the broker is not running.
"""

RELOADABLE_API_KEYS: tuple[str, ...] = ("keys",)
"""The one ``api`` key a running transport re-reads: the credential allow-list.

The auth guard resolves ``app.state.api_keys`` per request on purpose, so a
rotation takes effect on the next one -- which is the whole of "rotate without
a restart", and was unreachable while the ``api`` stanza was refused whole.

The whole list is adopted, so this reloads **authorization**, not only the
secret: ``api.keys[].capabilities`` and ``api.keys[].agent_id`` are live too,
and a reload can widen what a credential may do and which agent it may speak
for. That is deliberate -- the operational case is revoking or narrowing a
credential without a restart, and narrowing it is worth less if it needs one --
but it is a larger power than "rotate a secret" and the reason ``auth.mode``
stays restart-only is not that it changes authorization. It is that ``mode``
and ``trusted_proxies`` decide how a caller is authenticated at all: under
``proxy_trust`` the credential is a header the ingress is trusted to set, so
switching modes under a running process changes what the peer restriction is
protecting mid-flight.

Everything else under ``api`` stays restart-only. ``max_concurrent_requests``
and ``max_request_bytes`` are values inside middleware objects installed when
the app is built, and ``host``/``port`` are a bound socket.
"""

_RELOADABLE_SUBKEYS: dict[str, tuple[str, ...]] = {
    "session_store": RELOADABLE_SESSION_STORE_KEYS,
    "api": RELOADABLE_API_KEYS,
}
"""Stanzas where a reload adopts some sub-keys and refuses the rest."""


class ConfigNotReloadableError(Exception):
    """A new config file changes a key that is only read at startup.

    Carries the dotted names of every such key, so an operator who sent
    ``SIGHUP`` is told what to restart for rather than left wondering why the
    file on disk and the process disagree.
    """


@dataclass
class _ConfigGeneration:
    """One atomically-installable set of what a request reads from the config.

    A reload builds a whole new one and installs it with a single attribute
    assignment on the broker. Requests already running keep reading the object
    they pinned at entry, which is why the outgoing generation's router and
    retired adapters are closed after it drains and not at the swap.
    """

    config: NautilusConfig
    registry: SourceRegistry
    router: FathomRouter
    adapters: dict[str, Adapter]
    intent_analyzer: IntentAnalyzer | FallbackIntentAnalyzer
    #: Requests currently reading this generation.
    inflight: int = 0
    #: Set once ``inflight`` reaches zero *after* this generation was retired.
    #: ``None`` while the generation is the live one -- nothing is waiting.
    drained: asyncio.Event | None = None


def _adopted_changes(old: NautilusConfig, new: NautilusConfig) -> list[str]:
    """Dotted names of the reloadable keys that actually differ.

    What a reload *did*, for the audit entry and the process log. A file
    rewritten with no semantic change adopts nothing and says so, which is how
    an operator tells "SIGHUP worked" from "SIGHUP read the file I meant to
    edit and it was identical".
    """
    before = old.model_dump()
    after = new.model_dump()
    changed = [key for key in RELOADABLE_TOP_LEVEL_KEYS if before.get(key) != after.get(key)]
    for stanza, subs in _RELOADABLE_SUBKEYS.items():
        changed.extend(
            f"{stanza}.{sub}"
            for sub in subs
            if cast("dict[str, Any]", before[stanza]).get(sub)
            != cast("dict[str, Any]", after[stanza]).get(sub)
        )
    return changed


def _warn_about_orphaned_ledgers(old: NautilusConfig, new: NautilusConfig) -> int:
    """Name the credentials whose cumulative exposure this reload left behind.

    An ``api.keys`` entry accumulates exposure under the identity
    :func:`~nautilus.core.principal.ledger_identity` gives it, and a ledger is
    orphaned the moment no surviving entry claims that identity -- by rotating
    a ``key`` that named no ``principal``, and equally by *adding* a
    ``principal`` to an entry that had none, which is the first step of the
    documented rotation procedure. Either way a caller resumes on an empty
    escalation budget and is refused ``session_not_yours`` on the sessions it
    opened. That is a security control cleared by routine hygiene, and a reload
    must not do it quietly.

    Positions, principals and agent bindings only: a log line is not a place
    for a secret, and for an unnamed entry the identity *is* the secret.

    The positions enumerate the config being *replaced*, not the file the
    operator just edited -- an orphaned entry is by definition one the new file
    no longer has, so it has no position there. The message says which file it
    is counting in, because ``api.keys[3]`` read as the new one sends the
    operator to an entry that is fine.

    Returns:
        How many ledgers were orphaned, so the count reaches the audit entry as
        well as the process log. A warning is for the operator who was
        watching; the receipt is what answers for the reset afterwards.
    """
    surviving = {ledger_identity(entry) for entry in new.api.keys}
    orphaned = [
        (index, getattr(entry, "principal", None), getattr(entry, "agent_id", None))
        for index, entry in enumerate(old.api.keys)
        if ledger_identity(entry) not in surviving
    ]
    if not orphaned:
        return 0
    named = ", ".join(
        f"old api.keys[{index}] (principal={principal!r}, agent_id={agent!r})"
        for index, principal, agent in orphaned
    )
    log.warning(
        "Reload left %d credential(s) with no surviving api.keys[].principal to "
        "accumulate under (positions index the config it replaced, not the file "
        "you just edited): %s. Their cumulative exposure (sources_visited, "
        "data_types_seen, pii_sources_accessed_list) does NOT carry -- each caller "
        "resumes on an empty escalation budget, and requests naming a session it "
        "opened are refused session_not_yours. Rotate the key value under a stable "
        "api.keys[].principal to keep the ledger; nothing migrates one onto a "
        "principal added later.",
        len(orphaned),
        named,
    )
    return len(orphaned)


_PINNED_GENERATION: ContextVar[tuple[Broker, _ConfigGeneration] | None] = ContextVar(
    "nautilus_pinned_generation", default=None
)
"""The (broker, generation) the current request is running on.

A ``ContextVar`` rather than an argument because the generation is read from
about thirty places spread across the request pipeline, and threading a
parameter through all of them is a larger and more fragile change than pinning
it once at the entry point. ``asyncio.gather`` copies the context into each
child task, so the adapter fan-out inherits the pin.

The broker is stored alongside the generation because one process can run more
than one: a broker whose own pin is not on top of the stack falls back to its
live generation rather than reading a stranger's sources.
"""


def _restart_only_changes(old: NautilusConfig, new: NautilusConfig) -> list[str]:
    """Dotted names of keys that differ and are not reloadable.

    A reload that adopted these would leave the broker describing something it
    is not running: ``audit`` and ``attestation`` name a sink whose writer lock
    this process already holds, ``session_tokens`` names a key ring already
    minting tokens, ``session_store`` names a backend already dialled, and
    ``mcp``/``ui`` and the rest of ``api`` are read once when the ASGI app is
    constructed -- ``api.max_concurrent_requests`` is a semaphore inside an
    installed middleware object, not a value anything looks up again.
    Half-applying them is worse than refusing, so the reload refuses and names
    them. ``api.keys`` is the exception the transports re-read per request; see
    :data:`RELOADABLE_API_KEYS`.
    """
    before = old.model_dump()
    after = new.model_dump()
    changed: list[str] = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) == after.get(key) or key in RELOADABLE_TOP_LEVEL_KEYS:
            continue
        if key in _RELOADABLE_SUBKEYS:
            live_before = cast("dict[str, Any]", before[key])
            live_after = cast("dict[str, Any]", after[key])
            changed.extend(
                f"{key}.{sub}"
                for sub in sorted(set(live_before) | set(live_after))
                if sub not in _RELOADABLE_SUBKEYS[key]
                and live_before.get(sub) != live_after.get(sub)
            )
            continue
        changed.append(key)
    return changed


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
        broker_instance_id: str | None = None,
        base_dir: Path | None = None,
    ) -> None:
        # Everything a request reads out of the config file, in one object so
        # a reload can install a new one with a single assignment. A request
        # pins the generation it started on (``_pinned_generation``) and reads
        # every field through it, so a SIGHUP landing mid-request cannot move
        # the sources, the rules or the per-request limits out from under it.
        self._generation = _ConfigGeneration(
            config=config,
            registry=registry,
            router=router,
            adapters=adapters,
            intent_analyzer=intent_analyzer,
        )
        # Serialises reload swaps against each other. Held on the event loop
        # only, and never across the adapter/router teardown of the outgoing
        # generation, so a second SIGHUP waits for the swap and not for the
        # drain.
        self._reload_lock = asyncio.Lock()
        # Called after a reload installs a new generation. The auth guard reads
        # a credential list the ASGI app copied out of the config at startup,
        # and ``reload`` replaces the config object rather than mutating it, so
        # a rotation the broker adopted would otherwise never reach the door.
        self._reload_listeners: list[Callable[[], None]] = []
        self._last_reload_notes: list[str] = []
        # How long a reload waits in silence for the previous generation to
        # drain before saying so in the log. It bounds the log line, never the
        # wait -- see :meth:`_retire`. Tune it to the slowest source's
        # ``timeout_s`` if reloads routinely go quiet.
        self.reload_drain_timeout_s: float = 60.0
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
        # 4.1 -- the sync facade owns one long-lived loop on its own thread.
        # ``asyncio.run`` per call gave every call a fresh loop while adapter
        # clients stayed cached on the adapter, so call #2 used a pool bound
        # to a closed loop and every source landed in ``sources_errored``.
        # Built lazily: an async-only caller never starts a thread.
        self._sync_loop: asyncio.AbstractEventLoop | None = None
        self._sync_thread: threading.Thread | None = None
        # 4.2 -- ``_prepare_adapter`` does check-then-set across an await, so
        # concurrent first-requests to one source each built their own pool
        # and every loser was unreachable and survived aclose(). One lock per
        # source; the set is bounded by the number of configured sources.
        self._connect_locks: dict[str, asyncio.Lock] = {}
        # B3 -- the session ledger is read at routing time and written after
        # adapter fan-out, so concurrent requests on one session all merged
        # onto the same stale snapshot and the last writer won. The lock
        # spans the whole pipeline because routing policy reads the ledger
        # too: merging at write time alone would still route on stale
        # cumulative exposure.
        # ponytail: one entry per session id, never evicted. Swap for a TTL
        # map if session churn becomes a memory problem.
        self._session_locks: dict[str, asyncio.Lock] = {}
        # Tracks which adapter ids have already been ``connect()``-ed so
        # ``arequest`` can lazy-connect on first use and skip on subsequent
        # calls (design §3.5 — adapter lifecycle is owned by the broker).
        self._connected_adapters: set[str] = set()
        # Whether ``setup()`` has run. First use calls it if the caller did not;
        # see ``_ensure_setup``.
        self._setup_done: bool = False
        # When each source's last connect attempt failed, so a source that has
        # gone away is not re-dialled on every request. Without it one dead
        # source charged its whole ``timeout_s`` — 15 s by default — to every
        # request for as long as it stayed away, and every co-queried healthy
        # source waited with it.
        self._connect_failures: dict[str, float] = {}
        self.connect_cooldown_s: float = 30.0
        # Schema baselines live for the life of the broker, and on disk under
        # ``base_dir`` when one is known (``from_config`` passes ``state_dir``,
        # defaulting to the config file's directory). A per-call store would be
        # empty on every call, so every check would read as a first
        # registration and drift could never be detected — neither within a
        # process nor across a restart.
        self._fingerprint_store = SchemaFingerprintStore(root=self._fingerprint_root(base_dir))
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
        # It comes from configuration when there is one, because a per-process
        # uuid4 is unshareable: behind a load balancer every token minted by
        # one replica is rejected by the next, however carefully the operator
        # shares the key ring.
        self._instance_id: str = broker_instance_id or str(uuid.uuid4())
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
    # The reloadable generation — read through, never assigned directly
    # ------------------------------------------------------------------

    @property
    def _live(self) -> _ConfigGeneration:
        """The generation this call must read: the pinned one, or the current one.

        A request pins at entry and every read inside it resolves here, so a
        reload that lands halfway through cannot change the sources it is
        querying or the rules it was routed by. Calls outside a request --
        ``GET /v1/sources``, the metrics ruleset label, the CLI's read-only
        surfaces -- see the current generation, which is what they are for.
        """
        pinned = _PINNED_GENERATION.get()
        if pinned is not None and pinned[0] is self:
            return pinned[1]
        return self._generation

    # Each of the five reads through :attr:`_live` and writes through to the
    # *current* generation. The setters exist because unit tests wire fakes in
    # by assignment and did so before there was a generation to hold them; they
    # write to the live generation, never to a pinned one, so a fake installed
    # mid-request would be seen by the next request and not by that one.

    @property
    def _config(self) -> NautilusConfig:
        return self._live.config

    @_config.setter
    def _config(self, value: NautilusConfig) -> None:
        self._generation.config = value

    @property
    def _registry(self) -> SourceRegistry:
        return self._live.registry

    @_registry.setter
    def _registry(self, value: SourceRegistry) -> None:
        self._generation.registry = value

    @property
    def _router(self) -> FathomRouter:
        return self._live.router

    @_router.setter
    def _router(self, value: FathomRouter) -> None:
        self._generation.router = value

    @property
    def _adapters(self) -> dict[str, Adapter]:
        return self._live.adapters

    @_adapters.setter
    def _adapters(self, value: dict[str, Adapter]) -> None:
        self._generation.adapters = value

    @property
    def _intent_analyzer(self) -> IntentAnalyzer | FallbackIntentAnalyzer:
        return self._live.intent_analyzer

    @_intent_analyzer.setter
    def _intent_analyzer(self, value: IntentAnalyzer | FallbackIntentAnalyzer) -> None:
        self._generation.intent_analyzer = value

    @contextlib.contextmanager
    def _pinned_generation(self) -> Iterator[None]:
        """Hold this call to the generation that was live when it started."""
        gen = self._generation
        gen.inflight += 1
        token = _PINNED_GENERATION.set((self, gen))
        try:
            yield
        finally:
            _PINNED_GENERATION.reset(token)
            gen.inflight -= 1
            if gen.inflight == 0 and gen.drained is not None:
                gen.drained.set()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    async def afrom_config(cls, path: str | Path) -> Broker:
        """Async counterpart of :meth:`from_config` (README "What Ships Today").

        Construction is entirely blocking -- reading the YAML, reading the
        attestation key, compiling the rule tree into a CLIPS environment --
        so it runs on a worker thread rather than stalling the caller's event
        loop. Adapters are still connected lazily by the first request, exactly
        as with :meth:`from_config`.
        """
        return await asyncio.to_thread(cls.from_config, path)

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
        if not config.agents:
            # An empty registry makes the router read clearance, compartments
            # and purpose from ``context`` — i.e. from the caller. That is the
            # bootstrap default and getting-started teaches exactly this shape,
            # but it is the single largest posture difference between a demo
            # and a deployment, so it is said out loud rather than inferred.
            log.warning(
                "No 'agents:' are declared in %r, so every request declares its own "
                "clearance, compartments and purpose and the broker enforces them "
                "against the sources it knows. Declare agents to turn enforcement on.",
                str(path),
            )

        # Auto-generate base intent vocabulary from each source's declared
        # ``data_types`` (#24); explicit ``analysis.keyword_map`` entries
        # overlay and win on key collision.
        keyword_map = build_keyword_map(registry.sources, config.analysis.keyword_map)
        pattern_analyzer = PatternMatchingIntentAnalyzer(
            keyword_map=keyword_map,
        )
        # The configured vocabulary the router will intersect the analyzer's
        # answer against, handed to the LLM provider so the model is asked to
        # pick from it rather than to guess at it (§4.17).
        known_data_types = sorted({dt for src in registry.sources for dt in src.data_types})
        intent_analyzer = cls._build_intent_analyzer(config, pattern_analyzer, known_data_types)

        base_dir = Path(path).parent
        attestation = cls._build_attestation(config, base_dir)
        attestation_sink = cls._build_attestation_sink(config, attestation, base_dir)

        user_rules_dirs = [cls._resolve(base_dir, d) for d in config.rules.user_rules_dirs]
        router = FathomRouter(
            built_in_rules_dir=BUILT_IN_RULES_DIR,
            user_rules_dirs=user_rules_dirs,
            attestation=attestation,
            check_consistency=config.rules.consistency_checks,
            rule_packs=config.rules.packs,
        )

        # B1 -- an unrecognised level is ranked below ``unclassified`` by
        # ``fathom.engine.dominates``, so a typo in the primary access-control
        # field publishes the source to every agent. Reject at startup, where
        # the operator can still see the typo, rather than denying silently
        # for the life of the deployment.
        _validate_classification_labels(config, router)

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

        audit_path = cls._resolve(base_dir, config.audit.path)
        try:
            audit_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            # In the hardened image this is where a missing ``audit``
            # volumeMount lands: ``/var/log`` exists and UID 65532 cannot write
            # it, so the broker refuses before it binds. Measured, that read as
            # a bare ``[Errno 13] Permission denied: '/var/log/nautilus'`` --
            # an operator following the deployment guide went looking at
            # ``/readyz``, which nothing was listening on. Name the directory's
            # job and the two ways it goes wrong.
            raise OSError(
                f"cannot open the audit log directory {audit_path.parent}: {exc}. "
                f"Nautilus records one line per decision and will not serve "
                f"unrecorded requests, so this refuses startup rather than "
                f"degrading. Either the volume for it is not mounted, or it is "
                f"not writable by the UID this process runs as."
            ) from exc
        try:
            audit_logger = AuditLogger(sink=build_audit_sink(config, audit_path, attestation))
        except OSError as exc:
            # The second of the two causes named above arrives here, not at the
            # mkdir: ``exist_ok=True`` succeeds on a directory that exists, so a
            # mounted-but-unwritable volume walks straight past it and fails on
            # the open instead -- and refused with a bare
            # ``[Errno 13] Permission denied: '.../audit.jsonl'``. Same
            # consequence, same sentence.
            raise OSError(
                f"cannot open the audit log {audit_path}: {exc}. Nautilus "
                f"records one line per decision and will not serve unrecorded "
                f"requests, so this refuses startup rather than degrading. The "
                f"audit log directory exists but is not writable by the UID this "
                f"process runs as, or the file itself is not."
            ) from exc

        session_store = cls._build_session_store(config, base_dir=base_dir)

        synthesizer = BasicSynthesizer()

        # Session-provenance tokens (#18) — KeyRing only when enabled, so
        # Phase-1 YAML keeps the token path entirely off (NFR-5). A configured
        # ``key_ring_path`` persists the ring so replicas share signing keys.
        key_ring_path = config.session_tokens.key_ring_path
        key_ring = (
            KeyRing(cls._resolve(base_dir, key_ring_path) if key_ring_path else None)
            if config.session_tokens.enabled
            else None
        )
        # A token names the broker that minted it so it cannot be replayed
        # against an unrelated one that happens to share key material. That id
        # has to be the same on every replica of one deployment, or the check
        # rejects every token behind a load balancer. Configured id wins; a
        # shared ring means a shared deployment, so it defaults to a constant
        # there — deriving it from the ring's key material would change under
        # rotation and invalidate every token in flight.
        broker_instance_id = config.session_tokens.broker_instance_id or (
            "shared" if key_ring_path else None
        )

        if log.isEnabledFor(logging.DEBUG):
            # ``config check`` prints this; a running server did not, so
            # "which file is this process actually serving, and what did its
            # relative paths resolve to" was answerable only by reading the
            # deployment. ``dials`` goes through the same allowlist redactor as
            # every other endpoint the broker publishes, so a DSN password in
            # the file does not reach the process log with it.
            log.debug(
                "loaded config %s: %d source(s), %d agent(s), audit -> %s, "
                "session store %r, session tokens %s, state dir %s",
                Path(path).resolve(),
                len(registry.sources),
                len(config.agents),
                audit_path,
                config.session_store.backend,
                "on" if config.session_tokens.enabled else "off",
                cls._resolve(base_dir, config.state_dir) if config.state_dir else base_dir,
            )
            for source in registry:
                log.debug(
                    "config source %r: type %r, classification %r, data types %s, dials %s",
                    source.id,
                    source.type,
                    source.classification,
                    source.data_types,
                    redact_connection(source.connection) or "nothing",
                )

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
            broker_instance_id=broker_instance_id,
            # Where this broker's own state goes. ``state_dir`` exists because
            # the default -- the config file's directory -- is read-only in
            # every deployment shape this repo ships.
            base_dir=(cls._resolve(base_dir, config.state_dir) if config.state_dir else base_dir),
        )

    @classmethod
    def _build_intent_analyzer(
        cls,
        config: NautilusConfig,
        pattern_analyzer: PatternMatchingIntentAnalyzer,
        known_data_types: list[str] | None = None,
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
        provider = cls._build_llm_provider(analysis.provider, known_data_types)
        return FallbackIntentAnalyzer(
            primary=provider,
            fallback=pattern_analyzer,
            timeout_s=analysis.timeout_s,
            mode=analysis.mode,
        )

    @staticmethod
    def _build_llm_provider(
        spec: AnalysisProviderSpec, known_data_types: list[str] | None = None
    ) -> LLMIntentProvider:
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
                known_data_types=known_data_types,
            )
        if isinstance(spec, OpenAIProviderSpec):
            from nautilus.analysis.llm.openai_provider import OpenAIProvider

            return OpenAIProvider(
                api_key_env=spec.api_key_env,
                model=spec.model,
                timeout_s=spec.timeout_s,
                known_data_types=known_data_types,
            )
        # Discriminated union — only the local spec remains.
        assert isinstance(spec, LocalInferenceProviderSpec)
        from nautilus.analysis.llm.local_provider import LocalInferenceProvider

        return LocalInferenceProvider(
            base_url=spec.base_url,
            model=spec.model,
            api_key_env=spec.api_key_env,
            timeout_s=spec.timeout_s,
            known_data_types=known_data_types,
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

        ``ttl_seconds`` reaches every backend: a session idle for longer than
        the TTL reads as absent, so cumulative exposure state does not
        accumulate against one session id forever.

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

            dsn = sess_cfg.dsn
            if not dsn:
                dsn = os.environ.get("TEST_PG_DSN")
                if dsn:
                    # A test-shaped name reaching a production code path. It stays
                    # (the integration fixtures dial a container DSN through it),
                    # but silently: an operator who deleted `session_store.dsn`
                    # from the ConfigMap got a session store pointed at whatever
                    # TEST_PG_DSN happened to hold, and nothing said so.
                    log.warning(
                        "session_store.dsn is unset; falling back to the TEST_PG_DSN "
                        "environment variable. Set session_store.dsn explicitly -- "
                        "TEST_PG_DSN exists for the integration fixtures and is not "
                        "a supported way to configure a deployment."
                    )
            if not dsn:
                raise ConfigError(
                    "session_store.backend=postgres requires 'dsn' or TEST_PG_DSN env var"
                )
            return PostgresSessionStore(
                dsn,
                on_failure=sess_cfg.on_failure,
                sqlite_path=sqlite_path,
                ttl_seconds=sess_cfg.ttl_seconds,
                pool_min_size=sess_cfg.pool_min_size,
                pool_max_size=sess_cfg.pool_max_size,
                lock_pool_max_size=sess_cfg.lock_pool_max_size,
                acquire_timeout_s=sess_cfg.acquire_timeout_s,
            )
        if sess_cfg.backend == "sqlite":
            return SqliteSessionStore(sqlite_path, sess_cfg.ttl_seconds)
        return InMemorySessionStore(sess_cfg.ttl_seconds)

    @staticmethod
    def _resolve(base_dir: Path, value: str | Path) -> Path:
        """Resolve a config-declared path against the config file's directory.

        Relative paths in ``nautilus.yaml`` used to resolve against the
        process's working directory, so the same config produced a different
        audit log, a different attestation log and a different set of rule
        directories depending on where the operator happened to run
        ``nautilus serve`` from. Absolute paths are returned unchanged.
        """
        path = Path(value)
        return path if path.is_absolute() else base_dir / path

    @staticmethod
    def _build_attestation_sink(
        config: NautilusConfig, attestation: AttestationService | None, base_dir: Path
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
                    Broker._resolve(base_dir, sink_spec.path),
                    attestation,
                    checkpoint_interval=sink_spec.checkpoint_interval,
                )
            return FileAttestationSink(Broker._resolve(base_dir, sink_spec.path))
        if isinstance(sink_spec, HttpSinkSpec):
            rp_spec = sink_spec.retry_policy
            retry_policy = RetryPolicy(
                max_retries=rp_spec.max_retries,
                initial_backoff_s=rp_spec.initial_backoff_s,
                max_backoff_s=rp_spec.max_backoff_s,
            )
            dead_letter = (
                Broker._resolve(base_dir, sink_spec.dead_letter_path)
                if sink_spec.dead_letter_path
                else None
            )
            return HttpAttestationSink(
                url=sink_spec.url,
                retry_policy=retry_policy,
                dead_letter_path=dead_letter,
            )
        # Must be NullSinkSpec by virtue of the pydantic discriminated union.
        assert isinstance(sink_spec, NullSinkSpec)
        return NullAttestationSink()

    @staticmethod
    def _build_attestation(config: NautilusConfig, base_dir: Path) -> AttestationService | None:
        """Construct the attestation service per design §9.4.

        - ``enabled: false`` → ``None`` (token omitted on every response).
        - ``private_key_path`` set → load PEM from path.
        - Otherwise → generate an ephemeral Ed25519 keypair.
        """
        if not config.attestation.enabled:
            return None
        key_path = config.attestation.private_key_path
        if key_path:
            key_bytes = Broker._resolve(base_dir, key_path).read_bytes()
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

        adapter_cls = registry.get(source.type)
        if adapter_cls is None:
            raise ConfigError(f"Unsupported source type '{source.type}' for id='{source.id}'")

        # The driver-backed adapters are optional extras, and the registry
        # holds a stand-in for any whose driver is not installed. Fail here,
        # at startup, naming the extra -- not at first request with a
        # ModuleNotFoundError from three frames inside the adapter.
        extra = getattr(adapter_cls, "missing_extra", None)
        if extra is not None:
            raise ConfigError(
                f"source id='{source.id}' has type '{source.type}', whose driver is not "
                f"installed -- {getattr(adapter_cls, 'install_hint', extra)} "
                f"(import failed: {getattr(adapter_cls, 'import_error', '?')})"
            )

        # pgvector needs the embedder kwarg — special-case it. The class comes
        # from the registry, not a top-level import: asyncpg and pgvector are
        # optional extras, and importing the adapter module here made
        # ``import nautilus`` fail outright on a lean install, three lines below
        # the stand-in that exists to keep exactly that working.
        if source.type == "pgvector":
            return adapter_cls(broker_default_embedder=broker_default_embedder)  # type: ignore[call-arg]
        return adapter_cls()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def sources(self) -> list[SourceConfig]:
        """Registered source configs (identifier + metadata) — design §3.1."""
        return self._registry.sources

    def sources_visible_to(self, agent_id: str | None) -> list[SourceConfig]:
        """The catalogue as ``agent_id`` is allowed to know it.

        A source's name, prose description and data types are what a caller
        needs in order to ask for it — which is the reconnaissance step the
        classification rules refuse. Listing every source to every caller told
        an unclassified key exactly what it was being kept from, so the
        catalogue is filtered by the same clearance ladder the router routes
        by.

        ``None`` means no bound agent — a bare key, which is documented as
        "any agent_id, every capability" and has no clearance to filter
        against — or a deployment with no ``classification`` hierarchy
        registered, which has no ladder at all. Both see the whole catalogue.
        """
        if agent_id is None:
            return self.sources
        levels = self._router.hierarchy_levels()
        if not levels:
            return self.sources
        try:
            clearance = self._agent_registry.get(agent_id).clearance
        except UnknownAgentError:
            return self.sources
        if clearance not in levels:
            return self.sources
        rank = levels.index(clearance)
        # An unrecognised source label ranks below everything for fathom, so it
        # is visible on the same terms the router routes it on.
        return [
            s
            for s in self.sources
            if s.classification not in levels or levels.index(s.classification) <= rank
        ]

    @property
    def config(self) -> NautilusConfig:
        """The validated config this broker was built from.

        Exposed so a governance surface served by this broker uses the same
        ``rkm.sandbox`` and ``rules`` settings the broker itself runs under.
        """
        return self._config

    @property
    def audit_path(self) -> Path | None:
        """The JSONL file this broker's decisions are written to.

        The sandbox replays this log, so a governance surface that queues a
        proposal has to be able to find it rather than guessing
        ``./audit.jsonl`` relative to wherever the server was started.
        ``None`` when the sink is not a file.
        """
        return self._audit_logger.path

    @staticmethod
    def _fingerprint_root(base_dir: Path | None) -> str | None:
        """Directory the schema baselines persist under, or ``None`` for memory-only.

        A seam, not indirection: the test suite redirects baselines here so
        many brokers built from one fixture config do not share — or write
        into the source tree — a store that changes their behaviour.
        """
        return str(base_dir) if base_dir is not None else None

    @property
    def audit_logger(self) -> AuditLogger:
        """The sink every decision this broker records goes to.

        Exposed because the governance decisions taken over REST — approve,
        reject, retract, rollback — are made against this broker and belong in
        the same log as the routing decisions they change.
        """
        return self._audit_logger

    @property
    def fingerprint_store(self) -> SchemaFingerprintStore:
        """Schema baselines this broker compares against (AC-21.c).

        Exposed so ``nautilus adapters schema-diff`` / ``schema-ack`` read and
        write the same baselines the broker does, rather than a second store
        rooted somewhere else.
        """
        return self._fingerprint_store

    @property
    def api_config(self) -> ApiConfig:
        """``api:`` subsection of the loaded config (host, port, keys, auth).

        Exposed so ``nautilus serve`` can honour ``api.host`` / ``api.port``
        without re-loading the YAML or reaching into private state.
        """
        return self._config.api

    @property
    def ruleset_hash(self) -> str:
        """``sha256:…`` over the rules this broker is deciding with."""
        return self._router.ruleset_hash

    def rules_in_force(self) -> list[dict[str, str]]:
        """Every rule loaded into the running engine (module + name)."""
        return self._router.rules_in_force()

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
    ) -> str:
        """Mint a session token + emit ``session_token_issued`` audit (AC-18.f).

        Public surface for transports (``POST /v1/sessions``) so token
        issuance is always audited through the broker's single JSONL stream.

        ``clearance`` is read from the AgentRegistry, never taken from the
        caller. It used to be a parameter, and ``POST /v1/sessions`` passed
        ``body["clearance"]`` into it, so the broker would sign
        ``clearance: top-secret`` for an agent whose record says
        ``unclassified`` -- an authorization assertion, signed by Nautilus,
        verifiable by anyone against the unauthenticated JWKS, and forwarded to
        downstream sources in ``X-Nautilus-Session-Token``. The in-request
        minting path already read the registry; taking the parameter away means
        no caller can disagree with it.

        ``purpose`` gets the same treatment. It is caller free text, and it is
        a live authorization input: the router denies every source when it falls
        outside the agent's ``allowed_purposes``. Minting it unchecked meant a
        caller could ask this route for a signed assertion of a purpose the
        broker would refuse to act on, and be handed one.

        Raises:
            RuntimeError: when session tokens are disabled.
            PurposeNotPermittedError: when the agent may not claim ``purpose``.
        """
        if self._session_tokens is None:
            raise RuntimeError("session tokens are disabled (session_tokens.enabled: false)")
        try:
            record = self._agent_registry.get(agent_id)
        except UnknownAgentError:
            record = None
        if record is not None and not record.may_claim(purpose):
            raise PurposeNotPermittedError(
                f"purpose {purpose!r} is not one of the purposes agent "
                f"{agent_id!r} may claim ({sorted(record.allowed_purposes)})"
            )
        token = self._session_tokens.issue(
            session_id=session_id,
            agent_id=agent_id,
            purpose=purpose,
            clearance=record.clearance if record is not None else "",
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
        return self._run_sync(self.arequest(agent_id, intent, context, fact_set_hash=fact_set_hash))

    def _run_sync(self, coro: Coroutine[Any, Any, _T]) -> _T:
        """Run *coro* on the broker's own loop and block until it finishes.

        The loop and the connection pools it owns have to outlive the call:
        an ``asyncio.run`` per call closes the loop underneath pools that the
        adapter still holds, and the failure surfaces as an empty result set
        rather than an error.
        """
        loop = self._sync_loop
        if loop is None:
            loop = asyncio.new_event_loop()
            thread = threading.Thread(
                target=loop.run_forever, name="nautilus-broker-sync", daemon=True
            )
            thread.start()
            self._sync_loop = loop
            self._sync_thread = thread
        return asyncio.run_coroutine_threadsafe(coro, loop).result()

    async def arequest(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any] | None = None,
        *,
        fact_set_hash: str | None = None,
        caller: dict[str, str] | None = None,
    ) -> BrokerResponse:
        """Async request pipeline (design §3.1, §8, §9).

        ``caller`` is the transport's view of who is calling -- ``{"auth":
        <authenticated principal>, "peer": <network address>}`` -- and is what
        keys the cumulative-exposure ledger (§4.15). It is a parameter rather
        than a ``context`` key precisely because ``context`` is the caller's to
        fill in: a client that could set it could reset its own ledger. An
        in-library caller passes nothing and is identified by ``agent_id``
        alone.

        Linear sequence of awaits; heavy lifting lives in private helpers
        (`_run_pipeline`, `_build_adapter_jobs`, `_gather_adapter_results`,
        `_build_response`, `_emit_audit`). On policy-engine or unexpected
        failure, a single audit entry is still emitted before re-raising.
        """
        self._refuse_if_closed("arequest")
        await self._ensure_setup()
        with self._pinned_generation():
            return await self._arequest_pinned(agent_id, intent, context, fact_set_hash, caller)

    async def _arequest_pinned(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any] | None,
        fact_set_hash: str | None,
        caller: dict[str, str] | None,
    ) -> BrokerResponse:
        """:meth:`arequest`'s body, running on a pinned config generation.

        Split out so the pin is one ``with`` at the entry point rather than an
        indentation change over a hundred lines: everything below reads
        ``self._registry`` / ``self._router`` / ``self._adapters`` /
        ``self._config`` through :attr:`_live`, which resolves to the
        generation pinned here even if a SIGHUP installs a new one mid-request.
        """
        context = dict(context) if context else {}
        state = _new_request_state(context, intent)
        state.fact_set_hash = fact_set_hash
        state.principal_id = derive_principal_id(
            agent_id,
            auth_principal=(caller or {}).get("auth"),
            peer=(caller or {}).get("peer"),
        )
        # Session ownership is a boundary between callers, and an in-library
        # call has no other caller on the far side of it: no credential, no
        # peer, one process orchestrating its own agents. Transports always
        # pass one of the two, so the HTTP and MCP surfaces are always gated.
        state.caller_bound = bool((caller or {}).get("auth") or (caller or {}).get("peer"))
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
                    # ``state.attestation_token``, not None: a failure AFTER
                    # signing (the session write is the one such await) still
                    # produced a real token that reached the sink, and the
                    # canonical entry for this request must not deny it.
                    self._emit_audit(agent_id, state, state.attestation_token)
                raise
            except BaseException as exc:
                # BaseException, not Exception: a cancelled or timed-out
                # request is exactly the one whose audit entry matters, and
                # CancelledError inherits from BaseException.
                state.errored.append(_broker_error(exc, state.request_id))
                with broker_span(SPAN_AUDIT_EMIT):
                    self._emit_audit(agent_id, state, state.attestation_token)
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

        Reasoning-only path (design §3.6, FR-8, FR-10, AC-4.1): zero adapter
        calls. One session-store write, and only on ``action="allow"``: the
        receiving agent is recorded on the session row so
        :meth:`_gate_session_ownership` lets it continue a session another
        principal owns. Without that record a declared handoff was a statement
        with nothing behind it — the two parties merely agreed on a string, and
        so did anyone else who guessed the same one. Flow:

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
        self._refuse_if_closed("declare_handoff")
        await self._ensure_setup()
        with self._pinned_generation():
            return await self._declare_handoff_pinned(
                source_agent_id=source_agent_id,
                receiving_agent_id=receiving_agent_id,
                session_id=session_id,
                data_classifications=data_classifications,
                rule_trace_refs=rule_trace_refs,
                data_compartments=data_compartments,
                session_token=session_token,
            )

    async def _declare_handoff_pinned(
        self,
        *,
        source_agent_id: str,
        receiving_agent_id: str,
        session_id: str,
        data_classifications: list[str],
        rule_trace_refs: list[str] | None,
        data_compartments: list[str] | None,
        session_token: str | None,
    ) -> HandoffDecision:
        """:meth:`declare_handoff`'s body, on a pinned config generation."""
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

        # B1 -- the handoff rules need ``fathom-dominates`` to be TRUE before
        # they can deny, and an unrecognised classification ranks -1, so it is
        # dominated by every clearance and the handoff is allowed. Caller-
        # supplied labels cannot be checked at startup, so deny here.
        levels = self._router.hierarchy_levels()
        unknown = [c for c in data_classifications if c not in levels]
        if levels and unknown:
            decision = HandoffDecision(
                handoff_id=handoff_id,
                action="deny",
                denial_records=[
                    DenialRecord(
                        source_id=session_id,
                        reason=(
                            f"classification {unknown[0]!r} is not a level of the "
                            f"'classification' hierarchy ({', '.join(levels)})"
                        ),
                        rule_name="unknown-classification",
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
        if action == "allow" and session_id:
            await self._record_handoff_partner(session_id, receiving_agent_id)
        self._emit_handoff_audit(
            source_agent_id=source_agent_id,
            receiving_agent_id=receiving_agent_id,
            session_id=session_id,
            data_classifications=data_classifications,
            decision=decision,
            started=started,
        )
        return decision

    async def _record_handoff_partner(self, session_id: str, receiving_agent_id: str) -> None:
        """Let the receiving agent of an allowed handoff into the session.

        Read-merge-write on the session row's ``handoff_agents``. Best effort:
        a store that cannot take the note must not turn an allowed handoff into
        a denial — the receiving agent is refused later by the ownership gate,
        which is the safe direction to fail.
        """
        try:
            row = await self._session_get(session_id)
            prior: Any = row.get("handoff_agents")
            partners: list[str] = (
                [str(a) for a in cast("list[Any]", prior)] if isinstance(prior, list) else []
            )
            if receiving_agent_id in partners:
                return
            entry = {"handoff_agents": [*partners, receiving_agent_id]}
            if hasattr(self._session_store, "aupdate"):
                await self._session_store.aupdate(session_id, entry)  # type: ignore[attr-defined]
            else:
                sync_store: SessionStore = self._session_store  # type: ignore[assignment]
                sync_store.update(session_id, entry)
        except Exception:  # noqa: BLE001 — the gate refuses on its own if this is lost
            log.warning(
                "could not record the handoff to agent_id=%r on session %r; the "
                "receiving agent will be refused that session until the store "
                "accepts the note",
                receiving_agent_id,
                session_id,
            )

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
        # The minted session JWS rides in ``context`` so adapters can forward it
        # downstream (AC-18.b), but every LLM provider ``json.dumps`` the whole
        # context into its prompt -- so a live credential left the process on
        # every request with ``session_tokens.enabled: true``. It appears in no
        # context contract (``analysis/llm/base.py``) and no analyzer reads it.
        context = {k: v for k, v in context.items() if k != "session_token"}
        analyzer = self._intent_analyzer
        if isinstance(analyzer, FallbackIntentAnalyzer):
            analysis, provenance = await analyzer.analyze(intent, context)
            state.intent_analysis = analysis
            state.llm_provenance = provenance
            return
        state.intent_analysis = analyzer.analyze(intent, context)

    def _refuse_if_closed(self, method: str) -> None:
        """Raise if the broker has been closed.

        Nothing checked ``_closed``, so a post-close request opened a fresh
        pool and returned real rows with a signed attestation token while the
        sink was already closed and swallowed every line -- data egress with
        no receipt. The second ``aclose()`` then returned early and those
        connections were never released.
        """
        if self._closed:
            raise RuntimeError(
                f"Broker.{method}() called after close(); the attestation sink "
                f"and session store are already shut down, so this request "
                f"could not be receipted. Build a new Broker."
            )

    def _ledger_lock(self, *keys: str) -> AbstractAsyncContextManager[None]:
        """Serialise the read-merge-write of every exposure ledger this request touches.

        A request accumulates under two keys -- the declared session and the
        caller's principal -- and both are read-modify-written. Locking only the
        session left the principal record racing: two requests declaring
        different session ids took different locks, both read the principal
        ledger empty, and the loser's exposure was dropped. That is the B3
        defeat one key over, and it is reachable with ``asyncio.gather``.

        Keys are acquired in sorted order so two requests that share one key and
        differ on the other cannot deadlock. A no-op when there is no key at all.
        """
        wanted = sorted({k for k in keys if k})
        if not wanted:
            return contextlib.nullcontext()
        return self._hold_ledger_locks(wanted)

    @contextlib.asynccontextmanager
    async def _hold_ledger_locks(self, keys: list[str]) -> AsyncIterator[None]:
        """Hold every lock in ``keys`` (already sorted) for the block's duration.

        Two locks per key, not one: the ``asyncio.Lock`` serialises this
        process's own concurrent requests, and the session store's lock — when
        the store has one, i.e. when it is shared — serialises this replica
        against every other replica writing the same ledger.
        """
        # ``alock_all`` holds every key on one pooled connection. Entering the
        # store's per-key lock separately took a connection per key, which made
        # the store's ceiling ``pool_max_size / keys-per-request``.
        store_lock_all = getattr(self._session_store, "alock_all", None)
        store_lock = getattr(self._session_store, "alock", None)
        # The wait is bounded because the hold is long: the lock spans the whole
        # pipeline, source query included, so one caller's concurrent requests
        # run strictly one at a time. That serialisation is the guarantee -- two
        # requests that both read the ledger empty both pass a cumulative cap --
        # but ``SourceConfig.timeout_s`` only starts once the lock is won, so
        # the queueing used to sit outside every deadline the config had.
        budget = self._config.session_store.lock_timeout_s
        # Resolved once, from the store rather than from the config: with
        # ``session_store.dsn`` unset the broker falls back to ``TEST_PG_DSN``,
        # and the config would then name nothing while the process dials
        # something. ``None`` for a store with no remote dependency.
        endpoint = self._session_store_endpoint()
        deadline = None if budget is None else time.monotonic() + budget

        async def _hold(cm: AbstractAsyncContextManager[Any], what: str) -> Any:
            if deadline is None:
                return await stack.enter_async_context(cm)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrokerBusyError(_busy_message(what, budget, endpoint), endpoint=endpoint)
            try:
                return await asyncio.wait_for(stack.enter_async_context(cm), remaining)
            except TimeoutError as exc:
                raise BrokerBusyError(
                    _busy_message(what, budget, endpoint), endpoint=endpoint
                ) from exc

        async with contextlib.AsyncExitStack() as stack:
            for key in keys:
                await _hold(self._session_locks.setdefault(key, asyncio.Lock()), key)
            if store_lock_all is not None:
                await _hold(store_lock_all(keys), ", ".join(keys))
            elif store_lock is not None:
                for key in keys:
                    await _hold(store_lock(key), key)
            yield

    async def _run_pipeline(
        self,
        agent_id: str,
        intent: str,
        context: dict[str, Any],
        state: _RequestState,
    ) -> None:
        """Happy-path pipeline body — mutates ``state`` in place."""
        async with self._ledger_lock(state.session_id, state.principal_id):
            with broker_span(SPAN_INTENT_ANALYSIS):
                await self._analyze_intent(intent, context, state)
            with broker_span(SPAN_FATHOM_ROUTING):
                await self._route(agent_id, context, state)
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
                        principal_id=state.principal_id,
                        response=state.data or None,
                        source_response_hashes=state.source_response_hashes or None,
                    )
                state.attestation_token = token
                state.scope_hash_version = scope_hash_version
                await self._emit_attestation(token, nautilus_payload, state.request_id)
            await self._update_session(state, context)

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
            _metrics.attestation_total.add(1, {"outcome": "sink_error"})
        else:
            _metrics.attestation_total.add(1, {"outcome": "emitted"})
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
            try:
                constraint = (
                    item
                    if isinstance(item, ScopeConstraint)
                    else ScopeConstraint.model_validate(item)
                )
            except ValidationError as exc:
                # Caller input, so a typo is a client error. Unwrapped, the
                # ValidationError left arequest as a 500 with no audit entry.
                reasons = "; ".join(
                    f"{'.'.join(str(p) for p in e['loc']) or '(root)'}: {e['msg']}"
                    for e in exc.errors()
                )
                raise ValueError(
                    f"context['scope_constraints'] entry is not a scope constraint: {reasons}"
                ) from exc
            state.scope_by_source.setdefault(constraint.source_id, []).append(constraint)

    def _apply_temporal_filter(self, state: _RequestState) -> None:
        """Deny any source that loses a scope constraint to the temporal window.

        Wires :meth:`TemporalFilter.apply` into ``arequest`` per design
        §3.9 / FR-17. Dropped constraints produce ``scope-expired``
        :class:`DenialRecord` entries appended to ``state.denial_records``.
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
        """Fold temporal-filter denials into request state, denying the source.

        A scope constraint is a *restriction*, so dropping one can only widen
        what the adapter returns. The fan-out treats an empty scope list as
        "no restrictions", which made an expired grant strictly more
        permissive than a live one: the adapter ran with no WHERE clause and
        the caller got the rows the constraint existed to hide.

        The source is therefore denied for this request rather than queried
        under whatever restrictions happen to survive — the fail-closed
        reading of the window that :mod:`nautilus.core.temporal` documents.
        Re-granting means issuing a fresh, unexpired constraint.
        """
        state.denial_records = list(state.denial_records) + list(denials)
        expired_ids = {d.source_id for d in denials}
        state.routing_decisions = [
            rd for rd in state.routing_decisions if rd.source_id not in expired_ids
        ]
        for source_id in expired_ids:
            state.scope_by_source.pop(source_id, None)
        state.sources_denied = sorted(set(state.sources_denied) | expired_ids)
        state.sources_skipped = [s for s in state.sources_skipped if s not in expired_ids]
        state.skip_records = [r for r in state.skip_records if r.source_id not in expired_ids]

    async def _route(self, agent_id: str, context: dict[str, Any], state: _RequestState) -> None:
        """Invoke the Fathom router and classify sources into queried/denied/skipped.

        Prefers the async :meth:`AsyncSessionStore.aget` when the implementer
        provides it (design §3.2 — Phase-2 broker prefers async).
        """
        session_state = await self._session_get(state.session_id) if state.session_id else {}
        if state.session_id:
            session_state.setdefault("id", state.session_id)
        state.session_row = dict(session_state)
        self._gate_session_ownership(agent_id, state)
        # Fold the caller's principal-wide exposure in before the rules see it.
        # Without this a caller escaped cumulative escalation by declaring a
        # session id it had never used -- the ledger is the control, and the
        # key was the caller's to pick (§4.15). The union is the policy input
        # only; each record is written back with its own history.
        state.principal_row = await self._session_get(state.principal_id)
        session_state = _merge_exposure(state.principal_row, session_state)
        state.session_state = dict(session_state)
        route_result = self._router.route(
            agent_id=agent_id,
            context=context,
            intent=state.intent_analysis,
            sources=self._registry.sources,
            session=session_state,
            agent_registry=self._agent_registry,
        )
        state.apply_route_result(route_result)
        # One per decision, not one per request: incremented at the call site it
        # made ``nautilus_routing_decisions_total`` a second copy of
        # ``nautilus_requests_total``, so the dashboard panel plotted the
        # request rate under a routing label.
        _metrics.routing_decisions_total.add(len(route_result.routing_decisions))
        _metrics.fathom_evaluation_duration.record(route_result.duration_us / 1_000_000)
        for denial in route_result.denial_records:
            _metrics.scope_denials_total.add(1, {"rule_name": denial.rule_name})
        exposure_facts = route_result.facts_asserted_summary.get("session_exposure", 0)
        if exposure_facts:
            _metrics.session_exposure_flags_total.add(exposure_facts)
        state.sources_denied = sorted({d.source_id for d in state.denial_records})
        selected_ids = {rd.source_id for rd in state.routing_decisions}
        denied_ids = set(state.sources_denied)
        state.sources_skipped = sorted(
            s.id for s in self._registry if s.id not in selected_ids and s.id not in denied_ids
        )
        state.skip_records = self._skip_records(state)
        state.denial_records = [self._annotate_denial(d, state) for d in state.denial_records]
        if log.isEnabledFor(logging.DEBUG):
            self._log_route(state)

    def _log_route(self, state: _RequestState) -> None:
        """Put this request's routing reasoning on the process log (DEBUG).

        The reasoning existed only in the audit entry's ``rule_trace``, written
        after the request finished and readable only by whoever holds the audit
        file -- so "two brokers behind one address answered the same request
        with different ``sources_skipped``" was a question the process log could
        not answer at any verbosity. One summary line (what the intent parsed
        to, how many rules were evaluated, which fired), then one line per
        configured source giving its disposition and the reason the response
        already carries.

        Called under :meth:`~logging.Logger.isEnabledFor` because the loop is
        O(sources) of formatting on the path every request takes, and it has to
        cost nothing at the default level.
        """
        log.debug(
            "request %r: intent %r parsed to data types %r; %d rules in force, %d fired: %s",
            state.request_id,
            state.intent_analysis.raw_intent,
            state.intent_analysis.data_types_needed,
            len(self._router.rules_in_force()),
            len(state.rule_trace),
            state.rule_trace,
        )
        # Later assignments win, and the three sets are disjoint by
        # construction (``sources_skipped`` excludes both of the others).
        dispositions = {rd.source_id: ("queried", rd.reason) for rd in state.routing_decisions}
        dispositions.update({d.source_id: ("denied", d.reason) for d in state.denial_records})
        dispositions.update({s.source_id: ("skipped", s.reason) for s in state.skip_records})
        for source_id, (disposition, reason) in sorted(dispositions.items()):
            log.debug(
                "request %r: source %r %s -- %s",
                state.request_id,
                source_id,
                disposition,
                reason,
            )

    def _gate_session_ownership(self, agent_id: str, state: _RequestState) -> None:
        """Refuse a session that belongs to somebody else (§4.15 follow-on).

        §4.15 closed the *reset* — a caller could not wipe its own history by
        picking a new session id, because exposure also accumulates under a
        principal key it does not choose. The per-session record stayed
        write-shared: a session id is a name, and any credential that knew one
        could add to its ledger. That is a denial of service against another
        caller on the same broker (pour PII in, and cumulative escalation
        denies them every source) and a side channel out of it (which rules
        fire reports back what the ledger now holds).

        So the first principal to touch a session owns it. A session
        legitimately spans agents — a handoff is keyed on
        ``(session_id, source_agent, receiving_agent)`` — so the receiving
        agent of a handoff that was *declared and allowed in this session*
        joins, and inherits what the session has seen. Everyone else is
        refused before the router runs and before any adapter is touched.

        Only requests that arrived with a caller identity are gated. An
        in-library call presents no credential and no peer: there is no second
        caller for the boundary to be between, and one process running several
        of its own agents through one session is the supported shape.
        """
        if not state.caller_bound:
            return
        owner = str(state.session_row.get("owner_principal") or "")
        if not owner or owner == state.principal_id:
            return
        joined = state.session_row.get("joined_principals")
        if isinstance(joined, list) and state.principal_id in joined:
            return
        partners = state.session_row.get("handoff_agents")
        if isinstance(partners, list) and agent_id in partners:
            state.session_joining = True
            return
        raise SessionNotOwnedError(
            f"session_not_yours: session {state.session_id!r} belongs to "
            f"another principal. A session id is not a credential — either use "
            f"your own, or have its owner declare a handoff to "
            f"agent_id={agent_id!r} in it first."
        )

    def _annotate_denial(self, denial: DenialRecord, state: _RequestState) -> DenialRecord:
        """Say whether a refusal concerned the request, and what would work.

        Two things a denial cannot say for itself. The rules refuse a source on
        its own terms, with no view of whether the intent ever wanted it — so
        relevance is decided here, from the same data-type overlap
        :meth:`_skip_records` already uses. And a purpose refusal that never
        names an acceptable purpose is a dead end: a model measured against
        this surface spent 21 of 21 attempts on one guess, because nothing told
        it the guess was in the wrong vocabulary rather than merely refused.
        The allowed set is metadata the operator wrote, published already at
        ``GET /v1/sources``; the rule cannot interpolate it (fathom emits
        ``reason`` verbatim), so the broker appends it.
        """
        try:
            source = self._registry.get(denial.source_id)
        except Exception:  # noqa: BLE001 — a denial can name a source we cannot resolve
            return denial

        needed = set(state.intent_analysis.data_types_needed)
        # No identifiable data types means nothing to be relevant *to*: the
        # request was unanswerable, not refused.
        relevant = bool(needed) and bool(set(source.data_types) & needed)

        reason = denial.reason
        allowed = list(source.allowed_purposes or [])
        if allowed and "purpose" in reason.lower():
            names = ", ".join(sorted(allowed))
            reason = f"{reason} (source '{source.id}' allows purposes: {names})"
        return denial.model_copy(update={"relevant": relevant, "reason": reason})

    def _skip_records(self, state: _RequestState) -> list[SkipRecord]:
        """Say why each source in ``sources_skipped`` took no part.

        Almost always the data types: the source has nothing the intent asked
        for. Naming that turns "my source is missing from the response" from a
        support question into a one-line config fix.
        """
        needed = set(state.intent_analysis.data_types_needed)
        records: list[SkipRecord] = []
        for source_id in state.sources_skipped:
            offered = set(self._registry.get(source_id).data_types)
            if needed and not (offered & needed):
                reason = (
                    f"no data type in common with the intent: source '{source_id}' offers "
                    f"{sorted(offered)}, the request needed {sorted(needed)}"
                )
            else:
                reason = f"no routing rule selected source '{source_id}' for this request"
            records.append(SkipRecord(source_id=source_id, reason=reason))
        return records

    async def _update_session(self, state: _RequestState, context: dict[str, Any]) -> None:
        """Cumulative-exposure bookkeeping (design §3.9 — update at end).

        Prefers :meth:`AsyncSessionStore.aupdate` when available; falls back
        to the sync Phase-1 surface for :class:`InMemorySessionStore`.
        """
        if not state.session_id:
            return
        common: dict[str, Any] = {
            "last_request_id": state.request_id,
            "last_sources_queried": state.sources_queried,
        }
        # Two records, each folded onto its OWN prior. The session record is
        # what an operator reads and what TTL ages out, so it must describe that
        # session; the principal record is what survives the caller picking a
        # new session id. Writing the merged union to both made every session
        # row claim the caller's whole history.
        session_entry = common | self._accumulate_exposure(state, context, state.session_row)
        # Claim on first touch, and record a handoff partner that joined, so
        # the gate above has an owner to compare against next time. Written
        # only after the request survived, so a refused one claims nothing.
        if not state.caller_bound:
            pass
        elif not state.session_row.get("owner_principal"):
            session_entry["owner_principal"] = state.principal_id
        elif state.session_joining:
            prior_joined: Any = state.session_row.get("joined_principals")
            joined: list[str] = (
                [str(p) for p in cast("list[Any]", prior_joined)]
                if isinstance(prior_joined, list)
                else []
            )
            if state.principal_id not in joined:
                session_entry["joined_principals"] = [*joined, state.principal_id]
        principal_entry = common | self._accumulate_exposure(state, context, state.principal_row)
        if hasattr(self._session_store, "aupdate"):
            await self._session_store.aupdate(state.session_id, session_entry)  # type: ignore[attr-defined]
            await self._session_store.aupdate(state.principal_id, principal_entry)  # type: ignore[attr-defined]
            return
        # Sync fallback — only reachable when the store implements the Phase-1
        # :class:`SessionStore` Protocol (``update``). The union type widens to
        # include :class:`AsyncSessionStore` so pyright needs the explicit cast.
        sync_store: SessionStore = self._session_store  # type: ignore[assignment]
        sync_store.update(state.session_id, session_entry)
        sync_store.update(state.principal_id, principal_entry)

    def _accumulate_exposure(
        self, state: _RequestState, context: dict[str, Any], prior: dict[str, Any]
    ) -> dict[str, Any]:
        """Fold this request's exposure into ``prior``'s cumulative slots.

        :meth:`FathomRouter._assert_session` reads ``data_types_seen``,
        ``sources_visited``, ``pii_sources_accessed_list``,
        ``pii_sources_accessed``, ``purpose_start_ts`` and
        ``purpose_ttl_seconds`` off the session dict, and nothing wrote any of
        them: every request asserted zero ``session_exposure`` facts, so
        cross-request aggregation policy never saw accumulated exposure and
        the shipped ``purpose-expired-deny`` rule could never fire.

        Accumulation is over sources actually **queried** — a denied or
        skipped source exposed nothing. The purpose window starts on the
        first request of a session and restarts whenever the declared purpose
        changes, since a new purpose is a new grant.
        """
        by_id = {s.id: s for s in self._registry}
        queried = [by_id[sid] for sid in state.sources_queried if sid in by_id]

        visited = _merge_unique(prior.get("sources_visited"), state.sources_queried)
        data_types = _merge_unique(
            prior.get("data_types_seen"), [dt for s in queried for dt in s.data_types]
        )
        pii_sources = _merge_unique(
            prior.get("pii_sources_accessed_list"),
            [s.id for s in queried if _PII_DATA_TYPE in s.data_types],
        )
        entry: dict[str, Any] = {
            "sources_visited": visited,
            "data_types_seen": data_types,
            "pii_sources_accessed_list": pii_sources,
            "pii_sources_accessed": len(pii_sources),
        }

        ttl = self._config.session_store.purpose_ttl_seconds
        if ttl > 0:
            purpose = str(context.get("purpose", ""))
            restarted = purpose != str(prior.get("purpose", "")) or not prior.get(
                "purpose_start_ts"
            )
            entry["purpose"] = purpose
            entry["purpose_ttl_seconds"] = float(ttl)
            entry["purpose_start_ts"] = (
                time.time() if restarted else float(prior["purpose_start_ts"])
            )
        return entry

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
        """Lazy-connect + spawn one task per routed source (design §3.1).

        Per SOURCE, not per routing decision: two rules can route the same
        source (a user rule alongside a built-in one), and each fact would
        otherwise execute the adapter again — double cost and double side
        effects for a non-idempotent source — and duplicate the id in the
        signed ``sources_queried`` claim.
        """
        tasks: list[asyncio.Task[AdapterResult | None]] = []
        task_source_ids: list[str] = []
        seen: set[str] = set()
        for rd in state.routing_decisions:
            if rd.source_id in seen:
                continue
            seen.add(rd.source_id)
            # 4.18 -- connect runs inside the task, not here: awaiting it in
            # this loop meant one source with a hanging connect() delayed the
            # fan-out of every source after it in the list.
            tasks.append(asyncio.create_task(self._run_source(rd.source_id, state, context)))
            task_source_ids.append(rd.source_id)
        return tasks, task_source_ids

    async def _run_source(
        self, source_id: str, state: _RequestState, context: dict[str, Any]
    ) -> AdapterResult | None:
        """Connect and execute one source under its own wall-clock budget.

        Returns ``None`` when :meth:`_prepare_adapter` already recorded a
        per-source error (unknown, quarantined, or failed to connect).
        """
        source = self._registry.get(source_id)
        timeout = getattr(source, "timeout_s", None)
        try:
            async with asyncio.timeout(timeout):
                adapter = await self._prepare_adapter(source_id, state)
                if adapter is None:
                    return None
                scope = state.scope_by_source.get(source_id, [])
                return await self._execute_adapter(
                    adapter, source_id, state.intent_analysis, scope, context
                )
        except TimeoutError:
            # A budget spent without ever getting connected is a connect
            # failure, whichever side of the deadline noticed: it is the case
            # that costs every later request the same wait, so it arms the
            # cooldown in :meth:`_prepare_adapter`.
            if source_id not in self._connected_adapters:
                self._connect_failures[source_id] = time.monotonic()
            raise

    async def _prepare_adapter(self, source_id: str, state: _RequestState) -> Adapter | None:
        """Resolve and lazy-connect the adapter for ``source_id``.

        Records per-source :class:`ErrorRecord`\\ s on lookup / connect failure
        and returns ``None`` so the caller can skip this source.

        Quarantined adapters return an ADAPTER_QUARANTINED error record so the
        broker never silently routes to a drifted adapter (AC-21.e, PM Q3).
        """
        adapter = self._adapters.get(source_id)
        if source_id in self._quarantined_adapters and not (
            adapter is not None and await self._clear_quarantine_if_acked(source_id, adapter)
        ):
            self._fail_source(
                state,
                _source_error(
                    source_id,
                    "ADAPTER_QUARANTINED",
                    f"Adapter '{source_id}' is quarantined due to major schema drift. "
                    "Operator must acknowledge drift via schema-ack before resuming.",
                    state.request_id,
                ),
            )
            return None

        if adapter is None:
            self._fail_source(
                state,
                _source_error(
                    source_id,
                    "AdapterError",
                    f"No adapter registered for source '{source_id}'",
                    state.request_id,
                ),
            )
            return None
        if source_id in self._connected_adapters and source_id not in self._quarantined_adapters:
            return adapter
        failed_at = self._connect_failures.get(source_id)
        if failed_at is not None:
            waited = time.monotonic() - failed_at
            if waited < self.connect_cooldown_s:
                self._fail_source(
                    state,
                    _source_error(
                        source_id,
                        "AdapterError",
                        f"connect() failed {waited:.1f}s ago; not retried for another "
                        f"{self.connect_cooldown_s - waited:.1f}s",
                        state.request_id,
                    ),
                )
                return None
            del self._connect_failures[source_id]
        async with self._connect_locks.setdefault(source_id, asyncio.Lock()):
            # Re-check under the lock: the request that lost the race must
            # reuse the winner's pool, not build a second one -- and must see
            # the winner's drift verdict, which is why the gate below runs
            # before the adapter is published as connected. Checking after the
            # publish let the loser skip the gate and query a drifted source.
            if source_id in self._connected_adapters:
                drifted = source_id in self._quarantined_adapters
            else:
                # What this source dials, and how long dialling took. A source
                # pointed at a stopped backend answered 200 with a
                # ``sources_errored[]`` entry and left nothing on any
                # ``nautilus.*`` logger until it failed; a source that connects
                # normally left nothing at all, so "which backends did this
                # request actually open, and which one was slow" had no answer.
                # ``endpoint`` is rebuilt by allowlist from the connection
                # string, so the DSN password beside it cannot ride out here.
                endpoint = self._source_endpoint(source_id) or "no remote endpoint"
                log.debug(
                    "request %r: source %r dialling %s via %s",
                    state.request_id,
                    source_id,
                    endpoint,
                    type(adapter).__name__,
                )
                dial_started = time.monotonic()
                try:
                    await adapter.connect(self._registry.get(source_id))
                except Exception as exc:  # noqa: BLE001 — surface as per-source error
                    self._connect_failures[source_id] = time.monotonic()
                    self._fail_source(
                        state,
                        _source_error(
                            source_id,
                            type(exc).__name__,
                            f"connect() failed: {exc}",
                            state.request_id,
                        ),
                    )
                    return None
                self._connect_failures.pop(source_id, None)
                log.debug(
                    "request %r: source %r connected to %s in %.1f ms",
                    state.request_id,
                    source_id,
                    endpoint,
                    (time.monotonic() - dial_started) * 1000,
                )
                # Connect is lazy, so this is where an adapter's schema is
                # first reachable — checking only in setup() left the gate dead.
                drifted = await self._check_adapter_schema(source_id, adapter)
                self._connected_adapters.add(source_id)
        if drifted:
            self._fail_source(
                state,
                _source_error(
                    source_id,
                    "ADAPTER_QUARANTINED",
                    f"Adapter '{source_id}' is quarantined due to major schema drift. "
                    "Operator must acknowledge drift via schema-ack before resuming.",
                    state.request_id,
                ),
            )
            return None
        return adapter

    def _source_endpoint(self, source_id: str) -> str | None:
        """What ``source_id`` dials, as ``scheme://host[:port]``, or ``None``.

        Rebuilt from the source's ``connection`` by
        :func:`~nautilus.config.models.redact_connection`, which copies out
        scheme/host/port and nothing else, so a DSN password or a URL token
        cannot ride out of the config file on an error record.
        """
        try:
            source = self._registry.get(source_id)
        except KeyError:
            return None  # an id with no source: nothing to name
        return redact_connection(source.connection)

    async def aprobe_source(self, source_id: str) -> SourceProbe:
        """Dial what ``source_id`` connects to and report whether it answers.

        Sources do not gate readiness -- a broker that can still serve three of
        four is ready, and draining it would remove the only thing that can
        answer for the three -- so nothing at HTTP level distinguished a
        healthy broker from one whose every backend was gone. This is what
        does: it opens the source's ``scheme://host[:port]``, makes the server
        answer (see :data:`_PROBE_HELLO`), and is bounded by that source's own
        ``timeout_s``, capped at :data:`_PROBE_TIMEOUT_CEILING_S`.

        It is a deliberately smaller claim than "this source will serve a
        query": a server that answers says nothing about credentials, about a
        database that is up but still recovering, or about a model the endpoint
        does not host. It is exactly the difference between a backend that is
        *gone* and one that is there, which is the question an operator has.

        ``reachable`` is ``None`` -- never ``True`` -- when there was nothing to
        dial. A ``static`` source has no address, and a probe that answers for
        what it did not check is the failure this exists to end.
        """
        endpoint = self._source_endpoint(source_id)
        if endpoint is None:
            return SourceProbe(None, None, "no remote endpoint")
        parts = urlsplit(endpoint)
        host = parts.hostname
        # No entry in the table means no probe: guessing a port is the same
        # mistake ``redact_connection`` refuses to make when it guesses a host.
        port = parts.port or _DEFAULT_PORTS.get(parts.scheme)
        if host is None or port is None:
            return SourceProbe(
                endpoint,
                None,
                f"no port in {endpoint!r} and no default for scheme {parts.scheme!r}",
            )
        try:
            budget = self._registry.get(source_id).timeout_s
        except KeyError:  # pragma: no cover -- _source_endpoint already returned
            budget = None
        timeout_s = min(budget or _PROBE_TIMEOUT_CEILING_S, _PROBE_TIMEOUT_CEILING_S)
        try:
            note = await asyncio.wait_for(_dial(host, port, parts.scheme), timeout_s)
        except TimeoutError:
            return SourceProbe(
                endpoint, False, f"no answer from {endpoint} within {timeout_s:.1f}s"
            )
        # Total, deliberately. This is the whole of one source's answer and
        # ``GET /v1/adapters?probe=true`` gathers every source's, so anything
        # that escapes here 500s the endpoint and discards every healthy
        # sibling's result. Enumerating classes did not hold: ``except OSError``
        # missed ``UnicodeEncodeError`` from a host the resolver cannot encode,
        # and adding ``UnicodeError`` still missed ``OverflowError`` from a port
        # above 65535. A malformed address is a probe failure, not a crash, and
        # the class name is what the operator needs to see.
        except Exception as exc:
            return SourceProbe(endpoint, False, f"{type(exc).__name__}: {exc}")
        return SourceProbe(endpoint, True, note)

    def _session_store_endpoint(self) -> str | None:
        """What the session store dials, as ``scheme://host[:port]``, or ``None``.

        The source-side twin of :meth:`_source_endpoint`. ``None`` for a store
        with no remote dependency -- ``backend: memory`` holds an in-process
        dict and ``backend: sqlite`` a local file, and neither has an address
        an operator could dial -- and for a Postgres DSN with no host in it.
        """
        endpoint: object = getattr(self._session_store, "endpoint", None)
        return endpoint if isinstance(endpoint, str) else None

    def _timeout_message(self, source_id: str) -> str:
        """Message for a source that spent its whole wall-clock budget.

        ``TimeoutError`` carries no text, so interpolating it rendered
        ``exceeded the source's timeout_s budget: `` -- a sentence ending in a
        colon and nothing after it, and that was the entire text an operator
        got. Name the budget that was spent instead. ``timeout_s: null`` means
        the broker set no deadline, so a ``TimeoutError`` from that source came
        from inside the driver and there is no budget to quote.
        """
        budget = self._registry.get(source_id).timeout_s
        if budget is None:
            return "exceeded the source's timeout_s budget"
        return f"exceeded the source's timeout_s budget of {budget}s"

    def _fail_source(self, state: _RequestState, record: ErrorRecord) -> None:
        """Name the backend, log the failure, bucket it. One place, all paths.

        Every per-source failure -- unknown id, connect cooldown, connect
        error, schema quarantine, wall-clock timeout, adapter contract
        violation, and the typed record an adapter returns -- converges here
        before it reaches ``state.errored``, which is what both the response's
        ``sources_errored`` and the audit entry's ``error_records`` are built
        from.

        Two things happen that did not before, and both answer the same
        question -- *which dependency broke?*:

        * ``record.endpoint`` is filled from the source's ``connection``, so
          the address is in the durable audit trail. A ``source_id`` is the
          operator's label for a dependency, not the dependency's address, and
          the address appeared in nothing the broker wrote: an unreachable
          backend produced a 200, an error bucket, and no way to learn what
          was unreachable without already knowing.
        * One ``WARNING`` is emitted on the process's own logger. The broker's
          own loggers said nothing at all about a dead source at any level,
          including ``--log-level debug``; the only lines naming the host came
          from ``httpcore``/``httpx`` and were emitted identically on success,
          so they distinguished nothing.

        The endpoint is credential-free by construction -- see
        :meth:`_source_endpoint`. It is also, deliberately, in the response the
        requesting agent reads, not only in the operator's copy: the agent
        already receives ``source_id`` and the driver's own error text, and an
        endpoint an operator can act on is worth more than the hostname
        secrecy it trades away.
        """
        if record.endpoint is None:
            record = record.model_copy(update={"endpoint": self._source_endpoint(record.source_id)})
        log.warning(
            "source %r failed (endpoint=%s, error_type=%s, trace_id=%s): %s",
            record.source_id,
            record.endpoint or "<none configured>",
            record.error_type,
            record.trace_id,
            record.message,
        )
        state.errored.append(record)

    async def _gather_adapter_results(
        self,
        state: _RequestState,
        tasks: list[asyncio.Task[AdapterResult | None]],
        task_source_ids: list[str],
    ) -> list[AdapterResult]:
        """Await ``tasks`` and split into successes / errors (into state)."""
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        successful: list[AdapterResult] = []
        for source_id, res in zip(task_source_ids, raw, strict=True):
            if isinstance(res, BaseException):
                message = (
                    self._timeout_message(source_id) if isinstance(res, TimeoutError) else str(res)
                )
                self._fail_source(
                    state, _source_error(source_id, type(res).__name__, message, state.request_id)
                )
                continue
            if res is None:
                # _prepare_adapter already recorded why this source is out.
                continue
            if not isinstance(res, AdapterResult):
                coerced = _coerce_adapter_result(res)
                if coerced is None:
                    # B5 -- ``res.error`` below is outside any try block, so
                    # an adapter that *returns* the wrong type (rather than
                    # raising) took down every co-queried source with it.
                    self._fail_source(
                        state,
                        _source_error(
                            source_id,
                            "AdapterContractError",
                            f"adapter returned {type(res).__name__}, expected AdapterResult",
                            state.request_id,
                        ),
                    )
                    continue
                res = coerced
            if res.error is not None:
                # ``_execute_adapter`` cannot see the request id, so it leaves
                # trace_id empty for the typed errors and this is the caller
                # that fills it — otherwise one request's audit entry mixes
                # correlated and uncorrelated rows.
                self._fail_source(
                    state,
                    res.error
                    if res.error.trace_id
                    else res.error.model_copy(update={"trace_id": state.request_id}),
                )
                _metrics.adapter_errors_total.add(
                    1, {"source_id": source_id, "error_type": res.error.error_type}
                )
                continue
            res = self._bound_rows(source_id, res)
            successful.append(res)
            state.sources_queried.append(source_id)
            if res.truncated:
                state.truncated_sources.append(source_id)
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

    def _bound_rows(self, source_id: str, result: AdapterResult) -> AdapterResult:
        """Hold every adapter to the source's ``max_response_bytes``.

        The adapters that can stop reading do -- postgres streams and breaks at
        the budget rather than materialising the whole result first, which is
        the only thing that bounds the peak. This is the backstop for the ones
        that cannot, and the single place the rule is stated for all of them:
        the row cap was the only bound in the code, and a row can be any size.
        """
        try:
            budget = self._registry.get(source_id).max_response_bytes
        except Exception:  # noqa: BLE001 — never fail a served source over a budget lookup
            return result
        rows, trimmed = bounded_rows(result.rows, budget)
        if not trimmed:
            return result
        log.warning(
            "source %r returned more than max_response_bytes (%s); kept %d of %d rows",
            source_id,
            budget,
            len(rows),
            len(result.rows),
        )
        return result.model_copy(update={"rows": rows, "truncated": True})

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
            truncated_sources=sorted(state.truncated_sources),
            sources_denied=state.sources_denied,
            sources_skipped=state.sources_skipped,
            skip_records=state.skip_records,
            sources_errored=state.errored,
            denial_records=list(state.denial_records),
            rule_trace=list(state.rule_trace),
            scope_restrictions=state.scope_by_source,
            attestation_token=state.attestation_token,
            duration_ms=state.duration_ms(),
            fact_set_hash=state.fact_set_hash,
            session_token=state.session_token,
            source_info=self._source_info(state.sources_queried),
            ruleset_hash=self.ruleset_hash,
        )

    def _source_info(self, source_ids: list[str]) -> dict[str, SourceInfo] | None:
        """What each queried source is, so its rows can be read for what they are."""
        info: dict[str, SourceInfo] = {}
        for source_id in sorted(source_ids):
            try:
                source = self._registry.get(source_id)
            except Exception:  # noqa: BLE001 — never fail a served request over metadata
                continue
            info[source_id] = SourceInfo(
                description=source.description,
                classification=source.classification,
                data_types=list(source.data_types),
            )
        return info or None

    def _request_grant(self, agent_id: str, context: dict[str, Any]) -> tuple[str, str]:
        """The (purpose, clearance) this request actually runs under.

        One definition, read by both the mint path and the verify path, so a
        presented token can be compared against the same grant a fresh one
        would carry.
        """
        record: AgentRecord | None
        try:
            record = self._agent_registry.get(agent_id)
        except UnknownAgentError:
            record = None
        purpose = str(context.get("purpose") or "") or (
            (record.default_purpose or "") if record is not None else ""
        )
        clearance = record.clearance if record is not None else ""
        return purpose, clearance

    def _may_claim_purpose(self, agent_id: str, purpose: str) -> bool:
        """Whether a token for ``agent_id`` may carry this purpose claim.

        The router denies every source when the purpose is outside the agent's
        ``allowed_purposes``; the token used to be minted from the purpose the
        caller typed, so a request refused on exactly this ground still handed
        back a validly signed artefact asserting it — forwarded downstream,
        where the signature and the claims are all a reader has.
        """
        try:
            record = self._agent_registry.get(agent_id)
        except UnknownAgentError:
            # An undeclared agent is bounded by nothing, which is the shape
            # every config written before allowed_purposes existed has.
            return True
        return record.may_claim(purpose)

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
                # A token is minted for one agent. Verifying the signature and
                # then taking only its ``session_id`` let any agent replay
                # another's token and inherit that session's exposure ledger —
                # the same substitution ``_verify_handoff_token`` already
                # refuses on the handoff path.
                if claims.agent_id != agent_id:
                    raise SessionTokenError(
                        "agent_mismatch",
                        f"session token was minted for agent {claims.agent_id!r}, "
                        f"presented by {agent_id!r}",
                    )
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
            # The token is a bearer credential adapters forward downstream, and
            # a downstream reader has nothing but the signature and the claims.
            # ``purpose`` and ``clearance`` are written at mint time, so a
            # session carried into a second purpose kept attesting to the
            # first. Re-mint when either drifts, so what is signed is what was
            # enforced. The ORIGINAL expiry is kept in both cases (security
            # review C2): neither re-keying nor re-binding extends a session.
            purpose, clearance = self._request_grant(agent_id, context)
            claimable = self._may_claim_purpose(agent_id, purpose)
            stale_kid = claims.kid != self._key_ring.primary().kid
            drifted = claims.purpose != purpose or claims.clearance != clearance
            if drifted and not claimable:
                # The router is about to refuse this purpose. Leave the token
                # describing the last request that was actually served rather
                # than re-signing it into a claim the policy denies.
                return
            if stale_kid or drifted:
                fresh = self._session_tokens.issue(
                    session_id=claims.session_id,
                    agent_id=claims.agent_id,
                    purpose=purpose,
                    clearance=clearance,
                    expires_at=claims.expires_at,
                )
                trace: list[str] = []
                if stale_kid:
                    trace.append(f"resigned-from-kid={claims.kid}")
                if drifted:
                    trace.append(
                        f"rebound-from-purpose={claims.purpose!r}/clearance={claims.clearance!r}"
                    )
                state.session_token = fresh
                context["session_token"] = fresh
                self._emit_session_token_event(
                    "session_token_issued",
                    agent_id=claims.agent_id,
                    session_id=claims.session_id,
                    request_id=state.request_id,
                    trace=trace,
                )
            return
        # First request in the session — mint a token. A missing session_id
        # gets a broker-generated one so the token always pins a session.
        if not state.session_id:
            state.session_id = str(uuid.uuid4())
            context["session_id"] = state.session_id
            why = "the caller declared no session_id, so it is its own session"
        else:
            why = "no session_token was presented for the declared session_id"
        purpose, clearance = self._request_grant(agent_id, context)
        if not self._may_claim_purpose(agent_id, purpose):
            # The request still runs and the router still denies it. What must
            # not happen is a signature over the refused claim.
            log.warning(
                "not minting a session token for agent %r: purpose %r is not one "
                "it may claim, and the request will be denied on that ground",
                agent_id,
                purpose,
            )
            return
        # Every request from a caller that carries no session_id mints a token,
        # which writes a session_token_issued entry beside the request's own --
        # three audit lines where the documentation describes two. That is a
        # property of the caller, invisible from outside the process, so the
        # reason is said here rather than inferred from the entry count.
        log.debug(
            "minting a session token for agent %r in session %r (purpose %r, "
            "clearance %r): %s. This writes a session_token_issued audit entry "
            "beside the request's own.",
            agent_id,
            state.session_id,
            purpose,
            clearance,
            why,
        )
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
            _build_audit_entry(
                agent_id,
                state,
                attestation_token,
                self._session_store_mode(),
                self.ruleset_hash,
            )
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
        started = time.perf_counter()
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
                    trace_id="",  # filled in by _gather_adapter_results
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
        finally:
            # Timed here rather than derived from ``AdapterResult.duration_ms``:
            # that field is an int, so every sub-millisecond call recorded as
            # exactly 0.0 seconds and the first histogram bucket was the only
            # one that ever filled. Failures are timed too -- an adapter that
            # takes ten seconds to fail is a latency event.
            _metrics.adapter_latency.record(time.perf_counter() - started, {"source_id": source_id})

    def _sign(
        self,
        *,
        request_id: str,
        agent_id: str,
        sources_queried: list[str],
        scope_by_source: dict[str, list[ScopeConstraint]],
        rule_trace: list[str],
        session_id: str,
        principal_id: str = "",
        response: dict[str, Any] | None = None,
        source_response_hashes: dict[str, str] | None = None,
    ) -> tuple[str, Literal["v1", "v2"], dict[str, Any]]:
        """Compose the Nautilus attestation payload and sign it (design §9.3).

        Uses :func:`nautilus.core.attestation_payload.build_payload` so the
        ``scope_hash`` / ``rule_trace_hash`` derivation is deterministic
        (NFR-14) and unit-testable in isolation.

        Signs via ``AttestationService.sign_claims``, which takes a claim set
        verbatim. The six claims ``AttestationService.sign`` would have
        emitted are reproduced exactly, plus the four ``verify-a-token.md``
        documents (``request_id``, ``response_hash``, ``hash_skipped``,
        ``source_response_hashes``). The Nautilus payload is still what the
        ``input_hash`` covers, so that binding — and every verifier reading
        it — is unchanged.

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
        # ``principal`` joins them because ``agent_id`` is a name the caller
        # asserts: signing it alone proves a decision was made about a string
        # someone typed, and two credentials asserting the same name produce
        # the identical claim.
        decision = f"nautilus:{request_id}:agent={agent_id}:principal={principal_id}"

        # Pass the full Nautilus payload as a single synthetic fact so the
        # JWT's ``input_hash`` binds both ``scope_hash`` and
        # ``rule_trace_hash`` (plus request_id / agent_id / sources_queried).
        input_facts: list[dict[str, Any]] = [nautilus_payload]
        session_ref = session_id or request_id
        # ``sign_claims`` rather than ``sign``: the latter reduces the whole
        # Nautilus payload to an opaque ``input_hash``, so every check
        # ``docs/how-to/verify-a-token.md`` tells an offline verifier to make
        # raised KeyError. The six claims ``sign`` would have produced are
        # reproduced verbatim (existing verifiers keep working) and the four
        # documented ones are promoted alongside them. ``hash_skipped`` most of
        # all: it is sold in three docs as the honest disclosure that a
        # non-deterministic source makes a response unverifiable, and it never
        # reached the caller in any form.
        claims: dict[str, Any] = {
            "iss": "fathom",
            "iat": int(time.time()),
            "decision": decision,
            "rule_trace": list(rule_trace),
            "input_hash": canonical_input_hash(input_facts),
            "session_id": session_ref,
        }
        for documented in ("request_id", "response_hash", "hash_skipped", "source_response_hashes"):
            if documented in nautilus_payload:
                claims[documented] = nautilus_payload[documented]
        token = self._attestation.sign_claims(claims)
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
        self._setup_done = True

    async def _ensure_setup(self) -> None:
        """Stand the broker up on first use if the caller never did it.

        ``from_config``/``afrom_config`` connect adapters lazily and say so, so
        a durable session store that refused until an explicit ``setup()`` was
        the one piece that did not follow the documented shape — and it refused
        with ``SessionStoreUnavailableError``, which is exactly the class
        ``session_store.on_failure: fallback_memory`` exists to degrade past.
        One forgotten call therefore dropped a durable ledger to memory in one
        config and failed loudly in another.
        """
        if self._setup_done:
            return
        await self.setup()

    async def _check_schema_fingerprints(self) -> None:
        """Check schema drift for every connected adapter; quarantine on major drift.

        Called from :meth:`setup`. Adapters that are not connected yet are
        skipped here and checked by :meth:`_prepare_adapter` at first connect
        — connect is lazy, so at startup this loop usually has nothing to do
        and the connect-time check is what actually runs.

        AC-21.c: record fingerprint on first registration.
        AC-21.e: emit schema_drift_detected; quarantine on major drift.
        """
        for source_id, adapter in self._adapters.items():
            if source_id in self._connected_adapters:
                await self._check_adapter_schema(source_id, adapter)

    async def _check_adapter_schema(self, source_id: str, adapter: Adapter) -> bool:
        """Fingerprint one connected adapter against its baseline.

        Returns ``True`` when the adapter was quarantined by this check, so a
        caller mid-request can refuse to route to it. A drifted adapter must
        not serve the very request that discovered the drift.
        """
        if not hasattr(adapter, "get_schema"):
            return False
        try:
            schema = await adapter.get_schema()  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            log.warning(
                "schema fetch failed for adapter %r; skipping fingerprint check",
                source_id,
            )
            return False

        current_fp = schema.fingerprint()
        stored_fp = self._fingerprint_store.get(source_id)
        if stored_fp is None:
            # First registration — record baseline.
            self._fingerprint_store.record(source_id, current_fp)
            return False

        if stored_fp == current_fp:
            return False

        # Drift detected. Classifying minor vs major needs the PREVIOUS schema
        # object, and only its fingerprint was kept, so every mismatch counts
        # as major (fail closed, AC-21.e). An operator clears it with
        # ``nautilus adapters schema-ack``, which re-baselines the adapter.
        log.warning(
            "schema drift detected for adapter %r (previous=%s current=%s severity=major)",
            source_id,
            stored_fp[:16],
            current_fp[:16],
        )
        self.emit_adapter_event("schema_drift_detected", source_id)
        self.emit_adapter_event("adapter_quarantined", source_id)
        self._quarantined_adapters.add(source_id)
        return True

    # ------------------------------------------------------------------
    # Reload (SIGHUP) — see nautilus/cli/serve.py for the signal wiring
    # ------------------------------------------------------------------

    def on_reload(self, listener: Callable[[], None]) -> None:
        """Call ``listener`` after every adopted reload, on the reload's task.

        For state derived from the config and held outside the broker -- the
        credential allow-list a transport copies onto ``app.state`` at startup
        and re-reads per request. The reload has already installed the new
        generation when this runs, so a listener reads :attr:`config` and gets
        what was just adopted.

        A listener that raises does not fail the reload, does not stop the
        ones after it, and is named in :attr:`last_reload_notes` so the audit
        entry records that some outside state did not follow the config.

        There is no ``off_reload``: a listener stays registered for the
        lifetime of the broker. Building two apps against one broker therefore
        pins the first app's closure until the broker is closed. Acceptable
        rather than fixed: ``create_app`` registers once per app, one broker
        per process is the only shape ``serve`` builds, and a listener that
        writes to a dead app's ``state`` is a write nothing reads.
        """
        self._reload_listeners.append(listener)

    @property
    def last_reload_notes(self) -> list[str]:
        """What the last adopted reload did beyond adopting keys.

        Cumulative-exposure ledgers it left with nothing to accumulate under,
        and listeners that failed. Both are things the audit entry has to say
        and the adopted-key list cannot: one is a security budget cleared by a
        routine operation, the other is state outside the broker that no longer
        matches the config the broker is running.
        """
        return list(self._last_reload_notes)

    async def reload(self, candidate: Broker) -> list[str]:
        """Adopt ``candidate``'s sources, rules, credentials and live limits.

        ``candidate`` is a broker built from the new file by the *same*
        function ``nautilus serve`` and ``nautilus config check`` use
        (:func:`nautilus.cli.serve.broker_for_serve`), so a config this
        process would refuse to start on has already raised before this is
        called and in the same words. Nothing here re-validates: a second
        validator is a validator that drifts.

        What is adopted: the source registry and its adapters, the Fathom
        router (rule files are re-read, not just the ``rules:`` stanza, so an
        edit inside a ``user_rules_dirs`` directory arrives too), the intent
        analyzer -- its keyword map is generated from ``sources`` (#24), so a
        source change that did not rebuild it would route on a stale
        vocabulary -- ``api.keys``, which is how a credential is rotated
        without a restart, and the two ``session_store`` limits the request
        path reads per request.

        A transport holds the credential list on its own ``app.state`` and
        re-reads it per request, so it is handed the new one through
        :meth:`on_reload` rather than by reaching into the ASGI app from
        here.

        What is not: everything :data:`RELOADABLE_TOP_LEVEL_KEYS`,
        :data:`RELOADABLE_API_KEYS` and :data:`RELOADABLE_SESSION_STORE_KEYS`
        leave out. A file that changes
        one of those is refused whole rather than half-applied; see
        :func:`_restart_only_changes`.

        Adapter identity is preserved for every source whose spec is
        byte-identical: the live adapter object keeps its pool, its connect
        cooldown and its ``_connected_adapters`` entry, and the candidate's
        unused twin is closed. A source that changed or vanished has its
        adapter retired and its connect bookkeeping dropped so the replacement
        dials on next use. Schema-drift baselines and quarantines are keyed by
        source id and survive a reload untouched: re-pointing a source at
        another table must not be a way to clear a quarantine
        ``nautilus adapters schema-ack`` is the way to clear.

        Returns:
            The dotted names of the keys actually adopted, in file order.
            Empty when the new file is equivalent to the running one.

        Raises:
            ConfigNotReloadableError: When the new file changes a key that is
                only read at startup. ``candidate`` is closed first.
        """
        self._refuse_if_closed("reload")
        incoming = candidate._generation  # noqa: SLF001 - transplanting into self
        async with self._reload_lock:
            outgoing = self._generation
            blocked = _restart_only_changes(outgoing.config, incoming.config)
            if blocked:
                await candidate.aclose()
                raise ConfigNotReloadableError(
                    "these keys are read once at startup and cannot be reloaded: "
                    + ", ".join(blocked)
                    + ". Restart the process to adopt them."
                )

            adapters, retired = self._reconcile_adapters(outgoing, incoming)
            self._generation = _ConfigGeneration(
                config=incoming.config,
                registry=incoming.registry,
                router=incoming.router,
                adapters=adapters,
                intent_analyzer=incoming.intent_analyzer,
            )
            adopted = _adopted_changes(outgoing.config, incoming.config)

        notes: list[str] = []
        self._last_reload_notes = notes
        if "api.keys" in adopted:
            orphaned = _warn_about_orphaned_ledgers(outgoing.config, incoming.config)
            if orphaned:
                notes.append(f"cleared {orphaned} cumulative-exposure ledger(s)")
        for listener in self._reload_listeners:
            # ``on_reload`` is public, so this loop calls code the broker does
            # not own, after the generation is already installed and before the
            # outgoing one is retired. An escaping raise left the reload applied
            # but unrecorded (``reload_config`` catches only
            # ``ConfigNotReloadableError``), leaked the outgoing router and
            # retired adapters, and skipped every listener after the first --
            # so a second transport went on serving a retired credential while
            # the audit log said nothing. The failure is recorded instead, on
            # the receipt as well as in the log, because a listener that did
            # not run is state that no longer matches the adopted config.
            try:
                listener()
            except Exception:
                log.exception("a post-reload listener failed; the reload stands")
                # Its name, never its ``repr``: a listener bound to the
                # credential list would print it.
                named = getattr(listener, "__qualname__", type(listener).__name__)
                notes.append(f"a post-reload listener failed: {named}")

        # The candidate is now a shell around exactly what this reload retired:
        # the outgoing router, the adapters no longer in service, and its own
        # never-used audit sink, attestation sink and session store. One
        # ``aclose`` disposes of all of it, in the order ``aclose`` documents.
        candidate._generation = _ConfigGeneration(  # noqa: SLF001 - retiring it
            config=incoming.config,
            registry=incoming.registry,
            router=outgoing.router,
            adapters={str(i): adapter for i, adapter in enumerate(retired)},
            intent_analyzer=incoming.intent_analyzer,
        )
        await self._retire(outgoing, candidate)
        return adopted

    def _reconcile_adapters(
        self, outgoing: _ConfigGeneration, incoming: _ConfigGeneration
    ) -> tuple[dict[str, Adapter], list[Adapter]]:
        """Split the two generations' adapters into "keep serving" and "retire".

        An unchanged source keeps the object that is already connected --
        replacing it would drop a live pool and re-dial on the next request
        while ``_connected_adapters`` still claimed it was up.
        """
        before = {source.id: source for source in outgoing.registry}
        after = {source.id: source for source in incoming.registry}
        adapters: dict[str, Adapter] = {}
        retired: list[Adapter] = []
        for source_id, spec in after.items():
            if before.get(source_id) == spec and source_id in outgoing.adapters:
                adapters[source_id] = outgoing.adapters[source_id]
                retired.append(incoming.adapters[source_id])
                continue
            adapters[source_id] = incoming.adapters[source_id]
            if source_id in outgoing.adapters:
                retired.append(outgoing.adapters[source_id])
            self._forget_connect_state(source_id)
        for source_id, adapter in outgoing.adapters.items():
            if source_id not in after:
                retired.append(adapter)
                self._forget_connect_state(source_id)
        return adapters, retired

    def _forget_connect_state(self, source_id: str) -> None:
        """Drop the connect bookkeeping for a source whose adapter is being replaced.

        Not the quarantine set and not the schema baseline: both are the record
        of a drift an operator has to acknowledge, and a config edit is not an
        acknowledgement.
        """
        self._connected_adapters.discard(source_id)
        self._connect_failures.pop(source_id, None)
        self._connect_locks.pop(source_id, None)

    async def _retire(self, outgoing: _ConfigGeneration, shell: Broker) -> None:
        """Close ``shell`` once nothing is still reading ``outgoing``.

        The wait is what makes "in-flight requests finish on the config they
        started with" true rather than merely likely: the swap is atomic, but
        the adapters and the CLIPS environment the previous generation is
        still using are real objects, and closing them under a running request
        would fail it. The timeout only decides when to say so out loud -- it
        never shortens the wait, because a request holding the old generation
        is a request whose adapter must stay open.
        """
        outgoing.drained = asyncio.Event()
        if outgoing.inflight == 0:
            outgoing.drained.set()
        waiter = asyncio.ensure_future(outgoing.drained.wait())
        try:
            await asyncio.wait_for(asyncio.shield(waiter), self.reload_drain_timeout_s)
        except TimeoutError:
            log.warning(
                "reload: %d request(s) still running on the previous config after "
                "%.0fs; its adapters and rule engine stay open until they finish",
                outgoing.inflight,
                self.reload_drain_timeout_s,
            )
            await waiter
        await shell.aclose()

    def emit_reload_event(self, event_type: ReloadEventType, detail: str) -> None:
        """Write one config-reload entry to the audit log.

        A reload changes which sources exist and which rules decide, so the
        log that has to explain a decision has to record when that changed and
        when a change was refused. ``detail`` is the operator-facing sentence:
        the adopted keys, or the reason for the refusal -- the same words
        ``serve`` prints, when the refusal came from the config validator.
        """
        self._audit_logger.emit(
            AuditEntry(
                timestamp=AuditLogger.utcnow(),
                request_id=str(uuid.uuid4()),
                agent_id="<broker>",
                session_id=None,
                raw_intent=detail,
                intent_analysis=IntentAnalysis(raw_intent="", data_types_needed=[], entities=[]),
                facts_asserted_summary={},
                routing_decisions=[],
                scope_constraints=[],
                denial_records=[],
                error_records=[],
                rule_trace=[],
                ruleset_hash=self.ruleset_hash,
                sources_queried=[],
                sources_denied=[],
                sources_skipped=[],
                sources_errored=[],
                attestation_token=None,
                duration_ms=0,
                event_type=event_type,
            )
        )

    def emit_adapter_event(self, event_type: AdapterEventType, adapter_id: str) -> None:
        """Write one adapter-lifecycle entry to the audit log.

        These events belong to an adapter, not to a request: no intent, no
        sources, no decisions. ``adapter_id`` is the only thing that
        distinguishes one from another, which is why the entry carries it.

        Public because ``nautilus adapters schema-ack`` records the operator's
        override through the same broker and the same log as the drift entry
        it overrides.
        """
        self._audit_logger.emit(
            AuditEntry(
                timestamp=AuditLogger.utcnow(),
                request_id=str(uuid.uuid4()),
                agent_id="<broker>",
                session_id=None,
                raw_intent="",
                intent_analysis=IntentAnalysis(raw_intent="", data_types_needed=[], entities=[]),
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
                event_type=event_type,
                adapter_id=adapter_id,
            )
        )

    async def _clear_quarantine_if_acked(self, source_id: str, adapter: Adapter) -> bool:
        """Re-check a quarantined adapter against its stored baseline.

        ``nautilus adapters schema-ack`` re-baselines the adapter on disk, and
        the quarantine set lives in memory: without this the ADAPTER_QUARANTINED
        message ("acknowledge drift via schema-ack before resuming") was untrue
        for the running process, which stayed quarantined until restart.

        Returns ``True`` when the quarantine was lifted.
        """
        if not hasattr(adapter, "get_schema"):
            return False
        try:
            schema = await adapter.get_schema()  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001 — an unreachable adapter stays quarantined
            return False
        if self._fingerprint_store.get(source_id) != schema.fingerprint():
            return False
        self._quarantined_adapters.discard(source_id)
        log.info("quarantine lifted for adapter %r; baseline now matches", source_id)
        self.emit_adapter_event("adapter_unquarantined", source_id)
        return True

    @property
    def closed(self) -> bool:
        """True once :meth:`close` or :meth:`aclose` has run."""
        return self._closed

    def __enter__(self) -> Broker:
        """Enter the sync lifecycle: run :meth:`setup`, hand back the broker.

        ``setup()`` is mandatory for the persistent session stores — it is
        what creates their schema — and every example spelled it out by hand,
        or forgot to. So does ``close()``: it refuses to run inside a running
        event loop, which is why the docs' ``try/finally`` is doing real work
        and why the async form below exists separately.
        """
        self._run_sync(self.setup())
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Close on the way out, whatever happened inside."""
        self.close()

    async def __aenter__(self) -> Broker:
        """Async counterpart of :meth:`__enter__`."""
        await self.setup()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        """Async counterpart of :meth:`__exit__`."""
        await self.aclose()

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
        if self._sync_loop is None:
            # Nothing ran on the sync facade, so there is no loop to close on.
            asyncio.run(self.aclose())
            return
        loop, thread = self._sync_loop, self._sync_thread
        try:
            self._run_sync(self.aclose())
        finally:
            loop.call_soon_threadsafe(loop.stop)
            if thread is not None:
                thread.join(timeout=30)
            loop.close()
            self._sync_loop = None
            self._sync_thread = None

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
        # 2b. Audit sink: a chained audit log holds an exclusive writer lock
        #     and an open file handle. Nothing closed it before, so a process
        #     that built two brokers in sequence refused its own second one.
        audit_close = getattr(self._audit_logger.sink, "close", None)
        if audit_close is not None:
            with contextlib.suppress(Exception):
                audit_close()
        # 3. Adapters — release pools last so in-flight attestation can still
        #    reference their connections above.
        for adapter in self._adapters.values():
            try:
                await adapter.close()
            except Exception:
                # Best-effort, but not silent: swallowing this is how a pool
                # that never closed looked like a clean shutdown.
                log.warning("adapter close failed during aclose()", exc_info=True)
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


__all__ = ["Broker", "BrokerResponse", "ConfigNotReloadableError"]
