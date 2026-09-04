"""Nautilus adapter package.

Exposes the ``Adapter`` Protocol, exception hierarchy, scope validators, the
built-in ``PostgresAdapter`` / ``PgVectorAdapter`` (design §3.5), the Phase-2
``ElasticsearchAdapter`` / ``Neo4jAdapter`` (design §3.11), the ``Embedder``
Protocol + ``NoopEmbedder`` default (design §3.10), and the
``ADAPTER_REGISTRY`` mapping ``SourceConfig.type`` → adapter class for
broker-side construction.
"""

from typing import Any, ClassVar, cast

from nautilus.adapters.base import (
    Adapter,
    AdapterError,
    ScopeEnforcementError,
    quote_identifier,
    quote_table,
    render_field,
    validate_field,
    validate_operator,
)
from nautilus.adapters.embedder import (
    Embedder,
    EmbeddingUnavailableError,
    NoopEmbedder,
)
from nautilus.adapters.llm import LLMAdapter
from nautilus.adapters.rest import RestAdapter, SSRFBlockedError
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.adapters.static import StaticAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint
from nautilus.extras import install_extra_hint


def missing_driver_adapter(source_type: str, extra: str, exc: BaseException) -> type[Adapter]:
    """An adapter class standing in for one whose driver is not installed.

    The database and object-store drivers are optional extras, so importing
    :mod:`nautilus.adapters` on a lean install has to succeed with some of
    these modules unimportable. A stand-in keeps every built-in source type in
    :data:`ADAPTER_REGISTRY` — the registry is public API — and carries what
    the operator needs to fix it. :meth:`nautilus.core.Broker._build_adapter`
    turns a configured source pointing at one of these into a startup
    ``ConfigError`` naming the extra; the ``connect`` below is the backstop for
    anything that builds an adapter directly.
    """
    hint = f"source type '{source_type}' needs its driver -- {install_extra_hint(extra)}"

    class _MissingDriverAdapter:
        source_type: ClassVar[str] = ""
        missing_extra: ClassVar[str] = extra
        import_error: ClassVar[str] = str(exc)
        install_hint: ClassVar[str] = install_extra_hint(extra)

        async def connect(self, config: SourceConfig) -> None:
            raise AdapterError(f"{hint} (import failed: {exc})")

        async def execute(  # sqlgrep: ignore - the Adapter protocol method, not a DB call
            self,
            intent: IntentAnalysis,
            scope: list[ScopeConstraint],
            context: dict[str, Any],
        ) -> AdapterResult:
            raise AdapterError(hint)

        async def close(self) -> None:
            return

    _MissingDriverAdapter.source_type = source_type
    _MissingDriverAdapter.__name__ = f"Missing{source_type.title()}Adapter"
    return cast("type[Adapter]", _MissingDriverAdapter)


# Adapters whose driver is an optional extra. A lean install imports this
# package fine; only a config that names the source type fails, and it says
# which extra to install.
try:
    from nautilus.adapters.postgres import PostgresAdapter
except ImportError as _exc:  # pragma: no cover - exercised on lean installs
    PostgresAdapter = missing_driver_adapter("postgres", "postgres", _exc)  # type: ignore[assignment,misc]

try:
    from nautilus.adapters.pgvector import PgVectorAdapter
except ImportError as _exc:  # pragma: no cover - exercised on lean installs
    PgVectorAdapter = missing_driver_adapter("pgvector", "pgvector", _exc)  # type: ignore[assignment,misc]

try:
    from nautilus.adapters.elasticsearch import ElasticsearchAdapter
except ImportError as _exc:  # pragma: no cover - exercised on lean installs
    ElasticsearchAdapter = missing_driver_adapter("elasticsearch", "elasticsearch", _exc)  # type: ignore[assignment,misc]

try:
    from nautilus.adapters.neo4j import Neo4jAdapter
except ImportError as _exc:  # pragma: no cover - exercised on lean installs
    Neo4jAdapter = missing_driver_adapter("neo4j", "neo4j", _exc)  # type: ignore[assignment,misc]

try:
    from nautilus.adapters.influxdb import InfluxDBAdapter
except ImportError as _exc:  # pragma: no cover - exercised on lean installs
    InfluxDBAdapter = missing_driver_adapter("influxdb", "influxdb", _exc)  # type: ignore[assignment,misc]

try:
    from nautilus.adapters.s3 import S3Adapter
except ImportError as _exc:  # pragma: no cover - exercised on lean installs
    S3Adapter = missing_driver_adapter("s3", "s3", _exc)  # type: ignore[assignment,misc]

# ``SourceConfig.type`` literal -> adapter class, and the single definition of
# it: ``nautilus.core.broker`` imports this one rather than keeping a second
# copy. The two drifted -- this module still listed the six Phase-2 types while
# the broker had grown influxdb, s3 and llm -- so anything reaching for the
# public ``nautilus.adapters.ADAPTER_REGISTRY`` (the SDK discovery docs tell
# third parties to) raised ``KeyError`` on three built-in source types the
# broker itself serves.
ADAPTER_REGISTRY: dict[str, type[Adapter]] = {
    "postgres": PostgresAdapter,
    "pgvector": PgVectorAdapter,
    "elasticsearch": ElasticsearchAdapter,
    "neo4j": Neo4jAdapter,
    "rest": RestAdapter,
    "servicenow": ServiceNowAdapter,
    "influxdb": InfluxDBAdapter,
    "s3": S3Adapter,
    "llm": LLMAdapter,
    "static": StaticAdapter,
}

__all__ = [
    "ADAPTER_REGISTRY",
    "Adapter",
    "AdapterError",
    "ElasticsearchAdapter",
    "Embedder",
    "EmbeddingUnavailableError",
    "InfluxDBAdapter",
    "LLMAdapter",
    "Neo4jAdapter",
    "NoopEmbedder",
    "PgVectorAdapter",
    "PostgresAdapter",
    "RestAdapter",
    "SSRFBlockedError",
    "S3Adapter",
    "ScopeEnforcementError",
    "ServiceNowAdapter",
    "StaticAdapter",
    "missing_driver_adapter",
    "quote_identifier",
    "quote_table",
    "render_field",
    "validate_field",
    "validate_operator",
]
