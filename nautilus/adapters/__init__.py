"""Nautilus adapter package.

Exposes the ``Adapter`` Protocol, exception hierarchy, scope validators, the
built-in ``PostgresAdapter`` / ``PgVectorAdapter`` (design §3.5), the Phase-2
``ElasticsearchAdapter`` / ``Neo4jAdapter`` (design §3.11), the ``Embedder``
Protocol + ``NoopEmbedder`` default (design §3.10), and the
``ADAPTER_REGISTRY`` mapping ``SourceConfig.type`` → adapter class for
broker-side construction.
"""

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
from nautilus.adapters.elasticsearch import ElasticsearchAdapter
from nautilus.adapters.embedder import (
    Embedder,
    EmbeddingUnavailableError,
    NoopEmbedder,
)
from nautilus.adapters.influxdb import InfluxDBAdapter
from nautilus.adapters.llm import LLMAdapter
from nautilus.adapters.neo4j import Neo4jAdapter
from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.adapters.rest import RestAdapter, SSRFBlockedError
from nautilus.adapters.s3 import S3Adapter
from nautilus.adapters.servicenow import ServiceNowAdapter
from nautilus.adapters.static import StaticAdapter

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
    "quote_identifier",
    "quote_table",
    "render_field",
    "validate_field",
    "validate_operator",
]
