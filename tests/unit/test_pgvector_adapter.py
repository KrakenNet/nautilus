"""Unit tests for :class:`PgVectorAdapter` and :class:`NoopEmbedder` (Task 1.15).

Done-when (per tasks.md Task 1.15):
    a) Generated SQL for a pgvector source with 1 scope constraint and
       ``context["embedding"] = [0.1, 0.2, 0.3]`` contains
       ``ORDER BY embedding <=> $`` (the `"embedding"` column is quoted but
       the assertion tolerates that).
    b) The scope ``WHERE`` fragment appears *before* the ``ORDER BY`` in the
       generated SQL.
    c) ``NoopEmbedder(strict=True).embed("x")`` raises
       ``EmbeddingUnavailableError``.

Thick-unit stance: the adapter is exercised through its real method, against
a hand-constructed ``SourceConfig``. The ``asyncpg.Pool`` is NOT involved —
SQL generation is reached directly via ``_build_vector_sql`` (design §7.3).
"""

from __future__ import annotations

import pytest

from nautilus.adapters import (
    EmbeddingUnavailableError,
    NoopEmbedder,
    PgVectorAdapter,
)
from nautilus.config.models import SourceConfig
from nautilus.core.models import ScopeConstraint


def _make_source() -> SourceConfig:
    return SourceConfig(
        id="vuln-embeddings",
        type="pgvector",
        description="vulnerability embedding store",
        classification="secret",
        data_types=["vulnerability"],
        allowed_purposes=["research"],
        connection="postgres://localhost/vuln",
        table="vuln_embeddings",
        embedding_column="embedding",
        metadata_column="metadata",
        distance_operator="<=>",
        top_k=10,
    )


@pytest.mark.unit
def test_noop_embedder_strict_raises_embedding_unavailable() -> None:
    """Done-when (c): strict NoopEmbedder refuses to produce a vector."""
    embedder = NoopEmbedder(strict=True)
    with pytest.raises(EmbeddingUnavailableError):
        embedder.embed("any query text")


@pytest.mark.unit
def test_noop_embedder_non_strict_returns_zero_vector() -> None:
    """Non-strict path: zero vector of configured dimension."""
    embedder = NoopEmbedder(strict=False, dimension=5)
    v = embedder.embed("ignored")
    assert v == [0.0, 0.0, 0.0, 0.0, 0.0]


@pytest.mark.unit
def test_pgvector_build_sql_shape_with_one_scope_and_context_embedding() -> None:
    """Done-when (a)+(b): ORDER BY after WHERE, expected operator text."""
    source = _make_source()
    adapter = PgVectorAdapter(pool=object())  # pool unused for SQL-shape test
    # Skip ``connect()`` and wire the config directly — we are unit-testing
    # the SQL builder, not the pool lifecycle.
    adapter._config = source  # pyright: ignore[reportPrivateUsage]

    scope = [
        ScopeConstraint(
            source_id="vuln-embeddings",
            field="classification",
            operator="=",
            value="secret",
        )
    ]
    embedding = [0.1, 0.2, 0.3]

    sql, params = adapter._build_vector_sql(  # pyright: ignore[reportPrivateUsage]
        table=source.table or "vuln_embeddings",
        scope=scope,
        embedding_column=source.embedding_column or "embedding",
        distance_operator=source.distance_operator or "<=>",
        metadata_column=source.metadata_column or "metadata",
        embedding=embedding,
        top_k=source.top_k,
    )

    # (a) ORDER BY uses the requested operator + placeholder marker. The
    # embedding column is rendered quoted ("embedding") by the identifier
    # quoter; the Done-when substring is tolerant of that because the
    # quotes surround the bare name "embedding".
    assert "ORDER BY" in sql
    assert 'embedding" <=> $' in sql, f"missing ORDER BY template in {sql!r}"

    # (b) WHERE must precede ORDER BY.
    where_idx = sql.index(" WHERE ")
    order_idx = sql.index(" ORDER BY ")
    assert where_idx < order_idx, f"ORDER BY appeared before WHERE in SQL: {sql!r}"

    # Scope params come first, then embedding, then top_k (design §7.3).
    assert params[0] == "secret"
    assert params[1] == embedding
    assert params[2] == source.top_k


@pytest.mark.unit
def test_pgvector_build_sql_dotted_metadata_field_uses_jsonb_accessor() -> None:
    """Dotted field ``metadata.foo`` must render as ``"metadata"->>'foo'``."""
    source = _make_source()
    adapter = PgVectorAdapter(pool=object())
    adapter._config = source  # pyright: ignore[reportPrivateUsage]

    scope = [
        ScopeConstraint(
            source_id="vuln-embeddings",
            field="metadata.classification",
            operator="=",
            value="secret",
        )
    ]

    sql, _ = adapter._build_vector_sql(  # pyright: ignore[reportPrivateUsage]
        table=source.table or "vuln_embeddings",
        scope=scope,
        embedding_column=source.embedding_column or "embedding",
        distance_operator=source.distance_operator or "<=>",
        metadata_column=source.metadata_column or "metadata",
        embedding=[0.1, 0.2, 0.3],
        top_k=source.top_k,
    )
    assert "\"metadata\"->>'classification'" in sql, f"JSONB accessor not rendered in {sql!r}"


@pytest.mark.unit
def test_pgvector_context_embedding_overrides_per_source_embedder() -> None:
    """Design §7.2 precedence: context override > per-source > broker default.

    When ``context['embedding']`` is set, neither the per-source embedder nor
    the broker default is consulted. Here the per-source embedder is a strict
    NoopEmbedder that would raise if called — a successful resolve proves the
    context override bypassed it.
    """
    source = _make_source()
    adapter = PgVectorAdapter(
        pool=object(),
        per_source_embedder=NoopEmbedder(strict=True),
        broker_default_embedder=NoopEmbedder(strict=True),
    )
    adapter._config = source  # pyright: ignore[reportPrivateUsage]

    v = adapter._resolve_embedding({"embedding": [0.1, 0.2, 0.3]})  # pyright: ignore[reportPrivateUsage]
    assert v == [0.1, 0.2, 0.3]


@pytest.mark.unit
def test_pgvector_per_source_embedder_preferred_over_broker_default() -> None:
    """Design §7.2 precedence rung 2: per-source > broker default."""

    class _FixedEmbedder:
        def embed(self, text: str) -> list[float]:
            del text
            return [0.7, 0.8, 0.9]

    source = _make_source()
    adapter = PgVectorAdapter(
        pool=object(),
        per_source_embedder=_FixedEmbedder(),
        # Broker default would raise if reached.
        broker_default_embedder=NoopEmbedder(strict=True),
    )
    adapter._config = source  # pyright: ignore[reportPrivateUsage]

    v = adapter._resolve_embedding({"raw_intent": "find duplicates"})  # pyright: ignore[reportPrivateUsage]
    assert v == [0.7, 0.8, 0.9]


@pytest.mark.unit
def test_pgvector_no_embedding_source_or_context_raises() -> None:
    """Design §7.2 rung 3: strict broker default raises when nothing upstream."""
    source = _make_source()
    adapter = PgVectorAdapter(pool=object())  # default broker = strict Noop
    adapter._config = source  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(EmbeddingUnavailableError):
        adapter._resolve_embedding({})  # pyright: ignore[reportPrivateUsage]


@pytest.mark.unit
@pytest.mark.parametrize("operator", ["<=>", "<->", "<#>"])
def test_pgvector_build_sql_emits_each_allowed_distance_operator(operator: str) -> None:
    """Done-when (c): all three pgvector distance operators render verbatim.

    ``<=>`` = cosine, ``<->`` = L2, ``<#>`` = negative inner product. The
    adapter allowlist (design §7.3) pins exactly this set; each must pass
    through ``_build_vector_sql`` and appear inside the ``ORDER BY``.
    """
    source = _make_source()
    adapter = PgVectorAdapter(pool=object())
    adapter._config = source  # pyright: ignore[reportPrivateUsage]

    sql, _ = adapter._build_vector_sql(  # pyright: ignore[reportPrivateUsage]
        table=source.table or "vuln_embeddings",
        scope=[],
        embedding_column=source.embedding_column or "embedding",
        distance_operator=operator,
        metadata_column=source.metadata_column or "metadata",
        embedding=[0.1, 0.2, 0.3],
        top_k=source.top_k,
    )

    assert f'embedding" {operator} $' in sql, (
        f"distance operator {operator!r} not rendered in SQL: {sql!r}"
    )
    assert "ORDER BY" in sql
