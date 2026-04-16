"""pgvector adapter.

Implements design §3.5 (``PgVectorAdapter`` inherits postgres mechanics),
§3.10 (``Embedder`` Protocol), and §7 (pgvector-specific query template).

Reuses ``PostgresAdapter._build_sql`` for scope rendering — the WHERE clause
and the scope-parameter slice are identical to the postgres path. This adapter
then replaces the trailing ``LIMIT`` with the similarity-search tail
``ORDER BY <embedding_column> <op> $E LIMIT $L`` per §7.3 and appends the
embedding vector + top_k to the parameter list.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar, cast

import asyncpg  # pyright: ignore[reportMissingTypeStubs]
from pgvector.asyncpg import (  # pyright: ignore[reportMissingTypeStubs]
    register_vector as _register_vector_raw,  # pyright: ignore[reportUnknownVariableType]
)

from nautilus.adapters.base import AdapterError, quote_identifier
from nautilus.adapters.embedder import Embedder, EmbeddingUnavailableError, NoopEmbedder
from nautilus.adapters.postgres import PostgresAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import AdapterResult, IntentAnalysis, ScopeConstraint

# asyncpg's ``init`` hook has signature ``async (conn) -> None``; we re-export
# ``register_vector`` under a fully-typed alias so the ``create_pool(init=...)``
# call site does not leak ``Unknown`` types into strict pyright mode.
_register_vector: Callable[[Any], Awaitable[None]] = cast(
    "Callable[[Any], Awaitable[None]]", _register_vector_raw
)

# Default distance operator when ``SourceConfig.distance_operator`` is None
# (Pydantic default on SourceConfig is already "<=>" — this is belt-and-braces
# for hand-constructed SourceConfigs in tests).
_DEFAULT_DISTANCE_OPERATOR: str = "<=>"

# Default column names when not specified on the SourceConfig.
_DEFAULT_EMBEDDING_COLUMN: str = "embedding"

# Allowed pgvector distance operators — mirrors the ``Literal[...]`` on
# ``SourceConfig.distance_operator`` (design §4.1). A second-layer defense:
# never interpolate an attacker-supplied operator into SQL.
_ALLOWED_DISTANCE_OPERATORS: frozenset[str] = frozenset({"<=>", "<->", "<#>"})


class PgVectorAdapter(PostgresAdapter):
    """pgvector adapter (design §3.5, §7).

    Shares the ``asyncpg.Pool`` mechanics and scope rendering of the base
    ``PostgresAdapter``. Overrides ``execute()`` to resolve an embedding per
    §7.2 and build the similarity-search query per §7.3.
    """

    source_type: ClassVar[str] = "pgvector"

    def __init__(
        self,
        pool: Any = None,
        per_source_embedder: Embedder | None = None,
        broker_default_embedder: Embedder | None = None,
    ) -> None:
        super().__init__(pool=pool)
        self._per_source_embedder: Embedder | None = per_source_embedder
        # Broker wires its own default at adapter-construction time. When
        # unset, we fall back to strict NoopEmbedder so the configuration gap
        # is surfaced via ``EmbeddingUnavailableError`` rather than silent
        # zero-vector garbage (design §3.10 rationale).
        self._broker_default_embedder: Embedder = (
            broker_default_embedder
            if broker_default_embedder is not None
            else NoopEmbedder(strict=True)
        )

    async def connect(self, config: SourceConfig) -> None:
        """Create the pgvector-aware ``asyncpg.Pool`` (design §7.1).

        Overrides :meth:`PostgresAdapter.connect` to pass ``init=register_vector``
        so every pooled connection installs the pgvector codec for the
        ``vector`` / ``halfvec`` / ``sparsevec`` types. Without this codec,
        asyncpg tries to bind Python ``list[float]`` as ``str`` and raises
        ``DataError: invalid input for query argument``.
        """
        if config.table is None:
            raise AdapterError(f"PgVectorAdapter requires 'table' on source '{config.id}'")
        self._config = config
        if self._pool is None:
            self._pool = await asyncpg.create_pool(  # pyright: ignore[reportUnknownMemberType]
                dsn=config.connection,
                init=_register_vector,
            )

    def _resolve_embedding(
        self,
        context: dict[str, Any],
    ) -> list[float]:
        """Apply the §7.2 embedder resolution precedence.

        1. ``context["embedding"]: list[float]`` — always accepted if present.
        2. Per-source embedder named in ``SourceConfig.embedder``.
        3. Broker-default embedder (defaults to ``NoopEmbedder(strict=True)``).
        """
        override = context.get("embedding")
        if override is not None:
            if not isinstance(override, list):
                raise EmbeddingUnavailableError(
                    f"context['embedding'] must be list[float], got {type(override).__name__}"
                )
            # Cast via list comprehension preserves float-ness defensively;
            # trust-but-verify (pyright treats ``override`` as ``list[Unknown]``
            # since context is ``dict[str, Any]``).
            return [float(x) for x in cast(list[Any], override)]

        # Per-source embedder: a raw_intent string is the natural input, but
        # the broker only hands us the intent object. Pass the raw intent text
        # when available; otherwise embedder sees an empty string (a real
        # embedder would refuse; NoopEmbedder doesn't care).
        raw_text = str(context.get("raw_intent", ""))

        if self._per_source_embedder is not None:
            return self._per_source_embedder.embed(raw_text)

        return self._broker_default_embedder.embed(raw_text)

    def _build_vector_sql(
        self,
        table: str,
        scope: list[ScopeConstraint],
        embedding_column: str,
        distance_operator: str,
        metadata_column: str,
        embedding: list[float],
        top_k: int,
    ) -> tuple[str, list[Any]]:
        """Compose the §7.3 similarity-search SQL.

        Delegates scope rendering to ``PostgresAdapter._build_sql`` for full
        reuse of the §6.1 operator template table, then splices the trailing
        ``ORDER BY <embedding_column> <op> $E LIMIT $L`` onto the returned
        fragment.

        The base ``_build_sql`` returns SQL shaped like
        ``SELECT * FROM "t" [WHERE ...] LIMIT $N`` with scope params + the
        limit appended to ``params``. We discard both: rebuild the SELECT
        column list (``id, metadata, embedding``) and replace the trailing
        ``LIMIT $N`` with the similarity tail, keeping only the scope params.
        """
        if distance_operator not in _ALLOWED_DISTANCE_OPERATORS:
            # Defensive: SourceConfig's Literal[...] enforces this at load
            # time, but hand-constructed configs in unit tests can smuggle
            # bad operators through. Fail closed.
            raise AdapterError(
                f"distance_operator '{distance_operator}' not in allowlist: "
                f"{sorted(_ALLOWED_DISTANCE_OPERATORS)}"
            )

        # Run the base scope renderer with a sentinel limit so we can extract
        # both the scope params (everything except the last element) and the
        # WHERE substring. ``base_sql`` format is predictable and deterministic:
        # ``SELECT * FROM "t" [WHERE <clauses>] LIMIT $<pidx>``.
        base_sql, base_params = self._build_sql(table, scope, limit=1)
        scope_params: list[Any] = base_params[:-1]

        # Cut the WHERE fragment at the last " LIMIT $" — safe because
        # ``table`` and scope fields are regex-validated, so they cannot
        # contain the literal substring " LIMIT $".
        if scope:
            where_start = base_sql.find(" WHERE ")
            limit_start = base_sql.rfind(" LIMIT $")
            where_sql = base_sql[where_start:limit_start]
        else:
            where_sql = ""

        # Route every identifier through the shared ``quote_identifier`` helper
        # (Task 2.8): centralises the regex check + double-quote escaping so
        # ``pgvector`` and ``postgres`` agree byte-for-byte on identifier
        # rendering (NFR-4, design §6.2, §7.3).
        quoted_table = quote_identifier(table.split(".")[-1])
        quoted_metadata = quote_identifier(metadata_column)
        quoted_embedding = quote_identifier(embedding_column)

        # Allocate the two new positional placeholders. The base renderer
        # consumed $1..$len(scope_params); $E and $L come next.
        e_idx = len(scope_params) + 1
        l_idx = len(scope_params) + 2

        sql = (
            f"SELECT id, {quoted_metadata}, {quoted_embedding} "
            f"FROM {quoted_table}"
            f"{where_sql} "
            f"ORDER BY {quoted_embedding} {distance_operator} ${e_idx} "
            f"LIMIT ${l_idx}"
        )
        params: list[Any] = [*scope_params, embedding, top_k]
        return sql, params

    async def execute(
        self,
        intent: IntentAnalysis,
        scope: list[ScopeConstraint],
        context: dict[str, Any],
    ) -> AdapterResult:
        """Run the pgvector similarity query against the pool."""
        del intent  # embedding comes from context, not intent, in Phase 1
        if self._pool is None or self._config is None:
            raise AdapterError("PgVectorAdapter.execute called before connect()")
        config: SourceConfig = self._config
        table = config.table
        if table is None:
            raise AdapterError(f"PgVectorAdapter missing 'table' for source '{config.id}'")

        embedding_column = config.embedding_column or _DEFAULT_EMBEDDING_COLUMN
        metadata_column = config.metadata_column or "metadata"
        distance_operator = config.distance_operator or _DEFAULT_DISTANCE_OPERATOR
        top_k = config.top_k

        embedding = self._resolve_embedding(context)

        sql, params = self._build_vector_sql(
            table=table,
            scope=scope,
            embedding_column=embedding_column,
            distance_operator=distance_operator,
            metadata_column=metadata_column,
            embedding=embedding,
            top_k=top_k,
        )

        started = time.perf_counter()
        async with self._pool.acquire() as conn:
            records = await conn.fetch(sql, *params)
        duration_ms = int((time.perf_counter() - started) * 1000)

        # ``pgvector.asyncpg.register_vector`` decodes ``vector`` columns to
        # ``numpy.ndarray`` which pydantic's JSON serializer cannot handle
        # (PydanticSerializationError bubbles out of the FastAPI transport).
        # Normalize the embedding column — and any ndarray cell — to a plain
        # list so :class:`BrokerResponse` round-trips through FastAPI (FR-26,
        # AC-12.1 VE2a REST end-to-end).
        def _normalize(value: Any) -> Any:
            if hasattr(value, "tolist"):
                return value.tolist()
            return value

        rows: list[dict[str, Any]] = [
            {k: _normalize(v) for k, v in dict(r).items()} for r in records
        ]
        return AdapterResult(
            source_id=config.id,
            rows=rows,
            duration_ms=duration_ms,
        )


__all__ = ["PgVectorAdapter"]
