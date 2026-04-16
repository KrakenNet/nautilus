"""Integration test: :class:`PgVectorAdapter` similarity search + metadata filter.

Task 3.17 (AC-5.5, FR-9). The session-scoped ``pg_container`` fixture in
:mod:`tests.conftest` already boots the ``pgvector/pgvector:pg17`` testcontainer
and creates the ``vuln_embeddings`` table via ``tests/fixtures/seed.sql``
(``id int pk, embedding vector(3), metadata jsonb``).

This test seeds five additional rows (ids ``100..104``) with explicit
``metadata.classification`` values (three ``"cui"``, two ``"unclassified"``),
runs the adapter with scope ``metadata.classification = 'cui'`` and a known
query embedding, then asserts:

a) exactly the three ``cui`` rows are returned (the two unclassified rows
   are filtered out by the WHERE clause); and

b) the returned rows are ordered by increasing cosine distance (``<=>``) to
   the query embedding — equivalent to decreasing cosine similarity. The
   expected ordering is computed in the test from the seeded vectors.

Rows are cleaned up in a ``finally`` so the session-scoped container stays
usable for sibling tests.
"""

from __future__ import annotations

import json
from typing import Any

import asyncpg  # pyright: ignore[reportMissingTypeStubs]
import pytest
from pgvector.asyncpg import (  # pyright: ignore[reportMissingTypeStubs]
    register_vector as _register_vector_raw,  # pyright: ignore[reportUnknownVariableType]
)

from nautilus.adapters.pgvector import PgVectorAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

# Query embedding used by the similarity search. Chosen so the five seeded
# vectors have a strict, unambiguous cosine-distance ordering.
_QUERY_EMBEDDING: list[float] = [1.0, 0.0, 0.0]

# (id, classification, embedding) tuples — three ``cui`` rows with distinct
# distances to ``_QUERY_EMBEDDING`` plus two ``unclassified`` distractors.
# Cosine distance = 1 - cos(theta). For unit vectors with x-component
# dominating, the row with the largest x-component is closest.
#
# Expected cui distance ranking (closest → farthest): 100 < 101 < 102.
_SEED_ROWS: list[tuple[int, str, list[float]]] = [
    (100, "cui", [1.0, 0.0, 0.0]),  # identical to query — distance 0
    (101, "cui", [0.9, 0.1, 0.0]),  # slight off-axis
    (102, "cui", [0.7, 0.7, 0.0]),  # 45° off
    (103, "unclassified", [0.95, 0.05, 0.0]),  # nearer than 101/102 but filtered
    (104, "unclassified", [0.0, 0.0, 1.0]),  # orthogonal
]


def _cosine_distance(a: list[float], b: list[float]) -> float:
    """Cosine distance = 1 - cos(theta). Matches pgvector ``<=>``.

    Used only in test assertions to compute the expected ordering from the
    seeded vectors. Inputs are guaranteed non-zero (see ``_SEED_ROWS``).
    """
    import math

    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    return 1.0 - (dot / (norm_a * norm_b))


def _source_config(dsn: str) -> SourceConfig:
    """Build a pgvector ``SourceConfig`` pointing at the seeded table."""
    return SourceConfig(
        id="vuln-embeddings",
        type="pgvector",
        description="seeded vuln_embeddings table",
        classification="unclassified",
        data_types=["vulnerability"],
        allowed_purposes=["research"],
        connection=dsn,
        table="vuln_embeddings",
        embedding_column="embedding",
        metadata_column="metadata",
        distance_operator="<=>",
        # Request more than the 5 candidates so ``top_k`` never truncates
        # the filtered result below the 3 cui rows.
        top_k=10,
    )


def _empty_intent() -> IntentAnalysis:
    """Minimal ``IntentAnalysis`` — the adapter ignores it in Phase 1."""
    return IntentAnalysis(
        raw_intent="pgvector similarity integration test",
        data_types_needed=["vulnerability"],
        entities=[],
    )


async def _insert_seed_rows(dsn: str) -> None:
    """Insert the five task-3.17 rows. Uses ``ON CONFLICT DO NOTHING`` so a
    prior leaked run does not poison the test; we also delete in cleanup.
    """
    conn: Any = await asyncpg.connect(dsn=dsn)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType, reportAny]
    try:
        await _register_vector_raw(conn)  # pyright: ignore[reportUnknownArgumentType]
        for row_id, classification, embedding in _SEED_ROWS:
            await conn.execute(  # pyright: ignore[reportUnknownMemberType]
                "INSERT INTO vuln_embeddings (id, embedding, metadata) "
                "VALUES ($1, $2, $3::jsonb) ON CONFLICT (id) DO NOTHING",
                row_id,
                embedding,
                json.dumps({"classification": classification}),
            )
    finally:
        await conn.close()  # pyright: ignore[reportUnknownMemberType]


async def _delete_seed_rows(dsn: str) -> None:
    """Remove the task-3.17 rows so the session-scoped container is clean."""
    conn: Any = await asyncpg.connect(dsn=dsn)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType, reportAny]
    try:
        ids = [row_id for row_id, _, _ in _SEED_ROWS]
        await conn.execute(  # pyright: ignore[reportUnknownMemberType]
            "DELETE FROM vuln_embeddings WHERE id = ANY($1::int[])",
            ids,
        )
    finally:
        await conn.close()  # pyright: ignore[reportUnknownMemberType]


@pytest.mark.integration
async def test_pgvector_similarity_metadata_filter_and_ordering(pg_container: str) -> None:
    """(a) Only cui rows returned; (b) ordered by similarity to query embedding."""
    await _insert_seed_rows(pg_container)
    adapter = PgVectorAdapter()
    try:
        await adapter.connect(_source_config(pg_container))
        result = await adapter.execute(
            intent=_empty_intent(),
            scope=[
                ScopeConstraint(
                    source_id="vuln-embeddings",
                    field="metadata.classification",
                    operator="=",
                    value="cui",
                ),
            ],
            context={"embedding": _QUERY_EMBEDDING},
        )

        returned_ids: list[int] = [int(row["id"]) for row in result.rows]

        # (a) Only the three seeded cui rows are returned (and every row's
        # metadata confirms classification == "cui"). The two unclassified
        # rows must be filtered by the WHERE clause.
        assert len(result.rows) == 3, (
            f"expected exactly 3 cui rows, got {len(result.rows)}: {returned_ids!r}"
        )
        for row in result.rows:
            metadata_raw: Any = row["metadata"]
            # asyncpg + pgvector round-trips jsonb as a JSON string by default
            # (no codec registered for the json type). Accept either shape.
            metadata = json.loads(metadata_raw) if isinstance(metadata_raw, str) else metadata_raw
            assert metadata["classification"] == "cui", (
                f"non-cui row leaked through scope filter: {row!r}"
            )
        assert set(returned_ids) == {100, 101, 102}, f"unexpected cui row set: {returned_ids!r}"

        # (b) Ordering matches ascending cosine distance (== descending
        # similarity) to the query embedding. Compute the expected order from
        # the seeded vectors and compare.
        cui_rows = [(rid, emb) for (rid, cls, emb) in _SEED_ROWS if cls == "cui"]
        expected_order = [
            rid
            for rid, _emb in sorted(
                cui_rows, key=lambda pair: _cosine_distance(pair[1], _QUERY_EMBEDDING)
            )
        ]
        assert returned_ids == expected_order, (
            f"similarity ordering mismatch: got {returned_ids!r}, expected {expected_order!r}"
        )
    finally:
        await adapter.close()
        await _delete_seed_rows(pg_container)
