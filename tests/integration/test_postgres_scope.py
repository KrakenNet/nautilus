"""Integration test: :class:`PostgresAdapter` enforces scope against real PG.

Task 3.16 (AC-4.6, FR-8). The session-scoped ``pg_container`` fixture in
:mod:`tests.conftest` has already booted the ``pgvector/pgvector:pg17``
testcontainer and seeded the ``vulns`` table with 5 rows of varying
``severity`` values (``critical``, ``high``, ``medium``, ``low``, ``info``)
from ``tests/fixtures/seed.sql``.

The test targets the scope-enforcement contract at the adapter boundary —
we hand-craft :class:`ScopeConstraint` lists instead of routing through
:class:`FathomRouter`. That keeps the assertion focused on "do the
generated parameterized queries actually filter rows the way the §6.1
operator templates promise?" which is exactly the AC-4.6 / FR-8 claim.

Two requests, two assertions:

1. ``severity IN ('high','critical')`` — exactly the rows with matching
   severities come back, no others.
2. ``severity = 'low'`` — exactly one row (``CVE-2024-0004``) comes back;
   rows of any other severity are excluded.
"""

from __future__ import annotations

import pytest

from nautilus.adapters.postgres import PostgresAdapter
from nautilus.config.models import SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint


def _source_config(dsn: str) -> SourceConfig:
    """Build a ``SourceConfig`` pointing at the seeded ``vulns`` table."""
    return SourceConfig(
        id="vulns",
        type="postgres",
        description="seeded vulns table",
        classification="unclassified",
        data_types=["vulnerability"],
        allowed_purposes=["threat-analysis"],
        connection=dsn,
        table="vulns",
    )


def _empty_intent() -> IntentAnalysis:
    """Minimal ``IntentAnalysis`` — the adapter ignores it in Phase 1."""
    return IntentAnalysis(
        raw_intent="scope enforcement integration test",
        data_types_needed=["vulnerability"],
        entities=[],
    )


@pytest.mark.integration
async def test_postgres_scope_in_operator_filters_rows(pg_container: str) -> None:
    """Scope ``severity IN ('high','critical')`` returns only matching rows."""
    adapter = PostgresAdapter()
    await adapter.connect(_source_config(pg_container))
    try:
        result = await adapter.execute(
            intent=_empty_intent(),
            scope=[
                ScopeConstraint(
                    source_id="vulns",
                    field="severity",
                    operator="IN",
                    value=["high", "critical"],
                ),
            ],
            context={},
        )

        returned_severities = sorted(row["severity"] for row in result.rows)
        assert returned_severities == ["critical", "high"], (
            f"IN scope leaked non-matching rows: got {result.rows!r}"
        )
    finally:
        await adapter.close()


@pytest.mark.integration
async def test_postgres_scope_eq_operator_excludes_non_matching(pg_container: str) -> None:
    """Scope ``severity = 'low'`` returns only the single matching row."""
    adapter = PostgresAdapter()
    await adapter.connect(_source_config(pg_container))
    try:
        result = await adapter.execute(
            intent=_empty_intent(),
            scope=[
                ScopeConstraint(
                    source_id="vulns",
                    field="severity",
                    operator="=",
                    value="low",
                ),
            ],
            context={},
        )

        assert len(result.rows) == 1, (
            f"expected exactly 1 row with severity='low', got {result.rows!r}"
        )
        assert result.rows[0]["severity"] == "low"
        assert result.rows[0]["cve"] == "CVE-2024-0004"
    finally:
        await adapter.close()
