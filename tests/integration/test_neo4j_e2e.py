"""Integration e2e for :class:`Neo4jAdapter` (Task 3.15).

Boots a ``neo4j:5.13`` testcontainer (module-scoped), seeds a handful of
``(:Person {name, age, clearance})`` nodes via the sync driver, and
exercises the :class:`Neo4jAdapter` against the live upstream.

Two scenarios live here (AC-10.5 / FR-21):

1. ``test_neo4j_e2e_scoped_where_returns_matching_rows`` — scope
   ``clearance IN ('cui','secret')`` returns only the two matching
   :class:`Person` nodes.
2. ``test_neo4j_e2e_close_is_idempotent`` — calling ``close()`` twice
   against a real driver is a no-op (FR-17).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from testcontainers.neo4j import Neo4jContainer  # pyright: ignore[reportMissingTypeStubs]

from nautilus.adapters.neo4j import Neo4jAdapter
from nautilus.config.models import BasicAuth, SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Container fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def neo4j_container() -> Iterator[tuple[str, str, str]]:
    """Boot Neo4j 5.13 once per module, seed :class:`Person` nodes.

    Yields ``(uri, username, password)`` for adapter construction.
    """
    container = Neo4jContainer(
        image="neo4j:5.13",
        password="testpassword",
    )
    container.start()
    try:
        # Seed through the sync driver bundled with testcontainers' fixture.
        with container.get_driver() as driver, driver.session() as session:  # pyright: ignore[reportUnknownMemberType]
            session.run(  # pyright: ignore[reportUnknownMemberType]
                """
                CREATE (:Person {name: 'alice', age: 30, clearance: 'unclassified'})
                CREATE (:Person {name: 'bob',   age: 45, clearance: 'cui'})
                CREATE (:Person {name: 'carol', age: 29, clearance: 'secret'})
                CREATE (:Person {name: 'dan',   age: 51, clearance: 'top_secret'})
                """
            )

        yield (
            container.get_connection_url(),
            container.username,
            container.password,
        )
    finally:
        container.stop()


# ---------------------------------------------------------------------------
# Adapter helpers
# ---------------------------------------------------------------------------


def _neo4j_source(uri: str, username: str, password: str) -> SourceConfig:
    return SourceConfig(
        id="people",
        type="neo4j",
        description="seeded Person graph",
        classification="unclassified",
        data_types=["person"],
        allowed_purposes=["research"],
        connection=uri,
        label="Person",
        auth=BasicAuth(username=username, password=password),
    )


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="neo4j scope enforcement",
        data_types_needed=["person"],
        entities=[],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_neo4j_e2e_scoped_where_returns_matching_rows(
    neo4j_container: tuple[str, str, str],
) -> None:
    """Scope ``clearance IN ('cui','secret')`` returns only matching Person nodes."""
    uri, username, password = neo4j_container
    adapter = Neo4jAdapter()
    await adapter.connect(_neo4j_source(uri, username, password))
    try:
        result = await adapter.execute(
            intent=_intent(),
            scope=[
                ScopeConstraint(
                    source_id="people",
                    field="clearance",
                    operator="IN",
                    value=["cui", "secret"],
                )
            ],
            context={},
        )

        names = sorted(row["name"] for row in result.rows)
        assert names == ["bob", "carol"], f"IN scope leaked non-matching nodes: got {result.rows!r}"
        clearances = sorted(row["clearance"] for row in result.rows)
        assert clearances == ["cui", "secret"]
    finally:
        await adapter.close()


async def test_neo4j_e2e_close_is_idempotent(
    neo4j_container: tuple[str, str, str],
) -> None:
    """FR-17: ``close()`` is idempotent against a real driver."""
    uri, username, password = neo4j_container
    adapter = Neo4jAdapter()
    await adapter.connect(_neo4j_source(uri, username, password))

    # First close releases the driver.
    await adapter.close()
    # Subsequent closes are a no-op — must not raise.
    await adapter.close()
    await adapter.close()
