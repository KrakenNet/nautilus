"""Integration e2e for :class:`ElasticsearchAdapter` (Task 3.15).

Boots a single-node ``elasticsearch:9.0.2`` testcontainer (module-scoped),
seeds a small ``vulns`` index with mixed ``severity`` / ``title`` documents,
and exercises the adapter against the live upstream.

Three scenarios live here (AC-8.5 / FR-20):

1. ``test_elasticsearch_e2e_in_operator_filters_rows`` — scope
   ``severity IN ('high','critical')`` returns only matching docs.
2. ``test_elasticsearch_e2e_like_wildcard_round_trips`` — scope
   ``title LIKE '%foo%'`` returns only docs whose ``title.keyword`` matches
   the ``*foo*`` wildcard.
3. ``test_elasticsearch_e2e_operator_allowlist_round_trip`` — every operator
   in the adapter's allowlist composes a valid search against the live
   container with no exception (drift-guard companion for AC-8.5).

The :class:`ElasticsearchAdapter` requires keyword-shape fields for ``IN`` /
``LIKE`` / range queries to hit the inverted index predictably, so the seed
mapping pins ``severity`` and ``title`` as ``keyword`` types.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from elastic_transport import HttpxAsyncHttpNode
from elasticsearch import AsyncElasticsearch, Elasticsearch
from testcontainers.elasticsearch import (  # pyright: ignore[reportMissingTypeStubs]
    ElasticSearchContainer,
)

from nautilus.adapters.elasticsearch import ElasticsearchAdapter
from nautilus.config.models import NoneAuth, SourceConfig
from nautilus.core.models import IntentAnalysis, ScopeConstraint

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Container fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def es_container() -> Iterator[str]:
    """Boot ES 9.0.2 once per module, seed ``vulns`` index, yield base URL."""
    container = ElasticSearchContainer("elasticsearch:9.0.2", mem_limit="2G")
    container.start()
    try:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(9200)
        base_url = f"http://{host}:{port}"

        # Sync client is sufficient for seeding; the adapter itself uses the
        # async client.
        client = Elasticsearch(hosts=[base_url])
        try:
            # Keyword mapping so ``term``/``terms``/``wildcard`` hit the
            # inverted index without needing ``.keyword`` sub-fields.
            client.indices.create(
                index="vulns",
                mappings={
                    "properties": {
                        "cve": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "cvss": {"type": "float"},
                        "title": {"type": "keyword"},
                        "retired_at": {"type": "date"},
                    }
                },
            )

            seed_docs = [
                {"cve": "CVE-2024-0001", "severity": "critical", "cvss": 9.8, "title": "foobar"},
                {"cve": "CVE-2024-0002", "severity": "high", "cvss": 7.5, "title": "alpha"},
                {"cve": "CVE-2024-0003", "severity": "medium", "cvss": 5.2, "title": "myfoo"},
                {"cve": "CVE-2024-0004", "severity": "low", "cvss": 3.1, "title": "beta"},
                {"cve": "CVE-2024-0005", "severity": "info", "cvss": 0.0, "title": "gamma"},
                {"cve": "CVE-2024-0006", "severity": "high", "cvss": 8.2, "title": "foobaz"},
                {"cve": "CVE-2024-0007", "severity": "critical", "cvss": 9.1, "title": "delta"},
                {"cve": "CVE-2024-0008", "severity": "medium", "cvss": 4.4, "title": "epsilon"},
            ]
            for doc in seed_docs:
                client.index(index="vulns", document=doc)
            # Force a refresh so searches see the seed before the first test runs.
            client.indices.refresh(index="vulns")
        finally:
            client.close()

        yield base_url
    finally:
        container.stop()


# ---------------------------------------------------------------------------
# Adapter helpers
# ---------------------------------------------------------------------------


def _es_source(base_url: str) -> SourceConfig:
    return SourceConfig(
        id="vulns_es",
        type="elasticsearch",
        description="seeded vulns ES index",
        classification="unclassified",
        data_types=["vulnerability"],
        allowed_purposes=["threat-analysis"],
        connection=base_url,
        index="vulns",
        auth=NoneAuth(),
    )


def _build_adapter(base_url: str) -> ElasticsearchAdapter:
    """Construct an :class:`ElasticsearchAdapter` with the httpx async node.

    The ES Python client v9 defaults to ``AiohttpHttpNode`` for async, which
    is an unlisted dependency in this repo. Nautilus already depends on
    ``httpx``, so we inject an :class:`AsyncElasticsearch` client built on
    :class:`HttpxAsyncHttpNode` — semantically identical from the adapter's
    perspective (the adapter only sees the ``AsyncElasticsearch`` facade).
    """
    client = AsyncElasticsearch(hosts=[base_url], node_class=HttpxAsyncHttpNode)
    return ElasticsearchAdapter(client=client)


def _intent() -> IntentAnalysis:
    return IntentAnalysis(
        raw_intent="ES scope enforcement",
        data_types_needed=["vulnerability"],
        entities=[],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_elasticsearch_e2e_in_operator_filters_rows(es_container: str) -> None:
    """Scope ``severity IN ('high','critical')`` returns only matching docs."""
    adapter = _build_adapter(es_container)
    await adapter.connect(_es_source(es_container))
    try:
        result = await adapter.execute(
            intent=_intent(),
            scope=[
                ScopeConstraint(
                    source_id="vulns_es",
                    field="severity",
                    operator="IN",
                    value=["high", "critical"],
                )
            ],
            context={},
        )

        severities = sorted(row["severity"] for row in result.rows)
        assert severities == ["critical", "critical", "high", "high"], (
            f"IN scope leaked non-matching rows: got {result.rows!r}"
        )
    finally:
        await adapter.close()


async def test_elasticsearch_e2e_like_wildcard_round_trips(es_container: str) -> None:
    """Scope ``title LIKE '%foo%'`` matches the three ``foo`` docs."""
    adapter = _build_adapter(es_container)
    await adapter.connect(_es_source(es_container))
    try:
        result = await adapter.execute(
            intent=_intent(),
            scope=[
                ScopeConstraint(
                    source_id="vulns_es",
                    field="title",
                    operator="LIKE",
                    value="%foo%",
                )
            ],
            context={},
        )
        titles = sorted(row["title"] for row in result.rows)
        assert titles == ["foobar", "foobaz", "myfoo"], (
            f"LIKE '%foo%' did not round-trip; got {result.rows!r}"
        )
    finally:
        await adapter.close()


async def test_elasticsearch_e2e_operator_allowlist_round_trip(es_container: str) -> None:
    """Every allowlist operator composes a valid search against live ES (AC-8.5).

    This is the adapter-level drift-guard sibling of the Phase-1 static
    test — every operator declared on
    :data:`nautilus.adapters.elasticsearch._OPERATOR_ALLOWLIST` round-trips
    through the real container without raising. We assert each query returns
    a list of dict rows (possibly empty); the shape check guards against the
    DSL composer emitting something the client rejects.
    """
    adapter = _build_adapter(es_container)
    await adapter.connect(_es_source(es_container))
    try:
        # One constraint per operator. Values chosen so each query is well-typed
        # for its operand; semantic correctness of the match set is covered by
        # the dedicated IN / LIKE tests above.
        scopes: list[tuple[str, ScopeConstraint]] = [
            (
                "=",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="severity",
                    operator="=",
                    value="high",
                ),
            ),
            (
                "!=",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="severity",
                    operator="!=",
                    value="info",
                ),
            ),
            (
                "IN",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="severity",
                    operator="IN",
                    value=["high", "critical"],
                ),
            ),
            (
                "NOT IN",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="severity",
                    operator="NOT IN",
                    value=["info"],
                ),
            ),
            (
                "<",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="cvss",
                    operator="<",
                    value=5.0,
                ),
            ),
            (
                ">",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="cvss",
                    operator=">",
                    value=5.0,
                ),
            ),
            (
                "<=",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="cvss",
                    operator="<=",
                    value=5.0,
                ),
            ),
            (
                ">=",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="cvss",
                    operator=">=",
                    value=5.0,
                ),
            ),
            (
                "LIKE",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="title",
                    operator="LIKE",
                    value="%foo%",
                ),
            ),
            (
                "BETWEEN",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="cvss",
                    operator="BETWEEN",
                    value=[5.0, 9.0],
                ),
            ),
            (
                "IS NULL",
                ScopeConstraint(
                    source_id="vulns_es",
                    field="retired_at",
                    operator="IS NULL",
                    value=None,
                ),
            ),
        ]

        for op, constraint in scopes:
            result = await adapter.execute(intent=_intent(), scope=[constraint], context={})
            assert isinstance(result.rows, list), (
                f"operator {op!r} did not produce a list of rows: {result!r}"
            )
            for row in result.rows:
                assert isinstance(row, dict), f"operator {op!r} returned non-dict row: {row!r}"
    finally:
        await adapter.close()
