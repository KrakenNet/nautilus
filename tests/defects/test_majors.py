"""One pin per confirmed major defect (REPORT.md section 4).

Each test states the promise Nautilus makes and fails on the behaviour that
breaks it. These are expected to fail until their fix lands; a fix flips
exactly one named test.

They are written against live backends on purpose. The reason 1533 existing
tests catch none of these is that they assert substrings of *generated* SQL
and Flux against mocks -- which pins the broken form as expected -- or run
against an environment tuned so the defect cannot appear (the Elasticsearch
e2e test pins a ``keyword`` mapping, which is precisely the one mapping where
the adapter works).
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

import asyncpg
import pytest

pytestmark = pytest.mark.defect


def _one_source(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "src",
        "type": "postgres",
        "description": "a source",
        "classification": "unclassified",
        "data_types": ["patients"],
        "allowed_purposes": [],
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# 4.1 -- the sync API creates a throwaway event loop per call
# ---------------------------------------------------------------------------


def test_m41_second_sync_request_still_returns_data(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``broker.request()`` twice must work; the quickstart teaches exactly this.

    ``request()`` is ``asyncio.run(self.arequest(...))``, so every call gets a
    fresh event loop, but adapter clients are cached on the adapter and
    ``_connected_adapters`` memoizes past ``connect()``. Call #2 therefore
    reuses a pool bound to a closed loop. No exception reaches the caller: the
    source lands in ``sources_errored`` and ``response.data`` is ``{}``, which
    a doc-following caller reads as "no matching data".
    """
    from nautilus import Broker

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [_one_source(connection="${JOURNEY_PG_DSN}", table="journey.patients")],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    broker = Broker.from_config(config)
    try:
        first = broker.request("a", "patients", {"purpose": "p", "session_id": "s1"})
        second = broker.request("a", "patients", {"purpose": "p", "session_id": "s2"})
    finally:
        broker.close()

    assert first.data.get("src"), "the fixture is wrong: call #1 returned nothing"
    assert second.data.get("src"), (
        "the second sync request returned no rows. errored="
        f"{getattr(second, 'sources_errored', None)}. The caller is given an "
        "empty result set, not an error."
    )


def test_m41_sync_close_releases_the_backend_pool(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``broker.close()`` must actually close pools, or say that it could not.

    ``PostgresAdapter.close()`` raises ``Event loop is closed`` under the sync
    facade and ``aclose()``'s ``except Exception: continue  # best-effort``
    swallows it with no log line, so the connections stay open for the
    Broker's lifetime.
    """
    from nautilus import Broker

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [_one_source(connection="${JOURNEY_PG_DSN}", table="journey.patients")],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    async def _backends() -> int:
        conn: Any = await asyncpg.connect(dsn=pg_dsn)
        try:
            return int(
                await conn.fetchval(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND pid <> pg_backend_pid()"
                )
            )
        finally:
            await conn.close()

    before = asyncio.run(_backends())
    broker = Broker.from_config(config)
    broker.request("a", "patients", {"purpose": "p", "session_id": "s1"})
    broker.close()
    after = asyncio.run(_backends())

    assert after <= before, (
        f"backends went {before} -> {after} across one request and close(); "
        "close() swallowed the failure silently rather than releasing the pool"
    )


# ---------------------------------------------------------------------------
# 4.2 -- cold-start connect race leaks one pool per in-flight request
# ---------------------------------------------------------------------------


def test_m42_concurrent_cold_start_opens_one_pool_not_many(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent first-requests to one source must build one pool.

    ``_prepare_adapter`` does check-then-set across an ``await`` with no
    per-source lock, and ``PostgresAdapter.connect`` repeats the pattern.
    The trigger is the shipped deployment shape: one broker in an ASGI
    lifespan, concurrent handlers, lazy connect and no warm-up.
    """
    from nautilus import Broker

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [_one_source(connection="${JOURNEY_PG_DSN}", table="journey.patients")],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    async def _backends() -> int:
        conn: Any = await asyncpg.connect(dsn=pg_dsn)
        try:
            return int(
                await conn.fetchval(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND pid <> pg_backend_pid()"
                )
            )
        finally:
            await conn.close()

    async def _run() -> tuple[int, int]:
        before = await _backends()
        broker = Broker.from_config(config)
        try:
            await asyncio.gather(
                *(
                    broker.arequest("a", "patients", {"purpose": "p", "session_id": f"s{i}"})
                    for i in range(8)
                )
            )
            return before, await _backends()
        finally:
            await broker.aclose()

    before, peak = asyncio.run(_run())
    # One asyncpg pool is min_size..max_size connections; eight of them is not.
    assert peak - before <= 20, (
        f"eight concurrent first-requests to one source opened {peak - before} "
        "backends. Each racing request built its own pool; the losers are "
        "unreachable and survive aclose()."
    )


# ---------------------------------------------------------------------------
# 4.3 -- Elasticsearch scope constraints on text-mapped fields fail open
# ---------------------------------------------------------------------------


@pytest.fixture
def es_seeded(es_url: str) -> str:
    """An index built with ES's *default* dynamic mapping.

    Deliberately not pinned to ``keyword``. Pinning it is what hid this
    defect from the existing e2e test.
    """
    import httpx

    docs = [
        {"title": "nuclear launch codes", "classification": "top secret"},
        {"title": "cafeteria menu", "classification": "public"},
        {"title": "salary bands", "classification": "confidential"},
    ]
    httpx.delete(f"{es_url}/journey-docs", timeout=30)
    for i, doc in enumerate(docs):
        httpx.put(f"{es_url}/journey-docs/_doc/{i}", json=doc, timeout=30).raise_for_status()
    httpx.post(f"{es_url}/journey-docs/_refresh", timeout=30).raise_for_status()
    return es_url


@pytest.mark.parametrize(
    ("operator", "value", "expected"),
    [
        ("=", "top secret", {"nuclear launch codes"}),
        ("!=", "top secret", {"cafeteria menu", "salary bands"}),
        ("NOT IN", ["top secret", "confidential"], {"cafeteria menu"}),
    ],
)
def test_m43_es_scope_on_a_default_mapped_field_is_not_fail_open(
    es_seeded: str,
    write_config: Any,
    monkeypatch: pytest.MonkeyPatch,
    operator: str,
    value: Any,
    expected: set[str],
) -> None:
    """A constraint the adapter cannot translate must raise, not be ignored.

    ``docs/how-to/developing-adapters.md`` states the rule outright: "silently
    dropping a constraint returns over-scoped data". ES default dynamic
    mapping makes every string ``text`` + ``.keyword``; the adapter emits
    ``Term``/``Terms`` against the bare field, which does not analyse, while
    the indexed field was analysed. ``=`` then fails closed (silent empty
    result) and ``!=`` fails *open*, returning the excluded document.

    Asserting the exact expected set is deliberate: it catches fail-open and
    fail-closed with one assertion, so no case can pass by returning nothing.

    The adapter can detect this: ``get_schema()`` already calls
    ``indices.get_mapping`` and reads ``type``.
    """
    monkeypatch.setenv("JOURNEY_ES_URL", es_seeded)
    config = write_config(
        {
            "sources": [
                _one_source(
                    type="elasticsearch",
                    connection="${JOURNEY_ES_URL}",
                    index="journey-docs",
                    data_types=["docs"],
                )
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    from nautilus import Broker

    async def _run() -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest(
                "a",
                "docs",
                {
                    "purpose": "p",
                    "session_id": "s1",
                    "scope_constraints": [
                        {
                            "source_id": "src",
                            "field": "classification",
                            "operator": operator,
                            "value": value,
                        }
                    ],
                },
            )
        finally:
            await broker.aclose()

    response = asyncio.run(_run())
    titles = {r.get("title") for r in response.data.get("src", [])}

    assert titles == expected, (
        f"classification {operator} {value!r} returned {sorted(titles)}; the "
        f"seeded documents make {sorted(expected)} the correct answer. "
        f"The constraint is still reported as applied in scope_restrictions "
        f"and in the signed attestation -- a false receipt either way. "
        f"errored={getattr(response, 'sources_errored', None)}"
    )


# ---------------------------------------------------------------------------
# 4.4 -- S3 exact-key constraint silently drops every other constraint
# ---------------------------------------------------------------------------


@pytest.fixture
def s3_seeded(minio_endpoint: tuple[str, str, str]) -> tuple[str, str, str, str]:
    """A bucket where the sensitive object is tagged ``sensitivity=high``."""
    from aiobotocore.session import AioSession

    endpoint, access, secret = minio_endpoint
    bucket = "journey"

    async def _seed() -> None:
        session = AioSession()
        async with session.create_client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access,
            aws_secret_access_key=secret,
            region_name="us-east-1",
        ) as s3:
            with contextlib.suppress(Exception):  # already exists
                await s3.create_bucket(Bucket=bucket)
            for key, body, sensitivity in (
                ("restricted/secrets.txt", b"SECRET PAYROLL", "high"),
                ("open/menu.txt", b"tacos on tuesday", "low"),
            ):
                await s3.put_object(Bucket=bucket, Key=key, Body=body)
                await s3.put_object_tagging(
                    Bucket=bucket,
                    Key=key,
                    Tagging={"TagSet": [{"Key": "sensitivity", "Value": sensitivity}]},
                )

    asyncio.run(_seed())
    return (endpoint, access, secret, bucket)


def test_m44_s3_ands_an_exact_key_with_the_other_constraints(
    s3_seeded: tuple[str, str, str, str],
    write_config: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two constraints on one source must both apply, as every other adapter does.

    ``s3.py:225`` short-circuits on ``exact_key`` and consults neither
    ``tag_filters`` nor ``prefix``, both of which it already parsed. The
    dropped constraint still appears in ``BrokerResponse.scope_restrictions``
    and in the signed attestation as though it had been applied -- a false
    receipt. Postgres, Elasticsearch, Neo4j and InfluxDB all AND correctly.
    """
    endpoint, access, secret, bucket = s3_seeded
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", access)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    monkeypatch.setenv("AWS_ENDPOINT_URL", endpoint)
    monkeypatch.setenv("JOURNEY_S3", endpoint)
    config = write_config(
        {
            "sources": [
                _one_source(
                    type="s3",
                    connection="${JOURNEY_S3}",
                    table=bucket,
                    data_types=["docs"],
                )
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    from nautilus import Broker

    key_only = {
        "source_id": "src",
        "field": "key",
        "operator": "=",
        "value": "restricted/secrets.txt",
    }
    tag_only = {
        "source_id": "src",
        "field": "tag.sensitivity",
        "operator": "=",
        "value": "low",
    }

    async def _run(constraints: list[dict[str, Any]]) -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest(
                "a",
                "docs",
                {
                    "purpose": "p",
                    "session_id": "s1",
                    "scope_constraints": constraints,
                },
            )
        finally:
            await broker.aclose()

    def _bodies(response: Any) -> list[str]:
        return [str(r) for r in response.data.get("src", [])]

    # Controls: each constraint alone is honoured. Without these, an empty
    # result from a broken adapter would satisfy the real assertion for free.
    key_alone = asyncio.run(_run([key_only]))
    assert any("SECRET PAYROLL" in b for b in _bodies(key_alone)), (
        f"the fixture is wrong: key alone returned {_bodies(key_alone)!r}, "
        f"errored={getattr(key_alone, 'sources_errored', None)}"
    )
    tag_alone = asyncio.run(_run([tag_only]))
    assert not any("SECRET PAYROLL" in b for b in _bodies(tag_alone)), (
        f"the fixture is wrong: tag.sensitivity='low' alone returned the "
        f"high-tagged object: {_bodies(tag_alone)!r}"
    )

    both = asyncio.run(_run([key_only, tag_only]))
    assert not any("SECRET PAYROLL" in b for b in _bodies(both)), (
        "key='restricted/secrets.txt' AND tag.sensitivity='low' returned the "
        "object tagged sensitivity=high. The tag constraint was parsed, "
        "discarded on the exact-key branch, and still reported as applied in "
        "scope_restrictions and in the signed attestation."
    )


# ---------------------------------------------------------------------------
# 4.5 -- InfluxDB: two documented operator families produce invalid Flux
# ---------------------------------------------------------------------------


@pytest.fixture
def influx_seeded(influx: tuple[str, str, str, str]) -> tuple[str, str, str, str]:
    """Write a handful of points so a correct query has something to return."""
    import httpx

    url, org, bucket, token = influx
    lines = "\n".join(
        f"cpu,host=web-{i},region=us-east usage={i * 10}i {1700000000 + i}000000000"
        for i in range(5)
    )
    httpx.post(
        f"{url}/api/v2/write",
        params={"org": org, "bucket": bucket, "precision": "ns"},
        headers={"Authorization": f"Token {token}"},
        content=lines,
        timeout=30,
    ).raise_for_status()
    return influx


@pytest.mark.parametrize(
    ("field", "operator", "value"),
    [
        # _flux_like emits strings.hasPrefix(...) but _build_flux never emits
        # `import "strings"`, so the query is rejected as an undefined
        # identifier. get_schema already emits an import correctly.
        ("host", "LIKE", "web-%"),
        # _flux_escape quotes any non-numeric bound; Flux range() wants a time
        # or duration literal, and the scope_constraint.value slot is typed
        # `string`, so the one working input type is unreachable from a rule.
        ("_time", ">", "2023-11-14T00:00:00Z"),
        ("_time", ">", "-30d"),
    ],
)
def test_m45_documented_influx_operators_produce_valid_flux(
    influx_seeded: tuple[str, str, str, str],
    write_config: Any,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    operator: str,
    value: str,
) -> None:
    """A documented operator must produce Flux the server accepts.

    Both of these fail closed with a per-source ``ErrorRecord``, so the caller
    gets an empty result rather than an error. The existing unit tests assert
    *substrings* of the generated Flux and pin the broken quoted form as
    expected; nothing ever asks a Flux engine whether the query compiles.
    """
    url, org, bucket, token = influx_seeded
    monkeypatch.setenv("INFLUXDB_V2_ORG", org)
    monkeypatch.setenv("INFLUXDB_V2_TOKEN", token)
    monkeypatch.setenv("JOURNEY_INFLUX", url)
    config = write_config(
        {
            "sources": [
                _one_source(
                    type="influxdb",
                    connection="${JOURNEY_INFLUX}",
                    table=bucket,
                    data_types=["metrics"],
                )
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    from nautilus import Broker

    async def _run() -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest(
                "a",
                "metrics",
                {
                    "purpose": "p",
                    "session_id": "s1",
                    "scope_constraints": [
                        {
                            "source_id": "src",
                            "field": field,
                            "operator": operator,
                            "value": value,
                        }
                    ],
                },
            )
        finally:
            await broker.aclose()

    response = asyncio.run(_run())
    errors = list(getattr(response, "sources_errored", []) or [])
    assert not errors, (
        f"{field} {operator} {value!r} produced Flux the server rejected: "
        f"{[e.message for e in errors]}"
    )
    assert response.data.get("src"), (
        f"{field} {operator} {value!r} matched none of the 5 seeded points"
    )


# ---------------------------------------------------------------------------
# 4.6 -- Postgres IN/NOT IN hardcode ::text[]
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("operator", ["IN", "NOT IN"])
def test_m46_postgres_in_works_on_a_non_text_column(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, operator: str
) -> None:
    """``IN`` on an integer column must not raise a type error.

    ``postgres.py`` renders ``= ANY($n::text[])``. Postgres resolves the cast
    before operator lookup, so a non-text column raises ``operator does not
    exist: integer = text``. The justifying comment ("asyncpg will coerce to
    the column's actual type") is false; dropping the cast works for text and
    non-text alike. ``PgVectorAdapter`` delegates to ``_build_sql`` and
    carries the same defect. The unit test asserts the literal ``::text[]``
    against a mock and the one integration test's column is ``text``.
    """
    from nautilus import Broker

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [_one_source(connection="${JOURNEY_PG_DSN}", table="journey.patients")],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    async def _run() -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest(
                "a",
                "patients",
                {
                    "purpose": "p",
                    "session_id": "s1",
                    "scope_constraints": [
                        {
                            "source_id": "src",
                            "field": "severity",
                            "operator": operator,
                            "value": [2, 4],
                        }
                    ],
                },
            )
        finally:
            await broker.aclose()

    response = asyncio.run(_run())
    errors = list(getattr(response, "sources_errored", []) or [])
    assert not errors, (
        f"severity {operator} [2, 4] on an integer column failed: {[e.message for e in errors]}"
    )


# ---------------------------------------------------------------------------
# 4.7 -- a backend outage is reported and audited as "major schema drift"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source_type", "extra", "dsn"),
    [
        ("elasticsearch", {"index": "anything"}, "http://127.0.0.1:1"),
        ("neo4j", {"label": "Anything"}, "bolt://127.0.0.1:1"),
    ],
)
def test_m47_get_schema_raises_when_the_backend_is_unreachable(
    source_type: str, extra: dict[str, Any], dsn: str
) -> None:
    """An outage must surface as an exception, not as an ``unknown()`` schema.

    ``ElasticsearchAdapter.get_schema`` and ``Neo4jAdapter.get_schema`` swallow
    every exception and return ``AdapterSchema.unknown()``. Because ``connect()``
    for both only builds a lazy client, an outage first surfaces in
    ``_check_adapter_schema``, where ``unknown()`` differs from the stored
    baseline and is classified as **major schema drift**: the adapter is
    quarantined and ``schema_drift_detected`` + ``adapter_quarantined`` land in
    the audit trail, describing an event that did not occur.

    The broker already handles this correctly for an adapter that *raises* --
    ``broker.py:2217-2222`` logs "skipping fingerprint check" -- so returning
    the stub is what defeats the guard. Postgres is unaffected because
    ``create_pool`` does real I/O and fails first.

    And the prescribed remediation makes it permanent: ``schema-ack`` during
    the outage signs the ``unknown()`` fingerprint as the baseline, so the
    source is re-quarantined when the backend *recovers*.
    """
    from nautilus.adapters import ADAPTER_REGISTRY
    from nautilus.config.models import SourceConfig

    source = SourceConfig.model_validate(
        _one_source(type=source_type, connection=dsn, data_types=["docs"], **extra)
    )

    async def _probe() -> Any:
        adapter = ADAPTER_REGISTRY[source.type]()
        # connect() succeeds for both: it only builds a lazy client, which is
        # why the outage does not surface until the fingerprint check.
        await adapter.connect(source)
        try:
            return await adapter.get_schema()
        finally:
            await adapter.close()

    async def _bounded() -> Any:
        # Bounded because a get_schema that neither raises nor returns is just
        # as fatal to the guard as one that returns the stub -- the neo4j
        # driver spends ~30s in retry backoff before it gives up and stubs.
        return await asyncio.wait_for(_probe(), timeout=8)

    try:
        schema = asyncio.run(_bounded())
    except TimeoutError:
        pytest.fail(
            f"{source_type}.get_schema() neither raised nor returned within 8s "
            f"for an unreachable backend. The request, its session write and "
            f"its audit entry all wait on it (see 4.18)."
        )
    except Exception:  # noqa: BLE001 -- raising is the correct behaviour
        return

    pytest.fail(
        f"{source_type}.get_schema() returned {schema.fingerprint()[:16]}... "
        f"for an unreachable backend instead of raising. The broker reads that "
        f"as major schema drift and quarantines a source whose schema never "
        f"changed."
    )


# ---------------------------------------------------------------------------
# 4.8 -- Postgres schema fingerprint covers the whole public schema
# ---------------------------------------------------------------------------


def test_m48_postgres_fingerprint_covers_only_the_declared_table(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Co-tenant DDL must not change a source's schema fingerprint.

    ``postgres.py:214`` filters on ``table_schema = 'public'`` with no filter
    on ``SourceConfig.table``, even though ``connect()`` mandates that field
    and ``execute()`` reads only that one table. Any unrelated migration --
    another app's, a scratch table -- quarantines the source, and multiple
    Nautilus sources over one DSN cross-quarantine each other. Elasticsearch
    and S3 correctly scope to their declared index/bucket.
    """
    from nautilus.adapters.postgres import PostgresAdapter
    from nautilus.config.models import SourceConfig

    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    source = SourceConfig.model_validate(_one_source(connection=pg_dsn, table="public.declared"))

    async def _fingerprints() -> tuple[str, str]:
        conn: Any = await asyncpg.connect(dsn=pg_dsn)
        try:
            await conn.execute("DROP TABLE IF EXISTS public.declared, public.co_tenant")
            await conn.execute("CREATE TABLE public.declared (id int)")
        finally:
            await conn.close()

        adapter = PostgresAdapter()
        await adapter.connect(source)
        try:
            before = (await adapter.get_schema()).fingerprint()
            conn = await asyncpg.connect(dsn=pg_dsn)
            try:
                # An unrelated table, belonging to nobody in this config.
                await conn.execute("CREATE TABLE public.co_tenant (id int, note text)")
            finally:
                await conn.close()
            after = (await adapter.get_schema()).fingerprint()
            return before, after
        finally:
            await adapter.close()

    before, after = asyncio.run(_fingerprints())
    assert before == after, (
        "creating an unrelated table in the same database changed the "
        f"fingerprint of a source declared over public.declared "
        f"({before[:16]}... -> {after[:16]}...), which quarantines it."
    )
