"""Journey: a request is routed, denied, and scoped -- verified at the backend.

The promise under test (README, ``docs/concepts/architecture.md``): Nautilus
decides which sources a request may reach, and a scope constraint is a policy
decision that the adapter must actually apply. So these tests do not stop at
"the response says it was scoped": they run the equivalent query directly
against Postgres and assert the broker returned exactly the rows the constraint
allows, and no others.

That distinction is the whole point. A scope constraint that appears in
``BrokerResponse.scope_restrictions`` and in the signed attestation, but never
reaches the WHERE clause, is a false receipt -- and it is invisible to any test
that only inspects the response.
"""

from __future__ import annotations

import asyncio
from typing import Any

import asyncpg
import pytest

pytestmark = pytest.mark.journey


AGENTS: dict[str, Any] = {
    "intern": {"id": "intern", "clearance": "unclassified"},
    "analyst": {"id": "analyst", "clearance": "confidential"},
    "chief": {"id": "chief", "clearance": "secret"},
}


@pytest.fixture
def deployment(pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    """A three-source, three-agent deployment over the live journey schema."""
    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    return write_config(
        {
            "sources": [
                {
                    "id": "vulns",
                    "type": "postgres",
                    "description": "public vulnerability data",
                    "classification": "unclassified",
                    "data_types": ["cve"],
                    "allowed_purposes": ["threat-analysis"],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.vulns",
                },
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "confidential",
                    "data_types": ["patients"],
                    "allowed_purposes": ["care"],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                },
                {
                    "id": "classified",
                    "type": "postgres",
                    "description": "classified vulnerability data",
                    "classification": "secret",
                    "data_types": ["cve"],
                    "allowed_purposes": ["threat-analysis"],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.vulns",
                },
            ],
            "agents": AGENTS,
        }
    )


async def _request(config: str, agent: str, intent: str, **context: Any) -> Any:
    from nautilus import Broker

    broker = Broker.from_config(config)
    try:
        return await broker.arequest(agent, intent, {"session_id": "s1", **context})
    finally:
        await broker.aclose()


# ---------------------------------------------------------------------------
# The allow/deny matrix a README reader would predict
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("agent", "may_read", "must_not_read"),
    [
        # clearance must dominate the source's classification
        ("intern", {"vulns"}, {"classified"}),
        ("analyst", {"vulns"}, {"classified"}),
        ("chief", {"vulns", "classified"}, set()),
    ],
)
def test_clearance_decides_which_sources_a_request_reaches(
    deployment: str, agent: str, may_read: set[str], must_not_read: set[str]
) -> None:
    """Clearance dominance gates routing, and a denial is recorded as such."""
    response = asyncio.run(
        _request(deployment, agent, "cve vulnerability", purpose="threat-analysis")
    )
    queried = set(response.sources_queried)

    assert may_read <= queried, (
        f"{agent} (clearance {AGENTS[agent]['clearance']}) should reach "
        f"{sorted(may_read)} but reached {sorted(queried)}"
    )
    leaked = must_not_read & queried
    assert not leaked, f"{agent} reached {sorted(leaked)}, which its clearance does not dominate"
    for source in must_not_read:
        assert source in response.sources_denied, (
            f"{source} was withheld from {agent} but is not in sources_denied "
            f"({response.sources_denied}); a silent omission is not a denial"
        )


def test_purpose_mismatch_denies_the_source(deployment: str) -> None:
    """A purpose outside ``allowed_purposes`` is a denial, not an empty result."""
    response = asyncio.run(
        _request(deployment, "chief", "patient records", purpose="threat-analysis")
    )
    assert "patients" not in response.sources_queried
    assert "patients" in response.sources_denied, (
        "a request whose purpose the source does not allow must be denied "
        f"explicitly; got denied={response.sources_denied}"
    )


# ---------------------------------------------------------------------------
# Scope enforcement, checked against the database rather than the response
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "operator", "value", "predicate"),
    [
        ("region", "=", "us-east", "region = 'us-east'"),
        ("region", "!=", "us-east", "region <> 'us-east'"),
        ("region", "IN", ["us-east", "us-west"], "region IN ('us-east','us-west')"),
        ("region", "NOT IN", ["us-east"], "region NOT IN ('us-east')"),
        ("severity", ">", 3, "severity > 3"),
        ("severity", "<=", 4, "severity <= 4"),
        ("region", "LIKE", "us-%", "region LIKE 'us-%'"),
    ],
)
def test_a_scope_constraint_reaches_the_where_clause(
    pg_dsn: str,
    write_config: Any,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    operator: str,
    value: Any,
    predicate: str,
) -> None:
    """Every allowlisted operator must filter the same rows SQL would.

    Ground truth comes from running ``predicate`` directly against the
    container, so this fails both when the constraint is dropped (too many
    rows) and when it is mistranslated (wrong rows).
    """
    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "unclassified",
                    "data_types": ["patients"],
                    "allowed_purposes": [],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                }
            ],
            "agents": AGENTS,
        }
    )

    response = asyncio.run(
        _request(
            config,
            "intern",
            "patients",
            purpose="care",
            scope_constraints=[
                {
                    "source_id": "patients",
                    "field": field,
                    "operator": operator,
                    "value": value,
                }
            ],
        )
    )

    async def _ground_truth() -> set[str]:
        conn: Any = await asyncpg.connect(dsn=pg_dsn)
        try:
            rows = await conn.fetch(
                f"SELECT name FROM journey.patients WHERE {predicate}"  # noqa: S608
            )
            return {r["name"] for r in rows}
        finally:
            await conn.close()

    expected = asyncio.run(_ground_truth())
    got = {row["name"] for row in response.data.get("patients", [])}
    assert got == expected, (
        f"scope constraint {field} {operator} {value} returned {sorted(got)}; "
        f"SQL says {sorted(expected)}. A constraint the adapter drops or "
        f"mistranslates is an over-scoped read with a signed receipt saying "
        f"otherwise."
    )


@pytest.mark.parametrize(
    "hostile_field",
    [
        'region" OR "1"="1',
        "region; DROP TABLE journey.patients--",
        "region->>'a'--",
        "1region",
        "region OR 1=1",
    ],
)
def test_a_hostile_scope_field_is_refused_before_the_query(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, hostile_field: str
) -> None:
    """A field identifier that is not a plain column must never reach SQL.

    Values are parameterised, but the field name is an identifier and cannot
    be. The adapter has to reject it, and the request must not silently
    succeed unscoped.
    """
    monkeypatch.setenv("JOURNEY_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                {
                    "id": "patients",
                    "type": "postgres",
                    "description": "patient records",
                    "classification": "unclassified",
                    "data_types": ["patients"],
                    "allowed_purposes": [],
                    "connection": "${JOURNEY_PG_DSN}",
                    "table": "journey.patients",
                }
            ],
            "agents": AGENTS,
        }
    )

    response = asyncio.run(
        _request(
            config,
            "intern",
            "patients",
            purpose="care",
            scope_constraints=[
                {
                    "source_id": "patients",
                    "field": hostile_field,
                    "operator": "=",
                    "value": "us-east",
                }
            ],
        )
    )
    assert not response.data.get("patients"), (
        f"a scope constraint on the non-column field {hostile_field!r} returned "
        f"rows instead of being refused"
    )

    # and the table is still there
    async def _still_there() -> int:
        conn: Any = await asyncpg.connect(dsn=pg_dsn)
        try:
            return int(await conn.fetchval("SELECT count(*) FROM journey.patients"))
        finally:
            await conn.close()

    assert asyncio.run(_still_there()) == 5
