"""One pin per Wave 7 gate item (REAUDIT.md section 6, items 1-8 plus the
multi-process track).

These are the findings the *fix* waves left half-closed or opened. Several of
them exist because Waves 0-6 fixed the call site the report named and stopped
there, so every pin here deliberately exercises a **sibling** of the fixed
path: a second constraint on an already-handled field, a second transport
reaching the same broker, a second broker process against the same store.

Written against live backends for the same reason as the other defect pins: a
mock of the thing under test pins the broken form as expected.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import asyncpg
import pytest

pytestmark = pytest.mark.defect


def _pg_source(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "src",
        "type": "postgres",
        "description": "a source",
        "classification": "unclassified",
        "data_types": ["patients"],
        "allowed_purposes": [],
        "connection": "${WAVE7_PG_DSN}",
        "table": "journey.patients",
    }
    base.update(over)
    return base


# ===========================================================================
# Gate 1 -- the principal exposure ledger is not serialised, and only one
#           transport supplies the caller identity
# ===========================================================================


def test_w71_parallel_requests_do_not_lose_principal_exposure(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cumulative exposure must survive concurrency, on every key it is stored under.

    B3 was closed by serialising the read-merge-write on ``session_id``
    (``broker.py:_session_lock``). WAVE 6 then added a second ledger keyed on
    the caller's principal and wrote it through the *same* read-merge-write --
    but ``_session_lock`` is keyed on the session id, so two requests that
    declare *different* session ids take different locks and race the one
    principal record. Both read it empty, both write their own source, and the
    loser's exposure is gone.

    That is the original B3 defeat, one dictionary key over, and it is the
    escalation bypass the ledger exists to prevent: a caller that wants a
    clean ledger issues its reads in parallel under throwaway session ids.

    The control is the sequential run below: same requests, same principal,
    one at a time. If the sequential case does not accumulate either, the
    fixture is wrong and this pin proves nothing.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    kinds = ("ssn", "dob", "phone", "email")
    config = write_config(
        {
            "sources": [
                _pg_source(id=f"pii_{k}", data_types=["pii", k], classification="confidential")
                for k in kinds
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "confidential"}},
        }
    )

    from nautilus import Broker
    from nautilus.core.principal import derive_principal_id

    async def _drive(parallel: bool) -> set[str]:
        broker = Broker.from_config(config)
        try:
            calls = [
                broker.arequest(
                    "analyst",
                    k,
                    {"purpose": "care", "session_id": f"{'par' if parallel else 'seq'}-{k}"},
                )
                for k in kinds
            ]
            if parallel:
                await asyncio.gather(*calls)
            else:
                for c in calls:
                    await c
            store: Any = broker.session_store
            key = derive_principal_id("analyst")
            state = await store.aget(key) if hasattr(store, "aget") else store.get(key)
            return set((state or {}).get("sources_visited", []))
        finally:
            await broker.aclose()

    expected = {f"pii_{k}" for k in kinds}
    sequential = asyncio.run(_drive(parallel=False))
    assert sequential == expected, (
        f"control failed: even sequentially the principal ledger only holds "
        f"{sorted(sequential)}; the fixture, not the lock, is broken"
    )

    parallel = asyncio.run(_drive(parallel=True))
    assert parallel == expected, (
        f"four parallel requests under four session ids left the principal "
        f"ledger holding {sorted(parallel)}. The per-session lock does not "
        f"cover the principal record (broker.py:_session_lock keys on "
        f"session_id; the principal read-merge-write is at _route/_update_session). "
        f"A caller resets its own cumulative-exposure ledger with asyncio.gather."
    )


def test_w71_merging_the_principal_ledger_does_not_rewrite_the_session_row(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session's own record must describe that session.

    The principal's exposure is folded into the *policy input* so a fresh
    session id inherits the caller's history -- that is the intended fix. What
    is not intended is that the merged union is then written back into the
    per-session record, so session ``beta``'s row claims it visited the source
    only session ``alpha`` ever touched. An operator reading the session store
    (and the purpose-TTL window that rides on the same row) is told the wrong
    thing about which session did what.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                _pg_source(id="pii_ssn", data_types=["pii", "ssn"], classification="confidential"),
                _pg_source(id="pii_dob", data_types=["pii", "dob"], classification="confidential"),
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "confidential"}},
        }
    )

    from nautilus import Broker

    async def _run() -> tuple[set[str], set[str]]:
        broker = Broker.from_config(config)
        try:
            await broker.arequest("analyst", "ssn", {"purpose": "care", "session_id": "alpha"})
            await broker.arequest("analyst", "dob", {"purpose": "care", "session_id": "beta"})
            store: Any = broker.session_store

            async def _visited(sid: str) -> set[str]:
                state = await store.aget(sid) if hasattr(store, "aget") else store.get(sid)
                return set((state or {}).get("sources_visited", []))

            return await _visited("alpha"), await _visited("beta")
        finally:
            await broker.aclose()

    alpha, beta = asyncio.run(_run())
    assert alpha == {"pii_ssn"}, f"session alpha's own row says {sorted(alpha)}"
    assert beta == {"pii_dob"}, (
        f"session beta's stored row says it visited {sorted(beta)}; it queried "
        f"pii_dob only. The principal union belongs in the policy input, not "
        f"written back into the session record (broker.py:_update_session "
        f"stores the merged entry under both keys)."
    )


def test_w71_every_transport_keys_the_same_callers_ledger(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cumulative exposure must not be resettable by switching transport.

    ``caller=`` reaches ``Broker.arequest`` from exactly one call site --
    ``fastapi_app.py`` ``/v1/request``. ``mcp_server.py`` calls ``arequest``
    with no caller at all, so the same client, presenting the same API key to
    the same broker over the MCP HTTP port, derives an agent-id-only principal
    and accumulates into a *different* ledger. An agent that has tripped
    escalation over REST starts clean by sending the next request to the MCP
    port with the credentials it already has.

    Both transports are mounted on one broker here, so the only thing that can
    separate the two ledgers is the caller identity the transport supplies.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                _pg_source(id="pii_ssn", data_types=["pii", "ssn"], classification="confidential"),
                _pg_source(id="pii_dob", data_types=["pii", "dob"], classification="confidential"),
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "confidential"}},
            "api": {"keys": ["k-shared"]},
        }
    )

    from starlette.testclient import TestClient

    from nautilus import Broker
    from nautilus.core.principal import derive_principal_id
    from nautilus.transport.fastapi_app import create_app
    from nautilus.transport.mcp_server import create_server, http_app

    broker = Broker.from_config(config)
    rest_app = create_app(None, existing_broker=broker)
    mcp_app = http_app(create_server(None, existing_broker=broker), api_keys=["k-shared"])
    headers = {"X-API-Key": "k-shared"}

    with TestClient(rest_app) as rest:
        posted = rest.post(
            "/v1/request",
            headers=headers,
            json={
                "agent_id": "analyst",
                "intent": "ssn",
                "context": {"purpose": "care", "session_id": "rest-1"},
            },
        )
        assert posted.status_code == 200, posted.text

        # ``127.0.0.1`` because the MCP SDK's DNS-rebinding guard only accepts
        # loopback Host headers.
        with TestClient(mcp_app, base_url="http://127.0.0.1:8000") as mcp:
            mcp_headers = {
                **headers,
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            }
            mcp_headers = _mcp_handshake(mcp, mcp_headers)
            called = mcp.post(
                "/mcp",
                headers=mcp_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "nautilus_request",
                        "arguments": {
                            "agent_id": "analyst",
                            "intent": "dob",
                            "context": {"purpose": "care", "session_id": "mcp-1"},
                        },
                    },
                },
            )
            assert called.status_code == 200, f"control failed: MCP tools/call said {called.text}"

        store: Any = broker.session_store
        key = derive_principal_id("analyst", auth_principal="k-shared")
        record = await_sync(store, key)

    visited = set((record or {}).get("sources_visited", []))
    assert visited == {"pii_ssn", "pii_dob"}, (
        f"the ledger for API key 'k-shared' holds {sorted(visited)}. The MCP "
        f"request presented the same key to the same broker and landed in a "
        f"different ledger, because only fastapi_app.py passes caller= to "
        f"arequest (mcp_server.py, ui/router.py do not)."
    )


def _mcp_handshake(client: Any, headers: dict[str, str]) -> dict[str, str]:
    """Initialize an MCP streamable-HTTP session; return headers carrying its id.

    The transport is stateful, so every call after ``initialize`` must present
    the ``mcp-session-id`` the server issued -- that id is what keys session
    state for this caller.
    """
    init = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pin", "version": "0"},
            },
        },
    )
    assert init.status_code == 200, f"control failed: MCP initialize said {init.text}"
    session_id = init.headers.get("mcp-session-id")
    assert session_id, "control failed: the MCP server issued no session id at initialize"
    session_headers = {**headers, "mcp-session-id": session_id}
    client.post(
        "/mcp",
        headers=session_headers,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    return session_headers


def await_sync(store: Any, key: str) -> dict[str, Any]:
    """Read one session record through whichever surface the store implements."""

    async def _get() -> dict[str, Any]:
        return await store.aget(key)

    return asyncio.run(_get()) if hasattr(store, "aget") else store.get(key)


# ===========================================================================
# Gate 2 -- the shipped compliance packs scope on a column no table has
# ===========================================================================


@pytest.fixture
def purpose_table(pg_dsn: str) -> str:
    """A table that records what each row was collected for."""

    async def _seed() -> None:
        conn: Any = await asyncpg.connect(dsn=pg_dsn)
        try:
            await conn.execute("DROP TABLE IF EXISTS journey.consented")
            await conn.execute(
                "CREATE TABLE journey.consented ("
                "id serial PRIMARY KEY, name text NOT NULL, collected_for text NOT NULL)"
            )
            await conn.executemany(
                "INSERT INTO journey.consented (name, collected_for) VALUES ($1, $2)",
                [("ada", "treatment"), ("bob", "treatment"), ("cy", "marketing")],
            )
        finally:
            await conn.close()

    asyncio.run(_seed())
    return "journey.consented"


@pytest.mark.parametrize("pack", ["data-routing-hipaa", "data-routing-nist"])
def test_w72_a_shipped_pack_scopes_on_a_field_the_source_actually_has(
    pg_dsn: str,
    purpose_table: str,
    write_config: Any,
    monkeypatch: pytest.MonkeyPatch,
    pack: str,
) -> None:
    """Enabling a shipped compliance pack must not break every covered request.

    B2 reported that both packs raised ``ConsistencyError`` at routing time.
    Wave 0 added the missing ``routing_decision`` pattern, so they now load and
    route -- and then assert ``scope_constraint(field: "purpose")``, which the
    Postgres adapter turns into ``WHERE purpose = 'treatment'`` against the
    operator's own table. No table has a ``purpose`` column, so every covered
    request failed with ``UndefinedColumnError``: a load-time blocker became a
    run-time one.

    A pack cannot know the operator's schema, so the column is named by the
    source (``purpose_field``) and the pack scopes on whatever it names. The
    second half of the pin is the fail-closed case: a covered source that
    declares no such column is *denied*, not silently read unscoped -- a pack
    whose whole claim is minimisation must not serve data it cannot minimise.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                _pg_source(
                    table=purpose_table,
                    data_types=["phi", "pii", "patients"],
                    classification="confidential",
                    purpose_field="collected_for",
                )
            ],
            "agents": {"doc": {"id": "doc", "clearance": "confidential"}},
            "rules": {"packs": [pack], "user_rules_dirs": []},
        }
    )
    unscopable = write_config(
        {
            "sources": [
                _pg_source(
                    table=purpose_table,
                    data_types=["phi", "pii", "patients"],
                    classification="confidential",
                )
            ],
            "agents": {"doc": {"id": "doc", "clearance": "confidential"}},
            "rules": {"packs": [pack], "user_rules_dirs": []},
        },
        name="unscopable.yaml",
    )

    from nautilus import Broker

    async def _run(path: str) -> Any:
        broker = Broker.from_config(path)
        try:
            return await broker.arequest(
                "doc", "patients", {"purpose": "treatment", "session_id": "s1"}
            )
        finally:
            await broker.aclose()

    response = asyncio.run(_run(config))
    assert not response.sources_errored, (
        f"with pack {pack!r} enabled the request errored on "
        f"{response.sources_errored}. The pack must scope on the column the "
        f"source declares, not on a literal 'purpose' column that no table has."
    )
    names = {r.get("name") for r in response.data.get("src", [])}
    assert names == {"ada", "bob"}, (
        f"pack {pack!r} returned {sorted(names)}; scoping to purpose "
        f"'treatment' makes {{'ada', 'bob'}} the correct answer, and returning "
        f"nothing is the silent-empty half of the same defect"
    )

    denied = asyncio.run(_run(unscopable))
    assert not denied.data.get("src"), (
        f"pack {pack!r} served rows from a source it cannot scope: {denied.data.get('src')}"
    )
    assert not denied.sources_errored, (
        f"a source the pack cannot scope must be denied, not errored: {denied.sources_errored}"
    )
    assert "src" in denied.sources_denied, (
        f"a source with no purpose_field was neither served nor denied "
        f"(denied={denied.sources_denied}, skipped={denied.sources_skipped})"
    )


# ===========================================================================
# Gate 3 -- four silent scope fail-opens left after the adapter wave
# ===========================================================================


@pytest.fixture
def es_two_stage(es_url: str) -> str:
    """An index seeded, then extended with a field that arrives *after* first read.

    Default dynamic mapping, deliberately: pinning ``keyword`` is what hid
    the original ES defect.
    """
    import httpx

    httpx.delete(f"{es_url}/wave7-docs", timeout=30)
    for i, doc in enumerate(
        [
            {"title": "nuclear launch codes", "classification": "top secret"},
            {"title": "cafeteria menu", "classification": "public"},
        ]
    ):
        httpx.put(f"{es_url}/wave7-docs/_doc/{i}", json=doc, timeout=30).raise_for_status()
    httpx.post(f"{es_url}/wave7-docs/_refresh", timeout=30).raise_for_status()
    return es_url


def _es_config(write_config: Any, index: str) -> str:
    return write_config(
        {
            "sources": [
                {
                    "id": "src",
                    "type": "elasticsearch",
                    "description": "docs",
                    "classification": "unclassified",
                    "data_types": ["docs"],
                    "allowed_purposes": [],
                    "connection": "${WAVE7_ES_URL}",
                    "index": index,
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )


def _titles(response: Any) -> set[str]:
    return {r.get("title") for r in response.data.get("src", [])}


def _scoped_on_one_broker(
    config: str, requests: list[tuple[str, str, Any]], between: Any = None
) -> list[Any]:
    """Run several scoped requests against a single long-lived broker.

    One broker per request would give every request a freshly connected adapter,
    which is exactly what hides an adapter-lifetime cache defect. ``between`` is
    called after the first request, while the broker is still up.
    """
    from nautilus import Broker

    async def _run() -> list[Any]:
        broker = Broker.from_config(config)
        responses: list[Any] = []
        try:
            for i, (field, operator, value) in enumerate(requests):
                if i == 1 and between is not None:
                    between()
                responses.append(
                    await broker.arequest(
                        "a",
                        "docs",
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
                )
            return responses
        finally:
            await broker.aclose()

    return asyncio.run(_run())


def _scoped(config: str, field: str, operator: str, value: Any) -> Any:
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
                            "field": field,
                            "operator": operator,
                            "value": value,
                        }
                    ],
                },
            )
        finally:
            await broker.aclose()

    return asyncio.run(_run())


def test_w73_es_mapping_cache_sees_a_field_the_index_gained_later(
    es_two_stage: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A field added after the first query must still be matched exactly.

    ``execute`` fetched the mapping once (``if self._props is None``) and never
    refetched. ``_exact_field`` treats a field missing from that cache as
    "unmapped, or already an exact type" and returns the bare field -- which
    for a dynamically-mapped string is the analysed ``text`` field, the exact
    fail-open ``.keyword`` routing exists to close. A long-lived broker
    therefore leaks every field the index gains after its first scoped read.

    Both requests run on one broker, because one broker per request reconnects
    the adapter and refills the cache -- the defect is only reachable across an
    adapter's lifetime.
    """
    import httpx

    monkeypatch.setenv("WAVE7_ES_URL", es_two_stage)
    config = _es_config(write_config, "wave7-docs")

    def _extend_the_index() -> None:
        httpx.put(
            f"{es_two_stage}/wave7-docs/_doc/2",
            json={"title": "salary bands", "classification": "public", "owner": "finance dept"},
            timeout=30,
        ).raise_for_status()
        httpx.put(
            f"{es_two_stage}/wave7-docs/_doc/3",
            json={
                "title": "cafeteria roster",
                "classification": "public",
                "owner": "catering dept",
            },
            timeout=30,
        ).raise_for_status()
        httpx.post(f"{es_two_stage}/wave7-docs/_refresh", timeout=30).raise_for_status()

    warm, response = _scoped_on_one_broker(
        config,
        [("classification", "!=", "top secret"), ("owner", "!=", "finance dept")],
        between=_extend_the_index,
    )

    assert _titles(warm) == {"cafeteria menu"}, (
        f"control failed: the already-mapped field returned {_titles(warm)}; "
        f"the cache-refresh defect cannot be read off this run"
    )
    assert _titles(response) == {"nuclear launch codes", "cafeteria menu", "cafeteria roster"}, (
        f"owner != 'finance dept' returned {sorted(_titles(response))}. 'finance "
        f"dept' analyses to ['finance','dept'], so a must_not on the analysed "
        f"field excludes both documents that mention either token -- or none. "
        f"elasticsearch.py:_exact_field read a mapping cached before 'owner' "
        f"existed and fell back to the bare analysed field."
    )


@pytest.mark.parametrize(
    ("operator", "value", "expected"),
    [
        # Analysed: no term of 'top secret' sorts at or after 'top s' ('top' is
        # shorter, 'secret' starts with 's'), so the document silently vanishes.
        (">=", "top s", {"nuclear launch codes"}),
        # Analysed: the term 'top' sorts before 'top s', so the top-secret
        # document comes back through a constraint that excludes it -- fail-open.
        ("<", "top s", {"cafeteria menu"}),
    ],
)
def test_w73_es_range_operators_run_against_the_exact_field(
    es_two_stage: str,
    write_config: Any,
    monkeypatch: pytest.MonkeyPatch,
    operator: str,
    value: str,
    expected: set[str],
) -> None:
    """Range operators need a verbatim field just as much as ``=`` does.

    ``_EXACT_OPERATORS`` excluded ``<``/``>``/``<=``/``>=``/``BETWEEN`` with the
    comment "they are already lexicographic". They are -- over the *analysed
    terms*, one per whitespace-separated word. On a dynamically-mapped string a
    range bound that falls inside a multi-word value therefore compares against
    'top' and 'secret' rather than 'top secret', and the answer is wrong in both
    directions with no error to report it.
    """
    monkeypatch.setenv("WAVE7_ES_URL", es_two_stage)
    config = _es_config(write_config, "wave7-docs")
    response = _scoped(config, "classification", operator, value)
    assert _titles(response) == expected, (
        f"classification {operator} {value!r} returned {sorted(_titles(response))}, "
        f"expected {sorted(expected)}. The range builders run against the bare "
        f"analysed field (elasticsearch.py:_EXACT_OPERATORS)."
    )


def test_w73_s3_ands_two_constraints_on_the_same_field(
    minio_endpoint: tuple[str, str, str], write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two constraints on ``key`` must both apply; today the last one wins.

    ``_client_kwargs``/the scope loop assign ``exact_key`` and ``prefix``
    rather than accumulating, so a rule that narrows ``key`` twice keeps only
    the second narrowing. A policy that says "keys under restricted/ AND not
    the payroll object" returns the payroll object.
    """
    from nautilus import Broker

    endpoint, access, secret = minio_endpoint
    bucket = "wave7"

    async def _seed() -> None:
        from aiobotocore.session import AioSession

        session = AioSession()
        async with session.create_client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access,
            aws_secret_access_key=secret,
            region_name="us-east-1",
        ) as s3:
            with contextlib.suppress(Exception):
                await s3.create_bucket(Bucket=bucket)
            for key, body in (
                ("restricted/payroll.txt", b"SALARIES"),
                ("restricted/notes.txt", b"harmless"),
                ("open/menu.txt", b"tacos"),
            ):
                await s3.put_object(Bucket=bucket, Key=key, Body=body)

    asyncio.run(_seed())
    monkeypatch.setenv("WAVE7_S3", f"{endpoint}?region=us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", access)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", secret)
    config = write_config(
        {
            "sources": [
                {
                    "id": "src",
                    "type": "s3",
                    "description": "objects",
                    "classification": "unclassified",
                    "data_types": ["objects"],
                    "allowed_purposes": [],
                    "connection": "${WAVE7_S3}",
                    "table": bucket,
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    async def _run(constraints: list[dict[str, Any]]) -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest(
                "a",
                "objects",
                {"purpose": "p", "session_id": "s1", "scope_constraints": constraints},
            )
        finally:
            await broker.aclose()

    def _keys(response: Any) -> set[str]:
        return {r.get("key") for r in response.data.get("src", [])}

    control = asyncio.run(
        _run([{"source_id": "src", "field": "key", "operator": "LIKE", "value": "restricted/%"}])
    )
    assert _keys(control) == {"restricted/payroll.txt", "restricted/notes.txt"}, (
        f"control failed: a single prefix constraint returned {sorted(_keys(control))}"
    )

    # Narrow first, wide second: with "last assignment wins" the wide bound
    # survives and the payroll object comes back. Ordering the other way round
    # would pass for the wrong reason.
    response = asyncio.run(
        _run(
            [
                {
                    "source_id": "src",
                    "field": "key",
                    "operator": "LIKE",
                    "value": "restricted/notes%",
                },
                {"source_id": "src", "field": "key", "operator": "LIKE", "value": "restricted/%"},
            ]
        )
    )
    assert _keys(response) == {"restricted/notes.txt"}, (
        f"two narrowing constraints on 'key' returned {sorted(_keys(response))}; "
        f"s3.py assigns prefix/exact_key instead of intersecting, so only the "
        f"last constraint on a field survives"
    )


def test_w73_influx_intersects_two_time_bounds(
    influx: tuple[str, str, str, str], write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two lower bounds on ``_time`` must intersect, not overwrite.

    ``range_start = _flux_time(value)`` assigns. A rule that already narrowed
    the window to the last hour is silently widened back to 30 days by a
    second, looser bound -- the wrong direction for a scope constraint, and
    reachable for the first time now that time literals actually compile.
    """
    import httpx

    url, org, bucket, token = influx
    now_ns = time.time_ns()
    # The bucket is session-scoped and other tests write into it, so every
    # point carries a tag unique to this run and every query filters on it.
    run = f"w73-{os.getpid()}"
    lines = "\n".join(
        f"cpu,host=web-{i},run={run} usage={i}i {now_ns - i * 3600 * 1_000_000_000}"
        for i in range(6)
    )
    httpx.post(
        f"{url}/api/v2/write",
        params={"org": org, "bucket": bucket, "precision": "ns"},
        headers={"Authorization": f"Token {token}"},
        content=lines,
        timeout=30,
    ).raise_for_status()

    monkeypatch.setenv("INFLUXDB_V2_ORG", org)
    monkeypatch.setenv("INFLUXDB_V2_TOKEN", token)
    monkeypatch.setenv("WAVE7_INFLUX", url)
    config = write_config(
        {
            "sources": [
                {
                    "id": "src",
                    "type": "influxdb",
                    "description": "metrics",
                    "classification": "unclassified",
                    "data_types": ["metrics"],
                    "allowed_purposes": [],
                    "connection": "${WAVE7_INFLUX}",
                    "table": bucket,
                }
            ],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    from nautilus import Broker

    async def _run(constraints: list[dict[str, Any]]) -> Any:
        broker = Broker.from_config(config)
        try:
            return await broker.arequest(
                "a",
                "metrics",
                {"purpose": "p", "session_id": "s1", "scope_constraints": constraints},
            )
        finally:
            await broker.aclose()

    tight = {"source_id": "src", "field": "_time", "operator": ">=", "value": "-2h"}
    loose = {"source_id": "src", "field": "_time", "operator": ">=", "value": "-30d"}
    mine = {"source_id": "src", "field": "run", "operator": "=", "value": run}

    control = asyncio.run(_run([tight, mine]))
    narrow = len(control.data.get("src", []))
    assert 0 < narrow < 6, f"control failed: the -2h window returned {narrow} rows, expected 1-5"

    response = asyncio.run(_run([tight, loose, mine]))
    assert len(response.data.get("src", [])) == narrow, (
        f"a narrow bound followed by a looser one returned "
        f"{len(response.data.get('src', []))} rows against {narrow} for the "
        f"narrow bound alone. influxdb.py assigns range_start; the last bound "
        f"wins, so a second constraint widens the scope."
    )


# ===========================================================================
# Gate 4 -- the audit readers do not read the log the broker writes
# ===========================================================================


def test_w74_the_audit_api_reads_the_log_the_broker_writes(
    pg_dsn: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``GET /v1/audit`` must return the entries the request just wrote.

    Wave 4 made ``audit.path`` resolve against the config directory and exposed
    the resolved value as ``broker.audit_path``. One reader was updated
    (``fastapi_app.py`` ``/v1/audit/verify``); ``fastapi_app.py``'s
    ``AuditReader`` dependency and ``ui/dependencies.py`` still pass the raw
    config string, which is relative to the *process* cwd. The incident-response
    surface answers HTTP 200 with an empty trail.
    """
    import yaml
    from fastapi.testclient import TestClient

    from nautilus.transport.fastapi_app import create_app

    cfg_dir = tmp_path / "deploy"
    cfg_dir.mkdir()
    (cfg_dir / "nautilus.yaml").write_text(
        yaml.safe_dump(
            {
                "sources": [_pg_source()],
                "agents": {"a": {"id": "a", "clearance": "unclassified"}},
                # Relative on purpose: this is what the shipped examples write.
                "audit": {"path": "audit.jsonl"},
                "attestation": {"enabled": True},
                "rules": {"packs": [], "user_rules_dirs": []},
                "api": {"keys": ["k"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    # The process cwd is deliberately not the config dir -- that is the whole defect.
    monkeypatch.chdir(tmp_path)

    app = create_app(config_path=str(cfg_dir / "nautilus.yaml"))
    with TestClient(app) as client:
        posted = client.post(
            "/v1/request",
            headers={"X-API-Key": "k"},
            json={
                "agent_id": "a",
                "intent": "patients",
                "context": {"purpose": "p", "session_id": "s1"},
            },
        )
        assert posted.status_code == 200, posted.text
        request_id = posted.json()["request_id"]
        written = Path(app.state.broker.audit_path)
        assert written.exists() and written.read_text().strip(), (
            f"control failed: the broker wrote no audit log at {written}"
        )

        listed = client.get("/v1/audit", headers={"X-API-Key": "k"})

    assert listed.status_code == 200, listed.text
    entries = listed.json().get("entries", [])
    assert any(e.get("request_id") == request_id for e in entries), (
        f"GET /v1/audit returned {len(entries)} entries and none of them is the "
        f"request just made ({request_id}). The broker wrote {written}; the "
        f"reader was pointed at the unresolved config string "
        f"(fastapi_app.py AuditReader dependency, ui/dependencies.py:get_audit_path)."
    )


# ===========================================================================
# Gate 5 -- the chained attestation sink locks the file in its constructor
# ===========================================================================


def test_w75_a_second_broker_can_be_built_while_one_is_serving(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A read-only CLI must be able to build a Broker against a live config.

    ``ChainedFileAttestationSink.__init__`` takes an exclusive ``flock`` so a
    second writer cannot fork the hash chain. That is the right guarantee taken
    at the wrong moment: ``nautilus adapters list``/``schema-ack`` construct a
    Broker to read configuration and never write an attestation, and they now
    fail while the server runs. ``schema-ack`` is the only documented way to
    clear a schema-drift quarantine, so the operator's recovery path is the
    thing the lock blocks.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    chain = tmp_path / "chain.jsonl"
    config = write_config(
        {
            "sources": [_pg_source()],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
            "attestation": {
                "enabled": True,
                "sink": {"type": "file", "path": str(chain), "chained": True},
            },
        }
    )

    from nautilus import Broker

    serving = Broker.from_config(config)
    try:
        second = Broker.from_config(config)
        second.close()
    except Exception as exc:  # noqa: BLE001 - the pin is that this does not raise
        pytest.fail(
            f"building a second Broker against a live config raised "
            f"{type(exc).__name__}: {exc}. The chained sink takes its flock in "
            f"__init__ (attestation_sink.py); it belongs at first write, or the "
            f"CLI needs a no-sink construction path."
        )
    finally:
        serving.close()


# ===========================================================================
# Gate 6 -- the schema-drift gate races the connect lock
# ===========================================================================


def test_w76_the_drift_gate_runs_before_the_adapter_is_marked_connected(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent cold starts must not let a drifted source through.

    ``_check_adapter_schema`` runs outside the per-source connect lock and
    after ``_connected_adapters.add``, so of two requests arriving together the
    second sees the adapter as connected, skips the gate, and queries a source
    whose schema no longer matches its signed baseline. The gate is the control;
    a race that skips it is the control not existing.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [_pg_source()],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    from nautilus import Broker

    async def _run() -> list[Any]:
        broker = Broker.from_config(config)
        # Plant the baseline through the broker's own store so it lands wherever
        # that broker reads from, rather than at a path this test guessed.
        broker.fingerprint_store.record("src", "sha256:not-the-live-schema")
        try:
            return await asyncio.gather(
                *[
                    broker.arequest("a", "patients", {"purpose": "p", "session_id": f"s{i}"})
                    for i in range(4)
                ]
            )
        finally:
            await broker.aclose()

    responses = asyncio.run(_run())
    served = [r for r in responses if r.data.get("src")]
    assert not served, (
        f"{len(served)} of 4 concurrent requests were served rows from a source "
        f"whose fingerprint does not match its baseline. The drift check runs "
        f"outside the connect lock (broker.py _prepare_adapter/_check_adapter_schema)."
    )


def test_w76_an_upgrade_does_not_quarantine_every_existing_source(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A baseline written by the previous release must not read as drift.

    Wave 5 narrowed the Postgres fingerprint to the declared table. That is the
    right scope, and it changes the fingerprint of every source recorded under
    the old scope, so an operator who upgrades finds every Postgres source
    quarantined with no migration path. A fingerprint format needs a version
    tag and a one-time re-baseline on mismatch, or the change is a breaking one
    dressed as a fix.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [_pg_source()],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
        }
    )

    from nautilus import Broker

    def _plant_legacy_baseline(store: Any) -> None:
        """Write the shape 0.2.x wrote: a pre-narrowing fingerprint, no format tag.

        Through the store's own path resolver -- ``record()`` would stamp the
        current format, and the legacy shape is the whole point.
        """
        legacy = Path(store._path_for("src"))  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(
            json.dumps({"adapter_id": "src", "fingerprint": "sha256:" + "0" * 64}),
            encoding="utf-8",
        )

    async def _run() -> Any:
        broker = Broker.from_config(config)
        _plant_legacy_baseline(broker.fingerprint_store)
        try:
            return await broker.arequest("a", "patients", {"purpose": "p", "session_id": "s1"})
        finally:
            await broker.aclose()

    response = asyncio.run(_run())
    assert response.data.get("src"), (
        "a source carrying a baseline written before the fingerprint narrowed is "
        "quarantined on upgrade with no migration path. The stored fingerprint "
        "needs a format version so a mismatch of *format* re-baselines instead "
        "of quarantining (broker.py _check_adapter_schema, adapters/schema.py)."
    )


# ===========================================================================
# Gate 7 -- the MCP transport hands two agents the same session id
# ===========================================================================


def test_w77_mcp_http_does_not_share_one_session_across_callers(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Session state must not be shared between unrelated MCP callers.

    ``mcp_server.py`` built the server with ``stateless_http=True``, so there
    was no transport session at all. ``Context`` has no ``session_id``
    attribute either, so ``_resolve_session`` fell through to
    ``ctx.request_id`` -- the *client's* JSON-RPC id, which every client starts
    at 1. Two unrelated agents that did not declare a session id therefore both
    landed on session "1" and accumulated into one ledger.

    Neither caller declares a ``session_id`` here, and both send the same
    JSON-RPC id, which is what real clients do.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    config = write_config(
        {
            "sources": [
                _pg_source(id="pii_ssn", data_types=["pii", "ssn"], classification="confidential")
            ],
            "agents": {
                "alpha": {"id": "alpha", "clearance": "confidential"},
                "beta": {"id": "beta", "clearance": "confidential"},
            },
            "api": {"keys": ["k-alpha", "k-beta"]},
        }
    )

    from starlette.testclient import TestClient

    from nautilus import Broker
    from nautilus.transport.mcp_server import create_server, http_app

    broker = Broker.from_config(config)
    app = http_app(create_server(None, existing_broker=broker), api_keys=["k-alpha", "k-beta"])

    def _call(client: Any, agent_id: str, key: str) -> str:
        """Handshake as a fresh MCP client and run one tool call; return its session id."""
        headers = _mcp_handshake(
            client,
            {
                "X-API-Key": key,
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
        )
        called = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                # The same id both callers use: a fresh client starts at 1.
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "nautilus_request",
                    "arguments": {
                        "agent_id": agent_id,
                        "intent": "ssn",
                        # No session_id: the transport must supply one.
                        "context": {"purpose": "care"},
                    },
                },
            },
        )
        assert called.status_code == 200, f"control failed: MCP tools/call said {called.text}"
        payload = called.json()["result"]["structuredContent"]
        token = payload.get("attestation_token")
        assert token, f"control failed: the response carried no attestation: {payload}"
        # The signed attestation is where the session the request actually ran
        # under is recorded; the tool result does not echo it back.
        body = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        session_id = claims.get("session_id")
        assert session_id, f"control failed: the attestation carried no session id: {claims}"
        return str(session_id)

    try:
        with TestClient(app, base_url="http://127.0.0.1:8000") as client:
            alpha = _call(client, "alpha", "k-alpha")
            beta = _call(client, "beta", "k-beta")
    finally:
        broker.close()

    assert alpha != beta, (
        f"two unrelated MCP callers both resolved to session {alpha!r}, so they "
        f"share one cumulative-exposure ledger and one working memory. The "
        f"server ran stateless, and _resolve_session fell back to the client's "
        f"own JSON-RPC request id (mcp_server.py)."
    )


# ===========================================================================
# Gate 8 -- `rules validate` still passes rules that brick the broker
# ===========================================================================


_BAD_RULES: dict[str, str] = {
    "slot_allowed_values": """
module: nautilus-routing
ruleset: w7-bad-operator
version: "1.0"
rules:
  - name: bad-operator
    when:
      - template: source
        conditions:
          - slot: id
            bind: ?sid
    then:
      action: route
      reason: "r"
      assert:
        - template: scope_constraint
          slots:
            source_id: "?sid"
            field: "region"
            operator: "≈"
            value: "x"
""",
    "unknown_slot": """
module: nautilus-routing
ruleset: w7-unknown-slot
version: "1.0"
rules:
  - name: unknown-slot
    when:
      - template: source
        conditions:
          - slot: security_officer
            bind: ?x
    then:
      action: deny
      reason: "r"
""",
    "unknown_module": """
module: no-such-module
ruleset: w7-unknown-module
version: "1.0"
rules:
  - name: unknown-module
    when:
      - template: source
        conditions:
          - slot: id
            bind: ?sid
    then:
      action: deny
      reason: "r"
""",
}


@pytest.mark.parametrize("case", sorted(_BAD_RULES))
def test_w78_rules_validate_rejects_what_the_engine_rejects(tmp_path: Path, case: str) -> None:
    """``nautilus rules validate`` is the documented ship gate; it must compile.

    ``validate_static`` stops at ``compile_rule`` and never builds the rule into
    an engine, so four classes of rule pass the gate and then raise
    ``PolicyEngineError`` at ``FathomRouter`` construction -- the broker does
    not start, in production, on a file the shipped validator called ``OK``.
    """
    rule_file = tmp_path / f"{case}.yaml"
    rule_file.write_text(textwrap.dedent(_BAD_RULES[case]).lstrip(), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "nautilus.cli", "rules", "validate", str(rule_file)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode != 0, (
        f"`rules validate` accepted {case!r} (exit 0, stdout={proc.stdout.strip()!r}). "
        f"The engine rejects it at build time, so the gate passes a file that "
        f"stops the broker from starting (rkm/validator/static.py)."
    )


# ===========================================================================
# The multi-process track -- every lock is an in-process dict
# ===========================================================================


_CHILD = """
import asyncio, json, sys
from nautilus import Broker

config, agent, kinds = sys.argv[1], sys.argv[2], sys.argv[3].split(",")

async def main():
    broker = Broker.from_config(config)
    await broker.setup()
    try:
        for k in kinds:
            await broker.arequest(agent, k, {"purpose": "care", "session_id": "shared"})
    finally:
        await broker.aclose()

asyncio.run(main())
"""


def test_w79_two_broker_processes_share_one_exposure_ledger(
    pg_dsn: str, write_config: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Behind a load balancer the exposure ledger must still be one ledger.

    Every lock added in Waves 1 and 6 is an ``asyncio.Lock`` in a per-process
    dict, so two brokers sharing one Postgres session store serialise against
    nothing and lose each other's updates. The session store is explicitly the
    shared-state component -- an operator who runs two replicas because the
    docs describe a stateless HTTP service gets a cumulative-exposure control
    that silently does not accumulate.
    """
    monkeypatch.setenv("WAVE7_PG_DSN", pg_dsn)
    kinds = ("ssn", "dob", "phone", "email")
    config = write_config(
        {
            "sources": [
                _pg_source(id=f"pii_{k}", data_types=["pii", k], classification="confidential")
                for k in kinds
            ],
            "agents": {"analyst": {"id": "analyst", "clearance": "confidential"}},
            "session_store": {"backend": "postgres", "dsn": pg_dsn},
        }
    )
    child = tmp_path / "child.py"
    child.write_text(_CHILD, encoding="utf-8")

    from nautilus import Broker

    async def _create_schema() -> None:
        # Both replicas call setup(); doing it once here keeps the pin about
        # the ledger rather than about two CREATE TYPE statements racing.
        broker = Broker.from_config(config)
        await broker.setup()
        await broker.aclose()

    asyncio.run(_create_schema())

    env = dict(os.environ, WAVE7_PG_DSN=pg_dsn)
    procs = [
        subprocess.Popen(  # noqa: S603
            [sys.executable, str(child), config, "analyst", ",".join(half)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for half in (kinds[:2], kinds[2:])
    ]
    for p in procs:
        out, err = p.communicate(timeout=300)
        assert p.returncode == 0, f"child broker failed: {err or out}"

    async def _read() -> set[str]:
        broker = Broker.from_config(config)
        await broker.setup()
        try:
            store: Any = broker.session_store
            state = await store.aget("shared") if hasattr(store, "aget") else store.get("shared")
            return set((state or {}).get("sources_visited", []))
        finally:
            await broker.aclose()

    visited = asyncio.run(_read())
    assert visited == {f"pii_{k}" for k in kinds}, (
        f"two broker processes against one shared session store left the ledger "
        f"holding {sorted(visited)}. The read-merge-write is serialised by an "
        f"in-process asyncio.Lock (broker.py:_session_locks), which is not a "
        f"lock at all across replicas."
    )


def test_w79_a_token_minted_by_one_process_verifies_in_another(tmp_path: Path) -> None:
    """Session tokens must verify across replicas, or they are not a protocol.

    ``KeyRing()`` generated its own signing key in its constructor and had no
    persistence at all, so every broker process held a different key and a token
    minted by replica A was rejected by replica B with ``unknown_kid``. Every
    documented use of the session token -- hand it to an adapter, present it on
    the next request -- crosses a replica boundary the moment there are two, and
    the docs describe the HTTP surface as stateless and horizontally scalable.

    Two rings over one path stand in for two replicas over a shared volume. The
    controls are below: a ring verifies itself, and a ring pointed somewhere
    else does not.
    """
    from nautilus.attestation.key_ring import KeyRing
    from nautilus.attestation.session_token import SessionTokenError, SessionTokenService

    shared = tmp_path / "keyring.json"
    replica_a = SessionTokenService(key_ring=KeyRing(shared), broker_instance_id="nautilus")
    token = replica_a.issue(session_id="s1", agent_id="a", purpose="care", clearance="unclassified")
    assert replica_a.verify(token).session_id == "s1", "control failed: a ring cannot verify itself"

    replica_b = SessionTokenService(key_ring=KeyRing(shared), broker_instance_id="nautilus")
    try:
        claims = replica_b.verify(token)
    except SessionTokenError as exc:
        pytest.fail(
            f"a token minted by one broker process was rejected by another "
            f"({exc.reason_code}) although both rings share {shared}. KeyRing "
            f"material has to be persisted for a multi-replica deployment "
            f"(attestation/key_ring.py:KeyRing.__init__)."
        )
    assert claims.session_id == "s1"

    # Control: sharing is the *path's* doing, not a ring that verifies anything.
    stranger = SessionTokenService(
        key_ring=KeyRing(tmp_path / "other.json"), broker_instance_id="nautilus"
    )
    with pytest.raises(SessionTokenError):
        stranger.verify(token)


def test_w79_a_configured_key_ring_path_survives_a_broker_restart(
    write_config: Any, tmp_path: Path
) -> None:
    """``session_tokens.key_ring_path`` has to reach the ring the broker mints with.

    The config field is only worth anything if ``Broker.from_config`` passes it
    down; a restart is the cheapest way to see that it did.
    """
    from nautilus import Broker

    ring_path = tmp_path / "ring" / "keyring.json"
    config = write_config(
        {
            "sources": [],
            "agents": {"a": {"id": "a", "clearance": "unclassified"}},
            "session_tokens": {"enabled": True, "key_ring_path": str(ring_path)},
        }
    )

    first = Broker.from_config(config)
    try:
        ring = first.key_ring
        assert ring is not None, "control failed: session tokens are enabled but there is no ring"
        kid = ring.primary().kid
    finally:
        first.close()

    assert ring_path.exists(), f"the broker minted a ring but wrote nothing to {ring_path}"
    second = Broker.from_config(config)
    try:
        assert second.key_ring is not None
        assert second.key_ring.primary().kid == kid, (
            "a restarted broker minted a fresh signing key although "
            "session_tokens.key_ring_path names a persisted ring"
        )
    finally:
        second.close()
